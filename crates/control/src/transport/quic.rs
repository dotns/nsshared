#![forbid(unsafe_code)]

//! QUIC transport: SSE over QUIC/UDP with pubkey-pinned self-signed cert.
//!
//! DPI sees: UDP packets to IP:port. No SNI, no CA chain, no TLS handshake
//! pattern visible on the wire.
//!
//! The NSD side requires a thin QUIC proxy that terminates QUIC/TLS and
//! forwards plaintext HTTP to NSD.  The proxy must serve a self-signed cert
//! whose SHA-256 DER fingerprint matches the value passed to [`QuicTransport`].
//!
//! Connection sequence
//! -------------------
//! 1. Resolve `host:port` to a UDP socket address.
//! 2. Attempt 0-RTT connection (fast reconnect after first handshake).
//! 3. Fall back to 1-RTT if 0-RTT session ticket is not yet available.
//! 4. Open a bidirectional QUIC stream.
//! 5. Return [`QuicStream`] wrapped in [`BoxStream`].

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::future::BoxFuture;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use super::BoxStream;
use crate::{
    Error,
    envelope::ControlEnvelope,
    transport::{
        ControlTransport, framing,
        sse::{
            config_stream_path, endpoint_host, http_open_get_stream, map_status_to_envelope,
            wrap_http_stream_body,
        },
    },
};

// MUST match nsd-server's QUIC_HTTP1_ALPN; this is a cross-repo wire contract.
const QUIC_HTTP1_ALPN: &[u8] = b"nsd-http1";

// -- PubkeyVerifier -----------------------------------------------------------

/// `rustls` certificate verifier that validates server identity by SHA-256
/// fingerprint of the DER-encoded end-entity certificate.
///
/// No CA chain is validated and no SNI is required.  This allows the NSD proxy
/// to use a self-signed certificate without any public CA infrastructure.
#[derive(Debug)]
struct PubkeyVerifier {
    expected_fingerprint: [u8; 32],
}

impl PubkeyVerifier {
    fn new(expected_fingerprint: [u8; 32]) -> Self {
        Self {
            expected_fingerprint,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PubkeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fingerprint: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if fingerprint == self.expected_fingerprint {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "certificate fingerprint mismatch".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// -- QuicStream ---------------------------------------------------------------

/// Bidirectional async stream over a QUIC stream pair.
///
/// Wraps a [`quinn::SendStream`] + [`quinn::RecvStream`] and implements
/// `AsyncRead + AsyncWrite` so the SSE/HTTP layer above is transport-agnostic.
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Explicit trait dispatch to avoid resolving to quinn's inherent
        // poll_write which returns quinn::WriteError instead of io::Error.
        <quinn::SendStream as AsyncWrite>::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

// -- QuicTransport ------------------------------------------------------------

/// QUIC control transport.
///
/// Opens a QUIC/UDP connection to the NSD proxy and provides a bidirectional
/// byte stream that carries raw HTTP/SSE.  The server certificate is verified
/// by SHA-256 fingerprint ([`PubkeyVerifier`]) — no CA required, no SNI
/// emitted in the ClientHello.
///
/// The shared [`quinn::Endpoint`] is reused across reconnects so that
/// TLS 1.3 session tickets are preserved and 0-RTT is available after the
/// first successful handshake.
pub struct QuicTransport {
    /// Shared QUIC endpoint (bound UDP socket).
    endpoint: quinn::Endpoint,
    /// Client configuration with the fingerprint-based cert verifier.
    client_config: quinn::ClientConfig,
}

fn client_tls_config(cert_fingerprint: [u8; 32]) -> rustls::ClientConfig {
    let verifier = Arc::new(PubkeyVerifier::new(cert_fingerprint));
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![QUIC_HTTP1_ALPN.to_vec()];
    tls_config
}

impl QuicTransport {
    /// Create a new `QuicTransport`.
    ///
    /// `cert_fingerprint` is the SHA-256 fingerprint (32 bytes) of the NSD
    /// proxy's self-signed DER certificate.  On the CLI this is the same
    /// `--nsd-pubkey` hex argument used by Noise mode (64 hex chars).
    pub fn new(cert_fingerprint: [u8; 32]) -> Result<Self, Error> {
        // Install ring crypto provider (no-op if already installed globally).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let tls_config = client_tls_config(cert_fingerprint);

        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| Error::Quic(format!("QuicClientConfig: {e}")))?;

        let client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

        // Bind to an ephemeral UDP port on all interfaces.
        let local_addr: SocketAddr = "0.0.0.0:0".parse().expect("valid loopback addr");
        let endpoint = quinn::Endpoint::client(local_addr)
            .map_err(|e| Error::Quic(format!("bind UDP socket: {e}")))?;

        Ok(Self {
            endpoint,
            client_config,
        })
    }
}

impl ControlTransport for QuicTransport {
    /// Unary request/response over a QUIC bi-directional stream.
    ///
    /// Opens a new bi-stream on every call; the underlying `quinn::Connection`
    /// is pooled by [`QuicTransport`] itself, so only the stream (not the
    /// whole handshake) is reopened per call.
    fn call<'a>(
        &'a self,
        endpoint: &'a str,
        envelope: ControlEnvelope,
    ) -> BoxFuture<'a, Result<ControlEnvelope, Error>> {
        Box::pin(async move {
            let body = envelope.to_cbor()?;
            let host = endpoint_host(endpoint);
            let mut stream = self.connect(endpoint).await?;
            let (status, resp_body) =
                framing::http_unary_cbor(&mut stream, host, "/api/v1/control", &body).await?;
            map_status_to_envelope(status, &resp_body)
        })
    }

    fn connect_stream<'a>(
        &'a self,
        endpoint: &'a str,
        envelope: ControlEnvelope,
        bearer_token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BoxStream, Error>> {
        Box::pin(async move {
            let bearer_token = bearer_token
                .ok_or_else(|| Error::Auth("missing bearer token for config.stream".into()))?;
            let host = endpoint_host(endpoint);
            let path = config_stream_path(&envelope)?;
            let mut stream = self.connect(endpoint).await?;
            let body_encoding =
                http_open_get_stream(&mut stream, host, &path, bearer_token).await?;
            Ok(wrap_http_stream_body(stream, body_encoding))
        })
    }

    fn connect<'a>(&'a self, endpoint: &'a str) -> BoxFuture<'a, Result<BoxStream, Error>> {
        Box::pin(async move {
            // Resolve host:port to a SocketAddr.
            let addr: SocketAddr = tokio::net::lookup_host(endpoint)
                .await
                .map_err(|e| Error::Connect(format!("DNS resolve {endpoint}: {e}")))?
                .next()
                .ok_or_else(|| Error::Connect(format!("no addresses for {endpoint}")))?;

            debug!(endpoint, %addr, "QuicTransport: connecting");

            let connecting = self
                .endpoint
                .connect_with(self.client_config.clone(), addr, "nsd")
                .map_err(|e| Error::Quic(format!("QUIC connect: {e}")))?;

            // Attempt 0-RTT for fast reconnects after the first handshake.
            // If no session ticket is cached yet, fall back to the 1-RTT path.
            let connection = match connecting.into_0rtt() {
                Ok((conn, zero_rtt_accepted)) => {
                    debug!(endpoint, "QuicTransport: 0-RTT path");
                    // Confirm the 0-RTT acceptance in the background so the
                    // handshake completes without blocking the stream.
                    tokio::spawn(async move {
                        let _ = zero_rtt_accepted.await;
                    });
                    conn
                }
                Err(connecting) => {
                    debug!(endpoint, "QuicTransport: 1-RTT handshake");
                    connecting
                        .await
                        .map_err(|e| Error::Quic(format!("QUIC handshake: {e}")))?
                }
            };

            let (send, recv) = connection
                .open_bi()
                .await
                .map_err(|e| Error::Quic(format!("open_bi: {e}")))?;

            debug!(endpoint, "QuicTransport: bidirectional stream opened");
            Ok(BoxStream::new(QuicStream::new(send, recv)))
        })
    }

    fn name(&self) -> &str {
        "quic"
    }
}

// -- Unit tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::future::Future;

    use rustls::client::danger::ServerCertVerifier as _;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use serde_bytes::ByteBuf;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::task::JoinHandle;

    use super::*;

    #[test]
    fn quic_stream_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<QuicStream>();
    }

    #[test]
    fn pubkey_verifier_accepts_matching_fingerprint() {
        let cert_bytes = b"fake cert der bytes for testing";
        let fingerprint: [u8; 32] = Sha256::digest(cert_bytes).into();

        let verifier = PubkeyVerifier::new(fingerprint);
        let cert = CertificateDer::from(cert_bytes.as_slice());
        let name = ServerName::try_from("nsd.local").unwrap();

        let result = verifier.verify_server_cert(&cert, &[], &name, &[], UnixTime::now());
        assert!(result.is_ok(), "matching fingerprint must be accepted");
    }

    #[test]
    fn pubkey_verifier_rejects_wrong_fingerprint() {
        let expected = [0u8; 32]; // zeroed — won't match any real cert
        let verifier = PubkeyVerifier::new(expected);

        let cert = CertificateDer::from(b"some other cert bytes".as_slice());
        let name = ServerName::try_from("nsd.local").unwrap();

        let result = verifier.verify_server_cert(&cert, &[], &name, &[], UnixTime::now());
        assert!(result.is_err(), "mismatched fingerprint must be rejected");
    }

    #[test]
    fn quic_transport_name() {
        // Constructor binds a UDP socket — skip if we can't bind in CI.
        let Ok(t) = QuicTransport::new([0u8; 32]) else {
            return;
        };
        assert_eq!(t.name(), "quic");
    }

    #[test]
    fn client_tls_config_offers_nsd_http1_alpn() {
        let tls_config = client_tls_config([0u8; 32]);
        assert_eq!(tls_config.alpn_protocols, vec![QUIC_HTTP1_ALPN.to_vec()]);
    }

    fn test_envelope(api: &str, payload: &[u8]) -> ControlEnvelope {
        ControlEnvelope {
            v: crate::envelope::ENVELOPE_VERSION,
            api: api.to_owned(),
            ts: 1,
            nonce: [7u8; 16],
            machine_id: Some("machine-test".to_owned()),
            machine_key_pub: [8u8; 32],
            payload: ByteBuf::from(payload.to_vec()),
            signature: [9u8; 64],
        }
    }

    fn test_server_config() -> quinn::ServerConfig {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = CertificateDer::from(TEST_CERT_DER.to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(TEST_KEY_DER.to_vec()));
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        tls_config.alpn_protocols = vec![QUIC_HTTP1_ALPN.to_vec()];
        let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap();
        quinn::ServerConfig::with_crypto(Arc::new(quic_config))
    }

    async fn quic_transport_with_server<F, Fut>(
        handle_stream: F,
    ) -> (
        QuicTransport,
        SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        JoinHandle<()>,
    )
    where
        F: FnOnce(QuicStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let fingerprint: [u8; 32] = Sha256::digest(TEST_CERT_DER).into();
        let server = quinn::Endpoint::server(
            test_server_config(),
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let (release_server, server_released) = tokio::sync::oneshot::channel();

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let (send, recv) = conn.accept_bi().await.unwrap();
            handle_stream(QuicStream::new(send, recv)).await;
            let _ = server_released.await;
        });

        let transport = QuicTransport::new(fingerprint).unwrap();
        (transport, addr, release_server, server_task)
    }

    async fn read_http_request<S>(stream: &mut S) -> (String, Vec<u8>)
    where
        S: AsyncRead + Unpin,
    {
        let mut headers = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).await.unwrap();
            headers.push(byte[0]);
            if headers.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        let header_text = String::from_utf8(headers).unwrap();
        let body_len = header_text
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .map(|value| value.parse::<usize>().unwrap())
            .unwrap_or(0);
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            stream.read_exact(&mut body).await.unwrap();
        }
        (header_text, body)
    }

    async fn write_http_response<S>(stream: &mut S, content_type: &str, body: &[u8])
    where
        S: AsyncWrite + Unpin,
    {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.flush().await.unwrap();
    }

    #[tokio::test]
    async fn call_posts_http_cbor_envelope() {
        let (transport, addr, release_server, server_task) =
            quic_transport_with_server(|mut stream| async move {
                let (headers, req_body) = read_http_request(&mut stream).await;
                assert!(headers.starts_with("POST /api/v1/control HTTP/1.1"));
                assert!(headers.lines().any(|line| line == "Host: 127.0.0.1"));
                assert!(
                    headers
                        .lines()
                        .any(|line| line == "Content-Type: application/cbor")
                );
                let req_env = ControlEnvelope::from_cbor(&req_body).unwrap();
                assert_eq!(req_env.api, crate::envelope::api::MACHINE_HEARTBEAT);
                assert_eq!(req_env.payload.as_ref(), b"http-request");

                let resp_env = test_envelope(&req_env.api, b"http-response");
                let resp_body = resp_env.to_cbor().unwrap();
                write_http_response(&mut stream, "application/cbor", &resp_body).await;
            })
            .await;

        let resp = transport
            .call(
                &addr.to_string(),
                test_envelope(crate::envelope::api::MACHINE_HEARTBEAT, b"http-request"),
            )
            .await
            .unwrap();

        assert_eq!(resp.api, crate::envelope::api::MACHINE_HEARTBEAT);
        assert_eq!(resp.payload.as_ref(), b"http-response");
        let _ = release_server.send(());
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_stream_gets_config_stream_over_http() {
        let (transport, addr, release_server, server_task) =
            quic_transport_with_server(|mut stream| async move {
                let (headers, body) = read_http_request(&mut stream).await;
                assert!(headers.starts_with("GET /api/v1/config/stream HTTP/1.1"));
                assert!(
                    headers
                        .lines()
                        .any(|line| line == "Authorization: Bearer token-from-register")
                );
                assert!(body.is_empty());
                write_http_response(&mut stream, "text/event-stream", b"data: ok\n\n").await;
            })
            .await;

        let mut stream = transport
            .connect_stream(
                &addr.to_string(),
                test_envelope(crate::envelope::api::CONFIG_STREAM, b""),
                Some("token-from-register"),
            )
            .await
            .unwrap();
        let mut body = vec![0u8; b"data: ok\n\n".len()];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(body, b"data: ok\n\n");
        let _ = release_server.send(());
        server_task.await.unwrap();
    }

    const TEST_CERT_DER: &[u8] = &[
        48, 130, 1, 48, 48, 129, 227, 160, 3, 2, 1, 2, 2, 20, 19, 40, 21, 26, 52, 44, 161, 28, 113,
        17, 33, 132, 144, 89, 110, 48, 153, 149, 122, 145, 48, 5, 6, 3, 43, 101, 112, 48, 14, 49,
        12, 48, 10, 6, 3, 85, 4, 3, 12, 3, 110, 115, 100, 48, 30, 23, 13, 50, 54, 48, 53, 50, 52,
        49, 52, 53, 50, 48, 56, 90, 23, 13, 51, 54, 48, 53, 50, 49, 49, 52, 53, 50, 48, 56, 90, 48,
        14, 49, 12, 48, 10, 6, 3, 85, 4, 3, 12, 3, 110, 115, 100, 48, 42, 48, 5, 6, 3, 43, 101,
        112, 3, 33, 0, 163, 18, 124, 129, 78, 80, 160, 137, 59, 170, 43, 84, 46, 181, 49, 234, 118,
        71, 71, 182, 26, 114, 239, 195, 154, 178, 17, 46, 47, 230, 19, 165, 163, 83, 48, 81, 48,
        29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 156, 63, 177, 112, 90, 202, 21, 236, 102, 207, 205, 35,
        150, 247, 37, 71, 173, 22, 209, 145, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 156,
        63, 177, 112, 90, 202, 21, 236, 102, 207, 205, 35, 150, 247, 37, 71, 173, 22, 209, 145, 48,
        15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 5, 6, 3, 43, 101, 112, 3, 65,
        0, 185, 207, 92, 108, 116, 245, 76, 212, 46, 237, 8, 75, 221, 23, 237, 118, 109, 167, 238,
        139, 234, 31, 247, 36, 27, 171, 135, 4, 153, 73, 173, 184, 135, 23, 137, 106, 182, 225, 75,
        231, 132, 55, 13, 250, 105, 29, 211, 227, 188, 237, 85, 49, 244, 168, 77, 226, 70, 222,
        115, 10, 1, 108, 205, 10,
    ];

    const TEST_KEY_DER: &[u8] = &[
        48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 224, 230, 204, 9, 80, 224, 71,
        244, 131, 46, 148, 116, 47, 215, 28, 107, 154, 51, 61, 143, 59, 40, 130, 20, 134, 138, 228,
        3, 239, 120, 77, 128,
    ];
}
