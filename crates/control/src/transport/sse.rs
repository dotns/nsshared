#![forbid(unsafe_code)]

//! SSE transport: standard TLS/HTTPS via `tokio-rustls`.

use std::sync::Arc;

use futures_util::future::BoxFuture;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

use super::BoxStream;
use crate::{
    Error,
    auth::unauthorized_error_from_body,
    envelope::ControlEnvelope,
    transport::{ControlTransport, framing},
};

/// Control transport that wraps a standard TLS connection.
///
/// DPI can see: TCP + TLS handshake with SNI.  Best for normal networks.
pub struct SseTransport {
    connector: Option<TlsConnector>,
}

impl SseTransport {
    /// Build an `SseTransport` suitable for `base_url`.
    ///
    /// `http://` is treated as plaintext HTTP. `https://` and scheme-less URLs
    /// use TLS with Mozilla WebPKI roots. `noise://` and `quic://` are rejected
    /// here because those schemes must be routed through their matching secure
    /// transport, not plaintext SSE.
    pub fn from_base_url(base_url: &str) -> Result<Self, Error> {
        if base_url.starts_with("noise://") || base_url.starts_with("quic://") {
            return Err(Error::Connect(
                "noise/quic URLs require the matching control transport mode".to_string(),
            ));
        }
        if base_url.starts_with("http://") {
            return Ok(Self { connector: None });
        }
        Self::with_webpki_roots()
    }

    /// Build a plaintext HTTP `SseTransport`.
    pub fn plaintext() -> Self {
        Self { connector: None }
    }

    /// Build an `SseTransport` using the Mozilla WebPKI root certificates.
    pub fn with_webpki_roots() -> Result<Self, Error> {
        // Install the ring crypto provider (no-op if already installed).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self {
            connector: Some(TlsConnector::from(Arc::new(config))),
        })
    }
}

impl ControlTransport for SseTransport {
    fn connect<'a>(&'a self, endpoint: &'a str) -> BoxFuture<'a, Result<BoxStream, Error>> {
        Box::pin(async move {
            let tcp = TcpStream::connect(endpoint)
                .await
                .map_err(|e| Error::Connect(format!("TCP connect to {endpoint}: {e}")))?;

            // Extract the hostname for SNI (strip port if present).
            let host = endpoint
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(endpoint);

            let Some(connector) = self.connector.as_ref() else {
                debug!(endpoint, "SseTransport: plaintext HTTP connection");
                return Ok(BoxStream::new(tcp));
            };

            let server_name = ServerName::try_from(host.to_string())
                .map_err(|e| Error::Connect(format!("invalid server name '{host}': {e}")))?;

            debug!(endpoint, "SseTransport: TLS handshake");
            let tls = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| Error::Connect(format!("TLS handshake with {endpoint}: {e}")))?;

            Ok(BoxStream::new(tls))
        })
    }

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
        _envelope: ControlEnvelope,
        bearer_token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BoxStream, Error>> {
        Box::pin(async move {
            let bearer_token = bearer_token
                .ok_or_else(|| Error::Auth("missing bearer token for config.stream".into()))?;
            let host = endpoint_host(endpoint);
            let mut stream = self.connect(endpoint).await?;
            // The deployed NSD config stream is the GET route. The bearer
            // comes from the same control auth flow that follows envelope
            // registration; pushed events are signed `config-envelope.v1` SSE
            // frames verified by `crate::sse::SseFramer`.
            http_open_get_stream(&mut stream, host, "/api/v1/config/stream", bearer_token).await?;
            Ok(stream)
        })
    }

    fn name(&self) -> &str {
        "sse"
    }
}

/// Map an HTTP status + CBOR body into a `ControlEnvelope` result.
///
/// Shared by SSE `call()` and the plain-HTTP unit tests.
pub(crate) fn map_status_to_envelope(status: u16, body: &[u8]) -> Result<ControlEnvelope, Error> {
    match status {
        200 => ControlEnvelope::from_cbor(body).map_err(Error::from),
        401 => Err(unauthorized_error_from_body(
            body_text(body).as_ref(),
            "signed-envelope endpoint",
        )),
        409 => Err(crate::conflict_error_from_body(body)),
        408 => Err(Error::Timeout),
        s => Err(Error::ServerError(format!(
            "HTTP {s}: response body redacted ({} bytes)",
            body.len()
        ))),
    }
}

pub(crate) fn endpoint_host(endpoint: &str) -> &str {
    endpoint
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(endpoint)
}

fn body_text(body: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(body)
}

pub(crate) async fn http_open_get_stream<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    bearer_token: &str,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if bearer_token.contains('\r') || bearer_token.contains('\n') {
        return Err(Error::Auth("invalid bearer token for config.stream".into()));
    }

    let header = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Authorization: Bearer {bearer_token}\r\n\
         Accept: text/event-stream\r\n\
         Cache-Control: no-cache\r\n\
         Connection: keep-alive\r\n\
         \r\n"
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|e| Error::Connect(format!("write stream headers: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::Connect(format!("flush stream request: {e}")))?;

    let mut header_buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| Error::Connect(format!("read stream header byte: {e}")))?;
        header_buf.push(byte[0]);
        if header_buf.len() > framing::MAX_HTTP_HEADERS {
            return Err(Error::Sse(format!(
                "HTTP response headers exceed {} bytes",
                framing::MAX_HTTP_HEADERS
            )));
        }
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let header_str = std::str::from_utf8(&header_buf)
        .map_err(|_| Error::Sse("non-UTF-8 HTTP stream headers".into()))?;
    let status_line = header_str
        .lines()
        .next()
        .ok_or_else(|| Error::Sse("empty HTTP stream response".into()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Sse(format!("invalid HTTP status line: {status_line:?}")))?;
    if !(200..300).contains(&status) {
        return Err(Error::Connect(format!("SSE stream open failed: {status}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{self, ControlEnvelope};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use tokio::net::TcpListener;

    fn signed_envelope(api: &str) -> ControlEnvelope {
        let signer = SigningKey::generate(&mut OsRng);
        let pk = signer.verifying_key().to_bytes();
        ControlEnvelope::sign_request(api, Some("m-1".to_string()), pk, Vec::new(), |msg| {
            signer.sign(msg).to_bytes()
        })
        .unwrap()
    }

    // A 409 whose body names a known conflict token must surface as the typed
    // conflict so callers can distinguish replay from namespace collisions.
    #[test]
    fn conflict_status_distinguishes_known_conflicts_from_replay_fallback() {
        let with_epoch = br#"{"error":"version_conflict","current_epoch":42}"#;
        assert!(matches!(
            map_status_to_envelope(409, with_epoch).unwrap_err(),
            Error::VersionConflict {
                current_epoch: Some(42)
            }
        ));

        let without_epoch = br#"{"error":"version_conflict"}"#;
        assert!(matches!(
            map_status_to_envelope(409, without_epoch).unwrap_err(),
            Error::VersionConflict {
                current_epoch: None
            }
        ));

        assert!(matches!(
            map_status_to_envelope(409, br#"{"error":"replay"}"#).unwrap_err(),
            Error::Replay
        ));
        assert!(matches!(
            map_status_to_envelope(409, br#"{"error":"key_namespace_overlap"}"#).unwrap_err(),
            Error::KeyNamespaceOverlap
        ));
        assert!(matches!(
            map_status_to_envelope(409, b"not json").unwrap_err(),
            Error::Replay
        ));
    }

    #[test]
    fn server_error_redacts_response_body() {
        let body = b"server echoed bearer-token-that-must-not-hit-logs";
        let err = map_status_to_envelope(500, body).unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("HTTP 500"));
        assert!(rendered.contains("response body redacted"));
        assert!(rendered.contains(&body.len().to_string()));
        assert!(!rendered.contains("bearer-token-that-must-not-hit-logs"));
        assert!(!rendered.contains("server echoed"));
    }

    #[tokio::test]
    async fn connect_stream_gets_config_stream_with_bearer_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut header_buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                sock.read_exact(&mut byte).await.unwrap();
                header_buf.push(byte[0]);
                if header_buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let headers = String::from_utf8(header_buf).unwrap();
            assert!(headers.starts_with("GET /api/v1/config/stream HTTP/1.1"));
            assert!(
                headers
                    .lines()
                    .any(|line| line == "Authorization: Bearer token-from-register"),
                "config stream request must carry the registered control bearer"
            );
            assert!(
                !headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("content-length:")),
                "GET config stream request must not carry a body"
            );

            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n",
            )
            .await
            .unwrap();
            sock.flush().await.unwrap();
        });

        let transport = SseTransport::plaintext();
        let mut stream = transport
            .connect_stream(
                &addr.to_string(),
                signed_envelope(envelope::api::CONFIG_STREAM),
                Some("token-from-register"),
            )
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connect_stream_fails_closed_without_bearer_token() {
        let transport = SseTransport::plaintext();
        let err = transport
            .connect_stream(
                "127.0.0.1:9",
                signed_envelope(envelope::api::CONFIG_STREAM),
                None,
            )
            .await
            .err()
            .expect("missing bearer token must fail closed");

        assert!(matches!(err, Error::Auth(msg) if msg.contains("missing bearer token")));
    }
}
