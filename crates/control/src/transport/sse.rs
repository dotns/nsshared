#![forbid(unsafe_code)]

//! SSE transport: standard TLS/HTTPS via `tokio-rustls`.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::future::BoxFuture;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use super::BoxStream;
use crate::{
    Error, api,
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

            if let Err(e) = super::set_control_tcp_keepalive(&tcp) {
                warn!(endpoint, error = %e, "failed to enable TCP keepalive on control socket");
            }

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
        envelope: ControlEnvelope,
        bearer_token: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BoxStream, Error>> {
        Box::pin(async move {
            let bearer_token = bearer_token
                .ok_or_else(|| Error::Auth("missing bearer token for config.stream".into()))?;
            let host = endpoint_host(endpoint);
            let path = config_stream_path(&envelope)?;
            let mut stream = self.connect(endpoint).await?;
            // The deployed NSD config stream is the GET route. The bearer
            // comes from the same control auth flow that follows envelope
            // registration; pushed events are signed `config-envelope.v1` SSE
            // frames verified by `crate::sse::SseFramer`.
            let body_encoding =
                http_open_get_stream(&mut stream, host, &path, bearer_token).await?;
            Ok(wrap_http_stream_body(stream, body_encoding))
        })
    }

    fn name(&self) -> &str {
        "sse"
    }
}

/// Map an HTTP status + CBOR body into a `ControlEnvelope` result.
///
/// Shared by SSE, Noise, and QUIC unary `call()` implementations.
pub(crate) fn map_status_to_envelope(status: u16, body: &[u8]) -> Result<ControlEnvelope, Error> {
    match status {
        200 => ControlEnvelope::from_cbor(body).map_err(Error::from),
        401 => Err(unauthorized_error_from_body(
            body_text(body).as_ref(),
            "signed-envelope endpoint",
        )),
        409 => Err(crate::conflict_error_from_body(body)),
        429 => Err(crate::rate_limit_error_from_body(body)),
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

pub(crate) fn config_stream_path(envelope: &ControlEnvelope) -> Result<String, Error> {
    if envelope.payload.is_empty() {
        return Ok("/api/v1/config/stream".to_owned());
    }
    let request: api::ConfigStreamRequest = api::from_cbor(envelope.payload.as_ref())
        .map_err(|e| Error::Auth(format!("config.stream request cbor decode: {e}")))?;
    if request.capabilities.is_empty()
        && request.public_ingress_scopes.is_empty()
        && request.stream_session.is_none()
    {
        return Ok("/api/v1/config/stream".to_owned());
    }
    let request = URL_SAFE_NO_PAD.encode(envelope.to_cbor()?);
    Ok(format!("/api/v1/config/stream?request={request}"))
}

fn body_text(body: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(body)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HttpStreamBodyEncoding {
    Identity,
    Chunked,
}

pub(crate) fn wrap_http_stream_body(
    stream: BoxStream,
    encoding: HttpStreamBodyEncoding,
) -> BoxStream {
    match encoding {
        HttpStreamBodyEncoding::Identity => stream,
        HttpStreamBodyEncoding::Chunked => BoxStream::new(ChunkedBodyStream::new(stream)),
    }
}

pub(crate) async fn http_open_get_stream<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    bearer_token: &str,
) -> Result<HttpStreamBodyEncoding, Error>
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
    Ok(stream_body_encoding(header_str))
}

fn stream_body_encoding(headers: &str) -> HttpStreamBodyEncoding {
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        {
            return HttpStreamBodyEncoding::Chunked;
        }
    }
    HttpStreamBodyEncoding::Identity
}

struct ChunkedBodyStream {
    inner: BoxStream,
    raw: Vec<u8>,
    decoded: VecDeque<u8>,
    state: ChunkState,
}

const MAX_CHUNK_SIZE_LINE: usize = 1024;
const MAX_CHUNK_TRAILERS: usize = framing::MAX_HTTP_HEADERS;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ChunkState {
    Size,
    Data(usize),
    DataCrlf(usize),
    Trailers,
    Done,
}

impl ChunkedBodyStream {
    fn new(inner: BoxStream) -> Self {
        Self {
            inner,
            raw: Vec::new(),
            decoded: VecDeque::new(),
            state: ChunkState::Size,
        }
    }

    fn drain_decoded(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        let mut copied = false;
        while buf.remaining() > 0 {
            let Some(byte) = self.decoded.pop_front() else {
                break;
            };
            buf.put_slice(&[byte]);
            copied = true;
        }
        copied
    }

    fn decode_available(&mut self) -> io::Result<bool> {
        match self.state {
            ChunkState::Size => self.decode_size_line(),
            ChunkState::Data(remaining) => self.decode_data(remaining),
            ChunkState::DataCrlf(consumed) => self.decode_data_crlf(consumed),
            ChunkState::Trailers => self.decode_trailers(),
            ChunkState::Done => Ok(false),
        }
    }

    fn decode_size_line(&mut self) -> io::Result<bool> {
        let Some(pos) = find_crlf(&self.raw) else {
            if self.raw.len() > MAX_CHUNK_SIZE_LINE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP chunk size line exceeds 1024 bytes",
                ));
            }
            return Ok(false);
        };
        if pos > MAX_CHUNK_SIZE_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP chunk size line exceeds 1024 bytes",
            ));
        }
        let line = self.raw[..pos].to_vec();
        self.raw.drain(..pos + 2);
        let line = std::str::from_utf8(&line)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let size_hex = line.split(';').next().unwrap_or_default().trim();
        if size_hex.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty HTTP chunk size",
            ));
        }
        let size = usize::from_str_radix(size_hex, 16).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid HTTP chunk size: {err}"),
            )
        })?;
        self.state = if size == 0 {
            ChunkState::Trailers
        } else {
            ChunkState::Data(size)
        };
        Ok(true)
    }

    fn decode_data(&mut self, remaining: usize) -> io::Result<bool> {
        if self.raw.is_empty() {
            return Ok(false);
        }
        let take = remaining.min(self.raw.len());
        self.decoded.extend(self.raw.drain(..take));
        let remaining = remaining - take;
        self.state = if remaining == 0 {
            ChunkState::DataCrlf(0)
        } else {
            ChunkState::Data(remaining)
        };
        Ok(true)
    }

    fn decode_data_crlf(&mut self, mut consumed: usize) -> io::Result<bool> {
        const EXPECTED: [u8; 2] = [b'\r', b'\n'];
        let original = consumed;
        while consumed < EXPECTED.len() {
            let Some(byte) = self.raw.first().copied() else {
                self.state = ChunkState::DataCrlf(consumed);
                return Ok(consumed != original);
            };
            if byte != EXPECTED[consumed] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid HTTP chunk data terminator",
                ));
            }
            self.raw.remove(0);
            consumed += 1;
        }
        self.state = ChunkState::Size;
        Ok(true)
    }

    fn decode_trailers(&mut self) -> io::Result<bool> {
        if self.raw.starts_with(b"\r\n") {
            self.raw.drain(..2);
            self.state = ChunkState::Done;
            return Ok(true);
        }
        let Some(pos) = find_sequence(&self.raw, b"\r\n\r\n") else {
            if self.raw.len() > MAX_CHUNK_TRAILERS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("HTTP chunk trailers exceed {MAX_CHUNK_TRAILERS} bytes"),
                ));
            }
            return Ok(false);
        };
        if pos + 4 > MAX_CHUNK_TRAILERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("HTTP chunk trailers exceed {MAX_CHUNK_TRAILERS} bytes"),
            ));
        }
        self.raw.drain(..pos + 4);
        self.state = ChunkState::Done;
        Ok(true)
    }
}

impl AsyncRead for ChunkedBodyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.drain_decoded(buf) {
                return Poll::Ready(Ok(()));
            }
            if self.state == ChunkState::Done {
                return Poll::Ready(Ok(()));
            }
            if self.decode_available()? {
                continue;
            }

            let mut bytes = [0_u8; 8192];
            let mut read_buf = ReadBuf::new(&mut bytes);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                    if self.state == ChunkState::Done {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "HTTP chunked body ended mid-chunk",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    self.raw.extend_from_slice(read_buf.filled());
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }
    }
}

impl AsyncWrite for ChunkedBodyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    find_sequence(bytes, b"\r\n")
}

fn find_sequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ConfigStreamRequest;
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

    fn signed_config_stream_envelope(request: &ConfigStreamRequest) -> ControlEnvelope {
        let payload = crate::api::to_cbor(request).unwrap();
        let signer = SigningKey::generate(&mut OsRng);
        let pk = signer.verifying_key().to_bytes();
        ControlEnvelope::sign_request(
            envelope::api::CONFIG_STREAM,
            Some("m-1".to_string()),
            pk,
            payload,
            |msg| signer.sign(msg).to_bytes(),
        )
        .unwrap()
    }

    struct ScriptedStream {
        chunks: VecDeque<Vec<u8>>,
    }

    impl ScriptedStream {
        fn new(chunks: &[&[u8]]) -> Self {
            Self {
                chunks: chunks.iter().map(|chunk| chunk.to_vec()).collect(),
            }
        }

        fn from_vecs(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                chunks: chunks.into_iter().collect(),
            }
        }
    }

    impl AsyncRead for ScriptedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let Some(chunk) = self.chunks.pop_front() else {
                return Poll::Ready(Ok(()));
            };
            assert!(
                chunk.len() <= buf.remaining(),
                "scripted chunks must fit in one read"
            );
            buf.put_slice(&chunk);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn decode_chunked_body(chunks: &[&[u8]]) -> std::io::Result<Vec<u8>> {
        let stream = BoxStream::new(ScriptedStream::new(chunks));
        let mut stream = ChunkedBodyStream::new(stream);
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await?;
        Ok(body)
    }

    async fn decode_chunked_body_owned(chunks: Vec<Vec<u8>>) -> std::io::Result<Vec<u8>> {
        let stream = BoxStream::new(ScriptedStream::from_vecs(chunks));
        let mut stream = ChunkedBodyStream::new(stream);
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await?;
        Ok(body)
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
    fn rate_limit_status_surfaces_typed_optional_retry_fields() {
        let with_fields = br#"{"error":"rate_limited","current_epoch":42,"retry_after_ms":187}"#;
        assert!(matches!(
            map_status_to_envelope(429, with_fields).unwrap_err(),
            Error::RateLimited {
                current_epoch: Some(42),
                retry_after: Some(delay),
            } if delay == std::time::Duration::from_millis(187)
        ));

        assert!(matches!(
            map_status_to_envelope(429, br#"{"error":"rate_limited"}"#).unwrap_err(),
            Error::RateLimited {
                current_epoch: None,
                retry_after: None,
            }
        ));
        assert!(matches!(
            map_status_to_envelope(429, b"legacy empty body").unwrap_err(),
            Error::RateLimited {
                current_epoch: None,
                retry_after: None,
            }
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

    #[test]
    fn config_stream_path_omits_default_request_query() {
        let envelope = signed_config_stream_envelope(&ConfigStreamRequest::default());

        assert_eq!(
            config_stream_path(&envelope).unwrap(),
            "/api/v1/config/stream"
        );
    }

    #[test]
    fn config_stream_path_encodes_non_empty_signed_request_query() {
        let request = ConfigStreamRequest {
            capabilities: vec![
                common::CAPABILITY_CAPTURE_ROUTES_V1.to_owned(),
                common::CAPABILITY_NSC_APPLICATION_UDP_V1.to_owned(),
            ],
            public_ingress_scopes: Vec::new(),
            stream_session: None,
        };
        let envelope = signed_config_stream_envelope(&request);

        let path = config_stream_path(&envelope).unwrap();
        let encoded = path
            .strip_prefix("/api/v1/config/stream?request=")
            .expect("query prefix");
        let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let decoded = ControlEnvelope::from_cbor(&decoded).unwrap();
        assert_eq!(decoded.api, envelope::api::CONFIG_STREAM);
        assert!(decoded.verify_request(decoded.ts).is_ok());
        let decoded_request: ConfigStreamRequest =
            crate::api::from_cbor(decoded.payload.as_ref()).unwrap();
        assert_eq!(
            decoded_request.capabilities,
            vec![
                common::CAPABILITY_CAPTURE_ROUTES_V1.to_owned(),
                common::CAPABILITY_NSC_APPLICATION_UDP_V1.to_owned(),
            ]
        );
    }

    #[test]
    fn config_stream_path_encodes_session_only_signed_request_query() {
        let session = crate::api::ControlStreamSession::new();
        let request = ConfigStreamRequest {
            capabilities: Vec::new(),
            public_ingress_scopes: Vec::new(),
            stream_session: Some(session),
        };
        let envelope = signed_config_stream_envelope(&request);

        let path = config_stream_path(&envelope).unwrap();
        let encoded = path
            .strip_prefix("/api/v1/config/stream?request=")
            .expect("session-only request must use the signed query");
        let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let decoded = ControlEnvelope::from_cbor(&decoded).unwrap();
        assert!(decoded.verify_request(decoded.ts).is_ok());
        let decoded_request: ConfigStreamRequest =
            crate::api::from_cbor(decoded.payload.as_ref()).unwrap();
        assert_eq!(decoded_request.stream_session, Some(session));
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
    async fn connect_stream_decodes_chunked_body_split_inside_sse_data_line() {
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

            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
            for chunk in [
                b"event: config-envelope.v1\ndata: abc".as_slice(),
                b"123\n\n",
            ] {
                sock.write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await
                    .unwrap();
                sock.write_all(chunk).await.unwrap();
                sock.write_all(b"\r\n").await.unwrap();
            }
            sock.write_all(b"0\r\n\r\n").await.unwrap();
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
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"event: config-envelope.v1\ndata: abc123\n\n");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn chunked_body_stream_handles_boundary_splits_and_trailers() {
        let body = decode_chunked_body(&[b"3", b"\r\nabc\r\n0\r\n\r\n"])
            .await
            .unwrap();
        assert_eq!(body, b"abc");

        let body = decode_chunked_body(&[b"3\r\nabc\r", b"\n0\r\n\r\n"])
            .await
            .unwrap();
        assert_eq!(body, b"abc");

        let body = decode_chunked_body(&[b"3\r\nabc\r\n0\r\nX-Test: ok\r\nAnother: yes\r\n\r\n"])
            .await
            .unwrap();
        assert_eq!(body, b"abc");
    }

    #[tokio::test]
    async fn chunked_body_stream_handles_extensions_and_multi_chunk_sse_data() {
        let body = decode_chunked_body(&[b"3;foo=bar\r\nabc\r\n0\r\n\r\n"])
            .await
            .unwrap();
        assert_eq!(body, b"abc");

        let body = decode_chunked_body(&[
            b"22\r\nevent: config-envelope.v1\ndata: ab\r\n",
            b"3\r\ncde\r\n",
            b"6\r\nfghi\n\n\r\n",
            b"0\r\n\r\n",
        ])
        .await
        .unwrap();
        assert_eq!(body, b"event: config-envelope.v1\ndata: abcdefghi\n\n");
    }

    #[tokio::test]
    async fn chunked_body_stream_rejects_invalid_or_empty_size_lines() {
        let err = decode_chunked_body(&[b"zz\r\nabc\r\n0\r\n\r\n"])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        let err = decode_chunked_body(&[b"\r\n0\r\n\r\n"]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn chunked_body_stream_rejects_oversized_size_line_without_crlf() {
        let line = vec![b'1'; MAX_CHUNK_SIZE_LINE + 1];
        let err = decode_chunked_body_owned(vec![line]).await.unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn chunked_body_stream_rejects_oversized_trailers_without_terminator() {
        let err = decode_chunked_body_owned(vec![
            b"0\r\n".to_vec(),
            vec![b'X'; 8192],
            vec![b'Y'; 8192],
            vec![b'Z'; MAX_CHUNK_TRAILERS - 16384 + 1],
        ])
        .await
        .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn chunked_body_stream_handles_empty_body() {
        let body = decode_chunked_body(&[b"0\r\n\r\n"]).await.unwrap();

        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn chunked_body_stream_reports_unexpected_eof_mid_size_or_data() {
        let err = decode_chunked_body(&[b"3"]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

        let err = decode_chunked_body(&[b"3\r\nab"]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn chunked_body_stream_rejects_invalid_data_terminator() {
        let err = decode_chunked_body(&[b"3\r\nabcXX0\r\n\r\n"])
            .await
            .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn chunked_body_stream_rejects_overflow_chunk_size() {
        let err = decode_chunked_body(&[b"ffffffffffffffffffffffffffffffff\r\n"])
            .await
            .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn stream_body_encoding_detects_mixed_case_chunked_token_in_multi_value_header() {
        let headers = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, ChUnKeD\r\n\r\n";

        assert_eq!(
            stream_body_encoding(headers),
            HttpStreamBodyEncoding::Chunked
        );
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

    // The keepalive settings applied at connect time must stick on a real
    // socket: SO_KEEPALIVE enabled and the configured 30s idle time visible
    // through the socket2 getters.
    #[tokio::test]
    async fn control_tcp_keepalive_reads_back_on_localhost_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (_server, _) = listener.accept().await.unwrap();

        crate::transport::set_control_tcp_keepalive(&client).unwrap();

        let sock = socket2::SockRef::from(&client);
        assert!(sock.keepalive().unwrap(), "SO_KEEPALIVE must be enabled");
        assert_eq!(
            sock.tcp_keepalive_time().unwrap(),
            std::time::Duration::from_secs(30),
            "tcp_keepalive_time must read back the configured idle time"
        );
    }
}
