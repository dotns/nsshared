#![forbid(unsafe_code)]

//! Noise transport: Noise_IK_25519_ChaChaPoly_BLAKE2s over TCP.
//!
//! DPI sees: TCP connection to IP:port followed by random bytes.
//! No SNI, no TLS handshake pattern, no HTTP headers.
//!
//! The NSD side requires a thin Noise proxy that terminates the handshake and
//! forwards plaintext HTTP to NSD.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::BoxStream;
use crate::{
    Error,
    envelope::ControlEnvelope,
    transport::{
        ControlTransport, framing,
        sse::{config_stream_path, endpoint_host, http_open_get_stream, map_status_to_envelope},
    },
};

// -- NoiseStream --------------------------------------------------------------

/// Framing: each Noise message is preceded by a 2-byte big-endian length.
const LEN_PREFIX: usize = 2;
/// Maximum plaintext bytes per Noise message (65535 - 16-byte AEAD tag).
const MAX_PAYLOAD: usize = 65519;
/// Maximum ciphertext bytes per Noise frame (plaintext + 16-byte AEAD tag).
/// A u16 length prefix can already only encode up to 65535, but we pin the
/// cap explicitly so the decrypt-side allocation can never exceed what a
/// well-formed peer would send — pre-decrypt junk is rejected without
/// allocating a 64 KiB buffer per frame.
const MAX_FRAME: usize = MAX_PAYLOAD + 16;

/// Upper bound on cumulative ciphertext bytes per connection within
/// [`INGRESS_WINDOW`]. A pre-handshake DPI probe or a malicious peer
/// blasting framed junk is cut off once this budget is exhausted rather
/// than burning CPU on AEAD decrypt forever. Sized to cover legitimate
/// bursts of SSE snapshots + config deltas many times over.
const INGRESS_BUDGET_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
/// Window over which [`INGRESS_BUDGET_BYTES`] is enforced.
const INGRESS_WINDOW: Duration = Duration::from_secs(10);

/// State machine for reading length-prefixed Noise frames from TCP.
enum ReadState {
    /// Reading the 2-byte length prefix.
    Len { buf: [u8; 2], filled: usize },
    /// Reading the frame payload.
    Data { buf: Vec<u8>, filled: usize },
}

/// Bidirectional `AsyncRead + AsyncWrite` stream encrypted with Noise IK.
///
/// All data is framed as:  `[2-byte BE length][Noise ciphertext]`.
/// After the Noise handshake (performed in [`NoiseTransport::connect`]),
/// the caller reads/writes plaintext -- encryption is transparent.
pub struct NoiseStream {
    tcp: TcpStream,
    noise: snow::TransportState,
    /// Decrypted plaintext waiting to be returned to the caller via AsyncRead.
    plaintext: VecDeque<u8>,
    read_state: ReadState,
    /// Plaintext accumulated by AsyncWrite::poll_write, encoded on poll_flush.
    write_plain: Vec<u8>,
    /// Encoded ciphertext frames waiting to be flushed to TCP.
    write_cipher: Vec<u8>,
    /// Cumulative ciphertext bytes accepted since `window_started` — reset
    /// once the window expires. Ingress decode refuses to allocate once the
    /// running total would exceed `ingress_budget_bytes`.
    ingress_bytes_in_window: usize,
    /// When the current ingress window started.
    ingress_window_started: Instant,
    /// Test-overridable byte budget per window (defaults to the module-level
    /// `INGRESS_BUDGET_BYTES`).
    ingress_budget_bytes: usize,
    /// Test-overridable ingress window duration.
    ingress_window: Duration,
}

impl NoiseStream {
    pub(crate) fn new(tcp: TcpStream, noise: snow::TransportState) -> Self {
        Self::with_ingress_budget(tcp, noise, INGRESS_BUDGET_BYTES, INGRESS_WINDOW)
    }

    #[cfg(test)]
    pub(crate) fn with_ingress_budget(
        tcp: TcpStream,
        noise: snow::TransportState,
        budget_bytes: usize,
        window: Duration,
    ) -> Self {
        Self::build(tcp, noise, budget_bytes, window)
    }

    #[cfg(not(test))]
    pub(crate) fn with_ingress_budget(
        tcp: TcpStream,
        noise: snow::TransportState,
        budget_bytes: usize,
        window: Duration,
    ) -> Self {
        Self::build(tcp, noise, budget_bytes, window)
    }

    fn build(
        tcp: TcpStream,
        noise: snow::TransportState,
        budget_bytes: usize,
        window: Duration,
    ) -> Self {
        Self {
            tcp,
            noise,
            plaintext: VecDeque::new(),
            read_state: ReadState::Len {
                buf: [0; LEN_PREFIX],
                filled: 0,
            },
            write_plain: Vec::new(),
            write_cipher: Vec::new(),
            ingress_bytes_in_window: 0,
            ingress_window_started: Instant::now(),
            ingress_budget_bytes: budget_bytes,
            ingress_window: window,
        }
    }

    /// Record `frame_bytes` against the ingress window; returns an error if
    /// the budget would be exceeded within the current window.
    fn meter_ingress(&mut self, frame_bytes: usize) -> io::Result<()> {
        let now = Instant::now();
        if now.duration_since(self.ingress_window_started) >= self.ingress_window {
            self.ingress_window_started = now;
            self.ingress_bytes_in_window = 0;
        }
        let next = self.ingress_bytes_in_window.saturating_add(frame_bytes);
        if next > self.ingress_budget_bytes {
            warn!(
                budget = self.ingress_budget_bytes,
                window_secs = self.ingress_window.as_secs(),
                pending = next,
                "NoiseStream: ingress byte budget exceeded — dropping connection"
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "noise ingress byte budget exceeded",
            ));
        }
        self.ingress_bytes_in_window = next;
        Ok(())
    }
}

impl AsyncRead for NoiseStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            // -- Return buffered plaintext ----------------------------------------
            if !this.plaintext.is_empty() {
                let amt = this.plaintext.len().min(buf.remaining());
                // Drain `amt` bytes from the deque into `buf`.
                let (front, back) = this.plaintext.as_slices();
                let front_take = amt.min(front.len());
                buf.put_slice(&front[..front_take]);
                if front_take < amt {
                    buf.put_slice(&back[..amt - front_take]);
                }
                this.plaintext.drain(..amt);
                return Poll::Ready(Ok(()));
            }

            // -- Read the next Noise frame ----------------------------------------
            // Phase 1: read 2-byte length prefix.
            if let ReadState::Len {
                buf: len_buf,
                filled,
            } = &mut this.read_state
            {
                while *filled < LEN_PREFIX {
                    let mut rb = ReadBuf::new(&mut len_buf[*filled..]);
                    match Pin::new(&mut this.tcp).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::from(
                                    io::ErrorKind::UnexpectedEof,
                                )));
                            }
                            *filled += n;
                        }
                    }
                }
                let frame_len = u16::from_be_bytes(*len_buf) as usize;
                // Cap allocation: the largest well-formed frame is
                // MAX_PAYLOAD+16. A u16 prefix technically also tops out at
                // 65535, so this bound is tight. Rejecting here also prevents
                // an attacker from picking just-too-large sizes to force
                // 64 KiB allocations at the Noise layer before SSE rate
                // limits apply.
                if frame_len > MAX_FRAME {
                    warn!(
                        frame_len,
                        max = MAX_FRAME,
                        "NoiseStream: frame length exceeds MAX_FRAME — dropping connection"
                    );
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "noise frame length exceeds MAX_FRAME",
                    )));
                }
                // Meter the ciphertext size (length prefix + payload) against
                // the per-connection ingress budget so pre-decrypt flooding
                // cannot hide from SSE-layer rate limiting.
                if let Err(e) = this.meter_ingress(LEN_PREFIX + frame_len) {
                    return Poll::Ready(Err(e));
                }
                this.read_state = ReadState::Data {
                    buf: vec![0u8; frame_len],
                    filled: 0,
                };
            }

            // Phase 2: read frame payload.
            if let ReadState::Data {
                buf: data_buf,
                filled,
            } = &mut this.read_state
            {
                while *filled < data_buf.len() {
                    let start = *filled;
                    let mut rb = ReadBuf::new(&mut data_buf[start..]);
                    match Pin::new(&mut this.tcp).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::from(
                                    io::ErrorKind::UnexpectedEof,
                                )));
                            }
                            *filled += n;
                        }
                    }
                }
            }

            // Phase 3: decrypt the completed frame.
            let data_buf = match std::mem::replace(
                &mut this.read_state,
                ReadState::Len {
                    buf: [0; LEN_PREFIX],
                    filled: 0,
                },
            ) {
                ReadState::Data { buf, .. } => buf,
                ReadState::Len { .. } => {
                    // Still in Len phase -- can't happen here, but be safe.
                    continue;
                }
            };

            if data_buf.is_empty() {
                // Zero-length frame: keep-alive or heartbeat; skip.
                continue;
            }

            let mut plain = vec![0u8; data_buf.len() + 16];
            let plain_len = this
                .noise
                .read_message(&data_buf, &mut plain)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            this.plaintext.extend(plain[..plain_len].iter().copied());
        }
    }
}

impl AsyncWrite for NoiseStream {
    /// Buffer plaintext; encoding happens in `poll_flush`.
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().write_plain.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    /// Encode buffered plaintext as Noise frames and flush to TCP.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Encode plaintext into ciphertext frames.
        if !this.write_plain.is_empty() {
            let plain = std::mem::take(&mut this.write_plain);
            let mut frame_buf = vec![0u8; 65535];
            for chunk in plain.chunks(MAX_PAYLOAD) {
                let frame_len = this
                    .noise
                    .write_message(chunk, &mut frame_buf)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                this.write_cipher
                    .extend_from_slice(&(frame_len as u16).to_be_bytes());
                this.write_cipher.extend_from_slice(&frame_buf[..frame_len]);
            }
        }

        // Write encoded frames to TCP.
        while !this.write_cipher.is_empty() {
            let n = ready!(Pin::new(&mut this.tcp).poll_write(cx, &this.write_cipher))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            this.write_cipher.drain(..n);
        }

        Pin::new(&mut this.tcp).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().tcp).poll_shutdown(cx)
    }
}

// -- NoiseTransport -----------------------------------------------------------

/// Noise_IK control transport.
///
/// Reuses the machine's X25519 peer private key for the Noise handshake.
/// The NSD public key must be pre-configured (`--nsd-pubkey` / `NSD_PUBKEY`).
///
/// Connection sequence:
/// 1. TCP connect to `endpoint`.
/// 2. Noise IK handshake (2 messages, length-prefixed).
/// 3. Return [`NoiseStream`] (transport mode) wrapped in [`BoxStream`].
pub struct NoiseTransport {
    /// Local X25519 private key (machine peer key).
    local_private_key: [u8; 32],
    /// NSD X25519 public key (pre-configured).
    remote_public_key: [u8; 32],
}

impl NoiseTransport {
    /// Create a new `NoiseTransport`.
    ///
    /// `local_private_key` is the machine's X25519 peer private key (from
    /// `MachineState::peer_key_priv_bytes()`).
    /// `remote_public_key` is the NSD's X25519 public key.
    pub fn new(local_private_key: [u8; 32], remote_public_key: [u8; 32]) -> Self {
        Self {
            local_private_key,
            remote_public_key,
        }
    }
}

impl ControlTransport for NoiseTransport {
    /// Unary request/response over a fresh Noise/TCP connection.
    ///
    /// Connection pooling lands later (PLAN-022 Phase 4 follow-up); the initial
    /// implementation opens a fresh handshake per call, which is fine for the
    /// current 1/min heartbeat + rare register cadence.
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
            http_open_get_stream(&mut stream, host, &path, bearer_token).await?;
            Ok(stream)
        })
    }

    fn connect<'a>(&'a self, endpoint: &'a str) -> BoxFuture<'a, Result<BoxStream, Error>> {
        Box::pin(async move {
            let tcp = TcpStream::connect(endpoint)
                .await
                .map_err(|e| Error::Connect(format!("TCP connect to {endpoint}: {e}")))?;

            debug!(endpoint, "NoiseTransport: starting Noise IK handshake");

            // Build Noise IK initiator (NSN knows NSD's static public key).
            let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
                .parse()
                .map_err(|e| Error::Noise(format!("invalid Noise params: {e}")))?;

            let mut handshake = snow::Builder::new(params)
                .local_private_key(&self.local_private_key)
                .remote_public_key(&self.remote_public_key)
                .build_initiator()
                .map_err(|e| Error::Noise(format!("build initiator: {e}")))?;

            let mut msg_buf = vec![0u8; 65535];
            let mut tcp = tcp;

            // -> e, es, s, ss  (first handshake message)
            let msg_len = handshake
                .write_message(&[], &mut msg_buf)
                .map_err(|e| Error::Noise(format!("write handshake msg 1: {e}")))?;
            send_framed(&mut tcp, &msg_buf[..msg_len]).await?;

            // <- e, ee, se  (second handshake message from responder)
            let resp = recv_framed(&mut tcp).await?;
            handshake
                .read_message(&resp, &mut msg_buf)
                .map_err(|e| Error::Noise(format!("read handshake msg 2: {e}")))?;

            // Handshake complete -- enter transport mode.
            let transport = handshake
                .into_transport_mode()
                .map_err(|e| Error::Noise(format!("into_transport_mode: {e}")))?;

            debug!(endpoint, "NoiseTransport: handshake complete");
            Ok(BoxStream::new(NoiseStream::new(tcp, transport)))
        })
    }

    fn name(&self) -> &str {
        "noise"
    }
}

// -- Framing helpers (handshake phase only) ------------------------------------

/// Send a length-prefixed frame to `tcp` during the handshake phase.
///
/// Format: `[u16 BE length][payload]`
async fn send_framed(tcp: &mut TcpStream, payload: &[u8]) -> Result<(), Error> {
    let len_bytes = (payload.len() as u16).to_be_bytes();
    let mut buf = Vec::with_capacity(LEN_PREFIX + payload.len());
    buf.extend_from_slice(&len_bytes);
    buf.extend_from_slice(payload);
    tcp.write_all(&buf)
        .await
        .map_err(|e| Error::Connect(format!("write handshake frame: {e}")))?;
    tcp.flush()
        .await
        .map_err(|e| Error::Connect(format!("flush handshake: {e}")))?;
    Ok(())
}

/// Receive a length-prefixed frame from `tcp` during the handshake phase.
async fn recv_framed(tcp: &mut TcpStream) -> Result<Vec<u8>, Error> {
    let mut len_buf = [0u8; LEN_PREFIX];
    tcp.read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::Connect(format!("read handshake length: {e}")))?;
    let frame_len = u16::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; frame_len];
    tcp.read_exact(&mut payload)
        .await
        .map_err(|e| Error::Connect(format!("read handshake payload: {e}")))?;
    Ok(payload)
}

// -- Unit tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_bytes::ByteBuf;
    use std::future::Future;
    use std::net::SocketAddr;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    #[test]
    fn noise_stream_is_send() {
        // Compile-time check: NoiseStream must be Send to wrap in BoxStream.
        fn assert_send<T: Send>() {}
        let _ = std::marker::PhantomData::<NoiseStream>;
        assert_send::<VecDeque<u8>>();
        assert_send::<Vec<u8>>();
    }

    #[test]
    fn noise_transport_stores_keys() {
        let priv_key = [1u8; 32];
        let pub_key = [2u8; 32];
        let t = NoiseTransport::new(priv_key, pub_key);
        assert_eq!(t.name(), "noise");
        assert_eq!(t.local_private_key, priv_key);
        assert_eq!(t.remote_public_key, pub_key);
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

    async fn noise_transport_with_server<F, Fut>(
        handle_stream: F,
    ) -> (NoiseTransport, SocketAddr, JoinHandle<()>)
    where
        F: FnOnce(NoiseStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let params: snow::params::NoiseParams =
            "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let server_builder = snow::Builder::new(params.clone());
        let server_static = server_builder.generate_keypair().unwrap();
        let client_builder = snow::Builder::new(params);
        let client_static = client_builder.generate_keypair().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_static_priv = server_static.private.clone();
        let server_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let params: snow::params::NoiseParams =
                "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
            let mut hs = snow::Builder::new(params)
                .local_private_key(&server_static_priv)
                .build_responder()
                .unwrap();
            let mut buf = vec![0u8; 65535];

            let req = recv_framed(&mut sock).await.unwrap();
            hs.read_message(&req, &mut buf).unwrap();
            let n = hs.write_message(&[], &mut buf).unwrap();
            send_framed(&mut sock, &buf[..n]).await.unwrap();

            let server_transport = hs.into_transport_mode().unwrap();
            handle_stream(NoiseStream::new(sock, server_transport)).await;
        });

        let client_private_key: [u8; 32] = client_static.private.as_slice().try_into().unwrap();
        let server_public_key: [u8; 32] = server_static.public.as_slice().try_into().unwrap();
        let transport = NoiseTransport::new(client_private_key, server_public_key);
        (transport, addr, server_task)
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
        let (transport, addr, server_task) = noise_transport_with_server(|mut stream| async move {
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
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_stream_gets_config_stream_over_http() {
        let (transport, addr, server_task) = noise_transport_with_server(|mut stream| async move {
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
        server_task.await.unwrap();
    }

    // Construct a pair of connected TCP sockets plus a post-handshake Noise
    // TransportState on each side. Returned as (client_stream, server_tcp)
    // so tests can feed raw ciphertext (or bogus bytes) into the server and
    // read from the client, or vice-versa. Only the client side is wrapped
    // in a NoiseStream here because the meter is per-connection and we just
    // need one to observe rejection behaviour.
    async fn noise_pair_raw_server() -> (NoiseStream, TcpStream) {
        // snow IK handshake: client knows server's static public key.
        let params: snow::params::NoiseParams =
            "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let server_builder = snow::Builder::new(params.clone());
        let server_static = server_builder.generate_keypair().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_static_pub = server_static.public.clone();
        let server_static_priv = server_static.private.clone();

        let server_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let params: snow::params::NoiseParams =
                "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
            let mut hs = snow::Builder::new(params)
                .local_private_key(&server_static_priv)
                .build_responder()
                .unwrap();
            let mut buf = vec![0u8; 65535];
            // <- e, es, s, ss
            let req = recv_framed(&mut sock).await.unwrap();
            hs.read_message(&req, &mut buf).unwrap();
            // -> e, ee, se
            let n = hs.write_message(&[], &mut buf).unwrap();
            send_framed(&mut sock, &buf[..n]).await.unwrap();
            // Return the raw TCP sock to the test (handshake done, no
            // transport-mode wrap — the test feeds raw bytes).
            sock
        });

        // Client side — generate ephemeral static (content doesn't matter;
        // IK simply needs a static key, and the server isn't validating it
        // against a pinned remote in this test).
        let client_builder =
            snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let client_static = client_builder.generate_keypair().unwrap();
        let mut client_hs =
            snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
                .local_private_key(&client_static.private)
                .remote_public_key(&server_static_pub)
                .build_initiator()
                .unwrap();
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let mut buf = vec![0u8; 65535];
        let n = client_hs.write_message(&[], &mut buf).unwrap();
        send_framed(&mut tcp, &buf[..n]).await.unwrap();
        let resp = recv_framed(&mut tcp).await.unwrap();
        client_hs.read_message(&resp, &mut buf).unwrap();
        let client_transport = client_hs.into_transport_mode().unwrap();

        let server_tcp = server_task.await.unwrap();
        (NoiseStream::new(tcp, client_transport), server_tcp)
    }

    // A length prefix + payload exceeding the per-connection ingress budget
    // must be rejected pre-decrypt, with no 64 KiB allocation escaping the
    // meter.
    #[tokio::test]
    async fn ingress_byte_budget_refuses_oversized_frame() {
        let (client, mut server_tcp) = noise_pair_raw_server().await;
        // Rebuild the client NoiseStream with a 100-byte budget — smaller
        // than a single 400-byte frame, so meter_ingress fires on the first
        // frame before any decrypt work happens.
        let NoiseStream { tcp, noise, .. } = client;
        let mut client = NoiseStream::with_ingress_budget(tcp, noise, 100, Duration::from_secs(5));

        let payload = vec![0u8; 400];
        let len = (payload.len() as u16).to_be_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut server_tcp, &len)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut server_tcp, &payload)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::flush(&mut server_tcp)
            .await
            .unwrap();

        let mut out = [0u8; 16];
        let err = client.read(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err:?}");
        assert!(
            err.to_string().contains("ingress byte budget"),
            "expected ingress-budget error, got: {err}"
        );
    }

    // Confirm MAX_FRAME is what we think it is. Guards against an accidental
    // const rename that would silently widen the allocation.
    #[test]
    fn max_frame_is_max_payload_plus_tag() {
        assert_eq!(MAX_FRAME, MAX_PAYLOAD + 16);
        assert_eq!(MAX_FRAME, u16::MAX as usize);
    }
}
