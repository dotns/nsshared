use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tracing::{debug, instrument, warn};

use crate::{
    Error, api as envapi,
    auth::{
        ConfigStreamReplayCache, NsdEnvelopeTrustConfig, verify_config_stream_event,
        verify_pinned_envelope_response,
    },
    envelope::ControlEnvelope,
    messages::ControlMessage,
};

// ── Token-bucket rate limiter ─────────────────────────────────────────────────

/// A simple token-bucket rate limiter for inbound SSE events.
///
/// Tokens refill continuously at `rate` tokens per second up to `capacity`.
/// Each accepted event consumes one token.  When the bucket is empty the
/// caller should drop (not disconnect) the event.
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    /// Refill rate in tokens per second (equals `capacity` for a 1-second window).
    rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_per_sec: u32) -> Self {
        let capacity = f64::from(max_per_sec);
        Self {
            tokens: capacity,
            capacity,
            rate: capacity,
            last_refill: Instant::now(),
        }
    }

    /// Attempt to consume one token.  Returns `true` if the event is allowed.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ── SseFramer ────────────────────────────────────────────────────────────────

/// Shared SSE framing state: byte buffer + rate limiter + max-size cap.
///
/// Transport layers push raw bytes in via [`SseFramer::feed`] and pull verified
/// events out via [`SseFramer::poll_event`]. The framer is transport-agnostic
/// so the same logic drives SSE-over-reqwest and SSE-over-Noise.
struct SseFramer {
    buffer: String,
    rate_limiter: TokenBucket,
    max_message_size: usize,
    replay_cache: ConfigStreamReplayCache,
}

impl SseFramer {
    fn new(max_events_per_sec: u32, max_message_size: usize) -> Self {
        Self {
            buffer: String::new(),
            rate_limiter: TokenBucket::new(max_events_per_sec),
            max_message_size,
            replay_cache: ConfigStreamReplayCache::new(),
        }
    }

    fn clear(&mut self) {
        self.buffer.clear();
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let text = std::str::from_utf8(bytes).map_err(|e| Error::Sse(e.to_string()))?;
        self.buffer.push_str(text);
        Ok(())
    }

    /// Try to pull the next complete verified `ControlMessage` out of the buffer.
    /// Returns `Ok(Some(..))` when one is available, `Ok(None)` when more bytes
    /// are needed, `Err(..)` on parse failure of a well-sized event.
    async fn poll_event(
        &mut self,
        envelope_trust: Option<&NsdEnvelopeTrustConfig>,
        expected_machine_id: &str,
    ) -> Result<Option<ControlMessage>, Error> {
        while let Some(pos) = self.buffer.find("\n\n") {
            let event = self.buffer[..pos].to_string();
            self.buffer.drain(..pos + 2);
            if let Some(msg) = self
                .parse_event(&event, envelope_trust, expected_machine_id)
                .await?
            {
                return Ok(Some(msg));
            }
        }
        Ok(None)
    }

    async fn parse_event(
        &mut self,
        event: &str,
        envelope_trust: Option<&NsdEnvelopeTrustConfig>,
        expected_machine_id: &str,
    ) -> Result<Option<ControlMessage>, Error> {
        let mut event_name = None;
        let mut data = None;
        for line in event.lines() {
            if line.starts_with(':') {
                continue;
            }
            if let Some(name) = line.strip_prefix("event: ") {
                event_name = Some(name);
                continue;
            }
            let Some(value) = line
                .strip_prefix("data: ")
                .or_else(|| line.strip_prefix("data:"))
            else {
                continue;
            };
            if data.replace(value).is_some() {
                return Err(Error::Auth(
                    "config.stream event must contain exactly one data field".to_string(),
                ));
            }
        }

        let Some(data) = data else {
            return Ok(None);
        };

        if event_name != Some("config-envelope.v1") {
            return Err(Error::Auth(
                "config.stream event missing config-envelope.v1 envelope".to_string(),
            ));
        }

        // Rate limit BEFORE the size check so an attacker flooding
        // just-too-large events consumes tokens instead of trickling
        // through the oversize drop with no cost. Each event — oversize
        // or not — costs exactly one token.
        if !self.rate_limiter.try_consume() {
            warn!("SSE inbound rate limit exceeded, dropping event");
            return Ok(None);
        }

        if data.len() > self.max_message_size {
            warn!(
                size = data.len(),
                limit = self.max_message_size,
                "dropping oversized SSE event"
            );
            return Ok(None);
        }

        let payload = verify_config_stream_event(
            data,
            envelope_trust,
            expected_machine_id,
            &mut self.replay_cache,
        )
        .await?;
        let msg = payload.message;
        if matches!(msg, ControlMessage::Unknown) {
            // Verified event from a newer NSD with a variant this build does
            // not know. Already warn-logged (with the wire tag) by
            // `verify_config_stream_event`; skip it and keep the stream up.
            return Ok(None);
        }
        debug!(
            event_type = msg.event_type(),
            size = data.len(),
            "received verified SSE event"
        );
        Ok(Some(msg))
    }
}

// ── ControlStream trait ───────────────────────────────────────────────────────

/// Uniform interface over the control stream flavours.
///
/// The control-plane loop (in `lib.rs`) drives a `dyn ControlStream`, so SSE
/// and tunneled transports share a single reconnect / dispatch body.
#[async_trait]
pub trait ControlStream: Send {
    async fn post_services_report(&mut self, envelope: ControlEnvelope) -> Result<(), Error>;
    /// Open `config.stream`.
    ///
    /// All transports open the deployed GET endpoint with the current control
    /// bearer. Noise and QUIC carry that HTTP request inside the established
    /// encrypted tunnel. Each returned `config-envelope.v1` event is then
    /// verified with the pinned NSD envelope key before payload dispatch.
    async fn connect(&mut self, envelope: ControlEnvelope) -> Result<(), Error>;
    async fn next_message(&mut self) -> Result<ControlMessage, Error>;
    fn set_token(&mut self, token: String);
}

// ── SseControl ────────────────────────────────────────────────────────────────

/// SSE client for the NSIO control plane.
///
/// Outbound: `services.report` through [`crate::transport::ControlTransport::call`].
/// Inbound: `config.stream` through [`crate::transport::ControlTransport::connect_stream`].
pub struct SseControl {
    transport: std::sync::Arc<dyn crate::transport::ControlTransport>,
    envelope_trust: Option<NsdEnvelopeTrustConfig>,
    /// TCP endpoint (`host:port`) for connecting.
    endpoint: String,
    /// Active SSE connection stream.
    sse_stream: Option<crate::transport::BoxStream>,
    bearer_token: Option<String>,
    expected_machine_id: Option<String>,
    framer: SseFramer,
}

impl SseControl {
    /// Create a new `SseControl` client.
    ///
    /// * `max_events_per_sec`  — inbound event rate cap; excess events are
    ///   dropped with a WARN log.
    /// * `max_message_size`    — maximum payload bytes; larger payloads are
    ///   dropped before JSON parsing.
    pub fn new(
        transport: std::sync::Arc<dyn crate::transport::ControlTransport>,
        endpoint: String,
        max_events_per_sec: u32,
        max_message_size: usize,
        envelope_trust: Option<NsdEnvelopeTrustConfig>,
    ) -> Self {
        Self {
            transport,
            envelope_trust,
            endpoint,
            sse_stream: None,
            bearer_token: None,
            expected_machine_id: None,
            framer: SseFramer::new(max_events_per_sec, max_message_size),
        }
    }

    /// Returns `true` if the SSE stream is currently open.
    pub fn is_connected(&self) -> bool {
        self.sse_stream.is_some()
    }
}

#[async_trait]
impl ControlStream for SseControl {
    fn set_token(&mut self, token: String) {
        self.bearer_token = Some(token);
    }

    #[instrument(skip(self, report))]
    async fn post_services_report(&mut self, report: ControlEnvelope) -> Result<(), Error> {
        post_services_report_via_call(
            self.transport.as_ref(),
            &self.endpoint,
            report,
            self.envelope_trust.as_ref(),
        )
        .await
    }

    #[instrument(skip(self))]
    async fn connect(&mut self, envelope: ControlEnvelope) -> Result<(), Error> {
        let expected_machine_id = envelope
            .machine_id
            .clone()
            .ok_or_else(|| Error::Auth("config.stream envelope missing machine_id".to_string()))?;
        let stream = crate::transport::instrumented_connect_stream(
            self.transport.as_ref(),
            &self.endpoint,
            envelope,
            self.bearer_token.as_deref(),
        )
        .await?;

        self.sse_stream = Some(stream);
        self.expected_machine_id = Some(expected_machine_id);
        self.framer.clear();
        Ok(())
    }

    /// Receive and decode the next SSE event.
    ///
    /// Reads chunks from the streaming response, accumulates them in the
    /// shared framer, and returns each decoded event. Events that exceed
    /// `max_message_size` or arrive faster than `max_events_per_sec` are
    /// dropped with a WARN log.
    #[instrument(skip(self))]
    async fn next_message(&mut self) -> Result<ControlMessage, Error> {
        next_message_from_stream(
            &mut self.sse_stream,
            &mut self.framer,
            self.envelope_trust.as_ref(),
            self.expected_machine_id.as_deref(),
        )
        .await
    }
}

// ── NoiseControl ─────────────────────────────────────────────────────────────

/// SSE-over-secure-tunnel control client.
///
/// Opens the deployed HTTP control routes over a [`crate::transport::ControlTransport`]
/// such as [`crate::transport::noise::NoiseTransport`] or
/// [`crate::transport::quic::QuicTransport`].
pub struct NoiseControl {
    transport: std::sync::Arc<dyn crate::transport::ControlTransport>,
    envelope_trust: Option<NsdEnvelopeTrustConfig>,
    /// TCP endpoint (`host:port`) for connecting.
    endpoint: String,
    /// Active SSE connection stream.
    sse_stream: Option<crate::transport::BoxStream>,
    bearer_token: Option<String>,
    expected_machine_id: Option<String>,
    framer: SseFramer,
}

impl NoiseControl {
    pub fn new(
        transport: std::sync::Arc<dyn crate::transport::ControlTransport>,
        endpoint: String,
        max_events_per_sec: u32,
        max_message_size: usize,
        envelope_trust: Option<NsdEnvelopeTrustConfig>,
    ) -> Self {
        Self {
            transport,
            envelope_trust,
            endpoint,
            sse_stream: None,
            bearer_token: None,
            expected_machine_id: None,
            framer: SseFramer::new(max_events_per_sec, max_message_size),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.sse_stream.is_some()
    }
}

#[async_trait]
impl ControlStream for NoiseControl {
    fn set_token(&mut self, token: String) {
        self.bearer_token = Some(token);
    }

    async fn post_services_report(&mut self, report: ControlEnvelope) -> Result<(), Error> {
        post_services_report_via_call(
            self.transport.as_ref(),
            &self.endpoint,
            report,
            self.envelope_trust.as_ref(),
        )
        .await
    }

    async fn connect(&mut self, envelope: ControlEnvelope) -> Result<(), Error> {
        let expected_machine_id = envelope
            .machine_id
            .clone()
            .ok_or_else(|| Error::Auth("config.stream envelope missing machine_id".to_string()))?;
        let stream = crate::transport::instrumented_connect_stream(
            self.transport.as_ref(),
            &self.endpoint,
            envelope,
            self.bearer_token.as_deref(),
        )
        .await?;
        self.sse_stream = Some(stream);
        self.expected_machine_id = Some(expected_machine_id);
        self.framer.clear();
        Ok(())
    }

    async fn next_message(&mut self) -> Result<ControlMessage, Error> {
        next_message_from_stream(
            &mut self.sse_stream,
            &mut self.framer,
            self.envelope_trust.as_ref(),
            self.expected_machine_id.as_deref(),
        )
        .await
    }
}

// ── Shared helpers ───────────────────────────────────────────────────────────

async fn post_services_report_via_call(
    transport: &dyn crate::transport::ControlTransport,
    endpoint: &str,
    envelope: ControlEnvelope,
    envelope_trust: Option<&NsdEnvelopeTrustConfig>,
) -> Result<(), Error> {
    let response = crate::transport::instrumented_call(transport, endpoint, envelope).await?;
    verify_pinned_envelope_response(&response, envelope_trust).await?;
    let _: envapi::ServicesReportResponse = envapi::from_cbor(response.payload.as_ref())
        .map_err(|e| Error::Sse(format!("services.report cbor decode: {e}")))?;
    Ok(())
}

/// Maximum time to wait for any bytes on the established config stream before
/// treating the connection as dead.
///
/// The NSD server emits an SSE keepalive comment at least every 15s on an
/// otherwise idle stream (`KEEPALIVE_INTERVAL` = 15s, per the server contract
/// in `control-plane/02-transport-sse`), so a healthy stream always delivers
/// bytes well inside this window. 45s = 3x the server interval: expiry
/// requires three consecutive keepalives to be lost or late, so a half-open /
/// black-holed control path is detected instead of pinning stale ACL state
/// forever. An NSD-side interval change must revisit this constant.
const CONFIG_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(45);

async fn next_message_from_stream(
    sse_stream: &mut Option<crate::transport::BoxStream>,
    framer: &mut SseFramer,
    envelope_trust: Option<&NsdEnvelopeTrustConfig>,
    expected_machine_id: Option<&str>,
) -> Result<ControlMessage, Error> {
    let expected_machine_id = expected_machine_id
        .ok_or_else(|| Error::Auth("config.stream expected machine_id not set".to_string()))?;
    loop {
        if let Some(msg) = framer
            .poll_event(envelope_trust, expected_machine_id)
            .await?
        {
            return Ok(msg);
        }

        let stream = sse_stream
            .as_mut()
            .ok_or_else(|| Error::Sse("not connected".to_string()))?;

        let mut chunk = [0u8; 4096];
        let n =
            match tokio::time::timeout(CONFIG_STREAM_IDLE_TIMEOUT, stream.read(&mut chunk)).await {
                Ok(read_result) => read_result.map_err(|e| Error::Sse(e.to_string()))?,
                Err(_elapsed) => {
                    *sse_stream = None;
                    return Err(Error::Sse(
                        "config stream idle: no bytes in 45s (server keepalive 15s)".to_string(),
                    ));
                }
            };

        if n == 0 {
            *sse_stream = None;
            return Err(Error::Sse("stream ended".to_string()));
        }

        debug!(bytes = n, "received SSE chunk");
        framer.feed(&chunk[..n])?;
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use common::envelope_pins::{ed25519_pubkey_to_okp_thumbprint, persist_first_use_pins};
    use ed25519_dalek::{Signer, SigningKey};
    use futures_util::future::BoxFuture;
    use rand_core::OsRng;
    use serde::Serialize;
    use tokio::io::{AsyncWriteExt, duplex};
    use tracing_subscriber::fmt::MakeWriter;

    use super::{ControlStream, NoiseControl, SseControl, SseFramer, TokenBucket};
    use crate::{
        Error, api as envapi,
        auth::NsdEnvelopeTrustConfig,
        envelope::{self, ControlEnvelope},
        messages::{ControlMessage, ServiceReport, ServicesAck},
        transport::{BoxStream, ControlTransport},
    };

    #[derive(Clone, Default)]
    struct CapturedLogs {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturedLogs {
        fn contents(&self) -> String {
            String::from_utf8(self.bytes.lock().unwrap().clone()).unwrap()
        }
    }

    struct CapturedLogWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CapturedLogWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedLogWriter {
                bytes: Arc::clone(&self.bytes),
            }
        }
    }

    #[derive(Default)]
    struct RecordedTransportCalls {
        call_apis: Vec<String>,
        stream_apis: Vec<String>,
        stream_bearers: Vec<Option<String>>,
        legacy_connects: usize,
    }

    struct MockTransport {
        recorded: Arc<Mutex<RecordedTransportCalls>>,
        signer: SigningKey,
        transport_name: &'static str,
        stream_event: Option<String>,
        response_payload: Option<Vec<u8>>,
    }

    impl MockTransport {
        fn new() -> Arc<Self> {
            Self::with_name("mock")
        }

        fn with_name(transport_name: &'static str) -> Arc<Self> {
            Arc::new(Self {
                recorded: Arc::new(Mutex::new(RecordedTransportCalls::default())),
                signer: SigningKey::generate(&mut OsRng),
                transport_name,
                stream_event: None,
                response_payload: None,
            })
        }

        fn with_stream_event(transport_name: &'static str, event: impl Into<String>) -> Arc<Self> {
            Arc::new(Self {
                recorded: Arc::new(Mutex::new(RecordedTransportCalls::default())),
                signer: SigningKey::generate(&mut OsRng),
                transport_name,
                stream_event: Some(event.into()),
                response_payload: None,
            })
        }

        fn with_response_payload(transport_name: &'static str, payload: Vec<u8>) -> Arc<Self> {
            Arc::new(Self {
                recorded: Arc::new(Mutex::new(RecordedTransportCalls::default())),
                signer: SigningKey::generate(&mut OsRng),
                transport_name,
                stream_event: None,
                response_payload: Some(payload),
            })
        }

        fn recorded(&self) -> Arc<Mutex<RecordedTransportCalls>> {
            Arc::clone(&self.recorded)
        }

        fn response_pin(&self) -> String {
            ed25519_pubkey_to_okp_thumbprint(&self.signer.verifying_key().to_bytes()).unwrap()
        }
    }

    impl ControlTransport for MockTransport {
        fn connect<'a>(&'a self, _endpoint: &'a str) -> BoxFuture<'a, Result<BoxStream, Error>> {
            Box::pin(async move {
                self.recorded.lock().unwrap().legacy_connects += 1;
                Err(Error::Connect("legacy connect must not be used".into()))
            })
        }

        fn connect_stream<'a>(
            &'a self,
            _endpoint: &'a str,
            envelope: ControlEnvelope,
            bearer_token: Option<&'a str>,
        ) -> BoxFuture<'a, Result<BoxStream, Error>> {
            Box::pin(async move {
                let mut recorded = self.recorded.lock().unwrap();
                recorded.stream_apis.push(envelope.api);
                recorded
                    .stream_bearers
                    .push(bearer_token.map(str::to_owned));
                drop(recorded);
                let (client, mut server) = duplex(1024);
                if let Some(event) = self.stream_event.clone() {
                    tokio::spawn(async move {
                        server.write_all(event.as_bytes()).await.unwrap();
                        server.flush().await.unwrap();
                    });
                }
                Ok(BoxStream::new(client))
            })
        }

        fn call<'a>(
            &'a self,
            _endpoint: &'a str,
            envelope: ControlEnvelope,
        ) -> BoxFuture<'a, Result<ControlEnvelope, Error>> {
            Box::pin(async move {
                self.recorded
                    .lock()
                    .unwrap()
                    .call_apis
                    .push(envelope.api.clone());
                let payload = self.response_payload.clone().unwrap_or_else(|| {
                    envapi::to_cbor(&ServicesAck {
                        matched: Vec::new(),
                        unmatched: Vec::new(),
                        rejected: Vec::new(),
                    })
                    .unwrap()
                });
                let pk = self.signer.verifying_key().to_bytes();
                ControlEnvelope::sign_response(
                    envelope.api,
                    envelope.machine_id,
                    pk,
                    payload,
                    |m| self.signer.sign(m).to_bytes(),
                )
                .map_err(Error::from)
            })
        }

        fn name(&self) -> &str {
            self.transport_name
        }
    }

    /// Transport whose `config.stream` writes scripted chunks separated by
    /// virtual-time delays, then either drops the server end (EOF) or holds
    /// it open silently forever. Models an NSD that emits keepalive comments
    /// and then black-holes, for the idle-deadline tests.
    struct ScriptedStreamTransport {
        transport_name: &'static str,
        /// `(seconds to sleep before writing, bytes to write)` steps.
        script: Vec<(u64, Vec<u8>)>,
        /// Keep the server end open (silent) after the script instead of
        /// dropping it, which would surface as EOF rather than idleness.
        hold_open: bool,
    }

    impl ScriptedStreamTransport {
        fn new(
            transport_name: &'static str,
            script: Vec<(u64, Vec<u8>)>,
            hold_open: bool,
        ) -> Arc<Self> {
            Arc::new(Self {
                transport_name,
                script,
                hold_open,
            })
        }
    }

    impl ControlTransport for ScriptedStreamTransport {
        fn connect<'a>(&'a self, _endpoint: &'a str) -> BoxFuture<'a, Result<BoxStream, Error>> {
            Box::pin(async move { Err(Error::Connect("legacy connect must not be used".into())) })
        }

        fn connect_stream<'a>(
            &'a self,
            _endpoint: &'a str,
            _envelope: ControlEnvelope,
            _bearer_token: Option<&'a str>,
        ) -> BoxFuture<'a, Result<BoxStream, Error>> {
            Box::pin(async move {
                let (client, mut server) = duplex(1024);
                let script = self.script.clone();
                let hold_open = self.hold_open;
                tokio::spawn(async move {
                    for (delay_secs, bytes) in script {
                        if delay_secs > 0 {
                            tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                        }
                        server.write_all(&bytes).await.unwrap();
                        server.flush().await.unwrap();
                    }
                    if hold_open {
                        std::future::pending::<()>().await;
                    }
                });
                Ok(BoxStream::new(client))
            })
        }

        fn name(&self) -> &str {
            self.transport_name
        }
    }

    fn signed_envelope(api: &str, payload: Vec<u8>) -> ControlEnvelope {
        let signer = SigningKey::generate(&mut OsRng);
        let pk = signer.verifying_key().to_bytes();
        ControlEnvelope::sign_request(api, Some("m-1".to_string()), pk, payload, |m| {
            signer.sign(m).to_bytes()
        })
        .unwrap()
    }

    fn empty_report() -> ServiceReport {
        ServiceReport {
            services: Default::default(),
            strict_mode: false,
            system_info: None,
        }
    }

    fn envelope_trust_with_pins(pins: Vec<String>) -> NsdEnvelopeTrustConfig {
        NsdEnvelopeTrustConfig::new(
            "nsd-a",
            "realm-a",
            "/tmp/nsio-control-sse-test",
            "http://nsd.test",
            pins,
            None,
        )
    }

    fn services_report_envelope() -> ControlEnvelope {
        let payload = envapi::to_cbor(&empty_report()).unwrap();
        signed_envelope(envelope::api::SERVICES_REPORT, payload)
    }

    fn signed_config_event(
        signer: &SigningKey,
        api: &str,
        machine_id: &str,
        payload: Vec<u8>,
    ) -> ControlEnvelope {
        let pk = signer.verifying_key().to_bytes();
        ControlEnvelope::sign_response(api, Some(machine_id.to_string()), pk, payload, |m| {
            signer.sign(m).to_bytes()
        })
        .unwrap()
    }

    fn signed_config_message_event(
        signer: &SigningKey,
        machine_id: &str,
        message: ControlMessage,
    ) -> ControlEnvelope {
        let payload =
            envapi::to_cbor(&envapi::ConfigStreamEventPayloadV1 { v: 1, message }).unwrap();
        signed_config_event(signer, envelope::api::CONFIG_STREAM, machine_id, payload)
    }

    fn signed_config_sse_event(envelope: &ControlEnvelope) -> String {
        let data = URL_SAFE_NO_PAD.encode(envelope.to_cbor().unwrap());
        format!("event: config-envelope.v1\ndata: {data}\n\n")
    }

    /// Wire shape of a `ControlMessage` variant this build does not know yet.
    #[derive(Serialize)]
    struct FutureControlMessage {
        #[serde(rename = "type")]
        kind: &'static str,
        flux: u32,
        capacitor: &'static str,
    }

    #[derive(Serialize)]
    struct FutureEventPayload {
        v: u8,
        message: FutureControlMessage,
    }

    fn signed_future_variant_event(signer: &SigningKey, machine_id: &str) -> ControlEnvelope {
        let payload = envapi::to_cbor(&FutureEventPayload {
            v: 1,
            message: FutureControlMessage {
                kind: "flux_capacitor_config",
                flux: 88,
                capacitor: "charged",
            },
        })
        .unwrap();
        signed_config_event(signer, envelope::api::CONFIG_STREAM, machine_id, payload)
    }

    fn config_event_trust(signer: &SigningKey) -> NsdEnvelopeTrustConfig {
        let pin = ed25519_pubkey_to_okp_thumbprint(&signer.verifying_key().to_bytes()).unwrap();
        envelope_trust_with_pins(vec![pin])
    }

    #[derive(Serialize)]
    struct BadVersionPayload {
        v: u8,
        message: u64,
    }

    async fn post_services_report_for_transport(
        transport_name: &'static str,
        trust: Option<NsdEnvelopeTrustConfig>,
    ) -> Result<(), Error> {
        let transport = MockTransport::with_name(transport_name);
        let mut control: Box<dyn ControlStream> = if transport_name == "sse" {
            Box::new(SseControl::new(
                transport,
                "nsd.test:443".into(),
                100,
                4096,
                trust,
            ))
        } else {
            Box::new(NoiseControl::new(
                transport,
                "nsd.test:4001".into(),
                100,
                4096,
                trust,
            ))
        };
        control
            .post_services_report(services_report_envelope())
            .await
    }

    #[test]
    fn token_bucket_allows_first_message() {
        let mut bucket = TokenBucket::new(10);
        assert!(bucket.try_consume(), "first message must be allowed");
    }

    #[test]
    fn token_bucket_exhausts_after_capacity_messages() {
        let capacity = 5u32;
        let mut bucket = TokenBucket::new(capacity);

        for i in 0..capacity {
            assert!(
                bucket.try_consume(),
                "message {i} should be allowed while tokens remain"
            );
        }

        assert!(
            !bucket.try_consume(),
            "message after capacity exceeded must be dropped"
        );
    }

    #[test]
    fn token_bucket_refills_after_elapsed_time() {
        let mut bucket = TokenBucket::new(10);

        for _ in 0..10 {
            bucket.try_consume();
        }
        assert!(!bucket.try_consume(), "bucket must be empty");

        bucket.last_refill -= std::time::Duration::from_secs(1);

        assert!(
            bucket.try_consume(),
            "bucket must allow messages after refill interval"
        );
    }

    #[test]
    fn token_bucket_does_not_exceed_capacity_on_large_elapsed() {
        let capacity = 4u32;
        let mut bucket = TokenBucket::new(capacity);

        for _ in 0..capacity {
            bucket.try_consume();
        }

        bucket.last_refill -= std::time::Duration::from_secs(10);

        for i in 0..capacity {
            assert!(
                bucket.try_consume(),
                "token {i} must be available after refill"
            );
        }
        assert!(
            !bucket.try_consume(),
            "tokens must not accumulate beyond capacity"
        );
    }

    #[test]
    fn token_bucket_rate_1_allows_one_per_second() {
        let mut bucket = TokenBucket::new(1);

        assert!(bucket.try_consume(), "first message must be allowed");
        assert!(!bucket.try_consume(), "second message must be dropped");

        bucket.last_refill -= std::time::Duration::from_secs(1);
        assert!(
            bucket.try_consume(),
            "must be allowed after 1-second refill"
        );
        assert!(!bucket.try_consume(), "must be dropped immediately after");
    }

    // Regression for AUDIT-006 P2.5: oversized SSE events must consume a
    // rate-limit token so a flood of just-too-large events cannot bypass the
    // inbound rate limiter.
    #[tokio::test]
    async fn oversized_events_consume_rate_limit_tokens() {
        // max_events_per_sec=2, max_message_size=10. The payload is 50
        // bytes — well past the size cap.
        let mut framer = SseFramer::new(2, 10);
        let oversize = format!("event: config-envelope.v1\ndata: {}\n\n", "A".repeat(50));

        // Two oversize events exhaust the bucket even though both are
        // dropped for size. A third oversize event must hit rate-limiter.
        for _ in 0..2 {
            let res = framer
                .parse_event(&oversize, None, "m-1")
                .await
                .expect("parse ok");
            assert!(res.is_none(), "oversize event must be dropped");
        }
        // Bucket is now empty — the next event, regardless of size, must
        // also be dropped via the rate-limit branch (not the oversize one).
        let small = "event: config-envelope.v1\ndata: AA\n\n";
        let res = framer
            .parse_event(small, None, "m-1")
            .await
            .expect("parse ok");
        assert!(
            res.is_none(),
            "rate-limit must fire on the third event, even when it is well-formed"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn token_refresh_sse_logs_metadata_without_bearer_payload() {
        let token = "bearer-token-that-must-not-hit-logs";
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let envelope = signed_config_message_event(
            &signer,
            "m-1",
            ControlMessage::TokenRefresh {
                token: token.to_string(),
            },
        );
        let event = signed_config_sse_event(&envelope);
        let mut framer = SseFramer::new(100, 4096);

        let captured = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let msg = framer
            .parse_event(&event, Some(&trust), "m-1")
            .await
            .unwrap()
            .unwrap();
        drop(guard);
        assert!(matches!(msg, ControlMessage::TokenRefresh { .. }));
        let logs = captured.contents();

        if !logs.is_empty() {
            assert!(logs.contains("token_refresh"));
            assert!(logs.contains("size"));
        }
        assert!(!logs.contains(token));
        assert!(!logs.contains(&event));
        assert!(!logs.contains("payload"));
    }

    #[tokio::test]
    async fn sse_services_report_uses_transport_call() {
        let transport = MockTransport::new();
        let trust = envelope_trust_with_pins(vec![transport.response_pin()]);
        let recorded = transport.recorded();
        let mut control = SseControl::new(transport, "nsd.test:443".into(), 100, 4096, Some(trust));

        control
            .post_services_report(services_report_envelope())
            .await
            .unwrap();

        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.call_apis, vec![envelope::api::SERVICES_REPORT]);
        assert!(recorded.stream_apis.is_empty());
        assert_eq!(recorded.legacy_connects, 0);
    }

    #[tokio::test]
    async fn services_report_rejects_unpinned_response_key_for_all_transports() {
        for transport_name in ["sse", "noise", "quic"] {
            let attacker = SigningKey::generate(&mut OsRng);
            let attacker_pin =
                ed25519_pubkey_to_okp_thumbprint(&attacker.verifying_key().to_bytes()).unwrap();
            let err = post_services_report_for_transport(
                transport_name,
                Some(envelope_trust_with_pins(vec![attacker_pin])),
            )
            .await
            .expect_err("unpinned services.report response must be rejected");
            assert!(
                matches!(err, Error::Auth(ref msg) if msg.contains("not trusted")),
                "{transport_name}: unexpected error {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn services_report_fails_closed_without_envelope_pin() {
        let err = post_services_report_for_transport("sse", None)
            .await
            .expect_err("missing envelope trust config must fail closed");
        assert!(matches!(err, Error::Auth(msg) if msg.contains("not configured")));

        let err =
            post_services_report_for_transport("noise", Some(envelope_trust_with_pins(Vec::new())))
                .await
                .expect_err("empty envelope pin set with no TOFU pin must fail closed");
        assert!(matches!(err, Error::Auth(msg) if msg.contains("not configured")));
    }

    #[tokio::test]
    async fn services_report_rejects_wrong_key_after_tofu_pin() {
        let tempdir = tempfile::tempdir().unwrap();
        let trusted_nsd = SigningKey::generate(&mut OsRng);
        let trusted_pin =
            ed25519_pubkey_to_okp_thumbprint(&trusted_nsd.verifying_key().to_bytes()).unwrap();
        persist_first_use_pins(
            tempdir.path(),
            "realm-a",
            "http://nsd.test",
            vec![trusted_pin],
            1,
        )
        .await
        .unwrap();

        let trust = NsdEnvelopeTrustConfig::new(
            "nsd-a",
            "realm-a",
            tempdir.path(),
            "http://nsd.test",
            Vec::new(),
            None,
        );
        let err = post_services_report_for_transport("quic", Some(trust))
            .await
            .expect_err("wrong key after TOFU pin must be rejected");
        assert!(matches!(err, Error::Auth(msg) if msg.contains("not trusted")));
    }

    #[tokio::test]
    async fn services_report_verifies_pin_before_decoding_ack_payload() {
        let transport = MockTransport::with_response_payload("sse", b"not-cbor".to_vec());
        let untrusted_nsd = SigningKey::generate(&mut OsRng);
        let untrusted_pin =
            ed25519_pubkey_to_okp_thumbprint(&untrusted_nsd.verifying_key().to_bytes()).unwrap();
        let trust = envelope_trust_with_pins(vec![untrusted_pin]);
        let mut control = SseControl::new(transport, "nsd.test:443".into(), 100, 4096, Some(trust));

        let err = control
            .post_services_report(services_report_envelope())
            .await
            .expect_err("pin gate must run before services.report payload decode");
        assert!(matches!(err, Error::Auth(msg) if msg.contains("not trusted")));
    }

    #[tokio::test]
    async fn services_report_static_pin_takes_precedence_over_tofu_pin() {
        let tempdir = tempfile::tempdir().unwrap();
        let transport = MockTransport::with_name("noise");
        let static_pin = transport.response_pin();
        let stale_nsd = SigningKey::generate(&mut OsRng);
        let stale_pin =
            ed25519_pubkey_to_okp_thumbprint(&stale_nsd.verifying_key().to_bytes()).unwrap();
        persist_first_use_pins(
            tempdir.path(),
            "realm-a",
            "http://nsd.test",
            vec![stale_pin],
            1,
        )
        .await
        .unwrap();

        let trust = NsdEnvelopeTrustConfig::new(
            "nsd-a",
            "realm-a",
            tempdir.path(),
            "http://nsd.test",
            vec![static_pin],
            None,
        );
        let mut control =
            NoiseControl::new(transport, "nsd.test:4001".into(), 100, 4096, Some(trust));

        control
            .post_services_report(services_report_envelope())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn noise_config_stream_uses_bearer_connect_stream() {
        let transport = MockTransport::new();
        let recorded = transport.recorded();
        let mut control = NoiseControl::new(transport, "nsd.test:4001".into(), 100, 4096, None);
        let payload = envapi::to_cbor(&envapi::ConfigStreamRequest::default()).unwrap();
        control.set_token("token-from-register".to_string());

        control
            .connect(signed_envelope(envelope::api::CONFIG_STREAM, payload))
            .await
            .unwrap();

        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.stream_apis, vec![envelope::api::CONFIG_STREAM]);
        assert_eq!(
            recorded.stream_bearers,
            vec![Some("token-from-register".to_string())]
        );
        assert!(recorded.call_apis.is_empty());
        assert_eq!(recorded.legacy_connects, 0);
    }

    #[tokio::test]
    async fn config_stream_event_verifies_and_yields_message() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let event = signed_config_sse_event(&signed_config_message_event(
            &signer,
            "m-1",
            ControlMessage::Ping,
        ));
        let mut framer = SseFramer::new(100, 4096);

        let msg = framer
            .parse_event(&event, Some(&trust), "m-1")
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(msg, ControlMessage::Ping));
    }

    #[tokio::test]
    async fn config_stream_event_keeps_single_data_contract() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let event = signed_config_sse_event(&signed_config_message_event(
            &signer,
            "m-1",
            ControlMessage::Ping,
        ));
        let data = event
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap();
        let mut framer = SseFramer::new(100, 4096);

        let msg = framer
            .parse_event(
                &format!("event: config-envelope.v1\ndata: {data}"),
                Some(&trust),
                "m-1",
            )
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(msg, ControlMessage::Ping));

        let err = framer
            .parse_event(
                &format!("event: config-envelope.v1\ndata: {data}\ndata: {data}"),
                Some(&trust),
                "m-1",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Auth(msg) if msg.contains("exactly one data")));
    }

    #[tokio::test]
    async fn config_stream_rejects_unsigned_raw_json() {
        let mut framer = SseFramer::new(100, 4096);
        let err = framer
            .parse_event("data: {\"type\":\"ping\"}\n\n", None, "m-1")
            .await
            .expect_err("raw JSON config.stream events must be rejected");
        assert!(matches!(err, Error::Auth(msg) if msg.contains("config-envelope.v1")));
    }

    #[tokio::test]
    async fn config_stream_rejects_bad_signature() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let mut envelope = signed_config_message_event(&signer, "m-1", ControlMessage::Ping);
        envelope.signature[0] ^= 0x01;
        let event = signed_config_sse_event(&envelope);
        let mut framer = SseFramer::new(100, 4096);

        let err = framer
            .parse_event(&event, Some(&trust), "m-1")
            .await
            .expect_err("bad config.stream event signature must be rejected");

        assert!(matches!(
            err,
            Error::Envelope(envelope::Error::InvalidSignature)
        ));
    }

    #[tokio::test]
    async fn config_stream_rejects_wrong_api() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let payload = envapi::to_cbor(&envapi::ConfigStreamEventPayloadV1 {
            v: 1,
            message: ControlMessage::Ping,
        })
        .unwrap();
        let envelope = signed_config_event(&signer, envelope::api::INFO_GET, "m-1", payload);
        let event = signed_config_sse_event(&envelope);
        let mut framer = SseFramer::new(100, 4096);

        let err = framer
            .parse_event(&event, Some(&trust), "m-1")
            .await
            .expect_err("wrong config.stream event api must be rejected");

        assert!(matches!(err, Error::Auth(msg) if msg.contains("api mismatch")));
    }

    #[tokio::test]
    async fn config_stream_rejects_wrong_machine_id() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let event = signed_config_sse_event(&signed_config_message_event(
            &signer,
            "m-2",
            ControlMessage::Ping,
        ));
        let mut framer = SseFramer::new(100, 4096);

        let err = framer
            .parse_event(&event, Some(&trust), "m-1")
            .await
            .expect_err("wrong config.stream machine_id must be rejected");

        assert!(matches!(err, Error::Auth(msg) if msg.contains("machine_id mismatch")));
    }

    #[tokio::test]
    async fn config_stream_rejects_bad_payload_version_before_message_decode() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let payload = envapi::to_cbor(&BadVersionPayload { v: 2, message: 7 }).unwrap();
        let envelope = signed_config_event(&signer, envelope::api::CONFIG_STREAM, "m-1", payload);
        let event = signed_config_sse_event(&envelope);
        let mut framer = SseFramer::new(100, 4096);

        let err = framer
            .parse_event(&event, Some(&trust), "m-1")
            .await
            .expect_err("bad config.stream payload version must be rejected");

        assert!(matches!(err, Error::Auth(msg) if msg.contains("payload version: 2")));
    }

    #[tokio::test]
    async fn config_stream_rejects_stale_timestamp() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let mut envelope = signed_config_message_event(&signer, "m-1", ControlMessage::Ping);
        envelope.ts = envelope
            .ts
            .saturating_sub(envelope::MAX_CLOCK_SKEW_SECS + 1);
        let event = signed_config_sse_event(&envelope);
        let mut framer = SseFramer::new(100, 4096);

        let err = framer
            .parse_event(&event, Some(&trust), "m-1")
            .await
            .expect_err("stale config.stream event must be rejected");

        assert!(matches!(
            err,
            Error::Envelope(envelope::Error::ClockSkew { .. })
        ));
    }

    #[tokio::test]
    async fn config_stream_rejects_replayed_nonce() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let event = signed_config_sse_event(&signed_config_message_event(
            &signer,
            "m-1",
            ControlMessage::Ping,
        ));
        let mut framer = SseFramer::new(100, 4096);

        let first = framer
            .parse_event(&event, Some(&trust), "m-1")
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(first, ControlMessage::Ping));
        let err = framer
            .parse_event(&event, Some(&trust), "m-1")
            .await
            .expect_err("replayed config.stream event nonce must be rejected");

        assert!(matches!(err, Error::Replay));
    }

    #[tokio::test]
    async fn config_stream_rejects_malformed_base64_and_cbor() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let mut framer = SseFramer::new(100, 4096);

        let err = framer
            .parse_event(
                "event: config-envelope.v1\ndata: not@@base64\n\n",
                Some(&trust),
                "m-1",
            )
            .await
            .expect_err("malformed base64url must be rejected");
        assert!(matches!(err, Error::Auth(msg) if msg.contains("base64url")));

        let bad_cbor = URL_SAFE_NO_PAD.encode(b"not-cbor");
        let err = framer
            .parse_event(
                &format!("event: config-envelope.v1\ndata: {bad_cbor}\n\n"),
                Some(&trust),
                "m-1",
            )
            .await
            .expect_err("malformed envelope CBOR must be rejected");
        assert!(matches!(
            err,
            Error::Envelope(envelope::Error::CborDecode(_))
        ));
    }

    #[tokio::test]
    async fn config_stream_rejects_missing_trust_and_unpinned_key() {
        let signer = SigningKey::generate(&mut OsRng);
        let event = signed_config_sse_event(&signed_config_message_event(
            &signer,
            "m-1",
            ControlMessage::Ping,
        ));
        let mut framer = SseFramer::new(100, 4096);

        let err = framer
            .parse_event(&event, None, "m-1")
            .await
            .expect_err("missing config.stream envelope trust must fail closed");
        assert!(matches!(err, Error::Auth(msg) if msg.contains("not configured")));

        let other_signer = SigningKey::generate(&mut OsRng);
        let other_trust = config_event_trust(&other_signer);
        let mut framer = SseFramer::new(100, 4096);
        let err = framer
            .parse_event(&event, Some(&other_trust), "m-1")
            .await
            .expect_err("unpinned config.stream envelope key must fail closed");
        assert!(matches!(err, Error::Auth(msg) if msg.contains("not trusted")));
    }

    // Forward compatibility: an event carrying a `type` tag from a newer NSD
    // must be verified, warn-logged with the tag, and skipped — not error the
    // stream into a reconnect loop.
    #[tokio::test(flavor = "current_thread")]
    async fn config_stream_skips_unknown_variant_and_stays_up() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let unknown_event = signed_config_sse_event(&signed_future_variant_event(&signer, "m-1"));
        let mut framer = SseFramer::new(100, 4096);

        let captured = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let skipped = framer
            .parse_event(&unknown_event, Some(&trust), "m-1")
            .await
            .expect("unknown control message variant must not error the stream");
        drop(guard);
        assert!(skipped.is_none(), "unknown variant must be skipped");
        let logs = captured.contents();
        assert!(
            logs.contains("flux_capacitor_config"),
            "warn log must carry the unknown type tag: {logs}"
        );

        // The stream stays up: a later known event on the same framer applies.
        let known_event = signed_config_sse_event(&signed_config_message_event(
            &signer,
            "m-1",
            ControlMessage::Ping,
        ));
        let msg = framer
            .parse_event(&known_event, Some(&trust), "m-1")
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(msg, ControlMessage::Ping));
    }

    // A snapshot burst mixing one unknown variant with known ones must still
    // deliver every known variant.
    #[tokio::test]
    async fn config_stream_snapshot_burst_skips_unknown_and_delivers_known() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let mut stream = String::new();
        stream.push_str(&signed_config_sse_event(&signed_config_message_event(
            &signer,
            "m-1",
            ControlMessage::Ping,
        )));
        stream.push_str(&signed_config_sse_event(&signed_future_variant_event(
            &signer, "m-1",
        )));
        for _ in 0..2 {
            stream.push_str(&signed_config_sse_event(&signed_config_message_event(
                &signer,
                "m-1",
                ControlMessage::Ping,
            )));
        }
        let transport = MockTransport::with_stream_event("quic", stream);
        let mut control =
            NoiseControl::new(transport, "nsd.test:4002".into(), 100, 4096, Some(trust));
        let payload = envapi::to_cbor(&envapi::ConfigStreamRequest::default()).unwrap();
        control.set_token("token-from-register".to_string());

        control
            .connect(signed_envelope(envelope::api::CONFIG_STREAM, payload))
            .await
            .unwrap();

        for _ in 0..3 {
            let msg = control
                .next_message()
                .await
                .expect("known events around an unknown variant must still deliver");
            assert!(matches!(msg, ControlMessage::Ping));
        }
    }

    // Tolerant body decode must not loosen envelope verification: a bad
    // signature on an unknown-variant event still errors the stream.
    #[tokio::test]
    async fn config_stream_unknown_variant_with_bad_signature_still_errors() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let mut envelope = signed_future_variant_event(&signer, "m-1");
        envelope.signature[0] ^= 0x01;
        let event = signed_config_sse_event(&envelope);
        let mut framer = SseFramer::new(100, 4096);

        let err = framer
            .parse_event(&event, Some(&trust), "m-1")
            .await
            .expect_err("envelope verification must stay fail-closed for unknown variants");

        assert!(matches!(
            err,
            Error::Envelope(envelope::Error::InvalidSignature)
        ));
    }

    #[tokio::test]
    async fn config_stream_large_stream_errors_on_first_bad_event() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let mut stream = String::new();
        for _ in 0..25 {
            stream.push_str(&signed_config_sse_event(&signed_config_message_event(
                &signer,
                "m-1",
                ControlMessage::Ping,
            )));
        }
        stream.push_str("data: {\"type\":\"ping\"}\n\n");
        let transport = MockTransport::with_stream_event("quic", stream);
        let recorded = transport.recorded();
        let mut control =
            NoiseControl::new(transport, "nsd.test:4002".into(), 100, 4096, Some(trust));
        let payload = envapi::to_cbor(&envapi::ConfigStreamRequest::default()).unwrap();
        control.set_token("token-from-register".to_string());

        control
            .connect(signed_envelope(envelope::api::CONFIG_STREAM, payload))
            .await
            .unwrap();

        for _ in 0..25 {
            let msg = control.next_message().await.unwrap();
            assert!(matches!(msg, ControlMessage::Ping));
        }
        let err = control
            .next_message()
            .await
            .expect_err("bad event must terminate the stream attempt");
        assert!(matches!(err, Error::Auth(msg) if msg.contains("config-envelope.v1")));

        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.stream_apis, vec![envelope::api::CONFIG_STREAM]);
        assert_eq!(
            recorded.stream_bearers,
            vec![Some("token-from-register".to_string())]
        );
        assert!(recorded.call_apis.is_empty());
    }

    // A stream that delivers one keepalive comment and then black-holes (no
    // bytes, no EOF, no socket error) must trip the idle deadline: the read
    // expires after 45s of virtual time with an error naming the deadline,
    // and the client reports disconnected so the driver's reconnect and
    // fail-closed chain can engage.
    #[tokio::test(start_paused = true)]
    async fn config_stream_black_hole_trips_idle_deadline_and_disconnects() {
        let transport =
            ScriptedStreamTransport::new("sse", vec![(0, b": keepalive\n\n".to_vec())], true);
        let mut control = SseControl::new(transport, "nsd.test:443".into(), 100, 4096, None);
        let payload = envapi::to_cbor(&envapi::ConfigStreamRequest::default()).unwrap();
        control.set_token("token-from-register".to_string());
        control
            .connect(signed_envelope(envelope::api::CONFIG_STREAM, payload))
            .await
            .unwrap();
        assert!(control.is_connected());

        let start = tokio::time::Instant::now();
        let err = control
            .next_message()
            .await
            .expect_err("black-holed stream must expire instead of blocking forever");

        assert!(
            start.elapsed() >= std::time::Duration::from_secs(45),
            "deadline must not fire before 45s of stream silence: {:?}",
            start.elapsed()
        );
        assert!(
            matches!(err, Error::Sse(ref msg) if msg.contains("idle") && msg.contains("45s")),
            "error must name the idle deadline: {err:?}"
        );
        assert!(!control.is_connected());
    }

    // Keepalive comments at the server's 15s cadence must hold the stream
    // open across at least three 45s deadline windows without erroring, and
    // a real signed event arriving afterwards must still decode.
    #[tokio::test(start_paused = true)]
    async fn config_stream_keepalives_hold_stream_open_across_deadline_windows() {
        let signer = SigningKey::generate(&mut OsRng);
        let trust = config_event_trust(&signer);
        let event = signed_config_sse_event(&signed_config_message_event(
            &signer,
            "m-1",
            ControlMessage::Ping,
        ));
        let mut script: Vec<(u64, Vec<u8>)> =
            (0..9).map(|_| (15, b": keepalive\n\n".to_vec())).collect();
        script.push((15, event.into_bytes()));
        let transport = ScriptedStreamTransport::new("quic", script, false);
        let mut control =
            NoiseControl::new(transport, "nsd.test:4002".into(), 100, 4096, Some(trust));
        let payload = envapi::to_cbor(&envapi::ConfigStreamRequest::default()).unwrap();
        control.set_token("token-from-register".to_string());
        control
            .connect(signed_envelope(envelope::api::CONFIG_STREAM, payload))
            .await
            .unwrap();

        let start = tokio::time::Instant::now();
        let msg = control
            .next_message()
            .await
            .expect("15s keepalives must keep the stream inside the idle deadline");

        assert!(matches!(msg, ControlMessage::Ping));
        assert!(
            start.elapsed() >= std::time::Duration::from_secs(135),
            "stream must have stayed up across three 45s windows: {:?}",
            start.elapsed()
        );
        assert!(control.is_connected());
    }
}
