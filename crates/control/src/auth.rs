use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::envelope_pins::{
    ed25519_pubkey_hex_to_okp_thumbprint, ed25519_pubkey_to_okp_thumbprint,
    load_tofu_pins as load_envelope_tofu_pins, normalize_nsd_url,
    persist_first_use_pins as persist_first_use_envelope_pins, pin_set_contains,
    touch_tofu_entry as touch_envelope_tofu_entry,
};
use common::jwt_pins::{
    JwkSet, RsaJwk, load_tofu_pins, normalize_jwks_url, persist_first_use_pins, rsa_jwk_thumbprint,
    touch_tofu_entry, validate_rsa_jwk,
};
use common::{MachineState, NsdInfo, SystemInfo};
use opentelemetry::KeyValue;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{instrument, warn};

use crate::Error;
use crate::api as envapi;
use crate::envelope::{self, ControlEnvelope, api as envapi_ids};
use crate::messages::{ControlMessage, LinkMode};
use crate::transport::{ControlTransport, framing, sse::endpoint_host};
use crate::types::ConnectorType;

/// Client-side replay cache for signed `config.stream` events.
#[derive(Debug, Default)]
pub struct ConfigStreamReplayCache {
    seen: HashMap<ConfigStreamReplayKey, u64>,
}

impl ConfigStreamReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn check_and_insert(
        &mut self,
        trust: &NsdEnvelopeTrustConfig,
        machine_id: &str,
        nonce: [u8; 16],
        ts: u64,
        now: u64,
    ) -> Result<(), Error> {
        self.prune(now);
        let key = ConfigStreamReplayKey {
            nsd_id: trust.nsd_id.clone(),
            realm: trust.realm.clone(),
            machine_id: machine_id.to_string(),
            nonce,
        };
        if self.seen.contains_key(&key) {
            return Err(Error::Replay);
        }
        self.seen.insert(key, ts);
        Ok(())
    }

    fn prune(&mut self, now: u64) {
        let cutoff = now.saturating_sub(envelope::REPLAY_WINDOW_SECS);
        self.seen.retain(|_, ts| *ts >= cutoff);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConfigStreamReplayKey {
    nsd_id: String,
    realm: String,
    machine_id: String,
    nonce: [u8; 16],
}

#[derive(Deserialize)]
struct ConfigStreamEventPayloadHeader {
    v: u8,
}

/// Strip any URL scheme (`https?://`, `noise://`, `quic://`) and return
/// `host:port`. Used to feed `ControlTransport::call(endpoint, ..)`.
pub fn to_endpoint(url: &str) -> String {
    let no_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("noise://"))
        .or_else(|| url.strip_prefix("quic://"))
        .unwrap_or(url);
    let host_port = no_scheme.split('/').next().unwrap_or(no_scheme);
    if host_port.contains(':') {
        host_port.to_string()
    } else {
        // No explicit port: default by scheme. Covers a bare `https://host` and,
        // crucially, the `url::Url`-normalized `https://host:443` -> `https://host/`
        // case (the default port is dropped on round-trip), which otherwise
        // yields a portless "invalid socket address" on connect. noise/quic have
        // no universal default and still require an explicit port.
        if url.starts_with("https://") {
            format!("{host_port}:443")
        } else if url.starts_with("http://") {
            format!("{host_port}:80")
        } else {
            host_port.to_string()
        }
    }
}

fn is_anti_dpi_url(url: &str) -> bool {
    url.starts_with("noise://") || url.starts_with("quic://")
}

fn is_anti_dpi_transport(transport: &dyn ControlTransport) -> bool {
    matches!(transport.name(), "noise" | "quic")
}

// ── legacy JSON bodies (pre-envelope) ─────────────────────────────────────────

#[derive(Debug, Serialize)]
struct RegisterRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_key: Option<String>,
    /// Client-requested machine ID.  When provided the server MUST use this value
    /// and treat registration as idempotent (same ID → update existing record).
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_id: Option<String>,
    machine_key_pub: String,
    peer_key_pub: String,
    hostname: String,
    os: String,
    version: String,
    /// Machine role (D3). Absent on the wire when `None`; NSD treats absent
    /// as `Connector`.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    r#type: Option<ConnectorType>,
    /// Extended system information for device inventory.
    #[serde(skip_serializing_if = "Option::is_none")]
    system_info: Option<SystemInfo>,
    /// Client capability tokens advertised during registration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    capabilities: Vec<String>,
    /// Link modes this machine can participate in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    supported_link_modes: Vec<LinkMode>,
    /// Preferred link mode when several supported modes are viable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preferred_mode: Option<LinkMode>,
}

#[derive(Debug, Serialize)]
struct HeartbeatPayload {
    machine_id: String,
    uptime_secs: u64,
    local_ips: Vec<String>,
}

// ── HeartbeatClient ───────────────────────────────────────────────────────────

/// Lightweight client for sending periodic heartbeats to a single NSD endpoint.
///
/// Created before the main [`AuthClient`] is moved into the control plane so
/// that the heartbeat background task can run independently.
///
/// When a `transport` is attached, `heartbeat()` uses the signed
/// `ControlEnvelope` path via [`ControlTransport::call`]. Otherwise it falls
/// back to the legacy reqwest JSON path.
pub struct HeartbeatClient {
    http: reqwest::Client,
    base_url: String,
    machine_id: String,
    /// Optional signed-envelope path. When present, used in preference to
    /// the reqwest path.
    transport: Option<Arc<dyn ControlTransport>>,
    /// Endpoint (`host:port`) handed to `transport.call()`.
    endpoint: String,
    /// Machine Ed25519 identity. When set, the legacy reqwest path mints and
    /// caches a JWT here via the same `POST /api/v1/machine/auth` flow that
    /// [`AuthClient::authenticate`] uses, and refreshes it on a single 401.
    signer: Option<EnvelopeSigner>,
    /// Cached bearer JWT used by the legacy heartbeat path. Populated lazily
    /// the first time `heartbeat_legacy` runs with a signer attached, and
    /// invalidated on 401. The mutex is short-lived: never held across
    /// `await`s, so `std::sync::Mutex` is safe inside an async context here.
    bearer: std::sync::Mutex<Option<String>>,
    jwt_verifier: Option<Arc<NsdJwtVerifier>>,
    envelope_trust: Option<NsdEnvelopeTrustConfig>,
}

/// Signing material required to build outgoing request envelopes.
///
/// Holds only the envelope-relevant fields (Ed25519 public half + signing
/// key) so the heartbeat task and control plane can share a signer without
/// cloning the whole `MachineState` (which is not `Clone`) or wrapping it
/// in `Arc`.
#[derive(Clone)]
pub struct EnvelopeSigner {
    machine_key_pub: [u8; 32],
    signing_key: ed25519_dalek::SigningKey,
}

impl EnvelopeSigner {
    /// Build an `EnvelopeSigner` from a `MachineState`.  Clones the
    /// signing key so the returned signer has its own copy.
    pub fn from_state(state: &MachineState) -> Self {
        Self {
            machine_key_pub: state.machine_key_pub,
            signing_key: state.signing_key_clone(),
        }
    }

    pub fn machine_key_pub(&self) -> [u8; 32] {
        self.machine_key_pub
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message).to_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenPurpose {
    Control,
    Wss,
}

impl TokenPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Wss => "wss",
        }
    }
}

const CONTROL_ENVELOPE_PATH: &str = "/api/v1/control";

#[derive(Clone)]
pub struct NsdJwtTrustConfig {
    nsd_id: String,
    realm: String,
    state_dir: PathBuf,
    static_pins: Vec<String>,
    jwks_url: String,
}

impl NsdJwtTrustConfig {
    pub fn new(
        nsd_id: impl Into<String>,
        realm: impl Into<String>,
        state_dir: impl Into<PathBuf>,
        base_url: &str,
        static_pins: Vec<String>,
    ) -> Self {
        Self {
            nsd_id: nsd_id.into(),
            realm: realm.into(),
            state_dir: state_dir.into(),
            static_pins,
            jwks_url: default_jwks_url(base_url),
        }
    }

    pub fn jwks_url(&self) -> &str {
        &self.jwks_url
    }
}

#[derive(Clone)]
pub struct NsdEnvelopeTrustConfig {
    nsd_id: String,
    realm: String,
    state_dir: PathBuf,
    static_pins: Vec<String>,
    nsd_url: String,
    advertised_pubkey_hex: Option<String>,
    dev_tofu_enabled: bool,
}

impl NsdEnvelopeTrustConfig {
    pub fn new(
        nsd_id: impl Into<String>,
        realm: impl Into<String>,
        state_dir: impl Into<PathBuf>,
        base_url: &str,
        static_pins: Vec<String>,
        advertised_pubkey_hex: Option<String>,
    ) -> Self {
        Self {
            nsd_id: nsd_id.into(),
            realm: realm.into(),
            state_dir: state_dir.into(),
            static_pins,
            nsd_url: normalize_nsd_url(base_url),
            advertised_pubkey_hex,
            dev_tofu_enabled: cfg!(debug_assertions),
        }
    }

    #[cfg(test)]
    fn without_dev_tofu(mut self) -> Self {
        self.dev_tofu_enabled = false;
        self
    }
}

#[derive(Clone)]
pub struct NsdJwtVerifier {
    http: reqwest::Client,
    trust: Arc<NsdJwtTrustConfig>,
    transport: Option<Arc<dyn ControlTransport>>,
    endpoint: String,
    cache: Arc<Mutex<Option<TrustedJwks>>>,
}

#[derive(Clone)]
struct TrustedJwks {
    keys: Vec<TrustedJwk>,
    source: TrustSource,
}

#[derive(Clone)]
struct TrustedJwk {
    kid: String,
    thumbprint: String,
    jwk: RsaJwk,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrustSource {
    Static,
    Tofu,
    Bootstrap,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    kid: Option<String>,
}

impl NsdJwtVerifier {
    pub fn new(http: reqwest::Client, trust: NsdJwtTrustConfig) -> Self {
        let endpoint = to_endpoint(trust.jwks_url());
        Self {
            http,
            trust: Arc::new(trust),
            transport: None,
            endpoint,
            cache: Arc::new(Mutex::new(None)),
        }
    }

    pub fn from_trust_config(trust: NsdJwtTrustConfig) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self::new(http, trust)
    }

    pub fn with_transport(
        mut self,
        transport: Arc<dyn ControlTransport>,
        endpoint: String,
    ) -> Self {
        self.transport = Some(transport);
        self.endpoint = endpoint;
        self
    }

    async fn verify_token(&self, token: &str) -> Result<(), Error> {
        let parsed = ParsedJwt::parse(token)?;
        let cached = self.cache.lock().expect("jwks cache poisoned").clone();
        if let Some(jwks) = cached
            && self.verify_with_trusted_jwks(&parsed, &jwks).await?
        {
            return Ok(());
        }

        let refreshed = self.fetch_gated_jwks().await?;
        let verified = self.verify_with_trusted_jwks(&parsed, &refreshed).await?;
        if !verified {
            record_pin_rejection(&self.trust, "kid_miss", Some(parsed.kid.as_str()), None);
            return Err(Error::Auth(
                "JWT kid not trusted by pinned JWKS".to_string(),
            ));
        }
        *self.cache.lock().expect("jwks cache poisoned") = Some(refreshed);
        Ok(())
    }

    async fn verify_with_trusted_jwks(
        &self,
        parsed: &ParsedJwt,
        jwks: &TrustedJwks,
    ) -> Result<bool, Error> {
        let Some(key) = jwks.keys.iter().find(|key| key.kid == parsed.kid) else {
            return Ok(false);
        };
        verify_rs256(parsed, &key.jwk)?;
        match jwks.source {
            TrustSource::Bootstrap => {
                let pins = jwks
                    .keys
                    .iter()
                    .map(|key| key.thumbprint.clone())
                    .collect::<Vec<_>>();
                persist_first_use_pins(
                    &self.trust.state_dir,
                    &self.trust.realm,
                    &self.trust.jwks_url,
                    pins,
                    now_secs(),
                )
                .await
                .map_err(|e| Error::Auth(format!("persist NSD JWT TOFU pins failed: {e}")))?;
            }
            TrustSource::Tofu => {
                touch_tofu_entry(
                    &self.trust.state_dir,
                    &self.trust.realm,
                    &self.trust.jwks_url,
                    now_secs(),
                )
                .await
                .map_err(|e| Error::Auth(format!("touch NSD JWT TOFU pins failed: {e}")))?;
            }
            TrustSource::Static => {}
        }
        Ok(true)
    }

    async fn fetch_gated_jwks(&self) -> Result<TrustedJwks, Error> {
        let jwks_url = normalize_jwks_url(&self.trust.jwks_url);
        let jwks = if let Some(transport) = self
            .transport
            .as_ref()
            .filter(|transport| is_anti_dpi_transport(transport.as_ref()))
        {
            self.fetch_jwks_via_transport(transport.as_ref()).await?
        } else {
            self.http
                .get(&jwks_url)
                .send()
                .await
                .map_err(|e| Error::Auth(format!("fetch JWKS failed: {e}")))?
                .error_for_status()?
                .json::<JwkSet>()
                .await
                .map_err(|e| Error::Auth(format!("parse JWKS failed: {e}")))?
        };

        if !self.trust.static_pins.is_empty() {
            return Ok(gate_jwks(
                &self.trust,
                jwks,
                &self.trust.static_pins,
                TrustSource::Static,
            ));
        }

        if let Some(tofu_pins) = load_tofu_pins(&self.trust.state_dir, &self.trust.realm, &jwks_url)
            .await
            .map_err(|e| Error::Auth(format!("load NSD JWT TOFU pins failed: {e}")))?
        {
            return Ok(gate_jwks(&self.trust, jwks, &tofu_pins, TrustSource::Tofu));
        }

        let keys = jwks
            .keys
            .into_iter()
            .filter_map(|jwk| match trusted_jwk_from_valid(jwk) {
                Ok(key) => Some(key),
                Err(reason) => {
                    record_pin_rejection(&self.trust, reason, None, None);
                    None
                }
            })
            .collect::<Vec<_>>();
        if keys.is_empty() {
            return Err(Error::Auth(
                "JWKS contained no valid RS256 keys".to_string(),
            ));
        }
        Ok(TrustedJwks {
            keys,
            source: TrustSource::Bootstrap,
        })
    }

    async fn fetch_jwks_via_transport(
        &self,
        transport: &dyn ControlTransport,
    ) -> Result<JwkSet, Error> {
        let mut stream = transport.connect(&self.endpoint).await?;
        let (status, body) = framing::http_get(
            &mut stream,
            endpoint_host(&self.endpoint),
            "/.well-known/jwks.json",
        )
        .await?;
        if status == 401 {
            return Err(unauthorized_error_from_body(
                String::from_utf8_lossy(&body).as_ref(),
                &self.trust.jwks_url,
            ));
        }
        if !(200..300).contains(&status) {
            return Err(Error::Auth(format!(
                "fetch JWKS over control transport returned HTTP {status}: response body redacted ({} bytes)",
                body.len()
            )));
        }
        serde_json::from_slice::<JwkSet>(&body)
            .map_err(|e| Error::Auth(format!("parse JWKS failed: {e}")))
    }
}

struct ParsedJwt {
    kid: String,
    signing_input: String,
    signature: Vec<u8>,
}

impl ParsedJwt {
    fn parse(token: &str) -> Result<Self, Error> {
        let mut parts = token.split('.');
        let header_b64 = parts
            .next()
            .ok_or_else(|| Error::Auth("JWT header missing".to_string()))?;
        let payload_b64 = parts
            .next()
            .ok_or_else(|| Error::Auth("JWT payload missing".to_string()))?;
        let sig_b64 = parts
            .next()
            .ok_or_else(|| Error::Auth("JWT signature missing".to_string()))?;
        if parts.next().is_some() {
            return Err(Error::Auth(
                "JWT must have exactly three segments".to_string(),
            ));
        }
        let header: JwtHeader = serde_json::from_slice(&base64url_decode(header_b64)?)
            .map_err(|e| Error::Auth(format!("JWT header decode failed: {e}")))?;
        if header.alg != "RS256" {
            return Err(Error::Auth("JWT alg must be RS256".to_string()));
        }
        let kid = header
            .kid
            .filter(|kid| !kid.is_empty())
            .ok_or_else(|| Error::Auth("JWT kid must be non-empty".to_string()))?;
        Ok(Self {
            kid,
            signing_input: format!("{header_b64}.{payload_b64}"),
            signature: base64url_decode(sig_b64)?,
        })
    }
}

fn gate_jwks(
    trust: &NsdJwtTrustConfig,
    jwks: JwkSet,
    pins: &[String],
    source: TrustSource,
) -> TrustedJwks {
    let keys = jwks
        .keys
        .into_iter()
        .filter_map(|jwk| match trusted_jwk_from_valid(jwk) {
            Ok(key) => {
                if pins.iter().any(|pin| pin == &key.thumbprint) {
                    Some(key)
                } else {
                    record_pin_rejection(
                        trust,
                        "pin_mismatch",
                        Some(key.kid.as_str()),
                        Some(key.thumbprint.as_str()),
                    );
                    None
                }
            }
            Err(reason) => {
                record_pin_rejection(trust, reason, None, None);
                None
            }
        })
        .collect::<Vec<_>>();
    TrustedJwks { keys, source }
}

fn trusted_jwk_from_valid(jwk: RsaJwk) -> Result<TrustedJwk, &'static str> {
    validate_rsa_jwk(&jwk).map_err(|_| "invalid_jwk")?;
    let kid = jwk
        .kid
        .clone()
        .filter(|kid| !kid.is_empty())
        .ok_or("invalid_jwk")?;
    let thumbprint = rsa_jwk_thumbprint(&jwk).map_err(|_| "invalid_jwk")?;
    Ok(TrustedJwk {
        kid,
        thumbprint,
        jwk,
    })
}

fn verify_rs256(parsed: &ParsedJwt, jwk: &RsaJwk) -> Result<(), Error> {
    let n = base64url_decode(&jwk.n)?;
    let e = base64url_decode(&jwk.e)?;
    let key = RsaPublicKeyComponents { n: &n, e: &e };
    key.verify(
        &RSA_PKCS1_2048_8192_SHA256,
        parsed.signing_input.as_bytes(),
        &parsed.signature,
    )
    .map_err(|_| Error::Auth("JWT RS256 signature verification failed".to_string()))
}

fn record_pin_rejection(
    trust: &NsdJwtTrustConfig,
    reason: &'static str,
    kid: Option<&str>,
    thumbprint: Option<&str>,
) {
    let kid_hash8 = kid.map(log_id_hash8).unwrap_or_default();
    let thumbprint_hash8 = thumbprint.map(log_id_hash8).unwrap_or_default();
    warn!(
        nsd_id = %trust.nsd_id,
        realm = %trust.realm,
        jwks_url = %trust.jwks_url,
        kid_hash8 = %kid_hash8,
        thumbprint_hash8 = %thumbprint_hash8,
        reason,
        "NSD JWT signing key rejected by pin gate"
    );
    static COUNTER: OnceLock<opentelemetry::metrics::Counter<u64>> = OnceLock::new();
    let counter = COUNTER.get_or_init(|| {
        let meter = telemetry::meter::meter("nsn.control.jwt");
        telemetry::meter::counter_u64(
            &meter,
            "control_jwt_key_pin_rejections_total",
            "NSD JWT JWKs rejected by the key pin gate",
        )
    });
    counter.add(
        1,
        &[
            KeyValue::new("nsd_id", trust.nsd_id.clone()),
            KeyValue::new("realm", trust.realm.clone()),
            KeyValue::new("reason", reason),
        ],
    );
}

pub(crate) async fn verify_pinned_envelope_response(
    resp: &ControlEnvelope,
    trust: Option<&NsdEnvelopeTrustConfig>,
) -> Result<(), Error> {
    let Some(trust) = trust else {
        return Err(Error::Auth(
            "NSD envelope key pin not configured".to_string(),
        ));
    };
    let (pins, source) = trusted_envelope_pins(trust).await?;
    let response_pin = ed25519_pubkey_to_okp_thumbprint(&resp.machine_key_pub)
        .map_err(|e| Error::Auth(format!("compute NSD envelope key pin failed: {e}")))?;
    if !pin_set_contains(&pins, &response_pin) {
        record_envelope_pin_rejection(trust, "pin_mismatch", Some(response_pin.as_str()));
        return Err(Error::Auth(
            "NSD envelope response key not trusted by pinned set".to_string(),
        ));
    }
    if matches!(source, TrustSource::Tofu) {
        touch_envelope_tofu_entry(&trust.state_dir, &trust.realm, &trust.nsd_url, now_secs())
            .await
            .map_err(|e| Error::Auth(format!("touch NSD envelope TOFU pins failed: {e}")))?;
    }
    resp.verify_response(now_secs(), &resp.machine_key_pub)?;
    Ok(())
}

/// Verify and decode a signed `config.stream` SSE event data field.
pub async fn verify_config_stream_event(
    data: &str,
    trust: Option<&NsdEnvelopeTrustConfig>,
    expected_machine_id: &str,
    replay_cache: &mut ConfigStreamReplayCache,
) -> Result<envapi::ConfigStreamEventPayloadV1, Error> {
    let envelope_bytes = URL_SAFE_NO_PAD
        .decode(data.trim())
        .map_err(|e| Error::Auth(format!("malformed config.stream event base64url: {e}")))?;
    let envelope = ControlEnvelope::from_cbor(&envelope_bytes)?;
    verify_config_stream_envelope(&envelope, trust, expected_machine_id, replay_cache).await
}

/// Verify and decode a signed `config.stream` event envelope.
pub async fn verify_config_stream_envelope(
    envelope: &ControlEnvelope,
    trust: Option<&NsdEnvelopeTrustConfig>,
    expected_machine_id: &str,
    replay_cache: &mut ConfigStreamReplayCache,
) -> Result<envapi::ConfigStreamEventPayloadV1, Error> {
    let Some(trust) = trust else {
        return Err(Error::Auth(
            "NSD envelope key pin not configured".to_string(),
        ));
    };
    verify_pinned_envelope_response(envelope, Some(trust)).await?;
    if envelope.api != envapi_ids::CONFIG_STREAM {
        return Err(Error::Auth(format!(
            "config.stream event api mismatch: {}",
            envelope.api
        )));
    }
    let Some(machine_id) = envelope.machine_id.as_deref() else {
        return Err(Error::Auth(
            "config.stream event missing machine_id".to_string(),
        ));
    };
    if machine_id != expected_machine_id {
        return Err(Error::Auth(format!(
            "config.stream event machine_id mismatch: expected {expected_machine_id}, got {machine_id}"
        )));
    }
    replay_cache.check_and_insert(trust, machine_id, envelope.nonce, envelope.ts, now_secs())?;

    let header: ConfigStreamEventPayloadHeader = envapi::from_cbor(envelope.payload.as_ref())
        .map_err(|e| Error::Sse(format!("config.stream payload cbor decode: {e}")))?;
    if header.v != 1 {
        return Err(Error::Auth(format!(
            "unsupported config.stream event payload version: {}",
            header.v
        )));
    }
    let payload: envapi::ConfigStreamEventPayloadV1 = envapi::from_cbor(envelope.payload.as_ref())
        .map_err(|e| Error::Sse(format!("config.stream payload cbor decode: {e}")))?;
    if matches!(payload.message, ControlMessage::Unknown) {
        // `#[serde(other)]` discards the wire tag; recover it from the raw
        // verified payload so the skip is attributable. Forward compatibility:
        // a newer NSD may push variants this build does not know yet.
        let type_tag = envapi::probe_config_stream_message_type(envelope.payload.as_ref())
            .unwrap_or_else(|| "<unavailable>".to_string());
        warn!(
            type_tag = %type_tag,
            "skipping unknown config.stream control message variant from a newer NSD"
        );
    }
    Ok(payload)
}

async fn trusted_envelope_pins(
    trust: &NsdEnvelopeTrustConfig,
) -> Result<(Vec<String>, TrustSource), Error> {
    if !trust.static_pins.is_empty() {
        return Ok((trust.static_pins.clone(), TrustSource::Static));
    }

    if let Some(tofu_pins) = load_envelope_tofu_pins(&trust.state_dir, &trust.realm, &trust.nsd_url)
        .await
        .map_err(|e| Error::Auth(format!("load NSD envelope TOFU pins failed: {e}")))?
    {
        return Ok((tofu_pins, TrustSource::Tofu));
    }

    if trust.dev_tofu_enabled
        && let Some(hex32) = trust.advertised_pubkey_hex.as_deref()
    {
        let pin = ed25519_pubkey_hex_to_okp_thumbprint(hex32)
            .map_err(|e| Error::Auth(format!("compute advertised NSD envelope pin failed: {e}")))?;
        persist_first_use_envelope_pins(
            &trust.state_dir,
            &trust.realm,
            &trust.nsd_url,
            vec![pin.clone()],
            now_secs(),
        )
        .await
        .map_err(|e| Error::Auth(format!("persist NSD envelope TOFU pins failed: {e}")))?;
        return Ok((vec![pin], TrustSource::Bootstrap));
    }

    record_envelope_pin_rejection(trust, "unconfigured", None);
    Err(Error::Auth(
        "NSD envelope key pin not configured".to_string(),
    ))
}

fn record_envelope_pin_rejection(
    trust: &NsdEnvelopeTrustConfig,
    reason: &'static str,
    thumbprint: Option<&str>,
) {
    let thumbprint_hash8 = thumbprint.map(log_id_hash8).unwrap_or_default();
    warn!(
        nsd_id = %trust.nsd_id,
        realm = %trust.realm,
        nsd_url = %trust.nsd_url,
        thumbprint_hash8 = %thumbprint_hash8,
        reason,
        "NSD envelope signing key rejected by pin gate"
    );
    static COUNTER: OnceLock<opentelemetry::metrics::Counter<u64>> = OnceLock::new();
    let counter = COUNTER.get_or_init(|| {
        let meter = telemetry::meter::meter("nsn.control.envelope");
        telemetry::meter::counter_u64(
            &meter,
            "control_envelope_key_pin_rejections_total",
            "NSD envelope keys rejected by the key pin gate",
        )
    });
    counter.add(
        1,
        &[
            KeyValue::new("nsd_id", trust.nsd_id.clone()),
            KeyValue::new("realm", trust.realm.clone()),
            KeyValue::new("reason", reason),
        ],
    );
}

fn log_id_hash8(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(&digest[..4])
}

fn default_jwks_url(base_url: &str) -> String {
    format!("{}/.well-known/jwks.json", base_url.trim_end_matches('/'))
}

fn base64url_decode(input: &str) -> Result<Vec<u8>, Error> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    if bytes.contains(&b'=') || bytes.len() % 4 == 1 {
        return Err(Error::Auth("invalid base64url encoding".to_string()));
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut chunks = bytes.chunks_exact(4);
    for chunk in &mut chunks {
        let a = val(chunk[0]).ok_or_else(|| Error::Auth("invalid base64url".to_string()))? as u32;
        let b = val(chunk[1]).ok_or_else(|| Error::Auth("invalid base64url".to_string()))? as u32;
        let c = val(chunk[2]).ok_or_else(|| Error::Auth("invalid base64url".to_string()))? as u32;
        let d = val(chunk[3]).ok_or_else(|| Error::Auth("invalid base64url".to_string()))? as u32;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.push((n & 0xff) as u8);
    }
    let rem = chunks.remainder();
    if rem.len() == 2 {
        let a = val(rem[0]).ok_or_else(|| Error::Auth("invalid base64url".to_string()))? as u32;
        let b = val(rem[1]).ok_or_else(|| Error::Auth("invalid base64url".to_string()))? as u32;
        out.push(((a << 2) | (b >> 4)) as u8);
    } else if rem.len() == 3 {
        let a = val(rem[0]).ok_or_else(|| Error::Auth("invalid base64url".to_string()))? as u32;
        let b = val(rem[1]).ok_or_else(|| Error::Auth("invalid base64url".to_string()))? as u32;
        let c = val(rem[2]).ok_or_else(|| Error::Auth("invalid base64url".to_string()))? as u32;
        out.push(((a << 2) | (b >> 4)) as u8);
        out.push((((b & 0x0f) << 4) | (c >> 2)) as u8);
    }
    Ok(out)
}

/// Lightweight bearer-token refresher for paths that need a JWT after the main
/// [`AuthClient`] has been moved into the control-plane loop.
#[derive(Clone)]
pub struct BearerTokenRefresher {
    http: reqwest::Client,
    base_url: String,
    endpoint: String,
    transport: Option<Arc<dyn ControlTransport>>,
    machine_id: String,
    signer: EnvelopeSigner,
    purpose: TokenPurpose,
    verifier: Option<Arc<NsdJwtVerifier>>,
}

impl BearerTokenRefresher {
    /// Mint a fresh JWT via the legacy `/api/v1/machine/auth` flow.
    pub async fn refresh(&self) -> Result<String, Error> {
        if let Some(transport) = self
            .transport
            .as_ref()
            .filter(|transport| is_anti_dpi_transport(transport.as_ref()))
        {
            return self.refresh_via_transport(transport.as_ref()).await;
        }
        if is_anti_dpi_url(&self.base_url) {
            return Err(Error::Auth(
                "anti-DPI control auth requires a control transport".to_string(),
            ));
        }
        self.refresh_direct().await
    }

    async fn refresh_direct(&self) -> Result<String, Error> {
        let timestamp = now_secs();
        let message = format!("{}:{}", self.machine_id, timestamp);
        let sig_bytes = self.signer.sign(message.as_bytes());
        let body = AuthRequest {
            machine_id: self.machine_id.clone(),
            machine_key_pub: hex::encode(self.signer.machine_key_pub()),
            timestamp,
            signature: hex::encode(sig_bytes),
            purpose: Some(self.purpose.as_str().to_string()),
        };
        let resp = self
            .http
            .post(format!("{}/api/v1/machine/auth", self.base_url))
            .json(&body)
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(unauthorized_error_from_response(resp, &self.base_url).await);
        }
        let parsed: AuthResponse = resp.error_for_status()?.json().await?;
        if let Some(verifier) = &self.verifier {
            verifier.verify_token(&parsed.token).await?;
        }
        Ok(parsed.token)
    }

    async fn refresh_via_transport(
        &self,
        transport: &dyn ControlTransport,
    ) -> Result<String, Error> {
        let timestamp = now_secs();
        let message = format!("{}:{}", self.machine_id, timestamp);
        let sig_bytes = self.signer.sign(message.as_bytes());
        let body = AuthRequest {
            machine_id: self.machine_id.clone(),
            machine_key_pub: hex::encode(self.signer.machine_key_pub()),
            timestamp,
            signature: hex::encode(sig_bytes),
            purpose: Some(self.purpose.as_str().to_string()),
        };
        let body =
            serde_json::to_vec(&body).map_err(|e| Error::Auth(format!("auth json encode: {e}")))?;
        let mut stream = transport.connect(&self.endpoint).await?;
        let (status, resp_body) = framing::http_unary_json(
            &mut stream,
            endpoint_host(&self.endpoint),
            "/api/v1/machine/auth",
            &body,
        )
        .await?;
        if status == 401 {
            return Err(unauthorized_error_from_body(
                String::from_utf8_lossy(&resp_body).as_ref(),
                &self.base_url,
            ));
        }
        if !(200..300).contains(&status) {
            return Err(Error::Auth(format!(
                "machine auth over control transport returned HTTP {status}: response body redacted ({} bytes)",
                resp_body.len()
            )));
        }
        let parsed: AuthResponse = serde_json::from_slice(&resp_body)
            .map_err(|e| Error::Auth(format!("parse auth response failed: {e}")))?;
        if let Some(verifier) = &self.verifier {
            verifier.verify_token(&parsed.token).await?;
        }
        Ok(parsed.token)
    }
}

impl HeartbeatClient {
    /// Create a new `HeartbeatClient` for `machine_id` at `base_url`.
    pub fn new(base_url: &str, machine_id: &str) -> Self {
        // Building a reqwest client with these timeouts only fails if the
        // TLS backend (rustls) fails to initialise, which in turn means the
        // process is fundamentally unable to speak HTTPS — fail fast here
        // rather than silently falling back to a client with no timeouts,
        // which is exactly what AUDIT-006 P3.9 flagged.
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .expect("heartbeat reqwest client builder (rustls init must succeed)");
        Self {
            http,
            base_url: base_url.to_string(),
            machine_id: machine_id.to_string(),
            transport: None,
            endpoint: to_endpoint(base_url),
            signer: None,
            bearer: std::sync::Mutex::new(None),
            jwt_verifier: None,
            envelope_trust: None,
        }
    }

    /// Attach a signed-envelope path. `transport.call()` will be used for all
    /// subsequent heartbeats; reqwest is only used as a fallback when this is
    /// not set.
    pub fn with_transport(
        mut self,
        transport: Arc<dyn ControlTransport>,
        signer: EnvelopeSigner,
    ) -> Self {
        self.transport = Some(transport);
        self.signer = Some(signer);
        self
    }

    /// Attach the Ed25519 signer without a transport.
    ///
    /// When set, the legacy reqwest heartbeat path attaches a cached
    /// `Authorization: Bearer <jwt>` (minted via the same Ed25519-signed
    /// `POST /api/v1/machine/auth` that `AuthClient::authenticate` uses) and
    /// refreshes the JWT on a single 401 before bubbling
    /// [`Error::Unauthorized`]. Without a signer the heartbeat sends no
    /// `Authorization` header — the historic shape that the mock NSD
    /// (tests/docker/nsd-mock) accepts unconditionally.
    pub fn with_signer(mut self, signer: EnvelopeSigner) -> Self {
        self.signer = Some(signer);
        self
    }

    pub fn with_jwt_verifier(mut self, verifier: Arc<NsdJwtVerifier>) -> Self {
        self.jwt_verifier = Some(verifier);
        self
    }

    pub fn with_envelope_trust(mut self, trust: NsdEnvelopeTrustConfig) -> Self {
        self.envelope_trust = Some(trust);
        self
    }

    /// Send `POST /api/v1/machine/heartbeat` with updated uptime and local IPs.
    ///
    /// Errors are logged by the caller; this method propagates them so the
    /// heartbeat task can apply back-off if desired.
    pub async fn heartbeat(&self, uptime_secs: u64, local_ips: Vec<String>) -> Result<(), Error> {
        if let (Some(transport), Some(signer)) = (self.transport.as_ref(), self.signer.as_ref()) {
            return self
                .heartbeat_envelope(transport.as_ref(), signer, uptime_secs, local_ips)
                .await;
        }
        self.heartbeat_legacy(uptime_secs, local_ips).await
    }

    async fn heartbeat_legacy(
        &self,
        uptime_secs: u64,
        local_ips: Vec<String>,
    ) -> Result<(), Error> {
        // Pre-signer behaviour: send without `Authorization`. Retained so the
        // tier1/2 mock-NSD stacks (which never required a bearer) keep working
        // for callers that do not attach a signer.
        let Some(signer) = self.signer.as_ref() else {
            let resp = self
                .post_heartbeat_legacy(None, uptime_secs, &local_ips)
                .await?;
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                return Err(unauthorized_error_from_response(resp, &self.base_url).await);
            }
            resp.error_for_status()?;
            return Ok(());
        };

        let bearer = self.ensure_bearer_legacy(signer).await?;
        let resp = self
            .post_heartbeat_legacy(Some(&bearer), uptime_secs, &local_ips)
            .await?;
        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            resp.error_for_status()?;
            return Ok(());
        }
        let first_error = unauthorized_error_from_response(resp, &self.base_url).await;
        if matches!(first_error, Error::MachineUnknown(_)) {
            self.invalidate_bearer();
            return Err(first_error);
        }

        // Cached JWT is stale (expired, session revoked, kid rotated, or
        // NSD was previously bearer-less). Drop the cache and re-auth once.
        self.invalidate_bearer();
        let fresh = self.ensure_bearer_legacy(signer).await?;
        let resp = self
            .post_heartbeat_legacy(Some(&fresh), uptime_secs, &local_ips)
            .await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            // Second 401 in a row: re-auth itself succeeded (or we already
            // returned earlier) but NSD still rejects this machine. Bubble a
            // typed error so the heartbeat task can log distinctively without
            // bounding into a tight retry loop on this cadence.
            self.invalidate_bearer();
            return Err(unauthorized_error_from_response(resp, &self.base_url).await);
        }
        resp.error_for_status()?;
        Ok(())
    }

    /// Build and send a single legacy heartbeat POST. Does not interpret the
    /// status code — callers branch on it.
    async fn post_heartbeat_legacy(
        &self,
        bearer: Option<&str>,
        uptime_secs: u64,
        local_ips: &[String],
    ) -> Result<reqwest::Response, Error> {
        let body = HeartbeatPayload {
            machine_id: self.machine_id.clone(),
            uptime_secs,
            local_ips: local_ips.to_vec(),
        };
        let mut req = self
            .http
            .post(format!("{}/api/v1/machine/heartbeat", self.base_url))
            .json(&body);
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        Ok(req.send().await?)
    }

    /// Return the cached bearer JWT, minting one via the legacy
    /// `/api/v1/machine/auth` flow if the cache is empty.
    async fn ensure_bearer_legacy(&self, signer: &EnvelopeSigner) -> Result<String, Error> {
        if let Some(t) = self.bearer.lock().expect("bearer cache poisoned").clone() {
            return Ok(t);
        }
        let token = self.authenticate_legacy(signer).await?;
        *self.bearer.lock().expect("bearer cache poisoned") = Some(token.clone());
        Ok(token)
    }

    fn invalidate_bearer(&self) {
        *self.bearer.lock().expect("bearer cache poisoned") = None;
    }

    /// Mint a fresh JWT via `POST /api/v1/machine/auth` using the stored
    /// signer.  Mirrors [`AuthClient::authenticate`]'s body shape so the
    /// real NSD's legacy auth handler accepts it bit-for-bit.
    async fn authenticate_legacy(&self, signer: &EnvelopeSigner) -> Result<String, Error> {
        if is_anti_dpi_url(&self.base_url) {
            return Err(Error::Auth(
                "anti-DPI heartbeat auth requires a control transport".to_string(),
            ));
        }
        let timestamp = now_secs();
        let message = format!("{}:{}", self.machine_id, timestamp);
        let sig_bytes = signer.sign(message.as_bytes());
        let body = AuthRequest {
            machine_id: self.machine_id.clone(),
            machine_key_pub: hex::encode(signer.machine_key_pub()),
            timestamp,
            signature: hex::encode(sig_bytes),
            purpose: Some(TokenPurpose::Control.as_str().to_string()),
        };
        let resp = self
            .http
            .post(format!("{}/api/v1/machine/auth", self.base_url))
            .json(&body)
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(unauthorized_error_from_response(resp, &self.base_url).await);
        }
        let parsed: AuthResponse = resp.error_for_status()?.json().await?;
        if let Some(verifier) = self.jwt_verifier.as_ref() {
            verifier.verify_token(&parsed.token).await?;
        }
        Ok(parsed.token)
    }

    async fn heartbeat_envelope(
        &self,
        transport: &dyn ControlTransport,
        signer: &EnvelopeSigner,
        uptime_secs: u64,
        local_ips: Vec<String>,
    ) -> Result<(), Error> {
        let payload = envapi::HeartbeatRequest {
            uptime_secs,
            local_ips,
        };
        let payload_cbor = envapi::to_cbor(&payload)
            .map_err(|e| Error::Auth(format!("heartbeat cbor encode: {e}")))?;
        let env = ControlEnvelope::sign_request(
            envapi_ids::MACHINE_HEARTBEAT,
            Some(self.machine_id.clone()),
            signer.machine_key_pub(),
            payload_cbor,
            |m| signer.sign(m),
        )?;
        let resp = match crate::transport::instrumented_call(transport, &self.endpoint, env).await {
            Ok(resp) => resp,
            Err(Error::MachineUnknown(_)) => {
                return Err(Error::MachineUnknown(self.base_url.clone()));
            }
            Err(Error::Unauthorized(_)) => return Err(Error::Unauthorized(self.base_url.clone())),
            Err(e) => return Err(e),
        };
        verify_pinned_envelope_response(&resp, self.envelope_trust.as_ref()).await?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct RegisterResponse {
    machine_id: String,
    server_peer_key_pub: String,
    server_endpoint: String,
    domain_base: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nsd_envelope_pubkey: Option<String>,
}

async fn legacy_register_response(resp: reqwest::Response) -> Result<RegisterResponse, Error> {
    let status = resp.status();
    let status_error = resp.error_for_status_ref().err();
    if status == reqwest::StatusCode::CONFLICT {
        let body = resp.bytes().await?;
        if let Some(err) = crate::recognized_conflict_error_from_body(&body) {
            return Err(err);
        }
        return Err(status_error.map(Error::Http).unwrap_or_else(|| {
            Error::Auth(format!(
                "machine registration returned HTTP 409: response body redacted ({} bytes)",
                body.len()
            ))
        }));
    }
    if let Some(err) = status_error {
        return Err(Error::Http(err));
    }
    Ok(resp.json().await?)
}

// ── authenticate (legacy JSON path, to be removed once envelope is default) ──

#[derive(Debug, Serialize, Deserialize)]
struct AuthRequest {
    machine_id: String,
    machine_key_pub: String,
    timestamp: u64,
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    token: String,
}

// ── AuthClient ────────────────────────────────────────────────────────────────

/// HTTP client that manages machine registration and session authentication.
pub struct AuthClient {
    http: reqwest::Client,
    base_url: String,
    pub state: MachineState,
    /// System info included in the registration body. Set via [`set_system_info`].
    system_info: Option<SystemInfo>,
    /// Link modes advertised at registration. Set via [`set_link_modes`].
    /// Empty `supported` / `None` preferred reproduce the legacy behavior of
    /// letting NSD apply its backward-compatible default.
    supported_link_modes: Vec<LinkMode>,
    preferred_link_mode: Option<LinkMode>,
    /// Client capability tokens advertised at registration.
    capabilities: Vec<String>,
    /// Optional pluggable transport. When present the envelope path is used
    /// for [`register_via_envelope`] and related methods; reqwest remains
    /// available for the legacy paths until Phase 8 of PLAN-022 ships.
    transport: Option<Arc<dyn ControlTransport>>,
    /// Endpoint (`host:port`) used for `transport.call()`.
    endpoint: String,
    jwt_verifier: Option<Arc<NsdJwtVerifier>>,
    envelope_trust: Option<NsdEnvelopeTrustConfig>,
}

impl AuthClient {
    /// Create a new `AuthClient` wrapping an existing `MachineState`.
    pub fn new(base_url: &str, state: MachineState) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            http,
            base_url: base_url.to_string(),
            state,
            system_info: None,
            supported_link_modes: Vec::new(),
            preferred_link_mode: None,
            capabilities: Vec::new(),
            transport: None,
            endpoint: to_endpoint(base_url),
            jwt_verifier: None,
            envelope_trust: None,
        }
    }

    /// Attach a signed-envelope transport. When present, envelope-aware
    /// methods (`register_via_envelope`, `heartbeat_via_envelope`, ...) use
    /// it in preference to reqwest.
    pub fn with_transport(mut self, transport: Arc<dyn ControlTransport>) -> Self {
        if let Some(verifier) = self.jwt_verifier.take() {
            self.jwt_verifier = Some(Arc::new(
                verifier
                    .as_ref()
                    .clone()
                    .with_transport(transport.clone(), self.endpoint.clone()),
            ));
        }
        self.transport = Some(transport);
        self
    }

    pub fn with_jwt_trust(
        mut self,
        nsd_id: impl Into<String>,
        realm: impl Into<String>,
        state_dir: impl Into<PathBuf>,
        static_pins: Vec<String>,
    ) -> Self {
        let trust = NsdJwtTrustConfig::new(nsd_id, realm, state_dir, &self.base_url, static_pins);
        let mut verifier = NsdJwtVerifier::new(self.http.clone(), trust);
        if let Some(transport) = self.transport.clone() {
            verifier = verifier.with_transport(transport, self.endpoint.clone());
        }
        self.jwt_verifier = Some(Arc::new(verifier));
        self
    }

    pub fn with_envelope_trust(
        mut self,
        nsd_id: impl Into<String>,
        realm: impl Into<String>,
        state_dir: impl Into<PathBuf>,
        static_pins: Vec<String>,
        advertised_pubkey_hex: Option<String>,
    ) -> Self {
        self.envelope_trust = Some(NsdEnvelopeTrustConfig::new(
            nsd_id,
            realm,
            state_dir,
            &self.base_url,
            static_pins,
            advertised_pubkey_hex,
        ));
        self
    }

    pub(crate) fn envelope_trust(&self) -> Option<NsdEnvelopeTrustConfig> {
        self.envelope_trust.clone()
    }

    pub fn jwt_verifier(&self) -> Option<Arc<NsdJwtVerifier>> {
        self.jwt_verifier.clone()
    }

    pub(crate) fn transport(&self) -> Option<Arc<dyn ControlTransport>> {
        self.transport.clone()
    }

    /// Attach system info to be included in the next registration request.
    pub fn set_system_info(&mut self, info: SystemInfo) {
        self.system_info = Some(info);
    }

    /// Declare the link modes this machine can participate in (§4.1) and the
    /// preferred mode used by NSD edge resolution. An empty `supported` set with
    /// a `None` preferred keeps the legacy behavior (NSD applies its
    /// backward-compatible default).
    pub fn set_link_modes(&mut self, supported: Vec<LinkMode>, preferred: Option<LinkMode>) {
        self.supported_link_modes = supported;
        self.preferred_link_mode = preferred;
    }

    /// Declare client capability tokens advertised during machine registration.
    pub fn set_capabilities(&mut self, capabilities: Vec<String>) {
        self.capabilities = capabilities;
    }

    /// Build a [`HeartbeatClient`] for this NSD endpoint and machine ID.
    ///
    /// Call this before the `AuthClient` is moved into the control plane so
    /// the heartbeat background task can run independently.
    pub fn heartbeat_client(&self) -> Option<HeartbeatClient> {
        let verifier = self.jwt_verifier.clone();
        let envelope_trust = self.envelope_trust.clone();
        let transport = self.transport.clone();
        self.state.machine_id.as_deref().map(|mid| {
            let mut hc = HeartbeatClient::new(&self.base_url, mid);
            if let Some(verifier) = verifier {
                hc = hc.with_jwt_verifier(verifier);
            }
            if let Some(envelope_trust) = envelope_trust {
                hc = hc.with_envelope_trust(envelope_trust);
            }
            let signer = EnvelopeSigner::from_state(&self.state);
            hc = if let Some(transport) = transport.clone() {
                hc.with_transport(transport, signer)
            } else {
                hc.with_signer(signer)
            };
            hc
        })
    }

    fn token_refresher(&self, purpose: TokenPurpose) -> Result<BearerTokenRefresher, Error> {
        let machine_id = self
            .state
            .machine_id
            .as_deref()
            .ok_or_else(|| Error::Auth("not registered".to_string()))?
            .to_string();
        Ok(BearerTokenRefresher {
            http: self.http.clone(),
            base_url: self.base_url.clone(),
            endpoint: self.endpoint.clone(),
            transport: self.transport.clone(),
            machine_id,
            signer: EnvelopeSigner::from_state(&self.state),
            purpose,
            verifier: self.jwt_verifier.clone(),
        })
    }

    /// Build a WSS bearer-token refresher from this registered machine identity.
    pub fn bearer_token_refresher(&self) -> Result<BearerTokenRefresher, Error> {
        self.token_refresher(TokenPurpose::Wss)
    }

    pub fn control_token_refresher(&self) -> Result<BearerTokenRefresher, Error> {
        self.token_refresher(TokenPurpose::Control)
    }

    /// Whether this machine has been registered with the server.
    pub fn is_registered(&self) -> bool {
        self.state.is_registered()
    }

    /// Raw bytes of the local X25519 peer private key.
    pub fn peer_key_priv_bytes(&self) -> [u8; 32] {
        self.state.peer_key_priv_bytes()
    }

    /// Register using a pre-shared auth key (`POST /api/v1/machine/register`).
    #[instrument(skip(self, auth_key))]
    pub async fn register(&mut self, auth_key: &str) -> Result<(), Error> {
        if self.transport.is_some() {
            return self.register_via_envelope(auth_key).await;
        }
        self.register_legacy(auth_key).await
    }

    async fn register_legacy(&mut self, auth_key: &str) -> Result<(), Error> {
        let body = self.build_register_body(Some(auth_key.to_string()));
        let resp = self
            .http
            .post(format!("{}/api/v1/machine/register", self.base_url))
            .json(&body)
            .send()
            .await?;
        let resp = legacy_register_response(resp).await?;
        self.apply_registration(resp)
    }

    /// Register using an OAuth2 device-flow access token (`POST /api/v1/machine/register`
    /// with `Authorization: Bearer <token>`).
    #[instrument(skip(self, access_token))]
    pub async fn register_with_token(&mut self, access_token: &str) -> Result<(), Error> {
        if self.transport.is_some() {
            return self.register_with_token_via_envelope(access_token).await;
        }
        self.register_with_token_legacy(access_token).await
    }

    async fn register_with_token_legacy(&mut self, access_token: &str) -> Result<(), Error> {
        let body = self.build_register_body(None);
        let resp = self
            .http
            .post(format!("{}/api/v1/machine/register", self.base_url))
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await?;
        let resp = legacy_register_response(resp).await?;
        self.apply_registration(resp)
    }

    /// Signed-envelope variant of [`register`]. Routes through the attached
    /// [`ControlTransport`] (if any) using CBOR envelopes. Returns an
    /// error with `NotImplemented` when no transport is attached.
    #[instrument(skip(self, auth_key))]
    pub async fn register_via_envelope(&mut self, auth_key: &str) -> Result<(), Error> {
        let transport = self
            .transport
            .clone()
            .ok_or(Error::NotImplemented("no transport attached"))?;
        let payload = envapi::RegisterRequest {
            auth_key: Some(auth_key.to_string()),
            access_token: None,
            peer_key_pub: self.state.peer_key_pub,
            hostname: hostname(),
            os: std::env::consts::OS.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            r#type: None,
            system_info: self.system_info.clone(),
            capabilities: self.capabilities.clone(),
            supported_link_modes: self.supported_link_modes.clone(),
            preferred_mode: self.preferred_link_mode,
        };
        self.register_envelope_inner(transport.as_ref(), &payload)
            .await
    }

    /// Signed-envelope variant of [`register_with_token`].
    #[instrument(skip(self, access_token))]
    pub async fn register_with_token_via_envelope(
        &mut self,
        access_token: &str,
    ) -> Result<(), Error> {
        let transport = self
            .transport
            .clone()
            .ok_or(Error::NotImplemented("no transport attached"))?;
        let payload = envapi::RegisterRequest {
            auth_key: None,
            access_token: Some(access_token.to_string()),
            peer_key_pub: self.state.peer_key_pub,
            hostname: hostname(),
            os: std::env::consts::OS.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            r#type: None,
            system_info: self.system_info.clone(),
            capabilities: self.capabilities.clone(),
            supported_link_modes: self.supported_link_modes.clone(),
            preferred_mode: self.preferred_link_mode,
        };
        self.register_envelope_inner(transport.as_ref(), &payload)
            .await
    }

    async fn register_envelope_inner(
        &mut self,
        transport: &dyn ControlTransport,
        payload: &envapi::RegisterRequest,
    ) -> Result<(), Error> {
        let payload_cbor = envapi::to_cbor(payload)
            .map_err(|e| Error::Auth(format!("register cbor encode: {e}")))?;
        let env = ControlEnvelope::sign_request(
            envapi_ids::MACHINE_REGISTER,
            self.state.machine_id.clone(),
            self.state.machine_key_pub,
            payload_cbor,
            |m| self.state.sign(m),
        )?;
        let resp_env = crate::transport::instrumented_call(transport, &self.endpoint, env).await?;
        verify_pinned_envelope_response(&resp_env, self.envelope_trust.as_ref()).await?;
        let resp: envapi::RegisterResponse = envapi::from_cbor(resp_env.payload.as_ref())
            .map_err(|e| Error::Auth(format!("register cbor decode: {e}")))?;
        self.apply_registration(RegisterResponse {
            machine_id: resp.machine_id,
            server_peer_key_pub: resp.server_peer_key_pub,
            server_endpoint: resp.server_endpoint,
            domain_base: resp.domain_base,
            nsd_envelope_pubkey: resp.nsd_envelope_pubkey,
        })
    }

    fn build_register_body(&self, auth_key: Option<String>) -> RegisterRequest {
        RegisterRequest {
            auth_key,
            machine_id: self.state.machine_id.clone(),
            machine_key_pub: hex::encode(self.state.machine_key_pub),
            peer_key_pub: hex::encode(self.state.peer_key_pub),
            hostname: hostname(),
            os: std::env::consts::OS.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            // D3: NSN clients keep sending the field absent — NSD treats
            // missing as `Connector`. Wiring NSGW to emit `Gateway` is a
            // follow-up on the ns/ side.
            r#type: None,
            system_info: self.system_info.clone(),
            capabilities: self.capabilities.clone(),
            supported_link_modes: self.supported_link_modes.clone(),
            preferred_mode: self.preferred_link_mode,
        }
    }

    fn apply_registration(&mut self, resp: RegisterResponse) -> Result<(), Error> {
        let _nsd_envelope_pubkey = resp.nsd_envelope_pubkey;
        self.state
            .set_registered(
                resp.machine_id,
                &resp.server_peer_key_pub,
                &resp.server_endpoint,
                resp.domain_base,
            )
            .map_err(|e| Error::Auth(e.to_string()))
    }

    /// Authenticate with an Ed25519 signature (`POST /api/v1/machine/auth`).
    ///
    /// Signs `"{machine_id}:{unix_timestamp_secs}"` with the local signing key
    /// and returns the session JWT on success.
    #[instrument(skip(self))]
    pub async fn authenticate(&self) -> Result<String, Error> {
        self.authenticate_with_transport_fallback(TokenPurpose::Control)
            .await
    }

    pub async fn authenticate_wss(&self) -> Result<String, Error> {
        self.authenticate_with_transport_fallback(TokenPurpose::Wss)
            .await
    }

    async fn authenticate_with_transport_fallback(
        &self,
        purpose: TokenPurpose,
    ) -> Result<String, Error> {
        let Some(transport) = self.transport.as_ref() else {
            return self.token_refresher(purpose)?.refresh().await;
        };
        match self.authenticate_via_envelope(purpose).await {
            Ok(token) => Ok(token),
            Err(err)
                if !is_anti_dpi_transport(transport.as_ref())
                    && machine_auth_envelope_can_fallback(&err) =>
            {
                warn!(
                    path = CONTROL_ENVELOPE_PATH,
                    "machine.auth envelope route unavailable; falling back to legacy auth",
                );
                self.token_refresher(purpose)?.refresh().await
            }
            Err(err) => Err(err),
        }
    }

    /// Mint a session JWT via the signed-envelope `machine.auth` `call()`.
    ///
    /// Builds and signs a fresh [`ControlEnvelope`] on every invocation (new
    /// nonce + ts), so a retry layer that re-invokes `authenticate*` re-signs
    /// rather than resending cached request bytes — the latter would trip the
    /// server replay-nonce gate. No bearer is attached: the envelope's machine
    /// Ed25519 signature is the authentication, matching the registered-machine
    /// / no-bearer authorization bucket on NSD.
    async fn authenticate_via_envelope(&self, purpose: TokenPurpose) -> Result<String, Error> {
        let transport = self
            .transport
            .clone()
            .ok_or(Error::NotImplemented("no transport attached"))?;
        let machine_id = self
            .state
            .machine_id
            .clone()
            .ok_or_else(|| Error::Auth("not registered".to_string()))?;
        let payload = envapi::AuthPayload {
            purpose: Some(purpose.as_str().to_string()),
        };
        let payload_cbor = envapi::to_cbor(&payload)
            .map_err(|e| Error::Auth(format!("machine.auth cbor encode: {e}")))?;
        let env = ControlEnvelope::sign_request(
            envapi_ids::MACHINE_AUTH,
            Some(machine_id),
            self.state.machine_key_pub,
            payload_cbor,
            |m| self.state.sign(m),
        )?;
        let resp_env =
            crate::transport::instrumented_call(transport.as_ref(), &self.endpoint, env).await?;
        verify_pinned_envelope_response(&resp_env, self.envelope_trust.as_ref()).await?;
        let resp: envapi::AuthResponse = envapi::from_cbor(resp_env.payload.as_ref())
            .map_err(|e| Error::Auth(format!("machine.auth cbor decode: {e}")))?;
        if let Some(verifier) = self.jwt_verifier.as_ref() {
            verifier.verify_token(&resp.token).await?;
        }
        Ok(resp.token)
    }
}

/// Discover NSD type and realm by calling `GET /api/v1/info`.
///
/// Returns the [`NsdInfo`] on success, or an error if the endpoint is
/// unreachable or returns an unexpected status.  Falls back to a synthetic
/// `NsdInfo` with `nsd_type = SelfHosted` and `realm = "default"` when the
/// server does not implement the endpoint (HTTP 404).
pub async fn discover_nsd_info(base_url: &str) -> Result<NsdInfo, Error> {
    use common::{AuthMethod, NsdType};

    if is_anti_dpi_url(base_url) {
        return Err(Error::Connect(
            "noise/quic discovery requires signed info.get over the control transport".to_string(),
        ));
    }

    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let url = format!("{base_url}/api/v1/info");
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::Connect(e.to_string()))?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        // Server does not implement discovery; fall back to self-hosted default.
        return Ok(NsdInfo {
            nsd_type: NsdType::SelfHosted,
            realm: "default".to_string(),
            auth_methods: vec![AuthMethod::AuthKey],
            provider: "unknown".to_string(),
            version: "unknown".to_string(),
            nsd_noise_pubkey: None,
            nsd_quic_pubkey: None,
            signed_transport_keyset: None,
            nsd_envelope_pubkey: None,
            envelope_versions: Vec::new(),
            capabilities: Vec::new(),
            public_ingress_scopes: Vec::new(),
        });
    }

    if !resp.status().is_success() {
        return Err(Error::Connect(format!(
            "GET /api/v1/info returned {}",
            resp.status()
        )));
    }

    resp.json::<NsdInfo>()
        .await
        .map_err(|e| Error::Connect(format!("failed to parse NsdInfo: {e}")))
}

/// Envelope-path equivalent of [`discover_nsd_info`]. Issues an
/// unauthenticated signed envelope (`api = "info.get"`) over the supplied
/// transport and returns the parsed [`InfoGetResponse`].
///
/// The envelope's `machine_key_pub` carries the caller's Ed25519 identity
/// so the server can optionally pin it for future calls, even though the
/// payload itself is empty.
pub async fn discover_via_envelope(
    transport: &dyn ControlTransport,
    endpoint: &str,
    envelope_trust: &NsdEnvelopeTrustConfig,
    machine_key_pub: [u8; 32],
    sign: impl FnOnce(&[u8]) -> [u8; 64],
) -> Result<envapi::InfoGetResponse, Error> {
    let payload_cbor = envapi::to_cbor(&envapi::InfoGetRequest::default())
        .map_err(|e| Error::Connect(format!("info.get cbor encode: {e}")))?;
    let env = ControlEnvelope::sign_request(
        envapi_ids::INFO_GET,
        None,
        machine_key_pub,
        payload_cbor,
        sign,
    )?;
    let resp_env = crate::transport::instrumented_call(transport, endpoint, env).await?;
    verify_pinned_envelope_response(&resp_env, Some(envelope_trust)).await?;
    envapi::from_cbor(resp_env.payload.as_ref())
        .map_err(|e| Error::Connect(format!("info.get cbor decode: {e}")))
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| {
            // Fallback: read /etc/hostname on Unix.
            std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|_| "unknown".to_string())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn unauthorized_error_from_body(body: &str, base_url: &str) -> Error {
    if body_indicates_machine_unknown(body) {
        Error::MachineUnknown(base_url.to_string())
    } else {
        Error::Unauthorized(base_url.to_string())
    }
}

async fn unauthorized_error_from_response(resp: reqwest::Response, base_url: &str) -> Error {
    let body = resp.text().await.unwrap_or_default();
    unauthorized_error_from_body(&body, base_url)
}

fn body_indicates_machine_unknown(body: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return false;
    }
    if let Ok(value) = serde_json::from_str::<Value>(trimmed)
        && json_value_indicates_machine_unknown(&value)
    {
        return true;
    }
    text_indicates_machine_unknown(trimmed)
}

fn json_value_indicates_machine_unknown(value: &Value) -> bool {
    match value {
        Value::String(s) => text_indicates_machine_unknown(s),
        Value::Array(values) => values.iter().any(json_value_indicates_machine_unknown),
        Value::Object(map) => map.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "code" | "error" | "kind" | "reason" | "message" | "detail" | "details"
            ) && json_value_indicates_machine_unknown(value)
        }),
        _ => false,
    }
}

fn text_indicates_machine_unknown(text: &str) -> bool {
    let normalized = text.to_ascii_lowercase().replace(['-', ' '], "_");
    normalized.contains("machine_unknown")
        || normalized.contains("machine_not_registered")
        || normalized.contains("unknown_machine")
        || normalized.contains("unknown_machine_id")
        || normalized.contains("not_registered")
}

fn machine_auth_envelope_can_fallback(err: &Error) -> bool {
    let Error::ServerError(message) = err else {
        return false;
    };
    let normalized = message.to_ascii_lowercase().replace(['-', ' '], "_");
    message.contains("HTTP 404")
        || normalized.contains("unknown_api")
        || normalized.contains("unknown_control_api")
}

// Re-export envelope::Error so callers do not need two imports.
pub use envelope::Error as EnvelopeError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{BoxStream, builder::build_transport};
    use common::CAPABILITY_CAPTURE_ROUTES_V1;
    use ed25519_dalek::{Signer, SigningKey};
    use futures_util::future::BoxFuture;
    use rand_core::OsRng;
    use std::io;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

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

    fn capture_logs(f: impl FnOnce()) -> String {
        let captured = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        captured.contents()
    }

    // ── MockTransport -------------------------------------------------------
    // A tiny `ControlTransport` impl that records the incoming envelope and
    // returns a caller-supplied response.  Used by the envelope-path tests
    // below to exercise `register_via_envelope` / `heartbeat` without
    // spinning up an HTTP server.
    struct MockTransport {
        /// NSD-side Ed25519 key used to sign outgoing response envelopes.
        nsd_key: SigningKey,
        /// Response payload to embed in every reply (CBOR-encoded).
        resp_payload: Vec<u8>,
        /// The last envelope seen by `call()`.  Tests inspect this to verify
        /// that the client produced a valid request envelope.
        last_req: Mutex<Option<ControlEnvelope>>,
    }

    struct MockHttpTransport {
        name: &'static str,
        response: Vec<u8>,
        captured: Arc<Mutex<Vec<CapturedReq>>>,
    }

    impl MockHttpTransport {
        fn new(name: &'static str, response: Vec<u8>) -> Self {
            Self {
                name,
                response,
                captured: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl ControlTransport for MockHttpTransport {
        fn connect<'a>(&'a self, _endpoint: &'a str) -> BoxFuture<'a, Result<BoxStream, Error>> {
            let response = self.response.clone();
            let captured = Arc::clone(&self.captured);
            Box::pin(async move {
                let (client, mut server) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;

                    let req = read_http_request(&mut server).await;
                    captured.lock().unwrap().push(req);
                    server.write_all(&response).await.unwrap();
                    let _ = server.shutdown().await;
                });
                Ok(BoxStream::new(client))
            })
        }

        fn name(&self) -> &str {
            self.name
        }
    }

    impl MockTransport {
        fn new(nsd_key: SigningKey, resp_payload: Vec<u8>) -> Self {
            Self {
                nsd_key,
                resp_payload,
                last_req: Mutex::new(None),
            }
        }
    }

    impl ControlTransport for MockTransport {
        fn connect<'a>(&'a self, _endpoint: &'a str) -> BoxFuture<'a, Result<BoxStream, Error>> {
            Box::pin(async { Err(Error::NotImplemented("mock connect")) })
        }

        fn call<'a>(
            &'a self,
            _endpoint: &'a str,
            envelope: ControlEnvelope,
        ) -> BoxFuture<'a, Result<ControlEnvelope, Error>> {
            let api = envelope.api.clone();
            let mid = envelope.machine_id.clone();
            *self.last_req.lock().unwrap() = Some(envelope);
            let nsd_pk = self.nsd_key.verifying_key().to_bytes();
            let payload = self.resp_payload.clone();
            Box::pin(async move {
                let resp = ControlEnvelope::sign_response(api, mid, nsd_pk, payload, |m| {
                    self.nsd_key.sign(m).to_bytes()
                })?;
                Ok(resp)
            })
        }

        fn name(&self) -> &str {
            "mock"
        }
    }

    async fn fresh_machine_state() -> common::MachineState {
        // Build a MachineState from random keys — unregistered.  Leak the
        // tempdir so it outlives the returned state; wiped at process exit.
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path().to_path_buf();
        std::mem::forget(tmpdir);
        common::MachineState::load_or_create(&dir).await.unwrap()
    }

    #[test]
    fn pin_rejection_logs_hashes_without_full_identifiers() {
        let tempdir = tempfile::tempdir().unwrap();
        let jwt_trust = NsdJwtTrustConfig::new(
            "nsd-a",
            "realm-a",
            tempdir.path(),
            "https://nsd.example",
            Vec::new(),
        );
        let envelope_trust = NsdEnvelopeTrustConfig::new(
            "nsd-a",
            "realm-a",
            tempdir.path(),
            "https://nsd.example",
            Vec::new(),
            None,
        );
        let kid = "kid-sensitive-full-value";
        let thumbprint = "thumbprint-sensitive-full-value";
        let kid_hash8 = log_id_hash8(kid);
        let thumbprint_hash8 = log_id_hash8(thumbprint);

        let logs = capture_logs(|| {
            record_pin_rejection(&jwt_trust, "pin_mismatch", Some(kid), Some(thumbprint));
            record_envelope_pin_rejection(&envelope_trust, "pin_mismatch", Some(thumbprint));
        });

        assert!(logs.contains("kid_hash8"));
        assert!(logs.contains(&kid_hash8));
        assert!(logs.contains("thumbprint_hash8"));
        assert!(logs.contains(&thumbprint_hash8));
        assert!(!logs.contains(kid));
        assert!(!logs.contains(thumbprint));
    }

    fn envelope_pin_for_key(key: &SigningKey) -> String {
        ed25519_pubkey_to_okp_thumbprint(&key.verifying_key().to_bytes()).unwrap()
    }

    fn sse_v1_info(nsd_key: &SigningKey) -> NsdInfo {
        NsdInfo {
            nsd_type: common::NsdType::SelfHosted,
            realm: "realm-a".into(),
            auth_methods: vec![common::AuthMethod::AuthKey],
            provider: "mock".into(),
            version: "v1".into(),
            nsd_noise_pubkey: None,
            nsd_quic_pubkey: None,
            signed_transport_keyset: None,
            nsd_envelope_pubkey: Some(hex::encode(nsd_key.verifying_key().to_bytes())),
            envelope_versions: vec![1],
            capabilities: Vec::new(),
            public_ingress_scopes: Vec::new(),
        }
    }

    fn envelope_trust_with_pins(pins: Vec<String>) -> NsdEnvelopeTrustConfig {
        NsdEnvelopeTrustConfig::new(
            "nsd-a",
            "realm-a",
            "/tmp/nsio-test",
            "noise://nsd-1:4001",
            pins,
            None,
        )
        .without_dev_tofu()
    }

    #[tokio::test]
    async fn register_via_envelope_roundtrip() {
        let state = fresh_machine_state().await;
        assert!(!state.is_registered());

        let nsd_sk = SigningKey::generate(&mut OsRng);
        let nsd_pin = envelope_pin_for_key(&nsd_sk);
        let resp_payload = envapi::to_cbor(&envapi::RegisterResponse {
            machine_id: "machine-xyz".into(),
            server_peer_key_pub: "aa".repeat(32),
            server_endpoint: "10.0.0.1:51820".into(),
            domain_base: Some("n.ns".into()),
            nsd_envelope_pubkey: None,
            wg_tunnel_ip: None,
        })
        .unwrap();
        let mock = Arc::new(MockTransport::new(nsd_sk, resp_payload));
        let transport: Arc<dyn ControlTransport> = mock.clone();

        let mut auth = AuthClient::new("http://nsd-1:3001", state)
            .with_transport(transport)
            .with_envelope_trust("nsd-a", "realm-a", "/tmp/nsio-test", vec![nsd_pin], None);
        auth.set_capabilities(vec![CAPABILITY_CAPTURE_ROUTES_V1.to_owned()]);

        auth.register_via_envelope("secret-key").await.unwrap();

        assert!(auth.state.is_registered());
        assert_eq!(auth.state.machine_id.as_deref(), Some("machine-xyz"));

        // Inspect the captured request envelope via the owned Arc<MockTransport>.
        let last = mock.last_req.lock().unwrap().clone().unwrap();
        assert_eq!(last.api, envapi_ids::MACHINE_REGISTER);
        assert!(last.verify_request(now_secs()).is_ok());
        let req: envapi::RegisterRequest = envapi::from_cbor(last.payload.as_ref()).unwrap();
        assert_eq!(req.auth_key.as_deref(), Some("secret-key"));
        assert!(req.access_token.is_none());
        assert!(req.r#type.is_none());
        assert_eq!(req.capabilities, vec![CAPABILITY_CAPTURE_ROUTES_V1]);
    }

    #[tokio::test]
    async fn legacy_register_maps_key_namespace_overlap_conflict() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(run_mock_nsd(
            listener,
            vec![http_response(
                409,
                "application/json",
                r#"{"error":"key_namespace_overlap"}"#,
            )],
        ));

        let state = fresh_machine_state().await;
        let url = format!("http://{addr}");
        let mut auth = AuthClient::new(&url, state);

        let err = auth
            .register("secret-key")
            .await
            .expect_err("legacy register conflict must be typed");
        assert!(matches!(err, Error::KeyNamespaceOverlap));

        let captured = server.await.expect("mock task panicked");
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].path, "/api/v1/machine/register");
    }

    #[tokio::test]
    async fn default_sse_v1_register_and_heartbeat_use_control_endpoint() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let nsd_sk = SigningKey::generate(&mut OsRng);
        let nsd_pin = envelope_pin_for_key(&nsd_sk);
        let server = tokio::spawn(run_signed_envelope_mock_nsd(listener, nsd_sk.clone(), 2));

        let state = fresh_machine_state().await;
        let info = sse_v1_info(&nsd_sk);
        let url = format!("http://{addr}");
        let transport = build_transport("sse", &url, &info, state.peer_key_priv_bytes()).unwrap();
        let use_envelope = info.envelope_versions.contains(&1) && transport.is_some();
        assert!(use_envelope, "SSE v1-capable NSDs must use envelopes");

        let tempdir = tempfile::tempdir().unwrap();
        let mut auth = AuthClient::new(&url, state)
            .with_transport(transport.unwrap())
            .with_envelope_trust("nsd-a", "realm-a", tempdir.path(), vec![nsd_pin], None);

        auth.register_via_envelope("secret-key").await.unwrap();
        auth.heartbeat_client()
            .unwrap()
            .heartbeat(42, vec!["10.0.0.2".into()])
            .await
            .unwrap();

        let captured = server.await.expect("mock task panicked");
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].path, "/api/v1/control");
        assert_eq!(captured[1].path, "/api/v1/control");

        let register = ControlEnvelope::from_cbor(&captured[0].body).unwrap();
        let heartbeat = ControlEnvelope::from_cbor(&captured[1].body).unwrap();
        assert_eq!(register.api, envapi_ids::MACHINE_REGISTER);
        assert_eq!(heartbeat.api, envapi_ids::MACHINE_HEARTBEAT);
    }

    #[test]
    fn default_sse_without_envelope_v1_keeps_legacy_gate() {
        let nsd_sk = SigningKey::generate(&mut OsRng);
        let mut info = sse_v1_info(&nsd_sk);
        info.envelope_versions.clear();

        let transport = build_transport("sse", "http://nsd.test:3001", &info, [0u8; 32]).unwrap();
        let use_envelope = info.envelope_versions.contains(&1) && transport.is_some();

        assert!(transport.is_some(), "default SSE transport is available");
        assert!(
            !use_envelope,
            "legacy path remains intentional when NSD does not advertise envelope v1"
        );
    }

    #[tokio::test]
    async fn default_sse_v1_register_rejects_mismatched_response_pin() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let nsd_sk = SigningKey::generate(&mut OsRng);
        let other_sk = SigningKey::generate(&mut OsRng);
        let other_pin = envelope_pin_for_key(&other_sk);
        let server = tokio::spawn(run_signed_envelope_mock_nsd(listener, nsd_sk.clone(), 1));

        let state = fresh_machine_state().await;
        let info = sse_v1_info(&nsd_sk);
        let url = format!("http://{addr}");
        let transport = build_transport("sse", &url, &info, state.peer_key_priv_bytes())
            .unwrap()
            .unwrap();

        let tempdir = tempfile::tempdir().unwrap();
        let mut auth = AuthClient::new(&url, state)
            .with_transport(transport)
            .with_envelope_trust("nsd-a", "realm-a", tempdir.path(), vec![other_pin], None);

        let err = auth
            .register_via_envelope("secret-key")
            .await
            .expect_err("mismatched SSE envelope response pin must fail closed");
        assert!(matches!(err, Error::Auth(msg) if msg.contains("not trusted")));

        let captured = server.await.expect("mock task panicked");
        assert_eq!(captured[0].path, "/api/v1/control");
        let register = ControlEnvelope::from_cbor(&captured[0].body).unwrap();
        assert_eq!(register.api, envapi_ids::MACHINE_REGISTER);
    }

    #[tokio::test]
    async fn default_sse_v1_heartbeat_fails_closed_without_envelope_pin() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let nsd_sk = SigningKey::generate(&mut OsRng);
        let server = tokio::spawn(run_signed_envelope_mock_nsd(listener, nsd_sk.clone(), 1));

        let mut state = fresh_machine_state().await;
        let info = sse_v1_info(&nsd_sk);
        let url = format!("http://{addr}");
        let transport = build_transport("sse", &url, &info, state.peer_key_priv_bytes())
            .unwrap()
            .unwrap();
        state
            .set_registered(
                "machine-sse".to_string(),
                &"aa".repeat(32),
                "127.0.0.1:51820",
                None,
            )
            .unwrap();
        let signer = EnvelopeSigner::from_state(&state);

        let hb = HeartbeatClient::new(&url, "machine-sse").with_transport(transport, signer);
        let err = hb
            .heartbeat(42, vec!["10.0.0.2".into()])
            .await
            .expect_err("missing SSE envelope pin must fail closed");
        assert!(matches!(err, Error::Auth(msg) if msg.contains("not configured")));

        let captured = server.await.expect("mock task panicked");
        assert_eq!(captured[0].path, "/api/v1/control");
        let heartbeat = ControlEnvelope::from_cbor(&captured[0].body).unwrap();
        assert_eq!(heartbeat.api, envapi_ids::MACHINE_HEARTBEAT);
    }

    #[tokio::test]
    async fn heartbeat_via_envelope_signs_request() {
        let state = fresh_machine_state().await;
        let machine_key_pub = state.machine_key_pub;
        let signer = EnvelopeSigner::from_state(&state);

        let nsd_sk = SigningKey::generate(&mut OsRng);
        let nsd_pin = envelope_pin_for_key(&nsd_sk);
        let resp_payload = envapi::to_cbor(&envapi::HeartbeatResponse::default()).unwrap();
        let transport_impl = Arc::new(MockTransport::new(nsd_sk, resp_payload));
        let transport: Arc<dyn ControlTransport> = transport_impl.clone();

        let hb = HeartbeatClient::new("noise://nsd-1:4001", "m-1")
            .with_transport(transport, signer)
            .with_envelope_trust(envelope_trust_with_pins(vec![nsd_pin]));
        hb.heartbeat(42, vec!["10.0.0.2".into()]).await.unwrap();

        let last = transport_impl.last_req.lock().unwrap().clone().unwrap();
        assert_eq!(last.api, envapi_ids::MACHINE_HEARTBEAT);
        assert_eq!(last.machine_id.as_deref(), Some("m-1"));
        assert_eq!(last.machine_key_pub, machine_key_pub);
        assert!(last.verify_request(now_secs()).is_ok());

        let req: envapi::HeartbeatRequest = envapi::from_cbor(last.payload.as_ref()).unwrap();
        assert_eq!(req.uptime_secs, 42);
        assert_eq!(req.local_ips, vec!["10.0.0.2".to_string()]);
    }

    #[tokio::test]
    async fn heartbeat_via_envelope_rejects_unpinned_response_key() {
        let state = fresh_machine_state().await;
        let signer = EnvelopeSigner::from_state(&state);

        let nsd_sk = SigningKey::generate(&mut OsRng);
        let other_sk = SigningKey::generate(&mut OsRng);
        let other_pin = envelope_pin_for_key(&other_sk);
        let resp_payload = envapi::to_cbor(&envapi::HeartbeatResponse::default()).unwrap();
        let transport: Arc<dyn ControlTransport> =
            Arc::new(MockTransport::new(nsd_sk, resp_payload));

        let hb = HeartbeatClient::new("noise://nsd-1:4001", "m-1")
            .with_transport(transport, signer)
            .with_envelope_trust(envelope_trust_with_pins(vec![other_pin]));
        let err = hb
            .heartbeat(42, vec!["10.0.0.2".into()])
            .await
            .expect_err("unpinned envelope response key must fail closed");
        assert!(matches!(err, Error::Auth(msg) if msg.contains("not trusted")));
    }

    #[tokio::test]
    async fn heartbeat_via_envelope_fails_closed_without_envelope_pin() {
        let state = fresh_machine_state().await;
        let signer = EnvelopeSigner::from_state(&state);

        let nsd_sk = SigningKey::generate(&mut OsRng);
        let resp_payload = envapi::to_cbor(&envapi::HeartbeatResponse::default()).unwrap();
        let transport: Arc<dyn ControlTransport> =
            Arc::new(MockTransport::new(nsd_sk, resp_payload));

        let hb =
            HeartbeatClient::new("noise://nsd-1:4001", "m-1").with_transport(transport, signer);
        let err = hb
            .heartbeat(42, vec!["10.0.0.2".into()])
            .await
            .expect_err("missing envelope pin must fail closed");
        assert!(matches!(err, Error::Auth(msg) if msg.contains("not configured")));
    }

    #[tokio::test]
    async fn discover_via_envelope_parses_response() {
        use common::{AuthMethod, NsdType};

        let nsd_sk = SigningKey::generate(&mut OsRng);
        let info = NsdInfo {
            nsd_type: NsdType::SelfHosted,
            realm: "default".into(),
            auth_methods: vec![AuthMethod::AuthKey],
            provider: "mock".into(),
            version: "v1".into(),
            nsd_noise_pubkey: None,
            nsd_quic_pubkey: None,
            signed_transport_keyset: None,
            nsd_envelope_pubkey: None,
            envelope_versions: vec![1],
            capabilities: Vec::new(),
            public_ingress_scopes: Vec::new(),
        };
        let resp_payload = envapi::to_cbor(&envapi::InfoGetResponse { info }).unwrap();
        let nsd_pin = envelope_pin_for_key(&nsd_sk);
        let transport = Arc::new(MockTransport::new(nsd_sk, resp_payload));

        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        let trust = envelope_trust_with_pins(vec![nsd_pin]);
        let info_resp = discover_via_envelope(&*transport, "nsd:4001", &trust, pk, |m| {
            sk.sign(m).to_bytes()
        })
        .await
        .unwrap();
        assert_eq!(info_resp.info.realm, "default");
        assert_eq!(info_resp.info.envelope_versions, vec![1]);
    }

    #[test]
    fn auth_request_purpose_is_optional_and_never_null() {
        let req = AuthRequest {
            machine_id: "m-1".to_string(),
            machine_key_pub: "aa".repeat(32),
            timestamp: 1,
            signature: "bb".repeat(64),
            purpose: None,
        };
        let value = serde_json::to_value(&req).unwrap();
        assert!(value.get("purpose").is_none());

        let req = AuthRequest {
            purpose: Some("control".to_string()),
            ..req
        };
        let value = serde_json::to_value(&req).unwrap();
        assert_eq!(value["purpose"], "control");
    }

    #[test]
    fn pin_gate_accepts_pinned_key_and_ignores_extra_unpinned_keys() {
        let pinned = test_jwk("kid-a", "mod-a");
        let unpinned = test_jwk("kid-b", "mod-b");
        let pin = rsa_jwk_thumbprint(&pinned).unwrap();
        let trust = NsdJwtTrustConfig::new(
            "nsd-a",
            "realm-a",
            "/tmp/nsio-test",
            "https://nsd-a.example",
            vec![pin.clone()],
        );
        let gated = gate_jwks(
            &trust,
            JwkSet {
                keys: vec![pinned, unpinned],
            },
            &[pin],
            TrustSource::Static,
        );
        assert_eq!(gated.keys.len(), 1);
        assert_eq!(gated.keys[0].kid, "kid-a");
    }

    #[test]
    fn pin_gate_rejects_unpinned_key() {
        let jwk = test_jwk("kid-a", "mod-a");
        let trust = NsdJwtTrustConfig::new(
            "nsd-a",
            "realm-a",
            "/tmp/nsio-test",
            "https://nsd-a.example",
            vec!["not-the-pin".to_string()],
        );
        let gated = gate_jwks(
            &trust,
            JwkSet { keys: vec![jwk] },
            &["not-the-pin".to_string()],
            TrustSource::Static,
        );
        assert!(gated.keys.is_empty());
    }

    #[tokio::test]
    async fn heartbeat_via_envelope_rejects_response_domain_signature() {
        struct BadResponseTransport {
            signer: SigningKey,
        }

        impl ControlTransport for BadResponseTransport {
            fn connect<'a>(
                &'a self,
                _endpoint: &'a str,
            ) -> BoxFuture<'a, Result<BoxStream, Error>> {
                Box::pin(async { Err(Error::NotImplemented("mock connect")) })
            }

            fn call<'a>(
                &'a self,
                _endpoint: &'a str,
                envelope: ControlEnvelope,
            ) -> BoxFuture<'a, Result<ControlEnvelope, Error>> {
                let api = envelope.api;
                let mid = envelope.machine_id;
                let pk = self.signer.verifying_key().to_bytes();
                Box::pin(async move {
                    ControlEnvelope::sign_request(api, mid, pk, Vec::new(), |m| {
                        self.signer.sign(m).to_bytes()
                    })
                    .map_err(Error::from)
                })
            }

            fn name(&self) -> &str {
                "mock"
            }
        }

        let state = fresh_machine_state().await;
        let signer = EnvelopeSigner::from_state(&state);
        let nsd_sk = SigningKey::generate(&mut OsRng);
        let nsd_pin = envelope_pin_for_key(&nsd_sk);
        let transport: Arc<dyn ControlTransport> =
            Arc::new(BadResponseTransport { signer: nsd_sk });
        let hb = HeartbeatClient::new("noise://nsd-1:4001", "m-1")
            .with_transport(transport, signer)
            .with_envelope_trust(envelope_trust_with_pins(vec![nsd_pin]));
        let err = hb
            .heartbeat(42, vec!["10.0.0.2".into()])
            .await
            .expect_err("response signed as request must fail closed");
        assert!(matches!(
            err,
            Error::Envelope(envelope::Error::InvalidSignature)
        ));
    }

    // Records every envelope handed to `call()` and replies with a signed
    // `machine.auth` response carrying a fixed token. `connect()` is left
    // unimplemented so any fall-through to the legacy bearer-over-HTTP path
    // surfaces as a hard error — the success of these tests is itself proof
    // that `authenticate*` drove the `call(MACHINE_AUTH)` path.
    struct RecordingAuthTransport {
        nsd_key: SigningKey,
        token: String,
        seen: Mutex<Vec<ControlEnvelope>>,
    }

    impl RecordingAuthTransport {
        fn new(nsd_key: SigningKey, token: impl Into<String>) -> Self {
            Self {
                nsd_key,
                token: token.into(),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl ControlTransport for RecordingAuthTransport {
        fn connect<'a>(&'a self, _endpoint: &'a str) -> BoxFuture<'a, Result<BoxStream, Error>> {
            Box::pin(async { Err(Error::NotImplemented("legacy path must not be used")) })
        }

        fn call<'a>(
            &'a self,
            _endpoint: &'a str,
            envelope: ControlEnvelope,
        ) -> BoxFuture<'a, Result<ControlEnvelope, Error>> {
            let api = envelope.api.clone();
            let mid = envelope.machine_id.clone();
            self.seen.lock().unwrap().push(envelope);
            let nsd_pk = self.nsd_key.verifying_key().to_bytes();
            let payload = envapi::to_cbor(&envapi::AuthResponse {
                token: self.token.clone(),
            })
            .unwrap();
            Box::pin(async move {
                ControlEnvelope::sign_response(api, mid, nsd_pk, payload, |m| {
                    self.nsd_key.sign(m).to_bytes()
                })
                .map_err(Error::from)
            })
        }

        fn name(&self) -> &str {
            "mock"
        }
    }

    struct FailingAuthTransport {
        name: &'static str,
        seen: Mutex<Vec<ControlEnvelope>>,
    }

    impl FailingAuthTransport {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl ControlTransport for FailingAuthTransport {
        fn connect<'a>(&'a self, _endpoint: &'a str) -> BoxFuture<'a, Result<BoxStream, Error>> {
            Box::pin(async { Err(Error::NotImplemented("legacy path must not be used")) })
        }

        fn call<'a>(
            &'a self,
            _endpoint: &'a str,
            envelope: ControlEnvelope,
        ) -> BoxFuture<'a, Result<ControlEnvelope, Error>> {
            self.seen.lock().unwrap().push(envelope);
            Box::pin(async {
                Err(Error::ServerError(
                    "HTTP 404: response body redacted (0 bytes)".to_string(),
                ))
            })
        }

        fn name(&self) -> &str {
            self.name
        }
    }

    #[tokio::test]
    async fn authenticate_drives_machine_auth_envelope_with_fresh_nonce_per_call() {
        let mut state = fresh_machine_state().await;
        state
            .set_registered(
                "m-auth".to_string(),
                &"aa".repeat(32),
                "127.0.0.1:51820",
                None,
            )
            .unwrap();
        let nsd_sk = SigningKey::generate(&mut OsRng);
        let nsd_pin = envelope_pin_for_key(&nsd_sk);
        let transport_impl = Arc::new(RecordingAuthTransport::new(nsd_sk, "tok-control"));
        let transport: Arc<dyn ControlTransport> = transport_impl.clone();
        let tempdir = tempfile::tempdir().unwrap();
        let auth = AuthClient::new("noise://nsd-1:4001", state)
            .with_transport(transport)
            .with_envelope_trust("nsd-a", "realm-a", tempdir.path(), vec![nsd_pin], None);

        // Two independent attempts model the retry layer re-invoking auth.
        let first = auth.authenticate().await.unwrap();
        let second = auth.authenticate().await.unwrap();
        assert_eq!(first, "tok-control");
        assert_eq!(second, "tok-control");

        let seen = transport_impl.seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "both attempts must hit the call() path");
        for env in seen.iter() {
            assert_eq!(env.api, envapi_ids::MACHINE_AUTH);
            assert_eq!(env.machine_id.as_deref(), Some("m-auth"));
            assert!(env.verify_request(now_secs()).is_ok());
            let payload: envapi::AuthPayload = envapi::from_cbor(env.payload.as_ref()).unwrap();
            assert_eq!(payload.purpose.as_deref(), Some("control"));
        }
        // A retry must re-sign a fresh envelope, never resend cached bytes.
        assert_ne!(
            seen[0].nonce, seen[1].nonce,
            "each attempt must carry a fresh replay nonce"
        );
    }

    #[tokio::test]
    async fn authenticate_wss_drives_machine_auth_with_wss_purpose() {
        let mut state = fresh_machine_state().await;
        state
            .set_registered(
                "m-wss".to_string(),
                &"aa".repeat(32),
                "127.0.0.1:51820",
                None,
            )
            .unwrap();
        let nsd_sk = SigningKey::generate(&mut OsRng);
        let nsd_pin = envelope_pin_for_key(&nsd_sk);
        let transport_impl = Arc::new(RecordingAuthTransport::new(nsd_sk, "tok-wss"));
        let transport: Arc<dyn ControlTransport> = transport_impl.clone();
        let tempdir = tempfile::tempdir().unwrap();
        let auth = AuthClient::new("noise://nsd-1:4001", state)
            .with_transport(transport)
            .with_envelope_trust("nsd-a", "realm-a", tempdir.path(), vec![nsd_pin], None);

        let token = auth.authenticate_wss().await.unwrap();
        assert_eq!(token, "tok-wss");

        let seen = transport_impl.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].api, envapi_ids::MACHINE_AUTH);
        let payload: envapi::AuthPayload = envapi::from_cbor(seen[0].payload.as_ref()).unwrap();
        assert_eq!(payload.purpose.as_deref(), Some("wss"));
    }

    #[tokio::test]
    async fn authenticate_sse_404_falls_back_to_legacy_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(run_mock_nsd(
            listener,
            vec![
                http_response(404, "", ""),
                http_response(200, "application/json", r#"{"token":"tok-legacy"}"#),
            ],
        ));

        let mut state = fresh_machine_state().await;
        state
            .set_registered(
                "m-sse".to_string(),
                &"aa".repeat(32),
                "127.0.0.1:51820",
                None,
            )
            .expect("set registered");
        let nsd_sk = SigningKey::generate(&mut OsRng);
        let info = sse_v1_info(&nsd_sk);
        let url = format!("http://{addr}");
        let transport = build_transport("sse", &url, &info, state.peer_key_priv_bytes())
            .unwrap()
            .unwrap();
        let auth = AuthClient::new(&url, state).with_transport(transport);

        let token = auth.authenticate().await.unwrap();
        assert_eq!(token, "tok-legacy");

        let captured = server.await.expect("mock task panicked");
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].path, CONTROL_ENVELOPE_PATH);
        assert_eq!(captured[1].path, "/api/v1/machine/auth");
        let env = ControlEnvelope::from_cbor(&captured[0].body).unwrap();
        assert_eq!(env.api, envapi_ids::MACHINE_AUTH);
        let body: AuthRequest = serde_json::from_slice(&captured[1].body).unwrap();
        assert_eq!(body.machine_id, "m-sse");
        assert_eq!(body.purpose.as_deref(), Some("control"));
    }

    #[tokio::test]
    async fn authenticate_noise_and_quic_404_do_not_fallback_to_legacy_auth() {
        for name in ["noise", "quic"] {
            let mut state = fresh_machine_state().await;
            state
                .set_registered(
                    format!("m-{name}"),
                    &"aa".repeat(32),
                    "127.0.0.1:51820",
                    None,
                )
                .expect("set registered");
            let transport_impl = Arc::new(FailingAuthTransport::new(name));
            let transport: Arc<dyn ControlTransport> = transport_impl.clone();
            let auth =
                AuthClient::new(&format!("{name}://nsd-1:4001"), state).with_transport(transport);

            let err = auth
                .authenticate()
                .await
                .expect_err("anti-DPI auth must fail closed on machine.auth 404");
            assert!(
                matches!(&err, Error::ServerError(message) if message.contains("HTTP 404")),
                "unexpected {name} error: {err:?}"
            );
            let seen = transport_impl.seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].api, envapi_ids::MACHINE_AUTH);
        }
    }

    fn test_jwk(kid: &str, n: &str) -> RsaJwk {
        RsaJwk {
            kty: "RSA".to_string(),
            kid: Some(kid.to_string()),
            alg: Some("RS256".to_string()),
            key_use: Some("sig".to_string()),
            n: n.to_string(),
            e: "AQAB".to_string(),
        }
    }

    // ── Tiny HTTP mock for legacy reqwest-path heartbeat tests ──────────────
    //
    // Spins a `tokio::net::TcpListener` on `127.0.0.1:0`, accepts exactly N
    // connections, replays one scripted response per connection, and returns
    // the captured request lines.  Bespoke instead of `wiremock` because the
    // workspace pins no dev-dep for it and the request shape we need to
    // assert (`Authorization` header, request path) is tiny enough that a
    // ~40-line helper stays cheaper than a new dependency.
    struct CapturedReq {
        path: String,
        authorization: Option<String>,
        body: Vec<u8>,
    }

    async fn read_http_request<S>(sock: &mut S) -> CapturedReq
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 1024];
        // Read until the end of headers (\r\n\r\n), then drain the advertised
        // body so envelope-path tests can decode the CBOR request.
        loop {
            let n = sock.read(&mut tmp).await.expect("read http request");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let headers_end = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("complete request headers");
        let body_start = headers_end + 4;
        let headers_str =
            std::str::from_utf8(&buf[..headers_end]).expect("headers are utf8 in tests");
        let mut lines = headers_str.split("\r\n");
        let request_line = lines.next().expect("request line");
        let path = request_line
            .split(' ')
            .nth(1)
            .expect("path in request line")
            .to_string();
        let mut authorization = None;
        for line in lines {
            if let Some((k, v)) = line.split_once(": ")
                && k.eq_ignore_ascii_case("authorization")
            {
                authorization = Some(v.to_string());
            }
        }
        let content_length = headers_str
            .split("\r\n")
            .find_map(|line| {
                let (key, value) = line.split_once(": ")?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let mut body = buf.get(body_start..).unwrap_or_default().to_vec();
        while body.len() < content_length {
            let n = sock.read(&mut tmp).await.expect("read http body");
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(content_length);
        CapturedReq {
            path,
            authorization,
            body,
        }
    }

    fn http_response(status: u16, content_type: &str, body: &str) -> Vec<u8> {
        http_binary_response(status, content_type, body.as_bytes())
    }

    fn http_binary_response(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
        let phrase = match status {
            200 => "OK",
            204 => "No Content",
            401 => "Unauthorized",
            _ => "Status",
        };
        let mut resp = format!(
            "HTTP/1.1 {status} {phrase}\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        )
        .into_bytes();
        if !body.is_empty() {
            resp.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        }
        resp.extend_from_slice(b"\r\n");
        resp.extend_from_slice(body);
        resp
    }

    async fn run_mock_nsd(
        listener: tokio::net::TcpListener,
        responses: Vec<Vec<u8>>,
    ) -> Vec<CapturedReq> {
        use tokio::io::AsyncWriteExt;
        let mut captured = Vec::with_capacity(responses.len());
        for resp in responses {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let req = read_http_request(&mut sock).await;
            captured.push(req);
            sock.write_all(&resp).await.expect("write response");
            let _ = sock.shutdown().await;
        }
        captured
    }

    async fn run_signed_envelope_mock_nsd(
        listener: tokio::net::TcpListener,
        nsd_key: SigningKey,
        responses: usize,
    ) -> Vec<CapturedReq> {
        use tokio::io::AsyncWriteExt;

        let mut captured = Vec::with_capacity(responses);
        for _ in 0..responses {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let req = read_http_request(&mut sock).await;
            let req_env = ControlEnvelope::from_cbor(&req.body).expect("request envelope cbor");
            let resp_payload = match req_env.api.as_str() {
                envapi_ids::MACHINE_REGISTER => envapi::to_cbor(&envapi::RegisterResponse {
                    machine_id: "machine-sse".into(),
                    server_peer_key_pub: "aa".repeat(32),
                    server_endpoint: "127.0.0.1:51820".into(),
                    domain_base: Some("n.ns".into()),
                    nsd_envelope_pubkey: None,
                    wg_tunnel_ip: None,
                })
                .unwrap(),
                envapi_ids::MACHINE_HEARTBEAT => {
                    envapi::to_cbor(&envapi::HeartbeatResponse::default()).unwrap()
                }
                other => panic!("unexpected envelope api {other}"),
            };
            let nsd_pk = nsd_key.verifying_key().to_bytes();
            let resp_env = ControlEnvelope::sign_response(
                req_env.api,
                req_env.machine_id,
                nsd_pk,
                resp_payload,
                |m| nsd_key.sign(m).to_bytes(),
            )
            .unwrap();
            let resp_body = resp_env.to_cbor().unwrap();
            captured.push(req);
            sock.write_all(&http_binary_response(200, "application/cbor", &resp_body))
                .await
                .expect("write response");
            let _ = sock.shutdown().await;
        }
        captured
    }

    #[tokio::test]
    async fn heartbeat_legacy_attaches_bearer_and_refreshes_on_401() {
        // Scripted NSD: bootstrap auth → cached-bearer heartbeat returns 401
        // → re-auth → heartbeat with the refreshed bearer returns 204. The
        // full four-leg flow exercises both the lazy bootstrap and the
        // 401-driven refresh, which is the failure mode reported by the
        // cross-repo integration smoke.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(run_mock_nsd(
            listener,
            vec![
                http_response(200, "application/json", r#"{"token":"tok-1"}"#),
                http_response(401, "", ""),
                http_response(200, "application/json", r#"{"token":"tok-2"}"#),
                http_response(204, "", ""),
            ],
        ));

        let state = fresh_machine_state().await;
        let signer = EnvelopeSigner::from_state(&state);
        let url = format!("http://{addr}");
        let hc = HeartbeatClient::new(&url, "m-1").with_signer(signer);

        hc.heartbeat(99, vec!["10.0.0.1".into()])
            .await
            .expect("heartbeat must recover after a single 401");

        let captured = server.await.expect("mock task panicked");
        assert_eq!(captured.len(), 4, "expected exactly four requests");

        assert_eq!(captured[0].path, "/api/v1/machine/auth");
        assert!(
            captured[0].authorization.is_none(),
            "machine/auth POST must not carry a bearer"
        );

        assert_eq!(captured[1].path, "/api/v1/machine/heartbeat");
        assert_eq!(
            captured[1].authorization.as_deref(),
            Some("Bearer tok-1"),
            "first heartbeat must use the cached bootstrap bearer"
        );

        assert_eq!(
            captured[2].path, "/api/v1/machine/auth",
            "401 must invalidate the cache and trigger a re-auth"
        );

        assert_eq!(captured[3].path, "/api/v1/machine/heartbeat");
        assert_eq!(
            captured[3].authorization.as_deref(),
            Some("Bearer tok-2"),
            "retry heartbeat must carry the refreshed bearer"
        );
    }

    #[tokio::test]
    async fn heartbeat_legacy_propagates_unauthorized_after_retry() {
        // Even after a re-auth the server keeps rejecting — bubble a typed
        // `Error::Unauthorized` so the heartbeat task can log warn instead of
        // looping silently at debug.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(run_mock_nsd(
            listener,
            vec![
                http_response(200, "application/json", r#"{"token":"tok-1"}"#),
                http_response(401, "", ""),
                http_response(200, "application/json", r#"{"token":"tok-2"}"#),
                http_response(401, "", ""),
            ],
        ));

        let state = fresh_machine_state().await;
        let signer = EnvelopeSigner::from_state(&state);
        let url = format!("http://{addr}");
        let hc = HeartbeatClient::new(&url, "m-1").with_signer(signer);

        let err = hc
            .heartbeat(1, vec![])
            .await
            .expect_err("second 401 must propagate");
        match err {
            Error::Unauthorized(returned_url) => assert_eq!(returned_url, url),
            other => panic!("expected Error::Unauthorized, got {other:?}"),
        }

        let captured = server.await.expect("mock task panicked");
        assert_eq!(captured.len(), 4);
        assert_eq!(captured[1].authorization.as_deref(), Some("Bearer tok-1"));
        assert_eq!(captured[3].authorization.as_deref(), Some("Bearer tok-2"));
    }

    #[tokio::test]
    async fn heartbeat_legacy_distinguishes_machine_unknown_from_unauthorized() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(run_mock_nsd(
            listener,
            vec![
                http_response(200, "application/json", r#"{"token":"tok-1"}"#),
                http_response(
                    401,
                    "application/json",
                    r#"{"code":"machine_unknown","message":"machine row missing"}"#,
                ),
            ],
        ));

        let state = fresh_machine_state().await;
        let signer = EnvelopeSigner::from_state(&state);
        let url = format!("http://{addr}");
        let hc = HeartbeatClient::new(&url, "m-1").with_signer(signer);

        let err = hc
            .heartbeat(1, vec![])
            .await
            .expect_err("machine_unknown body must propagate distinctly");
        match err {
            Error::MachineUnknown(returned_url) => assert_eq!(returned_url, url),
            other => panic!("expected Error::MachineUnknown, got {other:?}"),
        }

        let captured = server.await.expect("mock task panicked");
        assert_eq!(
            captured.len(),
            2,
            "machine_unknown must not be treated as stale bearer"
        );
        assert_eq!(captured[0].path, "/api/v1/machine/auth");
        assert_eq!(captured[1].path, "/api/v1/machine/heartbeat");
    }

    #[tokio::test]
    async fn bearer_refresher_distinguishes_machine_unknown_from_unauthorized() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(run_mock_nsd(
            listener,
            vec![http_response(
                401,
                "application/json",
                r#"{"error":"machine_not_registered"}"#,
            )],
        ));

        let mut state = fresh_machine_state().await;
        state
            .set_registered("m-1".to_string(), &"aa".repeat(32), "127.0.0.1:51820", None)
            .expect("set registered");
        let url = format!("http://{addr}");
        let refresher = AuthClient::new(&url, state)
            .bearer_token_refresher()
            .expect("registered state builds refresher");

        let err = refresher
            .refresh()
            .await
            .expect_err("machine_not_registered body must propagate distinctly");
        match err {
            Error::MachineUnknown(returned_url) => assert_eq!(returned_url, url),
            other => panic!("expected Error::MachineUnknown, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn bearer_refresher_uses_tunnel_for_anti_dpi_auth() {
        let mut state = fresh_machine_state().await;
        state
            .set_registered("m-1".to_string(), &"aa".repeat(32), "127.0.0.1:51820", None)
            .expect("set registered");
        let tunnel = Arc::new(MockHttpTransport::new(
            "noise",
            http_response(200, "application/json", r#"{"token":"tok-tunnel"}"#),
        ));
        let transport: Arc<dyn ControlTransport> = tunnel.clone();

        let refresher = AuthClient::new("noise://nsd-1:4001", state)
            .with_transport(transport)
            .bearer_token_refresher()
            .expect("registered state builds refresher");

        let token = refresher.refresh().await.unwrap();
        assert_eq!(token, "tok-tunnel");

        let captured = tunnel.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].path, "/api/v1/machine/auth");
        let body: AuthRequest = serde_json::from_slice(&captured[0].body).unwrap();
        assert_eq!(body.machine_id, "m-1");
        assert_eq!(body.purpose.as_deref(), Some("wss"));
    }

    #[tokio::test]
    async fn jwks_fetch_uses_tunnel_for_anti_dpi_verifier() {
        let jwks = serde_json::json!({
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "kid-a",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "mod-a",
                    "e": "AQAB"
                }
            ]
        });
        let tunnel = Arc::new(MockHttpTransport::new(
            "quic",
            http_response(200, "application/json", &jwks.to_string()),
        ));
        let transport: Arc<dyn ControlTransport> = tunnel.clone();
        let verifier = NsdJwtVerifier::from_trust_config(NsdJwtTrustConfig::new(
            "nsd-a",
            "realm-a",
            "/tmp/nsio-test",
            "quic://nsd-1:4002",
            Vec::new(),
        ))
        .with_transport(transport, "nsd-1:4002".to_string());

        let trusted = verifier.fetch_gated_jwks().await.unwrap();
        assert_eq!(trusted.keys.len(), 1);
        assert_eq!(trusted.keys[0].kid, "kid-a");

        let captured = tunnel.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].path, "/.well-known/jwks.json");
    }

    #[tokio::test]
    async fn direct_discovery_rejects_anti_dpi_urls() {
        let err = discover_nsd_info("noise://nsd-1:4001")
            .await
            .expect_err("noise discovery must use signed info.get over transport");
        assert!(matches!(err, Error::Connect(msg) if msg.contains("signed info.get")));
    }

    #[tokio::test]
    async fn heartbeat_legacy_omits_bearer_when_no_signer_attached() {
        // Backwards-compat: tier1/2 mock NSDs and any caller that builds a
        // `HeartbeatClient` without a signer still send the legacy bearer-less
        // request shape they were written against.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(run_mock_nsd(listener, vec![http_response(204, "", "")]));

        let hc = HeartbeatClient::new(&format!("http://{addr}"), "m-2");
        hc.heartbeat(7, vec![]).await.expect("204 path");

        let captured = server.await.expect("mock task panicked");
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].path, "/api/v1/machine/heartbeat");
        assert!(
            captured[0].authorization.is_none(),
            "no signer => no Authorization header"
        );
    }

    #[test]
    fn to_endpoint_strips_scheme_and_path() {
        assert_eq!(to_endpoint("https://nsd-1:3001/api/v1"), "nsd-1:3001");
        assert_eq!(to_endpoint("noise://nsd-2:4001"), "nsd-2:4001");
        assert_eq!(to_endpoint("quic://nsd-3:4002"), "nsd-3:4002");
        assert_eq!(to_endpoint("host-only"), "host-only");
    }

    #[test]
    fn to_endpoint_defaults_port_by_scheme() {
        // Bare https/http (and the url::Url-normalized https://host:443 ->
        // https://host/ form) must yield an explicit default port, not a
        // portless host that fails as an "invalid socket address".
        assert_eq!(
            to_endpoint("https://nsd.example.com"),
            "nsd.example.com:443"
        );
        assert_eq!(
            to_endpoint("https://nsd.example.com/"),
            "nsd.example.com:443"
        );
        assert_eq!(to_endpoint("http://nsd.example.com"), "nsd.example.com:80");
        // Explicit port always wins.
        assert_eq!(
            to_endpoint("https://nsd.example.com:8443"),
            "nsd.example.com:8443"
        );
        // noise/quic without a port have no universal default; left unchanged.
        assert_eq!(to_endpoint("noise://nsd.example.com"), "nsd.example.com");
    }
}
