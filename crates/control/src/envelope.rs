//! `ControlEnvelope` — unified signed wrapper for every NSN ↔ NSD control
//! plane call, regardless of transport (SSE / Noise / QUIC).
//!
//! Wire format: CBOR (RFC 8949) via [`ciborium`]. Signing input is a
//! length-prefixed binary string, **not** the CBOR bytes, so signature
//! verification does not depend on a canonical encoder.
//!
//! Design context lives in the sibling `ns` repository's
//! `docs/plan/PLAN-022.md`; this crate contains the implemented wire type.
#![allow(missing_docs)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Wire-format version of the envelope. Bumped on breaking changes.
pub const ENVELOPE_VERSION: u8 = 1;

/// Domain separator for client → server signatures.
pub const DOMAIN_REQUEST: &[u8] = b"nsio-ctrl-v1\0";

/// Domain separator for server → client signatures.
pub const DOMAIN_RESPONSE: &[u8] = b"nsio-ctrl-v1-resp\0";

/// Maximum accepted clock skew between peers, in seconds.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;

/// Maximum lifetime of a WgRelay roster or forwarding lease (`L`).
pub const MAX_WG_RELAY_LEASE_SECS: u64 = 300;

/// Extra conservative margin added to the authenticated clock-skew bound (`M`).
pub const WG_RELAY_CLOCK_MARGIN_SECS: u64 = 5;

/// Skew-plus-margin guard used for monotonic deadline translation (`Q = K + M`).
pub const WG_RELAY_DEADLINE_GUARD_SECS: u64 = MAX_CLOCK_SKEW_SECS + WG_RELAY_CLOCK_MARGIN_SECS;

/// Maximum period between healthy WgRelay lease renewals (`R`).
///
/// The fixed causal overlap budget is `R + 2Q < L`:
/// `20 + 2 * (60 + 5) < 300`.
pub const MAX_HEALTHY_WG_RELAY_RENEWAL_SECS: u64 = 20;

/// Monotonic deadlines derived once from an authenticated WgRelay lease.
///
/// Consumers must compare only these instants after acceptance; they must not
/// revisit wall clock or independently reproduce the causal guard formula.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct WgRelayLeaseDeadlines {
    /// Earliest monotonic instant at which the roster or forwarding table may
    /// become active.
    pub not_before: Instant,
    /// Monotonic instant at which the roster or forwarding table expires.
    pub expires_at: Instant,
}

/// Fail-closed reasons returned by [`translate_wg_relay_lease_deadlines`].
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum WgRelayLeaseDeadlineError {
    #[error("WgRelay lease expiry is not after its authenticated signed timestamp")]
    ExpiryNotAfterSignedAt,
    #[error("WgRelay lease exceeds the shared maximum lifetime")]
    LeaseTooLong,
    #[error("WgRelay not-before barrier exceeds the shared maximum lifetime")]
    NotBeforeTooFar,
    #[error("WgRelay monotonic deadline arithmetic overflowed")]
    MonotonicOverflow,
    #[error("WgRelay guarded not-before deadline does not precede expiry")]
    NoUsableWindow,
}

/// Translate authenticated absolute WgRelay lease times into monotonic
/// deadlines, applying the fixed PLAN-114 causal guard only where wall-clock
/// uncertainty still matters.
///
/// Given authenticated signed timestamp `s`, not-before `b`, expiry `e`, and
/// the monotonic receipt anchor `m`, this enforces `0 < e - s <= L`, bounds a
/// future `b - s` by `L`, then computes:
///
/// - `expires_at = m + (e - s).saturating_sub(Q)`
/// - `not_before = m` when `b <= s` — a non-future barrier is already
///   satisfied under the authenticated signed timestamp, so the lease
///   activates immediately at receipt with no added guard
/// - `not_before = m + (b - s) + Q` when `b > s` — a legacy future barrier
///   from an old producer keeps the guarded calculation
///
/// The result is accepted only when `not_before < expires_at`. Under a
/// non-future barrier this admits signed intervals as short as `Q + 1`
/// seconds; the previous always-guarded translation needed more than `2Q`.
/// All arithmetic that can overflow is checked; any invalid or
/// unrepresentable deadline fails closed.
///
/// # Errors
///
/// Returns [`WgRelayLeaseDeadlineError`] for a non-positive or overlong lease,
/// an overlong future barrier, monotonic arithmetic overflow, or an empty
/// activation window.
pub fn translate_wg_relay_lease_deadlines(
    signed_at_unix_secs: u64,
    not_before_unix_secs: u64,
    expires_at_unix_secs: u64,
    received_at: Instant,
) -> Result<WgRelayLeaseDeadlines, WgRelayLeaseDeadlineError> {
    let lease_secs = expires_at_unix_secs
        .checked_sub(signed_at_unix_secs)
        .filter(|duration| *duration > 0)
        .ok_or(WgRelayLeaseDeadlineError::ExpiryNotAfterSignedAt)?;
    if lease_secs > MAX_WG_RELAY_LEASE_SECS {
        return Err(WgRelayLeaseDeadlineError::LeaseTooLong);
    }

    let future_not_before_secs = not_before_unix_secs.saturating_sub(signed_at_unix_secs);
    if future_not_before_secs > MAX_WG_RELAY_LEASE_SECS {
        return Err(WgRelayLeaseDeadlineError::NotBeforeTooFar);
    }

    let expiry_offset =
        Duration::from_secs(lease_secs.saturating_sub(WG_RELAY_DEADLINE_GUARD_SECS));
    let expires_at = received_at
        .checked_add(expiry_offset)
        .ok_or(WgRelayLeaseDeadlineError::MonotonicOverflow)?;
    let not_before = if future_not_before_secs == 0 {
        // The barrier is not after the authenticated signed timestamp, so it
        // is already satisfied; activate at the receipt anchor with no guard.
        received_at
    } else {
        let not_before_offset_secs = future_not_before_secs
            .checked_add(WG_RELAY_DEADLINE_GUARD_SECS)
            .ok_or(WgRelayLeaseDeadlineError::MonotonicOverflow)?;
        received_at
            .checked_add(Duration::from_secs(not_before_offset_secs))
            .ok_or(WgRelayLeaseDeadlineError::MonotonicOverflow)?
    };
    if not_before >= expires_at {
        return Err(WgRelayLeaseDeadlineError::NoUsableWindow);
    }

    Ok(WgRelayLeaseDeadlines {
        not_before,
        expires_at,
    })
}

/// Replay cache window. Envelopes older than this are rejected outright.
pub const REPLAY_WINDOW_SECS: u64 = 120;

/// Logical API identifiers carried in `ControlEnvelope::api`.
pub mod api {
    pub const INFO_GET: &str = "info.get";
    pub const MACHINE_REGISTER: &str = "machine.register";
    pub const MACHINE_AUTH: &str = "machine.auth";
    pub const MACHINE_HEARTBEAT: &str = "machine.heartbeat";
    pub const SERVICES_REPORT: &str = "services.report";
    pub const GATEWAY_SERVICES_REPORT: &str = "gateway.services_report";
    pub const PEER_CANDIDATES_REPORT: &str = "peer_candidates.report";
    pub const GATEWAY_REFLEXIVE: &str = "gateway.reflexive";
    pub const WG_RELAY_REGISTER_SOURCE: &str = "wg_relay.register_source";
    pub const CLIENT_EXIT_NODE_SELECTION: &str = "client.exit_node_selection.v1";
    /// NODE-001 (`PLAN-015`): node → NSD full-snapshot subnet-route
    /// advertisement. Reporting is intent only; approval and projection arrive
    /// separately through `subnet_route_config.v1`.
    pub const NODE_SUBNET_ROUTES_REPORT: &str = "node.subnet_routes.report.v1";
    /// D4 (`INGEST-005`): logical id for `POST /api/v1/gateway/report` over
    /// the envelope path. Must stay byte-equal to NSD's INGEST-004 local
    /// constant — adversarial gate C.
    pub const GATEWAY_REPORT: &str = "gateway.report";
    /// PLAN-098 S1: NSGW → NSD per-realm traffic metering for billing. Carries
    /// windowed byte counters (`gateway.usage_report`); dedup key is
    /// `(machine_id, report_seq)`.
    pub const GATEWAY_USAGE_REPORT: &str = "gateway.usage_report";
    pub const GATEWAY_REALM_CONFIG_SNAPSHOT: &str = "gateway.realm_config_snapshot";
    pub const CONFIG_STREAM: &str = "config.stream";
}

/// Errors raised during envelope construction, signing, or verification.
#[derive(Debug, Error)]
pub enum Error {
    #[error("unsupported envelope version: {0}")]
    InvalidVersion(u8),
    #[error("clock skew exceeds {MAX_CLOCK_SKEW_SECS}s: ts={ts}, now={now}")]
    ClockSkew { ts: u64, now: u64 },
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("malformed CBOR: {0}")]
    CborDecode(String),
    #[error("cbor encode: {0}")]
    CborEncode(String),
    #[error("invalid verifying key bytes")]
    InvalidKey,
    #[error("system clock before epoch")]
    ClockBeforeEpoch,
}

/// Unified signed envelope carried over every control-plane transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlEnvelope {
    /// Wire-format version. Currently [`ENVELOPE_VERSION`] (= 1).
    pub v: u8,

    /// Logical API identifier — see [`api`] module constants.
    pub api: String,

    /// Unix seconds at the time of construction.
    pub ts: u64,

    /// 16-byte random nonce. Servers keep a sliding-window cache keyed by
    /// `(machine_id, nonce)` over the past [`REPLAY_WINDOW_SECS`].
    #[serde(with = "serde_bytes_array")]
    pub nonce: [u8; 16],

    /// Logical caller. `None` only on `info.get` and `machine.register`
    /// before the machine_id has been assigned.
    pub machine_id: Option<String>,

    /// Ed25519 verifying key (public) of whoever signed this envelope.
    /// On requests this is the machine's key; on responses it is the NSD's.
    #[serde(with = "serde_bytes_array_32")]
    pub machine_key_pub: [u8; 32],

    /// CBOR-encoded inner payload. Opaque to the envelope layer.
    pub payload: ByteBuf,

    /// Ed25519 signature (64 bytes) over the canonical signing input.
    #[serde(with = "serde_bytes_array_64")]
    pub signature: [u8; 64],
}

impl ControlEnvelope {
    /// Build and sign a request envelope.
    ///
    /// `sign` is a closure that returns the Ed25519 signature (64 bytes)
    /// over its input. Taking a closure (rather than `&SigningKey`) keeps
    /// callers' private key material behind whatever abstraction they use
    /// (e.g. [`common::MachineState::sign`]).
    pub fn sign_request<F>(
        api: impl Into<String>,
        machine_id: Option<String>,
        machine_key_pub: [u8; 32],
        payload_cbor: Vec<u8>,
        sign: F,
    ) -> Result<Self, Error>
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        let ts = now_secs()?;
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let api_str = api.into();

        let sig_input = build_sig_input(SigInput {
            domain: DOMAIN_REQUEST,
            v: ENVELOPE_VERSION,
            api: &api_str,
            ts,
            nonce: &nonce,
            machine_id: machine_id.as_deref(),
            machine_key_pub: &machine_key_pub,
            payload_cbor: &payload_cbor,
        });
        let signature = sign(&sig_input);

        Ok(Self {
            v: ENVELOPE_VERSION,
            api: api_str,
            ts,
            nonce,
            machine_id,
            machine_key_pub,
            payload: ByteBuf::from(payload_cbor),
            signature,
        })
    }

    /// Build and sign a response envelope. Uses [`DOMAIN_RESPONSE`] domain
    /// and the NSD's signing key. `machine_id` should identify the target
    /// machine so a MitM cannot re-target the response.
    pub fn sign_response<F>(
        api: impl Into<String>,
        machine_id: Option<String>,
        nsd_key_pub: [u8; 32],
        payload_cbor: Vec<u8>,
        sign: F,
    ) -> Result<Self, Error>
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        let ts = now_secs()?;
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let api_str = api.into();

        let sig_input = build_sig_input(SigInput {
            domain: DOMAIN_RESPONSE,
            v: ENVELOPE_VERSION,
            api: &api_str,
            ts,
            nonce: &nonce,
            machine_id: machine_id.as_deref(),
            machine_key_pub: &nsd_key_pub,
            payload_cbor: &payload_cbor,
        });
        let signature = sign(&sig_input);

        Ok(Self {
            v: ENVELOPE_VERSION,
            api: api_str,
            ts,
            nonce,
            machine_id,
            machine_key_pub: nsd_key_pub,
            payload: ByteBuf::from(payload_cbor),
            signature,
        })
    }

    /// Verify a request envelope against the embedded `machine_key_pub`.
    ///
    /// Checks version, clock skew, and Ed25519 signature. Does **not**
    /// perform replay-cache lookup; callers own that state.
    pub fn verify_request(&self, now: u64) -> Result<(), Error> {
        self.verify_with_domain(DOMAIN_REQUEST, now)
    }

    /// Verify a response envelope. `expected_nsd_key` is the pinned NSD
    /// pubkey from registration (or `--nsd-pubkey`); it must match the
    /// envelope's `machine_key_pub` field.
    pub fn verify_response(&self, now: u64, expected_nsd_key: &[u8; 32]) -> Result<u64, Error> {
        if &self.machine_key_pub != expected_nsd_key {
            return Err(Error::InvalidSignature);
        }
        self.verify_with_domain(DOMAIN_RESPONSE, now)?;
        Ok(self.ts)
    }

    fn verify_with_domain(&self, domain: &[u8], now: u64) -> Result<(), Error> {
        if self.v != ENVELOPE_VERSION {
            return Err(Error::InvalidVersion(self.v));
        }
        let skew = now.abs_diff(self.ts);
        if skew > MAX_CLOCK_SKEW_SECS {
            return Err(Error::ClockSkew { ts: self.ts, now });
        }

        let vk = VerifyingKey::from_bytes(&self.machine_key_pub).map_err(|_| Error::InvalidKey)?;
        let sig = Signature::from_bytes(&self.signature);
        let sig_input = build_sig_input(SigInput {
            domain,
            v: self.v,
            api: &self.api,
            ts: self.ts,
            nonce: &self.nonce,
            machine_id: self.machine_id.as_deref(),
            machine_key_pub: &self.machine_key_pub,
            payload_cbor: self.payload.as_ref(),
        });
        vk.verify(&sig_input, &sig)
            .map_err(|_| Error::InvalidSignature)
    }

    /// Encode the envelope to CBOR bytes for the wire.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::with_capacity(256 + self.payload.len());
        ciborium::ser::into_writer(self, &mut buf).map_err(|e| Error::CborEncode(e.to_string()))?;
        Ok(buf)
    }

    /// Decode a CBOR-encoded envelope from the wire.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::de::from_reader(bytes).map_err(|e| Error::CborDecode(e.to_string()))
    }
}

/// Inputs to the canonical signing-input builder. Grouped into a struct so
/// callers pass a single value rather than 8 positional arguments.
struct SigInput<'a> {
    domain: &'a [u8],
    v: u8,
    api: &'a str,
    ts: u64,
    nonce: &'a [u8; 16],
    machine_id: Option<&'a str>,
    machine_key_pub: &'a [u8; 32],
    payload_cbor: &'a [u8],
}

/// Build the canonical signing input.
///
/// Format:
/// ```text
/// domain || u8(v)
///        || u32_be(len(api)) || api
///        || u64_be(ts)
///        || nonce[16]
///        || u8(0)           if machine_id is None
///        || u8(1) || u32_be(len) || machine_id   if Some
///        || machine_key_pub[32]
///        || sha256(payload_cbor)[32]
/// ```
fn build_sig_input(parts: SigInput<'_>) -> Vec<u8> {
    let SigInput {
        domain,
        v,
        api,
        ts,
        nonce,
        machine_id,
        machine_key_pub,
        payload_cbor,
    } = parts;
    let payload_hash = Sha256::digest(payload_cbor);
    let api_bytes = api.as_bytes();
    let mid_len = machine_id.map(|s| 1 + 4 + s.len()).unwrap_or(1);
    let total = domain.len() + 1 + 4 + api_bytes.len() + 8 + 16 + mid_len + 32 + 32;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(domain);
    out.push(v);
    out.extend_from_slice(&(api_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(api_bytes);
    out.extend_from_slice(&ts.to_be_bytes());
    out.extend_from_slice(nonce);
    match machine_id {
        None => out.push(0),
        Some(s) => {
            out.push(1);
            let b = s.as_bytes();
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(b);
        }
    }
    out.extend_from_slice(machine_key_pub);
    out.extend_from_slice(&payload_hash);
    out
}

fn now_secs() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::ClockBeforeEpoch)
}

// ── serde helpers ────────────────────────────────────────────────────────────
// CBOR major type 2 (byte string) for fixed-size arrays. `serde_bytes` does
// the trick but only for slices; we hand-roll for `[u8; N]`.

mod serde_bytes_array {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_bytes::ByteBuf;

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(v.as_slice(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let b = ByteBuf::deserialize(d)?;
        if b.len() != 16 {
            return Err(serde::de::Error::invalid_length(b.len(), &"16 bytes"));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(b.as_ref());
        Ok(out)
    }
}

mod serde_bytes_array_32 {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_bytes::ByteBuf;

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(v.as_slice(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let b = ByteBuf::deserialize(d)?;
        if b.len() != 32 {
            return Err(serde::de::Error::invalid_length(b.len(), &"32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(b.as_ref());
        Ok(out)
    }
}

mod serde_bytes_array_64 {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_bytes::ByteBuf;

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(v.as_slice(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let b = ByteBuf::deserialize(d)?;
        if b.len() != 64 {
            return Err(serde::de::Error::invalid_length(b.len(), &"64 bytes"));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(b.as_ref());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn sign_with(sk: &SigningKey) -> impl FnOnce(&[u8]) -> [u8; 64] + '_ {
        move |m| sk.sign(m).to_bytes()
    }

    #[test]
    fn round_trip_cbor() {
        let sk = keypair();
        let pk = sk.verifying_key().to_bytes();
        let env = ControlEnvelope::sign_request(
            api::MACHINE_HEARTBEAT,
            Some("machine-1".into()),
            pk,
            vec![0xA1, 0x01, 0x02],
            sign_with(&sk),
        )
        .unwrap();

        let bytes = env.to_cbor().unwrap();
        let decoded = ControlEnvelope::from_cbor(&bytes).unwrap();
        assert_eq!(env, decoded);
        decoded.verify_request(now_secs().unwrap()).unwrap();
    }

    #[test]
    fn verify_accepts_fresh() {
        let sk = keypair();
        let pk = sk.verifying_key().to_bytes();
        let env =
            ControlEnvelope::sign_request(api::INFO_GET, None, pk, vec![], sign_with(&sk)).unwrap();
        assert!(env.verify_request(now_secs().unwrap()).is_ok());
    }

    #[test]
    fn wg_relay_lease_constants_preserve_causal_overlap_budget() {
        assert_eq!(MAX_WG_RELAY_LEASE_SECS, 300);
        assert_eq!(MAX_CLOCK_SKEW_SECS, 60);
        assert_eq!(WG_RELAY_CLOCK_MARGIN_SECS, 5);
        assert_eq!(WG_RELAY_DEADLINE_GUARD_SECS, 65);
        assert_eq!(MAX_HEALTHY_WG_RELAY_RENEWAL_SECS, 20);
        assert_eq!(
            WG_RELAY_DEADLINE_GUARD_SECS,
            MAX_CLOCK_SKEW_SECS + WG_RELAY_CLOCK_MARGIN_SECS
        );
        let renewal = std::hint::black_box(MAX_HEALTHY_WG_RELAY_RENEWAL_SECS);
        let guard = std::hint::black_box(WG_RELAY_DEADLINE_GUARD_SECS);
        let lease = std::hint::black_box(MAX_WG_RELAY_LEASE_SECS);
        assert!(renewal + 2 * guard < lease);
        assert!(renewal > 0);
        assert!(MAX_CLOCK_SKEW_SECS < lease);
    }

    #[test]
    fn wg_relay_deadline_translation_activates_equal_barrier_at_receipt() {
        let signed_at = 10_000;
        let received_at = std::time::Instant::now();

        let deadlines = translate_wg_relay_lease_deadlines(
            signed_at,
            signed_at,
            signed_at + MAX_WG_RELAY_LEASE_SECS,
            received_at,
        )
        .expect("the exact maximum lease must remain valid");

        // `b == s` is a non-future barrier: immediate activation, no guard.
        assert_eq!(deadlines.not_before, received_at);
        // A 300-second signed lease keeps the conservative receipt-anchored
        // hard expiry of exactly 235 seconds (L - Q).
        assert_eq!(
            deadlines.expires_at,
            received_at + std::time::Duration::from_secs(235)
        );
        assert_eq!(
            deadlines.expires_at,
            received_at
                + std::time::Duration::from_secs(
                    MAX_WG_RELAY_LEASE_SECS - WG_RELAY_DEADLINE_GUARD_SECS,
                )
        );
    }

    #[test]
    fn wg_relay_deadline_translation_rejects_overlong_lease() {
        let signed_at = 10_000;
        let error = translate_wg_relay_lease_deadlines(
            signed_at,
            signed_at,
            signed_at + MAX_WG_RELAY_LEASE_SECS + 1,
            std::time::Instant::now(),
        )
        .expect_err("a lease longer than L must fail closed");

        assert!(matches!(error, WgRelayLeaseDeadlineError::LeaseTooLong));
    }

    #[test]
    fn wg_relay_deadline_translation_rejects_nonpositive_expiry_interval() {
        let signed_at = 10_000;
        for expires_at in [signed_at, signed_at - 1] {
            let error = translate_wg_relay_lease_deadlines(
                signed_at,
                signed_at,
                expires_at,
                std::time::Instant::now(),
            )
            .expect_err("zero or negative expiry interval must fail closed");

            assert!(matches!(
                error,
                WgRelayLeaseDeadlineError::ExpiryNotAfterSignedAt
            ));
        }
    }

    #[test]
    fn wg_relay_deadline_translation_bounds_future_not_before() {
        let signed_at = 10_000;
        let error = translate_wg_relay_lease_deadlines(
            signed_at,
            signed_at + MAX_WG_RELAY_LEASE_SECS + 1,
            signed_at + MAX_WG_RELAY_LEASE_SECS,
            std::time::Instant::now(),
        )
        .expect_err("a future barrier beyond L must fail closed");

        assert!(matches!(error, WgRelayLeaseDeadlineError::NotBeforeTooFar));
    }

    #[test]
    fn wg_relay_deadline_translation_activates_past_barrier_at_receipt() {
        let signed_at = 10_000;
        let received_at = std::time::Instant::now();
        // A stable generation timestamp may be far in the past; both a barely
        // and a deeply past barrier activate immediately at receipt.
        for not_before in [signed_at - 1, 1] {
            let deadlines = translate_wg_relay_lease_deadlines(
                signed_at,
                not_before,
                signed_at + MAX_WG_RELAY_LEASE_SECS,
                received_at,
            )
            .expect("an already-past barrier must remain valid");

            assert_eq!(deadlines.not_before, received_at);
        }
    }

    #[test]
    fn wg_relay_deadline_translation_guards_legacy_future_barrier() {
        let signed_at = 10_000;
        let received_at = std::time::Instant::now();
        let deadlines = translate_wg_relay_lease_deadlines(
            signed_at,
            signed_at + 100,
            signed_at + MAX_WG_RELAY_LEASE_SECS,
            received_at,
        )
        .expect("a moderate legacy future barrier must remain valid");

        // A legacy future barrier keeps the guarded calculation:
        // barrier delta (100) plus the 65-second guard.
        assert_eq!(
            deadlines.not_before,
            received_at + std::time::Duration::from_secs(165)
        );
        assert_eq!(
            deadlines.expires_at,
            received_at + std::time::Duration::from_secs(235)
        );

        // The minimal future barrier (one second) is already legacy: the
        // guard applies in full, pinning the branch boundary at `b == s`.
        let minimal = translate_wg_relay_lease_deadlines(
            signed_at,
            signed_at + 1,
            signed_at + MAX_WG_RELAY_LEASE_SECS,
            received_at,
        )
        .expect("the minimal legacy future barrier must remain valid");
        assert_eq!(
            minimal.not_before,
            received_at + std::time::Duration::from_secs(1 + WG_RELAY_DEADLINE_GUARD_SECS)
        );
        assert_eq!(
            minimal.expires_at,
            received_at + std::time::Duration::from_secs(235)
        );
    }

    #[test]
    fn wg_relay_deadline_translation_quarantines_legacy_first_lease() {
        // An old producer's first lease carries `b = s + L`, `e = s + L`;
        // the guarded activation never precedes expiry, so consumers keep
        // quarantining it until a later renewal shrinks the barrier.
        let signed_at = 10_000;
        let error = translate_wg_relay_lease_deadlines(
            signed_at,
            signed_at + MAX_WG_RELAY_LEASE_SECS,
            signed_at + MAX_WG_RELAY_LEASE_SECS,
            std::time::Instant::now(),
        )
        .expect_err("the legacy first-lease shape must still fail closed");

        assert!(matches!(error, WgRelayLeaseDeadlineError::NoUsableWindow));
    }

    #[test]
    fn wg_relay_deadline_translation_rejects_degenerate_short_lease() {
        // Even with immediate activation, a lease no longer than the expiry
        // guard leaves an empty window and must fail closed.
        let signed_at = 10_000;
        for lease_secs in [1, WG_RELAY_DEADLINE_GUARD_SECS] {
            let error = translate_wg_relay_lease_deadlines(
                signed_at,
                signed_at,
                signed_at + lease_secs,
                std::time::Instant::now(),
            )
            .expect_err("a lease inside the expiry guard must fail closed");

            assert!(matches!(error, WgRelayLeaseDeadlineError::NoUsableWindow));
        }
    }

    #[test]
    fn wg_relay_deadline_translation_requires_strict_usable_ordering() {
        let signed_at = 10_000;
        let error = translate_wg_relay_lease_deadlines(
            signed_at,
            signed_at + 170,
            signed_at + MAX_WG_RELAY_LEASE_SECS,
            std::time::Instant::now(),
        )
        .expect_err("equal guarded activation and expiry must fail closed");

        assert!(matches!(error, WgRelayLeaseDeadlineError::NoUsableWindow));
    }

    // Largest whole-second duration still addable to `from` without
    // overflowing the platform `Instant` representation.
    fn max_addable_secs(from: std::time::Instant) -> u64 {
        let mut low = 0_u64;
        let mut high = u64::MAX;
        while low < high {
            let distance = high - low;
            let midpoint = low + distance / 2 + distance % 2;
            if from
                .checked_add(std::time::Duration::from_secs(midpoint))
                .is_some()
            {
                low = midpoint;
            } else {
                high = midpoint - 1;
            }
        }
        low
    }

    #[test]
    fn wg_relay_deadline_translation_rejects_monotonic_overflow() {
        let now = std::time::Instant::now();
        let near_instant_limit = now
            .checked_add(std::time::Duration::from_secs(max_addable_secs(now)))
            .expect("binary search retains a representable Instant");
        let signed_at = 10_000;

        let error = translate_wg_relay_lease_deadlines(
            signed_at,
            signed_at,
            signed_at + MAX_WG_RELAY_LEASE_SECS,
            near_instant_limit,
        )
        .expect_err("Instant overflow must fail closed");

        assert!(matches!(
            error,
            WgRelayLeaseDeadlineError::MonotonicOverflow
        ));
    }

    #[test]
    fn wg_relay_deadline_translation_rejects_legacy_barrier_overflow() {
        // Anchor so the guarded expiry stays representable while the larger
        // legacy guarded activation offset overflows the Instant range.
        let now = std::time::Instant::now();
        let received_at = now
            .checked_add(std::time::Duration::from_secs(
                max_addable_secs(now) - MAX_WG_RELAY_LEASE_SECS,
            ))
            .expect("an anchor below the Instant limit is representable");
        let signed_at = 10_000;

        let error = translate_wg_relay_lease_deadlines(
            signed_at,
            signed_at + MAX_WG_RELAY_LEASE_SECS,
            signed_at + MAX_WG_RELAY_LEASE_SECS,
            received_at,
        )
        .expect_err("legacy barrier Instant overflow must fail closed");

        assert!(matches!(
            error,
            WgRelayLeaseDeadlineError::MonotonicOverflow
        ));
    }

    #[test]
    fn rejects_clock_skew() {
        let sk = keypair();
        let pk = sk.verifying_key().to_bytes();
        let mut env =
            ControlEnvelope::sign_request(api::INFO_GET, None, pk, vec![], sign_with(&sk)).unwrap();
        env.ts = env.ts.saturating_sub(MAX_CLOCK_SKEW_SECS + 10);
        // We don't re-sign, so the test verifies clock-skew fires before
        // signature verification.
        let err = env.verify_request(now_secs().unwrap()).unwrap_err();
        assert!(matches!(err, Error::ClockSkew { .. }));
    }

    #[test]
    fn rejects_wrong_version() {
        let sk = keypair();
        let pk = sk.verifying_key().to_bytes();
        let mut env =
            ControlEnvelope::sign_request(api::INFO_GET, None, pk, vec![], sign_with(&sk)).unwrap();
        env.v = 99;
        let err = env.verify_request(now_secs().unwrap()).unwrap_err();
        assert!(matches!(err, Error::InvalidVersion(99)));
    }

    #[test]
    fn cross_api_forgery_fails() {
        // Sign for heartbeat, re-tag as register — signature must fail.
        let sk = keypair();
        let pk = sk.verifying_key().to_bytes();
        let mut env = ControlEnvelope::sign_request(
            api::MACHINE_HEARTBEAT,
            Some("m-1".into()),
            pk,
            vec![1, 2, 3],
            sign_with(&sk),
        )
        .unwrap();
        env.api = api::MACHINE_REGISTER.into();
        let err = env.verify_request(now_secs().unwrap()).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature));
    }

    #[test]
    fn cross_machine_forgery_fails() {
        // Sign with machine A, replace machine_key_pub with machine B.
        let sk_a = keypair();
        let sk_b = keypair();
        let pk_a = sk_a.verifying_key().to_bytes();
        let pk_b = sk_b.verifying_key().to_bytes();

        let mut env = ControlEnvelope::sign_request(
            api::MACHINE_HEARTBEAT,
            Some("m-1".into()),
            pk_a,
            vec![1, 2, 3],
            sign_with(&sk_a),
        )
        .unwrap();
        env.machine_key_pub = pk_b;
        let err = env.verify_request(now_secs().unwrap()).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature));
    }

    #[test]
    fn tampered_payload_fails() {
        let sk = keypair();
        let pk = sk.verifying_key().to_bytes();
        let mut env = ControlEnvelope::sign_request(
            api::SERVICES_REPORT,
            Some("m-1".into()),
            pk,
            vec![1, 2, 3],
            sign_with(&sk),
        )
        .unwrap();
        env.payload = ByteBuf::from(vec![9, 9, 9]);
        let err = env.verify_request(now_secs().unwrap()).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature));
    }

    #[test]
    fn response_domain_isolated_from_request() {
        // A request envelope must not validate as a response.
        let sk = keypair();
        let pk = sk.verifying_key().to_bytes();
        let env =
            ControlEnvelope::sign_request(api::INFO_GET, None, pk, vec![], sign_with(&sk)).unwrap();
        // Same key, same api, same payload — but verify_response uses a
        // different domain and expected key match; should fail on key pin.
        let err = env.verify_response(now_secs().unwrap(), &pk).unwrap_err();
        // Key matches, but domain differs -> InvalidSignature
        assert!(matches!(err, Error::InvalidSignature));
    }

    #[test]
    fn response_round_trip() {
        let nsd_sk = keypair();
        let nsd_pk = nsd_sk.verifying_key().to_bytes();
        let env = ControlEnvelope::sign_response(
            api::MACHINE_REGISTER,
            Some("m-1".into()),
            nsd_pk,
            vec![1, 2, 3],
            sign_with(&nsd_sk),
        )
        .unwrap();
        let signed_at = env.verify_response(now_secs().unwrap(), &nsd_pk).unwrap();
        assert_eq!(signed_at, env.ts);
    }

    #[test]
    fn response_wrong_nsd_key_rejected() {
        let nsd_sk = keypair();
        let nsd_pk = nsd_sk.verifying_key().to_bytes();
        let env =
            ControlEnvelope::sign_response(api::INFO_GET, None, nsd_pk, vec![], sign_with(&nsd_sk))
                .unwrap();
        let wrong = [0u8; 32];
        let err = env
            .verify_response(now_secs().unwrap(), &wrong)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidSignature));
    }

    #[test]
    fn golden_sig_input_shape() {
        // Pin the signing-input shape so encoder drift is caught.
        let api = "machine.heartbeat";
        let ts: u64 = 0x0102_0304_0506_0708;
        let nonce = [0xAAu8; 16];
        let mid = Some("m-id");
        let key = [0xBBu8; 32];
        let payload = b"hello";
        let out = build_sig_input(SigInput {
            domain: DOMAIN_REQUEST,
            v: ENVELOPE_VERSION,
            api,
            ts,
            nonce: &nonce,
            machine_id: mid,
            machine_key_pub: &key,
            payload_cbor: payload,
        });

        // Prefix:
        //   "nsio-ctrl-v1\0"          (13 bytes)
        //   v                          (1)
        //   u32_be(len(api))           (4)
        //   api                        (17)
        //   u64_be(ts)                 (8)
        //   nonce                      (16)
        //   1 || u32_be(len) || mid    (1 + 4 + 4 = 9)
        //   machine_key_pub            (32)
        //   sha256(payload)            (32)
        let expected_len = 13 + 1 + 4 + 17 + 8 + 16 + 9 + 32 + 32;
        assert_eq!(out.len(), expected_len);
        assert_eq!(&out[0..13], DOMAIN_REQUEST);
        assert_eq!(out[13], ENVELOPE_VERSION);
        assert_eq!(&out[14..18], &(api.len() as u32).to_be_bytes());
        assert_eq!(&out[18..18 + 17], api.as_bytes());
        assert_eq!(&out[35..43], &ts.to_be_bytes());
        assert_eq!(&out[43..59], &nonce);
        assert_eq!(out[59], 1);
        assert_eq!(&out[60..64], &4u32.to_be_bytes());
        assert_eq!(&out[64..68], b"m-id");
        assert_eq!(&out[68..100], &key);
        let hash = Sha256::digest(payload);
        assert_eq!(&out[100..132], hash.as_slice());
    }

    #[test]
    fn none_machine_id_encoded_as_zero_byte() {
        let out = build_sig_input(SigInput {
            domain: DOMAIN_REQUEST,
            v: ENVELOPE_VERSION,
            api: "info.get",
            ts: 0,
            nonce: &[0u8; 16],
            machine_id: None,
            machine_key_pub: &[0u8; 32],
            payload_cbor: &[],
        });
        // 13 + 1 + 4 + 8 + 8 + 16 + 1 + 32 + 32
        assert_eq!(out.len(), 13 + 1 + 4 + 8 + 8 + 16 + 1 + 32 + 32);
        // marker byte for None machine_id is 0
        let offset_after_nonce = 13 + 1 + 4 + 8 + 8 + 16;
        assert_eq!(out[offset_after_nonce], 0);
    }
}
