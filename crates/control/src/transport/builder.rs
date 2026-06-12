#![forbid(unsafe_code)]

//! Control-plane transport construction helpers.
//!
//! Callers (`nsn`, `nsc`) discover each NSD via [`crate::auth::discover_nsd_info`]
//! and then ask [`build_transport`] for a [`ControlTransport`] tailored to the
//! chosen `control_mode` and the advertised pubkey material.
//!
//! Returning `Ok(None)` means "this mode does not request a control transport."
//! Explicit `noise` and `quic` modes fail closed when required key material is
//! missing or invalid.

use std::sync::Arc;

use common::NsdInfo;

use crate::Error;
use crate::transport::{
    ControlTransport, noise::NoiseTransport, quic::QuicTransport, sse::SseTransport,
};

/// Build a [`ControlTransport`] for the given `control_mode` and NSD descriptor.
///
/// * `mode = "sse"` — wraps the control-center HTTP(S) endpoint in
///   [`crate::transport::sse::SseTransport`].
/// * `mode = "noise"` — requires `info.nsd_noise_pubkey`; pairs it with the
///   caller's X25519 private key (`peer_key_priv`) to form a Noise IK initiator.
/// * `mode = "quic"` — requires `info.nsd_quic_pubkey`; uses it as a SHA-256
///   certificate fingerprint for the pubkey-pinning verifier.
/// * unknown modes return `Ok(None)`: no envelope transport is requested.
///
/// The returned `Arc` is safe to clone and hand to both `AuthClient` and
/// `HeartbeatClient` without requiring separate connections.
pub fn build_transport(
    mode: &str,
    base_url: &str,
    info: &NsdInfo,
    peer_key_priv: [u8; 32],
) -> Result<Option<Arc<dyn ControlTransport>>, Error> {
    match mode {
        "sse" => {
            let t = SseTransport::from_base_url(base_url)?;
            Ok(Some(Arc::new(t)))
        }
        "noise" => {
            let hex_str = info
                .signed_transport_keyset
                .as_ref()
                .and_then(|keyset| keyset.active_noise_pubkey.as_deref())
                .or(info.nsd_noise_pubkey.as_deref())
                .ok_or_else(|| Error::ControlTransportBuild {
                    mode: "noise",
                    reason: "missing nsd_noise_pubkey".to_string(),
                })?;
            let remote_pub = decode_pubkey(hex_str, "nsd_noise_pubkey").map_err(|e| {
                Error::ControlTransportBuild {
                    mode: "noise",
                    reason: e.to_string(),
                }
            })?;
            let t = NoiseTransport::new(peer_key_priv, remote_pub);
            Ok(Some(Arc::new(t)))
        }
        "quic" => {
            let hex_str = info
                .signed_transport_keyset
                .as_ref()
                .and_then(|keyset| keyset.active_quic_cert_sha256.as_deref())
                .or(info.nsd_quic_pubkey.as_deref())
                .ok_or_else(|| Error::ControlTransportBuild {
                    mode: "quic",
                    reason: "missing nsd_quic_pubkey".to_string(),
                })?;
            let fingerprint = decode_pubkey(hex_str, "nsd_quic_pubkey").map_err(|e| {
                Error::ControlTransportBuild {
                    mode: "quic",
                    reason: e.to_string(),
                }
            })?;
            let t = QuicTransport::new(fingerprint).map_err(|e| Error::ControlTransportBuild {
                mode: "quic",
                reason: e.to_string(),
            })?;
            Ok(Some(Arc::new(t)))
        }
        _ => Ok(None),
    }
}

fn decode_pubkey(hex_str: &str, field: &'static str) -> Result<[u8; 32], Error> {
    let bytes =
        hex::decode(hex_str).map_err(|e| Error::Connect(format!("invalid {field} hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Connect(format!(
            "{field} must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{AuthMethod, NsdTransportKeyset, NsdType};

    fn base_info() -> NsdInfo {
        NsdInfo {
            nsd_type: NsdType::SelfHosted,
            realm: "r".into(),
            auth_methods: vec![AuthMethod::AuthKey],
            provider: "p".into(),
            version: "v".into(),
            nsd_noise_pubkey: None,
            nsd_quic_pubkey: None,
            signed_transport_keyset: None,
            nsd_envelope_pubkey: None,
            envelope_versions: Vec::new(),
            capabilities: Vec::new(),
            public_ingress_scopes: Vec::new(),
        }
    }

    #[test]
    fn sse_http_builds_transport() {
        let t = build_transport("sse", "http://nsd.test:3001", &base_info(), [0u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(t.name(), "sse");
    }

    #[test]
    fn sse_https_builds_transport() {
        let t = build_transport("sse", "https://nsd.test", &base_info(), [0u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(t.name(), "sse");
    }

    #[test]
    fn noise_without_pubkey_fails_closed() {
        match build_transport("noise", "http://nsd.test:3001", &base_info(), [0u8; 32]) {
            Err(Error::ControlTransportBuild { mode, reason }) => {
                assert_eq!(mode, "noise");
                assert!(reason.contains("missing nsd_noise_pubkey"));
            }
            Err(other) => panic!("expected noise transport build error, got {other:?}"),
            Ok(_) => panic!("expected error for missing noise pubkey"),
        }
    }

    #[test]
    fn noise_with_pubkey_builds() {
        let mut info = base_info();
        info.nsd_noise_pubkey = Some("aa".repeat(32));
        let t = build_transport("noise", "http://nsd.test:3001", &info, [1u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(t.name(), "noise");
    }

    #[test]
    fn signed_transport_keyset_overrides_legacy_noise_key() {
        let mut info = base_info();
        info.nsd_noise_pubkey = Some("aa".repeat(16));
        info.signed_transport_keyset = Some(NsdTransportKeyset {
            version: 1,
            active_noise_pubkey: Some("bb".repeat(32)),
            active_quic_cert_sha256: None,
        });
        let t = build_transport("noise", "http://nsd.test:3001", &info, [1u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(t.name(), "noise");
    }

    #[test]
    fn noise_with_short_pubkey_errors() {
        let mut info = base_info();
        info.nsd_noise_pubkey = Some("aa".repeat(16));
        match build_transport("noise", "http://nsd.test:3001", &info, [1u8; 32]) {
            Err(Error::ControlTransportBuild { mode, reason }) => {
                assert_eq!(mode, "noise");
                assert!(reason.contains("32 bytes"));
            }
            Err(other) => panic!("expected noise transport build error, got {other:?}"),
            Ok(_) => panic!("expected error for short pubkey"),
        }
    }

    #[test]
    fn quic_without_pubkey_fails_closed() {
        match build_transport("quic", "http://nsd.test:3001", &base_info(), [0u8; 32]) {
            Err(Error::ControlTransportBuild { mode, reason }) => {
                assert_eq!(mode, "quic");
                assert!(reason.contains("missing nsd_quic_pubkey"));
            }
            Err(other) => panic!("expected quic transport build error, got {other:?}"),
            Ok(_) => panic!("expected error for missing quic pubkey"),
        }
    }

    #[test]
    fn quic_with_short_pubkey_errors() {
        let mut info = base_info();
        info.nsd_quic_pubkey = Some("aa".repeat(16));
        match build_transport("quic", "http://nsd.test:3001", &info, [1u8; 32]) {
            Err(Error::ControlTransportBuild { mode, reason }) => {
                assert_eq!(mode, "quic");
                assert!(reason.contains("32 bytes"));
            }
            Err(other) => panic!("expected quic transport build error, got {other:?}"),
            Ok(_) => panic!("expected error for short pubkey"),
        }
    }
}
