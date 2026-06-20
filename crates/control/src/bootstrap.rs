#![forbid(unsafe_code)]

//! Shared control-transport bootstrap orchestration.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use common::{AuthMethod, NsdInfo, NsdType};

use crate::Error;
use crate::auth::{NsdEnvelopeTrustConfig, discover_via_envelope, to_endpoint};
use crate::transport::{ControlTransport, builder::build_transport};

pub struct BootstrapControlConfig {
    pub mode: String,
    pub nsd_id: String,
    pub url: String,
    pub realm: String,
    pub state_dir: PathBuf,
    pub nsd_envelope_key_pins: Vec<String>,
    pub noise_bootstrap_pubkey: Option<String>,
    pub quic_bootstrap_cert_sha256: Option<String>,
}

pub struct BootstrapControlFallbackOutcome {
    pub info: NsdInfo,
    pub transport: Arc<dyn ControlTransport>,
    pub endpoint_url: String,
}

pub async fn bootstrap_control_transport<F>(
    cfg: BootstrapControlConfig,
    machine_key_pub: [u8; 32],
    peer_key_priv: [u8; 32],
    sign: F,
) -> Result<(NsdInfo, Arc<dyn ControlTransport>), Error>
where
    F: FnOnce(&[u8]) -> [u8; 64],
{
    if cfg.nsd_envelope_key_pins.is_empty() {
        return Err(Error::Auth(format!(
            "{} requires nsd_envelope_key_pins for control bootstrap",
            cfg.nsd_id
        )));
    }

    let bootstrap_info = bootstrap_nsd_info(&cfg)?;
    let first_transport = build_required_transport(
        &cfg.mode,
        &cfg.url,
        &bootstrap_info,
        peer_key_priv,
        "bootstrap",
    )?;

    let trust = NsdEnvelopeTrustConfig::new(
        cfg.nsd_id.clone(),
        cfg.realm.clone(),
        cfg.state_dir.clone(),
        &cfg.url,
        cfg.nsd_envelope_key_pins.clone(),
        None,
    );
    let endpoint = to_endpoint(&cfg.url);
    let info = discover_via_envelope(
        first_transport.as_ref(),
        &endpoint,
        &trust,
        machine_key_pub,
        sign,
    )
    .await?
    .info;

    if !info.envelope_versions.contains(&1) {
        return Err(Error::Auth(format!(
            "signed info.get for {} did not advertise envelope v1",
            cfg.nsd_id
        )));
    }

    let signed_transport =
        build_required_transport(&cfg.mode, &cfg.url, &info, peer_key_priv, "signed keyset")?;
    Ok((info, signed_transport))
}

pub async fn bootstrap_control_transport_fallback<F>(
    endpoints: Vec<BootstrapControlConfig>,
    endpoint_attempt_timeout: Duration,
    machine_key_pub: [u8; 32],
    peer_key_priv: [u8; 32],
    mut sign: F,
) -> Result<BootstrapControlFallbackOutcome, Error>
where
    F: FnMut(&[u8]) -> [u8; 64],
{
    if endpoints.is_empty() {
        return Err(Error::Connect(
            "no control bootstrap endpoints configured".to_string(),
        ));
    }

    let mut failures = Vec::new();
    for cfg in endpoints {
        let nsd_id = cfg.nsd_id.clone();
        let url = cfg.url.clone();
        let attempt = bootstrap_control_transport(cfg, machine_key_pub, peer_key_priv, |message| {
            sign(message)
        });
        match tokio::time::timeout(endpoint_attempt_timeout, attempt).await {
            Ok(Ok((info, transport))) => {
                return Ok(BootstrapControlFallbackOutcome {
                    info,
                    transport,
                    endpoint_url: url,
                });
            }
            Ok(Err(e)) => failures.push(format!("{nsd_id} ({url}): {e}")),
            Err(_) => failures.push(format!(
                "{nsd_id} ({url}): timed out after {}s",
                endpoint_attempt_timeout.as_secs()
            )),
        }
    }

    Err(Error::Connect(format!(
        "all control bootstrap endpoints failed: {}",
        failures.join("; ")
    )))
}

fn bootstrap_nsd_info(cfg: &BootstrapControlConfig) -> Result<NsdInfo, Error> {
    let mut info = default_nsd_info(&cfg.realm);
    info.envelope_versions = vec![1];
    match cfg.mode.as_str() {
        "noise" => {
            info.nsd_noise_pubkey = Some(required_bootstrap_key(
                cfg.noise_bootstrap_pubkey.as_deref(),
                &cfg.nsd_id,
                "noise",
            )?);
        }
        "quic" => {
            info.nsd_quic_pubkey = Some(required_bootstrap_key(
                cfg.quic_bootstrap_cert_sha256
                    .as_deref()
                    .or(cfg.noise_bootstrap_pubkey.as_deref()),
                &cfg.nsd_id,
                "quic",
            )?);
        }
        _ => {}
    }
    Ok(info)
}

fn required_bootstrap_key(
    value: Option<&str>,
    nsd_id: &str,
    mode: &'static str,
) -> Result<String, Error> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            Error::Connect(format!(
                "{nsd_id} requires static {mode} bootstrap key material for tunnel-first control bootstrap"
            ))
        })
}

fn default_nsd_info(realm: &str) -> NsdInfo {
    NsdInfo {
        nsd_type: NsdType::SelfHosted,
        realm: realm.to_string(),
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
    }
}

fn build_required_transport(
    mode: &str,
    url: &str,
    info: &NsdInfo,
    peer_key_priv: [u8; 32],
    stage: &'static str,
) -> Result<Arc<dyn ControlTransport>, Error> {
    build_transport(mode, url, info, peer_key_priv)?.ok_or_else(|| {
        Error::Connect(format!(
            "{mode} {stage} did not produce a control transport"
        ))
    })
}

#[cfg(test)]
mod tests {
    use common::envelope_pins::ed25519_pubkey_to_okp_thumbprint;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;
    use crate::api::{InfoGetResponse, to_cbor};
    use crate::envelope::{self, ControlEnvelope};

    enum InfoServerMode {
        Ok,
        CorruptSignature,
        BadEnvelopeVersion,
        ReplayRejected,
    }

    struct InfoServer {
        url: String,
        request: oneshot::Receiver<ControlEnvelope>,
        task: tokio::task::JoinHandle<()>,
    }

    struct StallingInfoServer {
        url: String,
        task: tokio::task::JoinHandle<()>,
    }

    fn cfg_for(mode: &str, url: String, pins: Vec<String>) -> BootstrapControlConfig {
        BootstrapControlConfig {
            mode: mode.to_string(),
            nsd_id: "nsd-1".to_string(),
            url,
            realm: "default".to_string(),
            state_dir: std::env::temp_dir(),
            nsd_envelope_key_pins: pins,
            noise_bootstrap_pubkey: None,
            quic_bootstrap_cert_sha256: None,
        }
    }

    fn v1_info() -> NsdInfo {
        let mut info = default_nsd_info("default");
        info.envelope_versions = vec![1];
        info
    }

    fn envelope_pin_for_key(key: &SigningKey) -> String {
        ed25519_pubkey_to_okp_thumbprint(&key.verifying_key().to_bytes()).unwrap()
    }

    async fn spawn_info_server(
        info: NsdInfo,
        nsd_key: SigningKey,
        mode: InfoServerMode,
    ) -> InfoServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req_body = read_http_request_body(&mut stream).await;
            let req_env = ControlEnvelope::from_cbor(&req_body).unwrap();
            let _ = request_tx.send(req_env.clone());

            if matches!(mode, InfoServerMode::ReplayRejected) {
                write_http_response(&mut stream, 409, &[]).await;
                return;
            }

            let payload = to_cbor(&InfoGetResponse { info }).unwrap();
            let nsd_key_pub = nsd_key.verifying_key().to_bytes();
            let mut resp = ControlEnvelope::sign_response(
                req_env.api,
                req_env.machine_id,
                nsd_key_pub,
                payload,
                |message| nsd_key.sign(message).to_bytes(),
            )
            .unwrap();
            match mode {
                InfoServerMode::Ok | InfoServerMode::ReplayRejected => {}
                InfoServerMode::CorruptSignature => {
                    resp.signature[0] ^= 0x01;
                }
                InfoServerMode::BadEnvelopeVersion => {
                    resp.v = envelope::ENVELOPE_VERSION + 1;
                }
            }
            let resp_body = resp.to_cbor().unwrap();
            write_http_response(&mut stream, 200, &resp_body).await;
        });
        InfoServer {
            url: format!("http://{addr}"),
            request: request_rx,
            task,
        }
    }

    async fn spawn_stalling_info_server() -> StallingInfoServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        StallingInfoServer {
            url: format!("http://{addr}"),
            task,
        }
    }

    async fn read_http_request_body<S>(stream: &mut S) -> Vec<u8>
    where
        S: AsyncRead + Unpin,
    {
        let mut hdrs = Vec::new();
        let mut b = [0u8; 1];
        loop {
            stream.read_exact(&mut b).await.unwrap();
            hdrs.push(b[0]);
            if hdrs.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let hdr_str = std::str::from_utf8(&hdrs).unwrap();
        let body_len: usize = hdr_str
            .lines()
            .filter_map(|line| line.strip_prefix("Content-Length: "))
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body).await.unwrap();
        body
    }

    async fn write_http_response<S>(stream: &mut S, status: u16, body: &[u8])
    where
        S: AsyncWrite + Unpin,
    {
        let reason = match status {
            200 => "OK",
            409 => "Conflict",
            _ => "Error",
        };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.flush().await.unwrap();
    }

    fn machine_key() -> (SigningKey, [u8; 32]) {
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key().to_bytes();
        (key, pubkey)
    }

    fn expect_bootstrap_err(result: Result<(NsdInfo, Arc<dyn ControlTransport>), Error>) -> Error {
        match result {
            Ok((_info, transport)) => {
                panic!(
                    "expected bootstrap error, got {} transport",
                    transport.name()
                )
            }
            Err(err) => err,
        }
    }

    #[tokio::test]
    async fn sse_bootstrap_sends_identity_agnostic_signed_info_get() {
        let nsd_key = SigningKey::generate(&mut OsRng);
        let pin = envelope_pin_for_key(&nsd_key);
        let server = spawn_info_server(v1_info(), nsd_key, InfoServerMode::Ok).await;
        let (machine_key, machine_pubkey) = machine_key();

        let (info, transport) = bootstrap_control_transport(
            cfg_for("sse", server.url, vec![pin]),
            machine_pubkey,
            [7u8; 32],
            |message| machine_key.sign(message).to_bytes(),
        )
        .await
        .unwrap();

        let request = server.request.await.unwrap();
        server.task.await.unwrap();
        assert_eq!(info.realm, "default");
        assert_eq!(transport.name(), "sse");
        assert_eq!(request.api, envelope::api::INFO_GET);
        assert_eq!(request.machine_id, None);
        assert_eq!(request.machine_key_pub, machine_pubkey);
        assert_eq!(request.v, envelope::ENVELOPE_VERSION);
    }

    #[tokio::test]
    async fn bootstrap_fallback_uses_first_success_in_order() {
        let nsd_key = SigningKey::generate(&mut OsRng);
        let pin = envelope_pin_for_key(&nsd_key);
        let server = spawn_info_server(v1_info(), nsd_key, InfoServerMode::Ok).await;
        let (machine_key, machine_pubkey) = machine_key();
        let mut first = cfg_for("sse", "http://127.0.0.1:9".to_string(), Vec::new());
        first.nsd_id = "primary".to_string();
        let mut second = cfg_for("sse", server.url, vec![pin]);
        second.nsd_id = "secondary".to_string();
        let expected_endpoint_url = second.url.clone();

        let outcome = bootstrap_control_transport_fallback(
            vec![first, second],
            std::time::Duration::from_secs(1),
            machine_pubkey,
            [7u8; 32],
            |message| machine_key.sign(message).to_bytes(),
        )
        .await
        .unwrap();

        let request = server.request.await.unwrap();
        server.task.await.unwrap();
        assert_eq!(outcome.info.realm, "default");
        assert_eq!(outcome.transport.name(), "sse");
        assert_eq!(outcome.endpoint_url, expected_endpoint_url);
        assert_eq!(request.api, envelope::api::INFO_GET);
    }

    #[tokio::test]
    async fn bootstrap_fallback_all_failures_are_aggregated() {
        let (_, machine_pubkey) = machine_key();
        let mut first = cfg_for("sse", "http://127.0.0.1:9".to_string(), Vec::new());
        first.nsd_id = "primary".to_string();
        let mut second = cfg_for("noise", "noise://127.0.0.1:4001".to_string(), Vec::new());
        second.nsd_id = "secondary".to_string();

        let err = match bootstrap_control_transport_fallback(
            vec![first, second],
            std::time::Duration::from_secs(1),
            machine_pubkey,
            [7u8; 32],
            |_| [0u8; 64],
        )
        .await
        {
            Ok(outcome) => {
                panic!(
                    "all endpoints should fail, got {} transport",
                    outcome.transport.name()
                )
            }
            Err(err) => err,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("primary"));
        assert!(rendered.contains("secondary"));
        assert!(rendered.contains("all control bootstrap endpoints failed"));
    }

    #[tokio::test]
    async fn bootstrap_fallback_timeout_advances_to_next_endpoint() {
        let stalled = spawn_stalling_info_server().await;
        let nsd_key = SigningKey::generate(&mut OsRng);
        let pin = envelope_pin_for_key(&nsd_key);
        let server = spawn_info_server(v1_info(), nsd_key, InfoServerMode::Ok).await;
        let (machine_key, machine_pubkey) = machine_key();
        let mut first = cfg_for("sse", stalled.url, vec![pin.clone()]);
        first.nsd_id = "primary".to_string();
        let mut second = cfg_for("sse", server.url, vec![pin]);
        second.nsd_id = "secondary".to_string();
        let expected_endpoint_url = second.url.clone();

        let outcome = bootstrap_control_transport_fallback(
            vec![first, second],
            std::time::Duration::from_millis(50),
            machine_pubkey,
            [7u8; 32],
            |message| machine_key.sign(message).to_bytes(),
        )
        .await
        .unwrap();

        let _ = server.request.await.unwrap();
        server.task.await.unwrap();
        stalled.task.abort();
        let _ = stalled.task.await;
        assert_eq!(outcome.transport.name(), "sse");
        assert_eq!(outcome.endpoint_url, expected_endpoint_url);
    }

    #[tokio::test]
    async fn noise_missing_bootstrap_key_fails_closed() {
        let cfg = cfg_for(
            "noise",
            "noise://127.0.0.1:4001".to_string(),
            vec!["pin".into()],
        );
        let (_, machine_pubkey) = machine_key();

        let err = expect_bootstrap_err(
            bootstrap_control_transport(cfg, machine_pubkey, [7u8; 32], |_| [0u8; 64]).await,
        );

        assert!(matches!(err, Error::Connect(msg) if msg.contains("static noise bootstrap key")));
    }

    #[tokio::test]
    async fn noise_invalid_bootstrap_key_fails_closed() {
        let mut cfg = cfg_for(
            "noise",
            "noise://127.0.0.1:4001".to_string(),
            vec!["pin".into()],
        );
        cfg.noise_bootstrap_pubkey = Some("aa".repeat(16));
        let (_, machine_pubkey) = machine_key();

        let err = expect_bootstrap_err(
            bootstrap_control_transport(cfg, machine_pubkey, [7u8; 32], |_| [0u8; 64]).await,
        );

        assert!(matches!(
            err,
            Error::ControlTransportBuild { mode: "noise", reason } if reason.contains("32 bytes")
        ));
    }

    #[tokio::test]
    async fn quic_missing_bootstrap_key_fails_closed() {
        let cfg = cfg_for(
            "quic",
            "quic://127.0.0.1:4002".to_string(),
            vec!["pin".into()],
        );
        let (_, machine_pubkey) = machine_key();

        let err = expect_bootstrap_err(
            bootstrap_control_transport(cfg, machine_pubkey, [7u8; 32], |_| [0u8; 64]).await,
        );

        assert!(matches!(err, Error::Connect(msg) if msg.contains("static quic bootstrap key")));
    }

    #[tokio::test]
    async fn quic_uses_noise_bootstrap_key_fallback() {
        let mut cfg = cfg_for(
            "quic",
            "quic://127.0.0.1:4002".to_string(),
            vec!["pin".into()],
        );
        cfg.noise_bootstrap_pubkey = Some("aa".repeat(16));
        let (_, machine_pubkey) = machine_key();

        let err = expect_bootstrap_err(
            bootstrap_control_transport(cfg, machine_pubkey, [7u8; 32], |_| [0u8; 64]).await,
        );

        assert!(matches!(
            err,
            Error::ControlTransportBuild { mode: "quic", reason } if reason.contains("32 bytes")
        ));
    }

    #[tokio::test]
    async fn missing_envelope_pins_fail_before_bootstrap_dial() {
        let mut cfg = cfg_for("noise", "noise://127.0.0.1:4001".to_string(), Vec::new());
        cfg.noise_bootstrap_pubkey = Some("aa".repeat(32));
        let (_, machine_pubkey) = machine_key();

        let err = expect_bootstrap_err(
            bootstrap_control_transport(cfg, machine_pubkey, [7u8; 32], |_| [0u8; 64]).await,
        );

        assert!(matches!(err, Error::Auth(msg) if msg.contains("nsd_envelope_key_pins")));
    }

    #[tokio::test]
    async fn signed_info_get_requires_advertised_envelope_v1() {
        let nsd_key = SigningKey::generate(&mut OsRng);
        let pin = envelope_pin_for_key(&nsd_key);
        let mut info = v1_info();
        info.envelope_versions.clear();
        let server = spawn_info_server(info, nsd_key, InfoServerMode::Ok).await;
        let (machine_key, machine_pubkey) = machine_key();

        let err = expect_bootstrap_err(
            bootstrap_control_transport(
                cfg_for("sse", server.url, vec![pin]),
                machine_pubkey,
                [7u8; 32],
                |message| machine_key.sign(message).to_bytes(),
            )
            .await,
        );

        let _ = server.request.await.unwrap();
        server.task.await.unwrap();
        assert!(matches!(err, Error::Auth(msg) if msg.contains("envelope v1")));
    }

    #[tokio::test]
    async fn signed_info_get_rejects_bad_response_signature() {
        let nsd_key = SigningKey::generate(&mut OsRng);
        let pin = envelope_pin_for_key(&nsd_key);
        let server = spawn_info_server(v1_info(), nsd_key, InfoServerMode::CorruptSignature).await;
        let (machine_key, machine_pubkey) = machine_key();

        let err = expect_bootstrap_err(
            bootstrap_control_transport(
                cfg_for("sse", server.url, vec![pin]),
                machine_pubkey,
                [7u8; 32],
                |message| machine_key.sign(message).to_bytes(),
            )
            .await,
        );

        let _ = server.request.await.unwrap();
        server.task.await.unwrap();
        assert!(matches!(
            err,
            Error::Envelope(envelope::Error::InvalidSignature)
        ));
    }

    #[tokio::test]
    async fn signed_info_get_rejects_bad_envelope_wire_version() {
        let nsd_key = SigningKey::generate(&mut OsRng);
        let pin = envelope_pin_for_key(&nsd_key);
        let server =
            spawn_info_server(v1_info(), nsd_key, InfoServerMode::BadEnvelopeVersion).await;
        let (machine_key, machine_pubkey) = machine_key();

        let err = expect_bootstrap_err(
            bootstrap_control_transport(
                cfg_for("sse", server.url, vec![pin]),
                machine_pubkey,
                [7u8; 32],
                |message| machine_key.sign(message).to_bytes(),
            )
            .await,
        );

        let _ = server.request.await.unwrap();
        server.task.await.unwrap();
        assert!(matches!(
            err,
            Error::Envelope(envelope::Error::InvalidVersion(version)) if version == envelope::ENVELOPE_VERSION + 1
        ));
    }

    #[tokio::test]
    async fn info_get_replay_rejection_propagates() {
        let nsd_key = SigningKey::generate(&mut OsRng);
        let pin = envelope_pin_for_key(&nsd_key);
        let server = spawn_info_server(v1_info(), nsd_key, InfoServerMode::ReplayRejected).await;
        let (machine_key, machine_pubkey) = machine_key();

        let err = expect_bootstrap_err(
            bootstrap_control_transport(
                cfg_for("sse", server.url, vec![pin]),
                machine_pubkey,
                [7u8; 32],
                |message| machine_key.sign(message).to_bytes(),
            )
            .await,
        );

        let _ = server.request.await.unwrap();
        server.task.await.unwrap();
        assert!(matches!(err, Error::Replay));
    }
}
