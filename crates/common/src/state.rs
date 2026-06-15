//! Machine identity and per-realm registration state.
//!
//! Global identity (Ed25519 + X25519 keys) is stored in `{state_dir}/machinekey.json`.
//! Per-realm registration is stored in `{state_dir}/registrations/{realm}.json`.
//!
//! This allows one machine to register with multiple NSD realms independently,
//! sharing the same keypair but with separate registration tokens.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Shared capability token for Envoy public edge config delivery.
pub const CAPABILITY_GATEWAY_PUBLIC_EDGE_V1: &str = "gateway_public_edge.v1";

/// Shared capability token for NSC route-capture config delivery.
pub const CAPABILITY_CAPTURE_ROUTES_V1: &str = "capture_routes.v1";

/// Public edge HTTP route snapshot scope token.
pub const PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_CONFIG: &str = "gateway_http_config.v1";

/// Public edge TCP/UDP listener-map snapshot scope token.
pub const PUBLIC_EDGE_SCOPE_GATEWAY_L4_MAP: &str = "gateway_l4_map.v1";

#[derive(Debug, Error)]
pub enum StateError {
    #[error("I/O error reading/writing state file: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid key material: {0}")]
    Key(String),
    #[error("invalid endpoint: {0}")]
    Endpoint(String),
    #[error("invalid realm name: {0}")]
    Realm(String),
}

// ── NSD discovery types ───────────────────────────────────────────────────────

/// Deployment type of an NSD instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NsdType {
    Cloud,
    #[serde(rename = "selfhosted")]
    SelfHosted,
}

/// Authentication method supported by an NSD instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    AuthKey,
    OAuth2,
    DeviceFlow,
}

/// Envelope-signed rotatable transport keyset advertised by `info.get`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsdTransportKeyset {
    /// Keyset wire version. Current version is 1.
    #[serde(default = "default_transport_keyset_version")]
    pub version: u8,
    /// Active Noise X25519 responder public key (64-char lowercase hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_noise_pubkey: Option<String>,
    /// Active QUIC certificate SHA-256 fingerprint (64-char lowercase hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_quic_cert_sha256: Option<String>,
}

fn default_transport_keyset_version() -> u8 {
    1
}

/// NSD discovery info returned by `GET /api/v1/info` or signed `info.get`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsdInfo {
    #[serde(rename = "type")]
    pub nsd_type: NsdType,
    pub realm: String,
    pub auth_methods: Vec<AuthMethod>,
    pub provider: String,
    pub version: String,
    /// Static X25519 public key for Noise IK (64-char hex).  Advertised by
    /// NSD when the Noise transport is enabled; used by NSN to pre-seed the
    /// Noise responder identity without an out-of-band provisioning step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsd_noise_pubkey: Option<String>,
    /// SHA-256 fingerprint of the QUIC TLS certificate (64-char hex).
    /// Advertised by NSD when the QUIC transport is enabled; used by NSN to
    /// pin the expected cert without a CA chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsd_quic_pubkey: Option<String>,
    /// Envelope-signed active transport keyset. In anti-DPI mode clients prefer
    /// this field over the legacy single-key fields after signed `info.get`
    /// verification, then rebuild the transport if the active key differs from
    /// the static first-transport bootstrap key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_transport_keyset: Option<NsdTransportKeyset>,
    /// Ed25519 envelope-signing public key (64-char lowercase hex).
    /// Advertised by NSD so clients can pin response envelope authenticity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsd_envelope_pubkey: Option<String>,
    /// Envelope wire-format versions the server accepts for the
    /// `POST /api/v1/control` signed-envelope path.  `[1]` means the envelope
    /// dispatcher is live; absent / empty means legacy JSON endpoints only.
    /// Clients use this to decide whether to call the envelope code path or
    /// fall back to reqwest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub envelope_versions: Vec<u8>,
    /// NSD-advertised capability tokens.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Public ingress route scopes the NSD can deliver.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_ingress_scopes: Vec<String>,
}

#[cfg(test)]
mod nsd_info_tests {
    use super::*;

    #[test]
    fn nsd_info_accepts_legacy_payload_without_public_ingress_fields() {
        let decoded: NsdInfo = serde_json::from_str(
            r#"{
                "type":"selfhosted",
                "realm":"default",
                "auth_methods":["auth_key"],
                "provider":"nsd-test",
                "version":"v1"
            }"#,
        )
        .unwrap();

        assert!(decoded.capabilities.is_empty());
        assert!(decoded.public_ingress_scopes.is_empty());
    }

    #[test]
    fn nsd_info_public_ingress_capabilities_round_trip() {
        let info = NsdInfo {
            nsd_type: NsdType::SelfHosted,
            realm: "default".into(),
            auth_methods: vec![AuthMethod::AuthKey],
            provider: "nsd-test".into(),
            version: "v1".into(),
            nsd_noise_pubkey: None,
            nsd_quic_pubkey: None,
            signed_transport_keyset: None,
            nsd_envelope_pubkey: None,
            envelope_versions: vec![1],
            capabilities: vec![CAPABILITY_GATEWAY_PUBLIC_EDGE_V1.into()],
            public_ingress_scopes: vec![
                PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_CONFIG.into(),
                PUBLIC_EDGE_SCOPE_GATEWAY_L4_MAP.into(),
            ],
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"capabilities\":[\"gateway_public_edge.v1\"]"));
        assert!(json.contains(
            "\"public_ingress_scopes\":[\"gateway_http_config.v1\",\"gateway_l4_map.v1\"]"
        ));
        let decoded: NsdInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(
            decoded.capabilities,
            vec![CAPABILITY_GATEWAY_PUBLIC_EDGE_V1]
        );
        assert_eq!(
            decoded.public_ingress_scopes,
            vec![
                PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_CONFIG,
                PUBLIC_EDGE_SCOPE_GATEWAY_L4_MAP
            ]
        );
    }
}

// ── Global machine identity (Ed25519 + X25519 keys) ───────────────────────────

/// Global machine identity: Ed25519 signing key + X25519 peer key.
/// Stored once in `{state_dir}/machinekey.json`; never changes.
pub struct MachineIdentity {
    pub machine_key_pub: [u8; 32],
    #[allow(dead_code)]
    signing_key: SigningKey,
    #[allow(dead_code)]
    peer_key_priv: SecretBox<[u8; 32]>,
    pub peer_key_pub: [u8; 32],
}

/// Per-realm registration state.
/// Stored in `{state_dir}/registrations/{realm}.json`.
#[derive(Debug, Clone)]
pub struct RealmRegistration {
    pub realm: String,
    pub machine_id: Option<String>,
    pub registered: bool,
    pub server_peer_pub: Option<[u8; 32]>,
    pub server_endpoint: Option<SocketAddr>,
}

// ── on-disk JSON representations ──────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    signing_key_hex: String,
    machine_key_pub_hex: String,
    peer_key_priv_hex: String,
    peer_key_pub_hex: String,
}

#[derive(Serialize, Deserialize, Default)]
struct RegistrationFile {
    machine_id: Option<String>,
    registered: bool,
    server_peer_pub_hex: Option<String>,
    server_endpoint: Option<String>,
    domain_base: Option<String>,
}

// ── MachineState ──────────────────────────────────────────────────────────────

/// Combined machine identity + per-realm registration state.
///
/// Identity (keypair) is global and never changes.
/// Registration (machine_id, server keys) is per-realm.
pub struct MachineState {
    // Identity (global)
    signing_key: SigningKey,
    pub machine_key_pub: [u8; 32],
    peer_key_priv: SecretBox<[u8; 32]>,
    pub peer_key_pub: [u8; 32],
    // Registration (per-realm)
    /// The realm this registration belongs to.  Defaults to `"default"`.
    pub realm: String,
    pub machine_id: Option<String>,
    pub registered: bool,
    pub server_peer_pub: Option<[u8; 32]>,
    pub server_endpoint: Option<SocketAddr>,
    /// Auto-assigned domain namespace returned by NSD on registration.
    /// Format: `"{machine_id}.n.ns"`.
    pub domain_base: Option<String>,
}

impl Clone for MachineState {
    fn clone(&self) -> Self {
        Self {
            signing_key: self.signing_key.clone(),
            machine_key_pub: self.machine_key_pub,
            peer_key_priv: SecretBox::new(Box::new(self.peer_key_priv_bytes())),
            peer_key_pub: self.peer_key_pub,
            realm: self.realm.clone(),
            machine_id: self.machine_id.clone(),
            registered: self.registered,
            server_peer_pub: self.server_peer_pub,
            server_endpoint: self.server_endpoint,
            domain_base: self.domain_base.clone(),
        }
    }
}

impl MachineState {
    /// Load state from `{state_dir}`, using the `"default"` realm.
    ///
    /// Loads or generates identity from `machinekey.json`, then loads or
    /// creates the `"default"` realm registration.
    pub async fn load_or_create(state_dir: &Path) -> Result<Self, StateError> {
        Self::load_or_create_for_realm(state_dir, "default").await
    }

    /// Load state from `{state_dir}` for the given realm.
    ///
    /// Loads or generates identity from `machinekey.json`, then loads or
    /// creates the per-realm registration from `registrations/{realm}.json`.
    pub async fn load_or_create_for_realm(
        state_dir: &Path,
        realm: &str,
    ) -> Result<Self, StateError> {
        validate_realm_name(realm)?;
        tokio::fs::create_dir_all(state_dir).await?;

        // Load or generate global identity.
        let identity_path = identity_file_path(state_dir);
        let (signing_key, machine_key_pub, peer_key_priv_bytes, peer_key_pub) =
            if identity_path.exists() {
                load_identity(&identity_path).await?
            } else {
                let id = generate_identity();
                save_identity_to_path(&identity_path, &id).await?;
                id
            };

        // Load or create per-realm registration.
        let reg_path = registration_file_path(state_dir, realm);
        if let Some(parent) = reg_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let reg = if reg_path.exists() {
            load_registration(&reg_path).await?
        } else {
            RegistrationFile::default()
        };

        let server_peer_pub = reg
            .server_peer_pub_hex
            .as_deref()
            .map(|h| -> Result<[u8; 32], StateError> {
                hex::decode(h)?
                    .try_into()
                    .map_err(|_| StateError::Key("server_peer_pub must be 32 bytes".to_string()))
            })
            .transpose()?;

        let server_endpoint = reg
            .server_endpoint
            .as_deref()
            .map(|s| {
                s.parse::<SocketAddr>()
                    .map_err(|e| StateError::Endpoint(e.to_string()))
            })
            .transpose()?;

        Ok(Self {
            signing_key,
            machine_key_pub,
            peer_key_priv: SecretBox::new(Box::new(peer_key_priv_bytes)),
            peer_key_pub,
            realm: realm.to_string(),
            machine_id: reg.machine_id,
            registered: reg.registered,
            server_peer_pub,
            server_endpoint,
            domain_base: reg.domain_base,
        })
    }

    /// Derive a `MachineState` deterministically from `auth_key` and `machine_id`.
    ///
    /// Keys are derived via SHA-512(`auth_key \0 machine_id`): the first 32 bytes
    /// seed the Ed25519 signing key and the second 32 bytes seed the X25519 peer key.
    /// Calling this with the same pair always produces identical key material, so no
    /// state file is needed — suitable for headless / config-file-free deployments.
    pub fn from_credentials(auth_key: &str, machine_id: &str) -> Self {
        let digest = Sha512::digest(format!("{auth_key}\0{machine_id}").as_bytes());
        let signing_seed: [u8; 32] = digest[..32].try_into().expect("sha512 is 64 bytes");
        let peer_seed: [u8; 32] = digest[32..].try_into().expect("sha512 is 64 bytes");

        let signing_key = SigningKey::from_bytes(&signing_seed);
        let machine_key_pub = signing_key.verifying_key().to_bytes();
        let peer_static = X25519Secret::from(peer_seed);
        let peer_key_pub = X25519Public::from(&peer_static).to_bytes();

        Self {
            machine_id: Some(machine_id.to_string()),
            signing_key,
            machine_key_pub,
            peer_key_priv: SecretBox::new(Box::new(peer_seed)),
            peer_key_pub,
            realm: "default".to_string(),
            registered: false,
            server_peer_pub: None,
            server_endpoint: None,
            domain_base: None,
        }
    }

    /// Persist identity to `{state_dir}/machinekey.json` and realm registration
    /// to `{state_dir}/registrations/{realm}.json`, both with 0600 permissions.
    pub async fn save(&self, state_dir: &Path) -> Result<(), StateError> {
        use secrecy::ExposeSecret;

        tokio::fs::create_dir_all(state_dir).await?;

        // Save global identity.
        let identity_path = identity_file_path(state_dir);
        if !identity_path.exists() {
            save_identity_to_path(
                &identity_path,
                &(
                    self.signing_key.clone(),
                    self.machine_key_pub,
                    *self.peer_key_priv.expose_secret(),
                    self.peer_key_pub,
                ),
            )
            .await?;
        }

        // Save per-realm registration.
        let reg_path = registration_file_path(state_dir, &self.realm);
        if let Some(parent) = reg_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let reg = RegistrationFile {
            machine_id: self.machine_id.clone(),
            registered: self.registered,
            server_peer_pub_hex: self.server_peer_pub.as_ref().map(hex::encode),
            server_endpoint: self.server_endpoint.map(|a| a.to_string()),
            domain_base: self.domain_base.clone(),
        };

        write_json_atomic(&reg_path, &reg).await?;
        Ok(())
    }

    /// Sign `message` with the Ed25519 signing key.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message).to_bytes()
    }

    /// Clone of the Ed25519 signing key.
    ///
    /// Hands the caller an independent `SigningKey` they can move into a
    /// longer-lived signer (e.g. `control::auth::EnvelopeSigner`) without
    /// borrowing this `MachineState`.  The key is still secret — callers
    /// must not log or persist the returned value.
    pub fn signing_key_clone(&self) -> SigningKey {
        self.signing_key.clone()
    }

    /// Whether this machine has been registered with the server.
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Raw bytes of the X25519 peer private key.
    pub fn peer_key_priv_bytes(&self) -> [u8; 32] {
        use secrecy::ExposeSecret;
        *self.peer_key_priv.expose_secret()
    }

    /// Mark the machine as registered and store server-provided data.
    pub fn set_registered(
        &mut self,
        machine_id: String,
        server_peer_pub_hex: &str,
        server_endpoint_str: &str,
        domain_base: Option<String>,
    ) -> Result<(), StateError> {
        let pub_bytes: [u8; 32] = hex::decode(server_peer_pub_hex)?
            .try_into()
            .map_err(|_| StateError::Key("server_peer_pub must be 32 bytes".to_string()))?;
        let endpoint: SocketAddr = server_endpoint_str
            .parse()
            .map_err(|e: std::net::AddrParseError| StateError::Endpoint(e.to_string()))?;

        self.machine_id = Some(machine_id);
        self.server_peer_pub = Some(pub_bytes);
        self.server_endpoint = Some(endpoint);
        self.domain_base = domain_base;
        self.registered = true;
        Ok(())
    }
}

// ── File path helpers ─────────────────────────────────────────────────────────

fn identity_file_path(state_dir: &Path) -> PathBuf {
    state_dir.join("machinekey.json")
}

fn registration_file_path(state_dir: &Path, realm: &str) -> PathBuf {
    state_dir
        .join("registrations")
        .join(format!("{realm}.json"))
}

/// Validate that a realm name is safe to use as a file name component.
/// Allows alphanumeric characters, dots, hyphens, and underscores.
fn validate_realm_name(realm: &str) -> Result<(), StateError> {
    if realm.is_empty() {
        return Err(StateError::Realm(
            "realm name must not be empty".to_string(),
        ));
    }
    if realm
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        Ok(())
    } else {
        Err(StateError::Realm(format!(
            "realm name {realm:?} contains invalid characters (allowed: alphanumeric, '.', '-', '_')"
        )))
    }
}

// ── Identity helpers ──────────────────────────────────────────────────────────

type IdentityTuple = (SigningKey, [u8; 32], [u8; 32], [u8; 32]);

fn generate_identity() -> IdentityTuple {
    let signing_key = SigningKey::generate(&mut OsRng);
    let machine_key_pub = signing_key.verifying_key().to_bytes();

    let peer_priv_bytes: [u8; 32] = {
        let mut buf = [0u8; 32];
        use rand_core::RngCore;
        OsRng.fill_bytes(&mut buf);
        buf
    };
    let peer_static = X25519Secret::from(peer_priv_bytes);
    let peer_key_pub = X25519Public::from(&peer_static).to_bytes();

    (signing_key, machine_key_pub, peer_priv_bytes, peer_key_pub)
}

async fn load_identity(path: &Path) -> Result<IdentityTuple, StateError> {
    let text = tokio::fs::read_to_string(path).await?;
    let f: IdentityFile = serde_json::from_str(&text)?;

    let signing_bytes: [u8; 32] = hex::decode(&f.signing_key_hex)?
        .try_into()
        .map_err(|_| StateError::Key("signing key must be 32 bytes".to_string()))?;
    let signing_key = SigningKey::from_bytes(&signing_bytes);

    let machine_key_pub: [u8; 32] = hex::decode(&f.machine_key_pub_hex)?
        .try_into()
        .map_err(|_| StateError::Key("machine_key_pub must be 32 bytes".to_string()))?;
    // Verify key consistency.
    if signing_key.verifying_key().to_bytes() != machine_key_pub {
        return Err(StateError::Key(
            "machine_key_pub does not match signing key".to_string(),
        ));
    }

    let peer_priv_bytes: [u8; 32] = hex::decode(&f.peer_key_priv_hex)?
        .try_into()
        .map_err(|_| StateError::Key("peer_key_priv must be 32 bytes".to_string()))?;
    let peer_key_pub: [u8; 32] = hex::decode(&f.peer_key_pub_hex)?
        .try_into()
        .map_err(|_| StateError::Key("peer_key_pub must be 32 bytes".to_string()))?;

    Ok((signing_key, machine_key_pub, peer_priv_bytes, peer_key_pub))
}

async fn save_identity_to_path(
    path: &Path,
    (signing_key, machine_key_pub, peer_priv_bytes, peer_key_pub): &IdentityTuple,
) -> Result<(), StateError> {
    let f = IdentityFile {
        signing_key_hex: hex::encode(signing_key.to_bytes()),
        machine_key_pub_hex: hex::encode(machine_key_pub),
        peer_key_priv_hex: hex::encode(peer_priv_bytes),
        peer_key_pub_hex: hex::encode(peer_key_pub),
    };
    write_json_atomic(path, &f).await
}

async fn load_registration(path: &Path) -> Result<RegistrationFile, StateError> {
    let text = tokio::fs::read_to_string(path).await?;
    Ok(serde_json::from_str(&text)?)
}

async fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), StateError> {
    let json = serde_json::to_vec_pretty(value)?;
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, &json).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp, perms)?;
    }

    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

// ── Verifying key helper (used by tests) ──────────────────────────────────────

#[cfg(test)]
impl MachineState {
    /// Ed25519 verifying key, for use in tests that need to verify signatures.
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[tokio::test]
    async fn generate_and_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let state1 = MachineState::load_or_create(dir.path()).await.unwrap();
        assert!(!state1.is_registered());

        let state2 = MachineState::load_or_create(dir.path()).await.unwrap();
        assert_eq!(state1.machine_key_pub, state2.machine_key_pub);
        assert_eq!(state1.peer_key_pub, state2.peer_key_pub);
        assert_eq!(state1.peer_key_priv_bytes(), state2.peer_key_priv_bytes());
    }

    #[tokio::test]
    async fn sign_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let state = MachineState::load_or_create(dir.path()).await.unwrap();

        let msg = b"machine-id:1234567890";
        let sig_bytes = state.sign(msg);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        state.verifying_key().verify(msg, &sig).unwrap();
    }

    #[tokio::test]
    async fn set_registered_persists() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = MachineState::load_or_create(dir.path()).await.unwrap();
        let server_pub = hex::encode([42u8; 32]);
        state
            .set_registered(
                "mid-001".to_string(),
                &server_pub,
                "127.0.0.1:51820",
                Some("mid-001.n.ns".to_string()),
            )
            .unwrap();
        state.save(dir.path()).await.unwrap();

        let loaded = MachineState::load_or_create(dir.path()).await.unwrap();
        assert!(loaded.is_registered());
        assert_eq!(loaded.machine_id.as_deref(), Some("mid-001"));
        assert_eq!(loaded.server_peer_pub, Some([42u8; 32]));
        assert_eq!(loaded.domain_base.as_deref(), Some("mid-001.n.ns"));
    }

    #[tokio::test]
    async fn realm_registrations_are_independent() {
        let dir = tempfile::tempdir().unwrap();

        // Generate identity once.
        let mut cloud = MachineState::load_or_create_for_realm(dir.path(), "nsio.cloud")
            .await
            .unwrap();
        let selfhosted = MachineState::load_or_create_for_realm(dir.path(), "company.internal")
            .await
            .unwrap();

        // Both share the same keypair.
        assert_eq!(cloud.machine_key_pub, selfhosted.machine_key_pub);
        assert_eq!(cloud.peer_key_pub, selfhosted.peer_key_pub);

        // Register cloud realm only.
        let server_pub = hex::encode([1u8; 32]);
        cloud
            .set_registered(
                "cloud-mid".to_string(),
                &server_pub,
                "1.2.3.4:51820",
                Some("cloud-mid.n.ns".to_string()),
            )
            .unwrap();
        cloud.save(dir.path()).await.unwrap();

        // Reload: cloud is registered, selfhosted is not.
        let cloud2 = MachineState::load_or_create_for_realm(dir.path(), "nsio.cloud")
            .await
            .unwrap();
        assert!(cloud2.is_registered());
        assert_eq!(cloud2.machine_id.as_deref(), Some("cloud-mid"));

        selfhosted.save(dir.path()).await.unwrap();
        let sh2 = MachineState::load_or_create_for_realm(dir.path(), "company.internal")
            .await
            .unwrap();
        assert!(!sh2.is_registered());
        assert_eq!(sh2.machine_id, None);
    }

    #[tokio::test]
    async fn identity_file_is_shared_across_realms() {
        let dir = tempfile::tempdir().unwrap();
        let a = MachineState::load_or_create_for_realm(dir.path(), "realm-a")
            .await
            .unwrap();
        let b = MachineState::load_or_create_for_realm(dir.path(), "realm-b")
            .await
            .unwrap();
        assert_eq!(a.machine_key_pub, b.machine_key_pub);
        assert_eq!(a.peer_key_pub, b.peer_key_pub);
    }

    #[test]
    fn validate_realm_name_accepts_valid() {
        assert!(validate_realm_name("nsio.cloud").is_ok());
        assert!(validate_realm_name("company.internal").is_ok());
        assert!(validate_realm_name("homelab_local").is_ok());
        assert!(validate_realm_name("default").is_ok());
    }

    #[test]
    fn validate_realm_name_rejects_invalid() {
        assert!(validate_realm_name("").is_err());
        assert!(validate_realm_name("bad/path").is_err());
        assert!(validate_realm_name("../../etc").is_err());
    }

    #[test]
    fn identity_path_is_machinekey_json() {
        let path = identity_file_path(Path::new("/var/lib/nsio"));
        assert_eq!(path, PathBuf::from("/var/lib/nsio/machinekey.json"));
    }

    #[test]
    fn registration_path_uses_realm() {
        let path = registration_file_path(Path::new("/var/lib/nsio"), "nsio.cloud");
        assert_eq!(
            path,
            PathBuf::from("/var/lib/nsio/registrations/nsio.cloud.json")
        );
    }
}
