use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwtPinError {
    #[error("I/O error reading/writing NSD JWT pin store: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid JWK: {0}")]
    InvalidJwk(String),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RsaJwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub key_use: Option<String>,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct JwkSet {
    pub keys: Vec<RsaJwk>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct NsdJwtPinStore {
    pub version: u8,
    pub entries: Vec<NsdJwtPinEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct NsdJwtPinEntry {
    pub realm: String,
    pub jwks_url: String,
    pub pins: Vec<String>,
    pub learned_at: u64,
    pub last_seen_at: u64,
}

impl Default for NsdJwtPinStore {
    fn default() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }
}

pub fn nsd_jwt_pin_store_path(state_dir: &Path) -> PathBuf {
    state_dir.join("trust").join("nsd_jwt_key_pins.json")
}

pub fn normalize_jwks_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

pub fn rsa_jwk_thumbprint(jwk: &RsaJwk) -> Result<String, JwtPinError> {
    validate_rsa_jwk(jwk)?;
    let e = serde_json::to_string(&jwk.e)?;
    let n = serde_json::to_string(&jwk.n)?;
    let canonical = format!("{{\"e\":{e},\"kty\":\"RSA\",\"n\":{n}}}");
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(base64_url_no_pad(&digest))
}

pub fn valid_rsa_jwk_thumbprints(jwks: &JwkSet) -> Vec<String> {
    jwks.keys
        .iter()
        .filter_map(|jwk| rsa_jwk_thumbprint(jwk).ok())
        .collect()
}

pub fn jwk_kid(jwk: &RsaJwk) -> Option<&str> {
    jwk.kid.as_deref().filter(|kid| !kid.is_empty())
}

pub fn validate_rsa_jwk(jwk: &RsaJwk) -> Result<(), JwtPinError> {
    if jwk.kty != "RSA" {
        return Err(JwtPinError::InvalidJwk("kty must be RSA".to_string()));
    }
    if jwk.alg.as_deref() != Some("RS256") {
        return Err(JwtPinError::InvalidJwk("alg must be RS256".to_string()));
    }
    if jwk_kid(jwk).is_none() {
        return Err(JwtPinError::InvalidJwk("kid must be non-empty".to_string()));
    }
    if jwk.n.is_empty() || jwk.e.is_empty() {
        return Err(JwtPinError::InvalidJwk("n/e must be non-empty".to_string()));
    }
    Ok(())
}

pub async fn load_tofu_pins(
    state_dir: &Path,
    realm: &str,
    jwks_url: &str,
) -> Result<Option<Vec<String>>, JwtPinError> {
    let path = nsd_jwt_pin_store_path(state_dir);
    if !path.exists() {
        return Ok(None);
    }
    let store = load_store(&path).await?;
    let jwks_url = normalize_jwks_url(jwks_url);
    Ok(store
        .entries
        .into_iter()
        .find(|entry| entry.realm == realm && normalize_jwks_url(&entry.jwks_url) == jwks_url)
        .map(|entry| entry.pins))
}

pub async fn persist_first_use_pins(
    state_dir: &Path,
    realm: &str,
    jwks_url: &str,
    pins: Vec<String>,
    now: u64,
) -> Result<(), JwtPinError> {
    let path = nsd_jwt_pin_store_path(state_dir);
    let mut store = if path.exists() {
        load_store(&path).await?
    } else {
        NsdJwtPinStore::default()
    };
    store.version = 1;
    let jwks_url = normalize_jwks_url(jwks_url);
    if let Some(entry) = store
        .entries
        .iter_mut()
        .find(|entry| entry.realm == realm && normalize_jwks_url(&entry.jwks_url) == jwks_url)
    {
        entry.last_seen_at = now;
    } else {
        store.entries.push(NsdJwtPinEntry {
            realm: realm.to_string(),
            jwks_url,
            pins,
            learned_at: now,
            last_seen_at: now,
        });
    }
    write_store_atomic(&path, &store).await
}

pub async fn touch_tofu_entry(
    state_dir: &Path,
    realm: &str,
    jwks_url: &str,
    now: u64,
) -> Result<(), JwtPinError> {
    let path = nsd_jwt_pin_store_path(state_dir);
    if !path.exists() {
        return Ok(());
    }
    let mut store = load_store(&path).await?;
    let jwks_url = normalize_jwks_url(jwks_url);
    if let Some(entry) = store
        .entries
        .iter_mut()
        .find(|entry| entry.realm == realm && normalize_jwks_url(&entry.jwks_url) == jwks_url)
    {
        entry.last_seen_at = now;
        write_store_atomic(&path, &store).await?;
    }
    Ok(())
}

async fn load_store(path: &Path) -> Result<NsdJwtPinStore, JwtPinError> {
    let text = tokio::fs::read_to_string(path).await?;
    let mut store: NsdJwtPinStore = serde_json::from_str(&text)?;
    store
        .entries
        .iter_mut()
        .for_each(|entry| entry.jwks_url = normalize_jwks_url(&entry.jwks_url));
    Ok(store)
}

async fn write_store_atomic(path: &Path, store: &NsdJwtPinStore) -> Result<(), JwtPinError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let json = serde_json::to_vec_pretty(store)?;
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, json).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp, perms)?;
    }
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
    }
    let rem = chunks.remainder();
    if rem.len() == 1 {
        let n = (rem[0] as u32) << 16;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
    } else if rem.len() == 2 {
        let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwk() -> RsaJwk {
        RsaJwk {
            kty: "RSA".to_string(),
            kid: Some("kid-1".to_string()),
            alg: Some("RS256".to_string()),
            key_use: Some("sig".to_string()),
            e: "AQAB".to_string(),
            n: "sXchDaQpW6q4lgPdugDL1cYgmzZKdO8eU1X6w3E4NtQ".to_string(),
        }
    }

    #[test]
    fn thumbprint_uses_rfc7638_rsa_fields_only() {
        let a = rsa_jwk_thumbprint(&jwk()).unwrap();
        let mut b = jwk();
        b.key_use = Some("enc".to_string());
        assert_eq!(a, rsa_jwk_thumbprint(&b).unwrap());
    }

    #[test]
    fn pin_gate_rejects_non_rs256_or_empty_kid() {
        let mut no_kid = jwk();
        no_kid.kid = Some(String::new());
        assert!(validate_rsa_jwk(&no_kid).is_err());

        let mut bad_alg = jwk();
        bad_alg.alg = Some("RS512".to_string());
        assert!(validate_rsa_jwk(&bad_alg).is_err());
    }

    #[tokio::test]
    async fn tofu_first_use_persists_store_schema() {
        let dir = tempfile::tempdir().unwrap();
        let pins = vec!["pin-a".to_string(), "pin-b".to_string()];
        persist_first_use_pins(
            dir.path(),
            "realm-a",
            "https://nsd/.well-known/jwks.json",
            pins,
            7,
        )
        .await
        .unwrap();

        let loaded = load_tofu_pins(dir.path(), "realm-a", "https://nsd/.well-known/jwks.json/")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded, vec!["pin-a", "pin-b"]);

        let text = tokio::fs::read_to_string(nsd_jwt_pin_store_path(dir.path()))
            .await
            .unwrap();
        let store: NsdJwtPinStore = serde_json::from_str(&text).unwrap();
        assert_eq!(store.version, 1);
        assert_eq!(store.entries[0].learned_at, 7);
        assert_eq!(store.entries[0].last_seen_at, 7);
    }

    #[tokio::test]
    async fn tofu_first_use_fails_when_store_cannot_persist() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let err = persist_first_use_pins(
            file.path(),
            "realm-a",
            "https://nsd/.well-known/jwks.json",
            vec!["pin-a".to_string()],
            7,
        )
        .await
        .expect_err("state_dir as a file must reject memory-only TOFU");
        assert!(matches!(err, JwtPinError::Io(_)));
    }
}
