use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnvelopePinError {
    #[error("I/O error reading/writing NSD envelope pin store: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid Ed25519 public key: {0}")]
    InvalidKey(String),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct NsdEnvelopePinStore {
    pub version: u8,
    pub entries: Vec<NsdEnvelopePinEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct NsdEnvelopePinEntry {
    pub realm: String,
    pub nsd_url: String,
    pub pins: Vec<String>,
    pub learned_at: u64,
    pub last_seen_at: u64,
}

impl Default for NsdEnvelopePinStore {
    fn default() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }
}

pub fn nsd_envelope_pin_store_path(state_dir: &Path) -> PathBuf {
    state_dir.join("trust").join("nsd_envelope_key_pins.json")
}

pub fn normalize_nsd_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

pub fn ed25519_pubkey_hex_to_okp_thumbprint(hex32: &str) -> Result<String, EnvelopePinError> {
    if hex32.len() != 64 {
        return Err(EnvelopePinError::InvalidKey(format!(
            "expected 64 hex chars, got {}",
            hex32.len()
        )));
    }
    if !hex32
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(EnvelopePinError::InvalidKey(
            "expected lowercase hex".to_string(),
        ));
    }
    let bytes = hex::decode(hex32)?;
    let pubkey: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EnvelopePinError::InvalidKey("expected 32 bytes".to_string()))?;
    ed25519_pubkey_to_okp_thumbprint(&pubkey)
}

pub fn ed25519_pubkey_to_okp_thumbprint(pubkey: &[u8; 32]) -> Result<String, EnvelopePinError> {
    let x = base64_url_no_pad(pubkey);
    let x = serde_json::to_string(&x)?;
    let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":{x}}}");
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(base64_url_no_pad(&digest))
}

pub fn pin_set_contains(pins: &[String], pin: &str) -> bool {
    pins.iter().any(|trusted| trusted == pin)
}

pub async fn load_tofu_pins(
    state_dir: &Path,
    realm: &str,
    nsd_url: &str,
) -> Result<Option<Vec<String>>, EnvelopePinError> {
    let path = nsd_envelope_pin_store_path(state_dir);
    if !path.exists() {
        return Ok(None);
    }
    let store = load_store(&path).await?;
    let nsd_url = normalize_nsd_url(nsd_url);
    Ok(store
        .entries
        .into_iter()
        .find(|entry| entry.realm == realm && normalize_nsd_url(&entry.nsd_url) == nsd_url)
        .map(|entry| entry.pins))
}

pub async fn persist_first_use_pins(
    state_dir: &Path,
    realm: &str,
    nsd_url: &str,
    pins: Vec<String>,
    now: u64,
) -> Result<(), EnvelopePinError> {
    let path = nsd_envelope_pin_store_path(state_dir);
    let mut store = if path.exists() {
        load_store(&path).await?
    } else {
        NsdEnvelopePinStore::default()
    };
    store.version = 1;
    let nsd_url = normalize_nsd_url(nsd_url);
    if let Some(entry) = store
        .entries
        .iter_mut()
        .find(|entry| entry.realm == realm && normalize_nsd_url(&entry.nsd_url) == nsd_url)
    {
        entry.last_seen_at = now;
    } else {
        store.entries.push(NsdEnvelopePinEntry {
            realm: realm.to_string(),
            nsd_url,
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
    nsd_url: &str,
    now: u64,
) -> Result<(), EnvelopePinError> {
    let path = nsd_envelope_pin_store_path(state_dir);
    if !path.exists() {
        return Ok(());
    }
    let mut store = load_store(&path).await?;
    let nsd_url = normalize_nsd_url(nsd_url);
    if let Some(entry) = store
        .entries
        .iter_mut()
        .find(|entry| entry.realm == realm && normalize_nsd_url(&entry.nsd_url) == nsd_url)
    {
        entry.last_seen_at = now;
        write_store_atomic(&path, &store).await?;
    }
    Ok(())
}

async fn load_store(path: &Path) -> Result<NsdEnvelopePinStore, EnvelopePinError> {
    let text = tokio::fs::read_to_string(path).await?;
    let mut store: NsdEnvelopePinStore = serde_json::from_str(&text)?;
    store
        .entries
        .iter_mut()
        .for_each(|entry| entry.nsd_url = normalize_nsd_url(&entry.nsd_url));
    Ok(store)
}

async fn write_store_atomic(
    path: &Path,
    store: &NsdEnvelopePinStore,
) -> Result<(), EnvelopePinError> {
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

    #[test]
    fn okp_thumbprint_uses_rfc7638_ed25519_fields() {
        let hex32 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let thumbprint = ed25519_pubkey_hex_to_okp_thumbprint(hex32).unwrap();
        assert_eq!(thumbprint, "P7IdLIpiTZiFaIoOSqbX3JrSyps3hvZ4Y2SieP96XIY");
    }

    #[test]
    fn pin_membership_accepts_pinned_and_rejects_unpinned() {
        let pins = vec!["pin-a".to_string(), "pin-b".to_string()];
        assert!(pin_set_contains(&pins, "pin-a"));
        assert!(!pin_set_contains(&pins, "pin-c"));
    }

    #[test]
    fn hex_helper_rejects_non_lowercase_or_wrong_length_keys() {
        assert!(ed25519_pubkey_hex_to_okp_thumbprint(&"aa".repeat(31)).is_err());
        assert!(ed25519_pubkey_hex_to_okp_thumbprint(&"AA".repeat(32)).is_err());
    }

    #[tokio::test]
    async fn tofu_first_use_persists_store_schema() {
        let dir = tempfile::tempdir().unwrap();
        let pins = vec!["pin-a".to_string(), "pin-b".to_string()];
        persist_first_use_pins(dir.path(), "realm-a", "https://nsd/", pins, 7)
            .await
            .unwrap();

        let loaded = load_tofu_pins(dir.path(), "realm-a", "https://nsd")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded, vec!["pin-a", "pin-b"]);

        let text = tokio::fs::read_to_string(nsd_envelope_pin_store_path(dir.path()))
            .await
            .unwrap();
        let store: NsdEnvelopePinStore = serde_json::from_str(&text).unwrap();
        assert_eq!(store.version, 1);
        assert_eq!(store.entries[0].nsd_url, "https://nsd");
        assert_eq!(store.entries[0].learned_at, 7);
        assert_eq!(store.entries[0].last_seen_at, 7);
    }

    #[tokio::test]
    async fn tofu_first_use_fails_when_store_cannot_persist() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let err = persist_first_use_pins(
            file.path(),
            "realm-a",
            "https://nsd",
            vec!["pin-a".to_string()],
            7,
        )
        .await
        .expect_err("state_dir as a file must reject memory-only TOFU");
        assert!(matches!(err, EnvelopePinError::Io(_)));
    }
}
