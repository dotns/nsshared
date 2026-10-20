//! Public RS256 claim/key values; signature verification and custody remain external.
use super::{AccountError, MAX_BYTES, require};
use crate::{
    IdentityKey,
    encoding::{decode_base64url, encode_base64url},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Audience of the distinct NSD machine-token verifier.
pub const MACHINE_AUDIENCE: &str = "nsd-machine-control";
/// Inclusive gateway expiration leeway in seconds.
pub const MACHINE_EXPIRY_LEEWAY_SECONDS: i64 = 30;
/// Inclusive refresh-before-expiry window in seconds.
pub const MACHINE_REFRESH_WINDOW_SECONDS: i64 = 300;

/// String or array audience. Absence is represented by None on MachineClaims.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum TokenAudience {
    /// One exact audience string.
    Single(String),
    /// Ordered audience strings, preserved without normalization.
    Multiple(Vec<String>),
}
impl TokenAudience {
    /// Exact audience membership; this performs no token authentication.
    #[must_use]
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(value) => value == expected,
            Self::Multiple(values) => values.iter().any(|value| value == expected),
        }
    }
}

/// Machine claims only. Unknown legacy role/gateway members grant no authority.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct MachineClaims {
    /// Informational issuer; the gateway predicate does not compare it.
    #[serde(default)]
    pub iss: String,
    /// Exact registered machine subject.
    pub sub: String,
    /// Producer's realm label; not inferred from an unverified token.
    pub realm: String,
    /// Optional single/array audience; deliberately unchecked by the gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<TokenAudience>,
    /// Self-binding key type; required to equal ed25519 unless explicitly waived.
    #[serde(default)]
    pub mid_kty: String,
    /// Lowercase hex Ed25519 signing identity.
    #[serde(default)]
    pub mid_pub: String,
    /// Issued Unix seconds, preserved but not compared by the gateway predicate.
    pub iat: i64,
    /// Actual expiration Unix seconds.
    pub exp: i64,
    /// Producer's revocation identifier.
    pub jti: String,
}

/// Typed machine claim or qualified-key refusal.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TokenError {
    /// Malformed public value.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// Subject differs from the accepted registration.
    #[error("machine subject mismatch")]
    Subject,
    /// Signing identity self-binding differs.
    #[error("machine self-binding mismatch")]
    SelfBinding,
    /// Gateway expiry plus its retained leeway has passed.
    #[error("machine token expired")]
    Expired,
    /// Distinct NSD machine verifier audience mismatch.
    #[error("NSD machine audience mismatch")]
    Audience,
    /// Token header names another algorithm.
    #[error("machine token algorithm is not RS256")]
    Algorithm,
    /// Unsupported or malformed public RSA key.
    #[error("unusable RSA signing key")]
    Key,
    /// No qualified keys remain.
    #[error("no usable signing keys")]
    Empty,
    /// Usable keys do not intersect the effective pins.
    #[error("no trusted signing keys")]
    Untrusted,
    /// Explicit key id is unknown; consumer may perform one paced refresh.
    #[error("unknown signing key id")]
    UnknownKeyId,
    /// No key id and no qualified key.
    #[error("missing signing key id")]
    MissingKeyId,
    /// No key id and multiple qualified keys.
    #[error("ambiguous signing key id")]
    AmbiguousKeyId,
    /// Stored pin ownership differs from supplied realm/address.
    #[error("key-set owner mismatch")]
    Owner,
}

fn json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AccountError> {
    require(
        bytes.len() <= MAX_BYTES && bytes.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{'),
    )?;
    Ok(serde_json::from_slice(bytes)?)
}
impl MachineClaims {
    /// Decodes a bounded object, preserving duplicate named-field refusal.
    /// # Errors
    /// Refuses invalid types, missing required fields, duplicates or trailing data.
    pub fn decode_json(bytes: &[u8]) -> Result<Self, AccountError> {
        json(bytes)
    }
    /// Encodes public claim values in declared field order; not a signed JWT.
    /// # Errors
    /// Refuses oversized output or JSON encoding failures.
    pub fn canonical_json(&self) -> Result<Vec<u8>, AccountError> {
        super::bounded(serde_json::to_vec(self)?)
    }
    /// Compares externally authenticated claims using the pinned gateway predicate.
    /// Signature, RS256 algorithm and qualified-key verification must precede this call.
    /// No issuer, realm or audience authority is inferred or compared here.
    /// # Errors
    /// Refuses subject, nonwaived self-binding and expiration beyond 30 seconds.
    pub fn validate_gateway(
        &self,
        subject: &str,
        identity: IdentityKey,
        allow_unbound: bool,
        now_seconds: u64,
    ) -> Result<(), TokenError> {
        if i128::from(now_seconds)
            > i128::from(self.exp) + i128::from(MACHINE_EXPIRY_LEEWAY_SECONDS)
        {
            return Err(TokenError::Expired);
        }
        if self.sub != subject {
            return Err(TokenError::Subject);
        }
        let key: String = identity
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if !allow_unbound && (self.mid_kty != "ed25519" || self.mid_pub != key) {
            return Err(TokenError::SelfBinding);
        }
        Ok(())
    }
    /// Only the distinct NSD verifier's audience predicate; never gateway admission.
    /// # Errors
    /// Refuses absent or nonmatching machine audience.
    pub fn validate_nsd_audience(&self) -> Result<(), TokenError> {
        if self
            .aud
            .as_ref()
            .is_some_and(|aud| aud.contains(MACHINE_AUDIENCE))
        {
            Ok(())
        } else {
            Err(TokenError::Audience)
        }
    }
}

/// Pure refresh decision; no token is stored and no clock is read.
#[must_use]
pub fn machine_refresh_needed(expires_seconds: Option<i64>, now_seconds: u64) -> bool {
    expires_seconds.is_none_or(|expiry| {
        i128::from(expiry) - i128::from(now_seconds) <= i128::from(MACHINE_REFRESH_WINDOW_SECONDS)
    })
}

/// Public RFC 7517 RSA JWK shape, preserving optional metadata.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct RsaJwk {
    /// Must be RSA for qualification.
    pub kty: String,
    /// Nonempty identifier for a usable key.
    #[serde(default)]
    pub kid: Option<String>,
    /// Must be RS256 for qualification.
    #[serde(default)]
    pub alg: Option<String>,
    /// Absent or sig; encryption keys cannot verify tokens.
    #[serde(default, rename = "use")]
    pub key_use: Option<String>,
    /// Base64url unsigned big-endian modulus.
    pub n: String,
    /// Base64url unsigned big-endian exponent.
    pub e: String,
}
/// Public machine key-set; source order is significant for selection.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct JwkSet {
    /// Advertised RSA descriptions; unsupported members are not trusted.
    pub keys: Vec<RsaJwk>,
}
impl JwkSet {
    /// Decodes a bounded object, preserving supported key descriptions in source order.
    /// Unsupported object members are discarded; malformed JSON or scalar members refuse.
    /// # Errors
    /// Refuses invalid key-set shape, duplicate key lists or trailing data.
    pub fn decode_json(bytes: &[u8]) -> Result<Self, AccountError> {
        #[derive(Deserialize)]
        struct Descriptions {
            keys: Vec<Box<serde_json::value::RawValue>>,
        }
        let raw: Descriptions = json(bytes)?;
        let mut keys = Vec::new();
        for value in raw.keys {
            require(value.get().trim_start().starts_with('{'))?;
            if let Ok(key) = serde_json::from_str(value.get()) {
                keys.push(key);
            }
        }
        Ok(Self { keys })
    }
    /// Encodes public key descriptions deterministically.
    /// # Errors
    /// Refuses oversized output or encoding failures.
    pub fn canonical_json(&self) -> Result<Vec<u8>, AccountError> {
        super::bounded(serde_json::to_vec(self)?)
    }
}
impl RsaJwk {
    /// Checks supplied signing-key metadata and canonical unsigned components.
    /// # Errors
    /// Refuses wrong algorithm/use/type, missing kid or malformed components.
    pub fn validate(&self) -> Result<(), TokenError> {
        if self.kty != "RSA"
            || self.alg.as_deref() != Some("RS256")
            || self.kid.as_deref().is_none_or(str::is_empty)
            || self.key_use.as_deref().is_some_and(|usage| usage != "sig")
        {
            return Err(TokenError::Key);
        }
        for part in [&self.n, &self.e] {
            let bytes = decode_base64url(part, MAX_BYTES).map_err(|_| TokenError::Key)?;
            if bytes.is_empty() || bytes[0] == 0 || encode_base64url(&bytes) != *part {
                return Err(TokenError::Key);
            }
        }
        Ok(())
    }
    /// Computes the exact RFC 7638 public RSA thumbprint.
    /// # Errors
    /// Refuses unusable keys and JSON encoding failure.
    pub fn thumbprint(&self) -> Result<String, TokenError> {
        self.validate()?;
        let e = serde_json::to_string(&self.e).map_err(AccountError::from)?;
        let n = serde_json::to_string(&self.n).map_err(AccountError::from)?;
        Ok(encode_base64url(&Sha256::digest(
            format!("{{\"e\":{e},\"kty\":\"RSA\",\"n\":{n}}}").as_bytes(),
        )))
    }
}

/// Pin-qualified key descriptions plus first-use pins requiring external persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualifiedKeySet {
    /// Source-order keys matching effective pins.
    pub keys: Vec<RsaJwk>,
    /// Present only on first use with neither static nor stored pins.
    pub learned_pins: Option<Vec<String>>,
}
/// Qualifies supplied keys against static or already owner-matched stored pins.
/// The caller must obtain keys confidentially and persist new pins before use.
/// # Errors
/// Refuses no usable keys or empty pin intersection.
pub fn qualify_key_set(
    set: &JwkSet,
    static_pins: &[String],
    stored_pins: Option<&[String]>,
) -> Result<QualifiedKeySet, TokenError> {
    let usable: Vec<_> = set
        .keys
        .iter()
        .filter_map(|key| key.thumbprint().ok().map(|pin| (key, pin)))
        .collect();
    if usable.is_empty() {
        return Err(TokenError::Empty);
    }
    let learned_pins = if static_pins.is_empty() && stored_pins.is_none() {
        Some(
            usable
                .iter()
                .map(|(_, pin)| pin.clone())
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    let pins = if static_pins.is_empty() {
        stored_pins
            .or(learned_pins.as_deref())
            .ok_or(TokenError::Empty)?
    } else {
        static_pins
    };
    let keys: Vec<_> = usable
        .into_iter()
        .filter(|(_, pin)| pins.contains(pin))
        .map(|(key, _)| key.clone())
        .collect();
    if keys.is_empty() {
        return Err(TokenError::Untrusted);
    }
    Ok(QualifiedKeySet { keys, learned_pins })
}
impl QualifiedKeySet {
    /// Selects the first exact kid, or the sole qualified key for absent kid.
    /// # Errors
    /// Refuses missing, ambiguous or unknown key ids without fetching anything.
    pub fn select(&self, kid: Option<&str>) -> Result<&RsaJwk, TokenError> {
        if let Some(kid) = kid {
            return self
                .keys
                .iter()
                .find(|key| key.kid.as_deref() == Some(kid))
                .ok_or(TokenError::UnknownKeyId);
        }
        match self.keys.as_slice() {
            [key] => Ok(key),
            [] => Err(TokenError::MissingKeyId),
            _ => Err(TokenError::AmbiguousKeyId),
        }
    }
}

/// Exact persisted token-pin owner, separate from envelope signer trust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySetOwner {
    /// Provisioned realm label.
    pub realm: String,
    /// Confidential acquisition address, normalized only for comparison.
    pub address: String,
}
impl KeySetOwner {
    /// Compares the existing realm/address ownership rule without I/O.
    /// # Errors
    /// Refuses differing realm or normalized address.
    pub fn compare(&self, expected: &Self) -> Result<(), TokenError> {
        if self.realm == expected.realm
            && self.address.trim().trim_end_matches('/')
                == expected.address.trim().trim_end_matches('/')
        {
            Ok(())
        } else {
            Err(TokenError::Owner)
        }
    }
}

/// Public JWT header facts; a selected key still requires external RSA verification.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct MachineTokenHeader {
    /// Exact algorithm; only RS256 selects a machine verification key.
    pub alg: String,
    /// Optional key identifier; absence requires exactly one qualified key.
    #[serde(default)]
    pub kid: Option<String>,
}
impl MachineTokenHeader {
    /// Decodes a bounded header object with duplicate named-field refusal.
    /// # Errors
    /// Refuses malformed, nonobject or trailing JSON.
    pub fn decode_json(bytes: &[u8]) -> Result<Self, AccountError> {
        json(bytes)
    }
    /// Checks algorithm before selecting the qualified verification key.
    /// # Errors
    /// Refuses algorithm confusion and missing, unknown or ambiguous key ids.
    pub fn select_key<'a>(&self, keys: &'a QualifiedKeySet) -> Result<&'a RsaJwk, TokenError> {
        if self.alg != "RS256" {
            return Err(TokenError::Algorithm);
        }
        keys.select(self.kid.as_deref())
    }
}

/// Previously persisted pins bound to their original acquisition owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredKeyPins {
    /// Original provisioned realm and confidential key-set address.
    pub owner: KeySetOwner,
    /// Original first-use pins; rotations never append to these.
    pub pins: Vec<String>,
}
/// Checks stored ownership before qualifying a fetched rotation.
/// Static pins bypass stored ownership and persistence, as in the consumer.
/// # Errors
/// Refuses mismatched stored owners, unusable keys or an empty pin intersection.
pub fn qualify_owned_key_set(
    set: &JwkSet,
    owner: &KeySetOwner,
    static_pins: &[String],
    stored: Option<&StoredKeyPins>,
) -> Result<QualifiedKeySet, TokenError> {
    if static_pins.is_empty()
        && let Some(stored) = stored
    {
        stored.owner.compare(owner)?;
    }
    qualify_key_set(set, static_pins, stored.map(|s| s.pins.as_slice()))
}
