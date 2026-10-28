use crate::{
    account::AccountError, account::MAX_BYTES, account::MAX_IDENTITIES, account::SCHEMA,
    account::codec::ascending_by, account::codec::bounded, account::codec::identity,
    account::codec::reader, account::codec::require, account::domains::ROSTER_DOMAIN,
    account::signing::verify,
};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::{collections::BTreeSet, fmt, marker::PhantomData, str::FromStr};

/// Minimum signed roster lifetime: 24 hours, in milliseconds.
pub const MIN_ROSTER_VALIDITY_MS: u64 = 86_400_000;

/// Strictly increasing within one issuer/participant scope; also the attribution epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RosterVersion(pub u64);

/// Attribution class published atomically with admission membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum IdentityClass {
    /// Ordinary membership Node.
    OrdinaryNode,
    /// Gateway acting as an ordinary membership Node.
    GatewayNode,
}

/// Full identity and its inseparable attribution class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RosterEntry {
    /// Full, validated identity, never NodeId alone.
    pub identity: IdentityKey,
    /// Class used for usage attributed to this roster version.
    pub class: IdentityClass,
}

/// Identity, class and the start of its current uninterrupted admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionSnapshotEntry {
    /// Full, validated identity, never NodeId alone.
    pub identity: IdentityKey,
    /// Class held throughout this admission.
    pub class: IdentityClass,
    /// Version when admission with this class began; removal or reclassification resets it.
    pub admission_since: RosterVersion,
}

/// Validated local JSON schema 3 content. No file ownership or I/O is implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionSnapshot {
    /// Local JSON schema, always 3 after validation.
    pub schema_version: u8,
    /// Issue time supplied by the controlled-file producer.
    pub issued_at_unix_ms: u64,
    /// Attribution epoch for both membership and classes.
    pub roster_version: RosterVersion,
    /// Complete identity/class/admission-start set; empty withdraws admission.
    pub identities: Vec<AdmissionSnapshotEntry>,
}

// Derived structs also accept positional sequences. Forward map access directly
// so named-field validation sees every key, including duplicates.
struct JsonObject<T>(T);

struct JsonObjectVisitor<T>(PhantomData<T>);

impl<'de, T: Deserialize<'de>> Visitor<'de> for JsonObjectVisitor<T> {
    type Value = JsonObject<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        T::deserialize(MapAccessDeserializer::new(map)).map(JsonObject)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for JsonObject<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(JsonObjectVisitor(PhantomData))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonSnapshot {
    schema_version: u8,
    issued_at_unix_ms: u64,
    roster_version: u64,
    identities: Vec<JsonObject<JsonEntry>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonEntry {
    identity: String,
    class: String,
    admission_since: u64,
}

/// Validates local snapshot bytes, including strict shape, identity and freshness.
/// The caller supplies time and max age and owns the controlled-file trust boundary.
///
/// # Errors
/// Rejects missing/unknown/duplicate fields, invalid keys/classes, duplicate identities,
/// unsupported schemas, zero versions, invalid admission starts, bounds and stale/future times.
pub fn validate_admission_snapshot(
    bytes: &[u8],
    now_ms: u64,
    max_age_ms: u64,
) -> Result<AdmissionSnapshot, AccountError> {
    if bytes.len() > MAX_BYTES {
        return Err(AccountError::Bounds);
    }
    let JsonObject(snapshot): JsonObject<JsonSnapshot> = serde_json::from_slice(bytes)?;
    require(snapshot.schema_version == 3 && snapshot.roster_version > 0)?;
    if snapshot.identities.len() > MAX_IDENTITIES {
        return Err(AccountError::Bounds);
    }
    if now_ms
        .checked_sub(snapshot.issued_at_unix_ms)
        .is_none_or(|age| age > max_age_ms)
    {
        return Err(AccountError::Authority);
    }
    let mut seen = BTreeSet::new();
    let mut identities = Vec::with_capacity(snapshot.identities.len());
    for JsonObject(entry) in snapshot.identities {
        let identity = IdentityKey::from_str(&entry.identity).map_err(|_| AccountError::Field)?;
        require(seen.insert(identity))?;
        let class = match entry.class.as_str() {
            "ordinary_node" => IdentityClass::OrdinaryNode,
            "gateway_node" => IdentityClass::GatewayNode,
            _ => return Err(AccountError::Field),
        };
        require(entry.admission_since > 0 && entry.admission_since <= snapshot.roster_version)?;
        identities.push(AdmissionSnapshotEntry {
            identity,
            class,
            admission_since: RosterVersion(entry.admission_since),
        });
    }
    Ok(AdmissionSnapshot {
        schema_version: snapshot.schema_version,
        issued_at_unix_ms: snapshot.issued_at_unix_ms,
        roster_version: RosterVersion(snapshot.roster_version),
        identities,
    })
}

/// Complete signed participant roster content, before its signature wrapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Roster {
    /// Issuing authority, checked against caller trust during verification.
    pub issuer: IdentityKey,
    /// Independent relay participant receiving admission authority.
    pub recipient: IdentityKey,
    /// Monotonic version and attribution epoch.
    pub version: RosterVersion,
    /// Issue time in Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Exclusive validity deadline; lifetime must be at least 24 hours.
    pub valid_until_unix_ms: u64,
    /// Complete set, sorted strictly by full identity bytes.
    pub identities: Vec<RosterEntry>,
}

impl Roster {
    fn validate(&self) -> Result<(), AccountError> {
        require(self.version.0 > 0)?;
        require(
            self.valid_until_unix_ms
                .checked_sub(self.issued_at_unix_ms)
                .is_some_and(|duration| duration >= MIN_ROSTER_VALIDITY_MS),
        )?;
        if self.identities.len() > MAX_IDENTITIES {
            return Err(AccountError::Bounds);
        }
        require(ascending_by(&self.identities, |value| &value.identity))
    }

    /// Encodes canonical content for signing with the roster signature domain.
    ///
    /// # Errors
    /// Rejects zero version, insufficient lifetime, duplicate/order or bound violations.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(7)
            .uint(SCHEMA)
            .bytes(self.issuer.as_bytes())
            .bytes(self.recipient.as_bytes())
            .uint(self.version.0)
            .uint(self.issued_at_unix_ms)
            .uint(self.valid_until_unix_ms)
            .array(self.identities.len());
        for entry in &self.identities {
            out.array(2)
                .bytes(entry.identity.as_bytes())
                .uint(entry.class as u64);
        }
        bounded(out.into_bytes())
    }

    /// Decodes exact canonical roster content without granting trust to its issuer.
    ///
    /// # Errors
    /// Rejects malformed fields, unknown classes, bounds and invalid lifetime/order.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 7)?;
        let mut value = Self {
            issuer: identity(&mut input)?,
            recipient: identity(&mut input)?,
            version: RosterVersion(input.uint()?),
            issued_at_unix_ms: input.uint()?,
            valid_until_unix_ms: input.uint()?,
            identities: vec![],
        };
        let count = input.array_up_to(MAX_IDENTITIES)?;
        value.identities.reserve(count);
        for _ in 0..count {
            input.array(2)?;
            let identity = identity(&mut input)?;
            let class = match input.uint()? {
                0 => IdentityClass::OrdinaryNode,
                1 => IdentityClass::GatewayNode,
                _ => return Err(AccountError::Field),
            };
            value.identities.push(RosterEntry { identity, class });
        }
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}

/// Signed carrier. Decoding checks shape; [`Self::verify`] authenticates authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRoster {
    /// Canonical roster content, including membership and class in one publication.
    pub content: Roster,
    /// Ed25519 signature over the domain, zero separator and canonical content.
    pub signature: [u8; 64],
}

impl SignedRoster {
    /// Encodes the exact signed carrier, preserving the content's canonical bytes.
    ///
    /// # Errors
    /// Rejects invalid roster content or an oversized carrier.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        let content = self.content.canonical()?;
        let mut out = CborWriter::default();
        out.array(2).bytes(&content).bytes(&self.signature);
        bounded(out.into_bytes())
    }

    /// Decodes one carrier; the caller must verify it before installing admission.
    ///
    /// # Errors
    /// Rejects noncanonical bytes, trailing data or invalid roster content.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = CborReader::new(bytes, MAX_BYTES)?;
        input.array(2)?;
        let content = Roster::decode(input.bytes_up_to(MAX_BYTES)?)?;
        let signature = input.fixed_bytes()?;
        input.finish()?;
        Ok(Self { content, signature })
    }

    /// Authenticates issuer, recipient, monotonic epoch, validity and signature.
    /// Caller persistence of `last_version` supplies rollback resistance.
    ///
    /// # Errors
    /// Rejects invalid content, wrong authority, non-increasing version, time or signature.
    pub fn verify(
        &self,
        issuer: IdentityKey,
        recipient: IdentityKey,
        last_version: u64,
        now_ms: u64,
    ) -> Result<(), AccountError> {
        let content = self.content.canonical()?;
        if self.content.issuer != issuer
            || self.content.recipient != recipient
            || self.content.version.0 <= last_version
            || now_ms < self.content.issued_at_unix_ms
            || now_ms >= self.content.valid_until_unix_ms
        {
            return Err(AccountError::Authority);
        }
        verify(issuer, ROSTER_DOMAIN, &content, &self.signature)
            .map_err(|_| AccountError::Signature)
    }
}
