use crate::{Identity, NetworkId, codec::CborReader};
use blake2::{
    Blake2sMac,
    digest::{KeyInit, Mac, consts::U3},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Serialize, ser::SerializeTuple};

const ALIAS_KEY: &[u8] = b"keynet-alias-v1";
const NAME_OWNER_CONTEXT: &[u8] = b"keynet/name-record/v1";
const NAME_NETWORK_CONTEXT: &[u8] = b"keynet/name-record-network/v1";
const MAX_NAME_RECORD_BYTES: usize = 286;

/// A configured IPv4 alias-pool range expressed as a base and address count (§13.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AliasPool {
    /// The first IPv4 address, represented in network byte order as a `u32`.
    pub base: u32,
    /// The number of addresses in the pool.
    pub size: u64,
}

/// A failure to derive an H22 alias candidate (§13.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AliasCandidateError {
    /// The service kind was neither native IPv6 (`6`) nor IPv4 (`4`).
    InvalidKind,
    /// The sequence index was outside `0..=15`.
    InvalidIndex,
    /// The configured pool contained no addresses.
    EmptyPool,
    /// The configured base and size did not describe an IPv4 address range.
    PoolOutOfRange,
    /// The keyed BLAKE2s digest could not be initialized.
    Derivation,
    /// Adding the selected offset to the pool base overflowed an IPv4 address.
    AddressOverflow,
}

/// Returns the 22-bit H22 value for one valid alias sequence position (§13.4).
pub fn alias_h22(
    network_id: &NetworkId,
    identity: &Identity,
    kind: u8,
    index: u8,
) -> Result<u32, AliasCandidateError> {
    validate_alias_inputs(kind, index)?;
    let mut input = [0_u8; 66];
    input[..32].copy_from_slice(network_id);
    input[32..64].copy_from_slice(identity);
    input[64] = kind;
    input[65] = index;
    let mut hash = <Blake2sMac<U3> as KeyInit>::new_from_slice(ALIAS_KEY)
        .map_err(|_| AliasCandidateError::Derivation)?;
    hash.update(&input);
    let digest = hash.finalize().into_bytes();
    Ok(u32::from_be_bytes([0, digest[0], digest[1], digest[2]]) >> 2)
}

/// Derives one deterministic IPv4 alias candidate without allocation filtering (§§6.2-6.3, 13.4).
pub fn alias_candidate(
    network_id: &NetworkId,
    identity: &Identity,
    kind: u8,
    index: u8,
    pool: AliasPool,
) -> Result<u32, AliasCandidateError> {
    validate_pool(pool)?;
    let offset = u64::from(alias_h22(network_id, identity, kind, index)?) % pool.size;
    let offset = u32::try_from(offset).map_err(|_| AliasCandidateError::AddressOverflow)?;
    pool.base
        .checked_add(offset)
        .ok_or(AliasCandidateError::AddressOverflow)
}

/// Derives all sixteen deterministic alias candidates in sequence order (§§6.2-6.3, 13.4).
pub fn alias_candidates(
    network_id: &NetworkId,
    identity: &Identity,
    kind: u8,
    pool: AliasPool,
) -> Result<[u32; 16], AliasCandidateError> {
    validate_pool(pool)?;
    validate_alias_inputs(kind, 0)?;
    let mut candidates = [0_u32; 16];
    for (index, candidate) in candidates.iter_mut().enumerate() {
        *candidate = alias_candidate(network_id, identity, kind, index as u8, pool)?;
    }
    Ok(candidates)
}

fn validate_alias_inputs(kind: u8, index: u8) -> Result<(), AliasCandidateError> {
    if kind != 6 && kind != 4 {
        return Err(AliasCandidateError::InvalidKind);
    }
    if index > 15 {
        return Err(AliasCandidateError::InvalidIndex);
    }
    Ok(())
}

fn validate_pool(pool: AliasPool) -> Result<(), AliasCandidateError> {
    if pool.size == 0 {
        return Err(AliasCandidateError::EmptyPool);
    }
    let last_offset = pool.size - 1;
    if last_offset > u64::from(u32::MAX)
        || u64::from(pool.base)
            .checked_add(last_offset)
            .is_none_or(|last| last > u64::from(u32::MAX))
    {
        return Err(AliasCandidateError::PoolOutOfRange);
    }
    Ok(())
}

/// A Keynet label normalization or validation failure (§§7.2, 13.4, 13.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelError {
    /// Normalization produced an empty label or validation received one.
    Empty,
    /// The label exceeded 63 bytes.
    TooLong,
    /// A received label contained a byte outside lowercase ASCII letters, digits, and hyphen.
    InvalidCharacter,
    /// A received label began or ended with a hyphen.
    LeadingOrTrailingHyphen,
    /// The label was the reserved `id` or `v4` label.
    Reserved,
}

/// Normalizes a UTF-8 display name using byte-defined lowercase-ASCII label rules (§13.4).
pub fn normalize_label(display_name: &str) -> Result<String, LabelError> {
    let mut output = Vec::with_capacity(63);
    let mut other_run = false;
    for byte in display_name.bytes() {
        let kept = byte.is_ascii_lowercase() || byte.is_ascii_digit();
        if !kept {
            other_run = true;
            continue;
        }
        if other_run && !output.is_empty() {
            if output.len() == 63 {
                break;
            }
            output.push(b'-');
        }
        other_run = false;
        if output.len() == 63 {
            break;
        }
        output.push(byte);
    }
    if output.last() == Some(&b'-') {
        let _ = output.pop();
    }
    if output.is_empty() {
        return Err(LabelError::Empty);
    }
    let normalized = String::from_utf8(output).map_err(|_| LabelError::InvalidCharacter)?;
    reject_reserved(&normalized)?;
    Ok(normalized)
}

/// Validates an already-normalized Keynet label without rewriting it (§§7.2, 13.4, 13.6).
pub fn validate_label(label: &str) -> Result<(), LabelError> {
    if label.is_empty() {
        return Err(LabelError::Empty);
    }
    if label.len() > 63 {
        return Err(LabelError::TooLong);
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(LabelError::LeadingOrTrailingHyphen);
    }
    if !label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(LabelError::InvalidCharacter);
    }
    reject_reserved(label)
}

fn reject_reserved(label: &str) -> Result<(), LabelError> {
    if label == "id" || label == "v4" {
        Err(LabelError::Reserved)
    } else {
        Ok(())
    }
}

/// A fixed NameRecord operation tag (§§7.7, 13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NameOperation {
    /// Allocate the record's label.
    Claim = 0,
    /// Rename the identity to the record's label.
    Rename = 1,
    /// Release the record's label.
    Release = 2,
}

impl NameOperation {
    fn from_tag(tag: u64) -> Result<Self, NameRecordDecodeError> {
        match tag {
            0 => Ok(Self::Claim),
            1 => Ok(Self::Rename),
            2 => Ok(Self::Release),
            _ => Err(NameRecordDecodeError::InvalidOperation),
        }
    }

    fn tag(self) -> u8 {
        self as u8
    }
}

/// The canonical owner-signed eight-field NameRecord form (§§7.7, 13.1-13.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSignedNameRecord {
    /// The record version, fixed to one.
    pub ver: u8,
    /// The network public key and record scope.
    pub network_id: NetworkId,
    /// The owner identity public key.
    pub identity: Identity,
    /// The normalized label affected by the operation.
    pub label: String,
    /// The fixed claim, rename, or release operation.
    pub op: NameOperation,
    /// The caller-interpreted unsigned record version.
    pub version: u64,
    /// The exclusive Unix-second expiry.
    pub not_after: u64,
    /// The owner's Ed25519 signature over the seven-field form.
    pub signature_owner: [u8; 64],
}

/// The canonical network-countersigned nine-field NameRecord form (§§7.7, 13.1-13.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameRecord {
    /// The record version, fixed to one.
    pub ver: u8,
    /// The network public key and record scope.
    pub network_id: NetworkId,
    /// The owner identity public key.
    pub identity: Identity,
    /// The normalized label affected by the operation.
    pub label: String,
    /// The fixed claim, rename, or release operation.
    pub op: NameOperation,
    /// The caller-interpreted unsigned record version.
    pub version: u64,
    /// The exclusive Unix-second expiry.
    pub not_after: u64,
    /// The owner's Ed25519 signature over the seven-field form.
    pub signature_owner: [u8; 64],
    /// The network's Ed25519 countersignature over the eight-field owner record.
    pub signature_network: [u8; 64],
}

/// A structural failure while encoding a NameRecord (§§13.1, 13.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameRecordEncodeError {
    /// The record version was not one.
    UnsupportedVersion,
    /// The label did not satisfy the exact received-label rules.
    InvalidLabel(LabelError),
    /// Canonical serialization unexpectedly failed.
    Serialization,
}

/// A strict canonical NameRecord decoding failure (§13.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameRecordDecodeError {
    /// The input was not the exact bounded canonical array.
    InvalidEncoding,
    /// The record version was not one.
    UnsupportedVersion,
    /// The operation tag was not zero, one, or two.
    InvalidOperation,
    /// The label did not satisfy the exact received-label rules.
    InvalidLabel(LabelError),
}

/// A NameRecord signing or signature-verification failure (§13.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameRecordSignatureError {
    /// The in-memory record was structurally invalid.
    InvalidRecord(NameRecordEncodeError),
    /// The supplied signer did not match the owner identity.
    OwnerSignerMismatch,
    /// The supplied signer did not match the network public key.
    NetworkSignerMismatch,
    /// The owner identity was not a strict Ed25519 public key.
    InvalidOwnerKey,
    /// The network identifier was not a strict Ed25519 public key.
    InvalidNetworkKey,
    /// The owner signature did not authenticate the seven-field record.
    InvalidOwnerSignature,
    /// The network signature did not authenticate the eight-field owner record.
    InvalidNetworkSignature,
}

/// A decoded NameRecord acceptance failure with no state-transition semantics (§§13.1-13.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameRecordValidationError {
    /// Canonical decoding failed before cryptographic validation.
    Decode(NameRecordDecodeError),
    /// One of the two signatures failed validation.
    Signature(NameRecordSignatureError),
    /// The record named a different network or owner identity than the caller selected.
    ScopeMismatch,
    /// The record reached its exclusive expiry.
    Expired,
}

/// A canonical NameRecord with both signatures, scope, and currentness checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentNameRecord(NameRecord);

impl CurrentNameRecord {
    /// Returns the checked record without granting any version or installation decision.
    #[must_use]
    pub fn record(&self) -> &NameRecord {
        &self.0
    }
}

impl OwnerSignedNameRecord {
    /// Returns the canonical seven-field array authenticated by the owner (§13.2).
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, NameRecordEncodeError> {
        validate_record_structure(self.ver, &self.label)?;
        serialize(&UnsignedNameWire(self))
    }

    /// Returns the canonical owner-signed eight-field array (§§13.1-13.2).
    pub fn encode(&self) -> Result<Vec<u8>, NameRecordEncodeError> {
        validate_record_structure(self.ver, &self.label)?;
        serialize(&OwnerNameWire(self))
    }

    /// Returns the exact owner-signature message (§13.2).
    pub fn signing_preimage(&self) -> Result<Vec<u8>, NameRecordEncodeError> {
        prepend_context(NAME_OWNER_CONTEXT, self.unsigned_bytes()?)
    }

    /// Signs the seven-field record using the matching owner identity key (§13.2).
    pub fn sign(&mut self, signer: &SigningKey) -> Result<(), NameRecordSignatureError> {
        if signer.verifying_key().to_bytes() != self.identity {
            return Err(NameRecordSignatureError::OwnerSignerMismatch);
        }
        let preimage = self
            .signing_preimage()
            .map_err(NameRecordSignatureError::InvalidRecord)?;
        self.signature_owner = signer.sign(&preimage).to_bytes();
        Ok(())
    }

    /// Verifies the owner signature without checking expiry or caller scope (§13.2).
    pub fn verify_signature(&self) -> Result<(), NameRecordSignatureError> {
        let preimage = self
            .signing_preimage()
            .map_err(NameRecordSignatureError::InvalidRecord)?;
        let key = VerifyingKey::from_bytes(&self.identity)
            .map_err(|_| NameRecordSignatureError::InvalidOwnerKey)?;
        key.verify_strict(&preimage, &Signature::from_bytes(&self.signature_owner))
            .map_err(|_| NameRecordSignatureError::InvalidOwnerSignature)
    }

    /// Strictly decodes one canonical owner-signed eight-field array (§13.1).
    pub fn decode(encoded: &[u8]) -> Result<Self, NameRecordDecodeError> {
        decode_owner(encoded)
    }
}

impl NameRecord {
    fn owner_record(&self) -> OwnerSignedNameRecord {
        OwnerSignedNameRecord {
            ver: self.ver,
            network_id: self.network_id,
            identity: self.identity,
            label: self.label.clone(),
            op: self.op,
            version: self.version,
            not_after: self.not_after,
            signature_owner: self.signature_owner,
        }
    }

    /// Returns the canonical owner-signed eight-field array (§§13.1-13.2).
    pub fn owner_signed_bytes(&self) -> Result<Vec<u8>, NameRecordEncodeError> {
        self.owner_record().encode()
    }

    /// Returns the canonical network-countersigned nine-field array (§§13.1-13.2).
    pub fn encode(&self) -> Result<Vec<u8>, NameRecordEncodeError> {
        validate_record_structure(self.ver, &self.label)?;
        serialize(&NetworkNameWire(self))
    }

    /// Signs the owner seven-field form and invalidates any prior countersignature (§13.2).
    pub fn sign_owner(&mut self, signer: &SigningKey) -> Result<(), NameRecordSignatureError> {
        let mut owner = self.owner_record();
        owner.sign(signer)?;
        self.signature_owner = owner.signature_owner;
        self.signature_network = [0; 64];
        Ok(())
    }

    /// Countersigns the exact owner-signed eight-field record with the network key (§13.2).
    pub fn sign_network(&mut self, signer: &SigningKey) -> Result<(), NameRecordSignatureError> {
        if signer.verifying_key().to_bytes() != self.network_id {
            return Err(NameRecordSignatureError::NetworkSignerMismatch);
        }
        self.owner_record().verify_signature()?;
        let preimage = prepend_context(
            NAME_NETWORK_CONTEXT,
            self.owner_signed_bytes()
                .map_err(NameRecordSignatureError::InvalidRecord)?,
        )
        .map_err(NameRecordSignatureError::InvalidRecord)?;
        self.signature_network = signer.sign(&preimage).to_bytes();
        Ok(())
    }

    /// Verifies both ordinary Ed25519 signatures in their distinct contexts (§13.2).
    pub fn verify_signatures(&self) -> Result<(), NameRecordSignatureError> {
        self.owner_record().verify_signature()?;
        let preimage = prepend_context(
            NAME_NETWORK_CONTEXT,
            self.owner_signed_bytes()
                .map_err(NameRecordSignatureError::InvalidRecord)?,
        )
        .map_err(NameRecordSignatureError::InvalidRecord)?;
        let key = VerifyingKey::from_bytes(&self.network_id)
            .map_err(|_| NameRecordSignatureError::InvalidNetworkKey)?;
        key.verify_strict(&preimage, &Signature::from_bytes(&self.signature_network))
            .map_err(|_| NameRecordSignatureError::InvalidNetworkSignature)
    }

    /// Strictly decodes one canonical network-countersigned nine-field array (§13.1).
    pub fn decode(encoded: &[u8]) -> Result<Self, NameRecordDecodeError> {
        decode_network(encoded)
    }

    /// Checks signatures, exact caller scope, and exclusive currentness without version decisions.
    pub fn validate(
        self,
        expected_network_id: &NetworkId,
        expected_identity: &Identity,
        now: u64,
    ) -> Result<CurrentNameRecord, NameRecordValidationError> {
        if &self.network_id != expected_network_id || &self.identity != expected_identity {
            return Err(NameRecordValidationError::ScopeMismatch);
        }
        self.verify_signatures()
            .map_err(NameRecordValidationError::Signature)?;
        if now >= self.not_after {
            return Err(NameRecordValidationError::Expired);
        }
        Ok(CurrentNameRecord(self))
    }

    /// Decodes canonically before checking signatures, caller scope, and expiry (§§13.1-13.2).
    pub fn decode_and_validate(
        encoded: &[u8],
        expected_network_id: &NetworkId,
        expected_identity: &Identity,
        now: u64,
    ) -> Result<CurrentNameRecord, NameRecordValidationError> {
        Self::decode(encoded)
            .map_err(NameRecordValidationError::Decode)?
            .validate(expected_network_id, expected_identity, now)
    }
}

fn validate_record_structure(ver: u8, label: &str) -> Result<(), NameRecordEncodeError> {
    if ver != 1 {
        return Err(NameRecordEncodeError::UnsupportedVersion);
    }
    validate_label(label).map_err(NameRecordEncodeError::InvalidLabel)
}

fn prepend_context(context: &[u8], encoded: Vec<u8>) -> Result<Vec<u8>, NameRecordEncodeError> {
    let capacity = context
        .len()
        .checked_add(encoded.len())
        .ok_or(NameRecordEncodeError::Serialization)?;
    let mut preimage = Vec::with_capacity(capacity);
    preimage.extend_from_slice(context);
    preimage.extend_from_slice(&encoded);
    Ok(preimage)
}

fn serialize(value: &impl Serialize) -> Result<Vec<u8>, NameRecordEncodeError> {
    let mut encoded = Vec::with_capacity(MAX_NAME_RECORD_BYTES);
    ciborium::ser::into_writer(value, &mut encoded)
        .map_err(|_| NameRecordEncodeError::Serialization)?;
    Ok(encoded)
}

fn decode_owner(encoded: &[u8]) -> Result<OwnerSignedNameRecord, NameRecordDecodeError> {
    if encoded.is_empty() || encoded.len() > MAX_NAME_RECORD_BYTES {
        return Err(NameRecordDecodeError::InvalidEncoding);
    }
    let mut reader = CborReader::new(encoded);
    reader
        .array(8)
        .map_err(|_| NameRecordDecodeError::InvalidEncoding)?;
    let owner = read_owner_fields(&mut reader)?;
    if !reader.finished() {
        return Err(NameRecordDecodeError::InvalidEncoding);
    }
    Ok(owner)
}

fn decode_network(encoded: &[u8]) -> Result<NameRecord, NameRecordDecodeError> {
    if encoded.is_empty() || encoded.len() > MAX_NAME_RECORD_BYTES {
        return Err(NameRecordDecodeError::InvalidEncoding);
    }
    let mut reader = CborReader::new(encoded);
    reader
        .array(9)
        .map_err(|_| NameRecordDecodeError::InvalidEncoding)?;
    let owner = read_owner_fields(&mut reader)?;
    let signature_network = reader
        .fixed_bytes()
        .map_err(|_| NameRecordDecodeError::InvalidEncoding)?;
    if !reader.finished() {
        return Err(NameRecordDecodeError::InvalidEncoding);
    }
    Ok(NameRecord {
        ver: owner.ver,
        network_id: owner.network_id,
        identity: owner.identity,
        label: owner.label,
        op: owner.op,
        version: owner.version,
        not_after: owner.not_after,
        signature_owner: owner.signature_owner,
        signature_network,
    })
}

fn read_owner_fields(
    reader: &mut CborReader<'_>,
) -> Result<OwnerSignedNameRecord, NameRecordDecodeError> {
    let ver = u8::try_from(
        reader
            .uint()
            .map_err(|_| NameRecordDecodeError::InvalidEncoding)?,
    )
    .map_err(|_| NameRecordDecodeError::InvalidEncoding)?;
    if ver != 1 {
        return Err(NameRecordDecodeError::UnsupportedVersion);
    }
    let network_id = reader
        .fixed_bytes()
        .map_err(|_| NameRecordDecodeError::InvalidEncoding)?;
    let identity = reader
        .fixed_bytes()
        .map_err(|_| NameRecordDecodeError::InvalidEncoding)?;
    let label = reader
        .text()
        .map_err(|_| NameRecordDecodeError::InvalidEncoding)?;
    validate_label(&label).map_err(NameRecordDecodeError::InvalidLabel)?;
    let op = NameOperation::from_tag(
        reader
            .uint()
            .map_err(|_| NameRecordDecodeError::InvalidEncoding)?,
    )?;
    let version = reader
        .uint()
        .map_err(|_| NameRecordDecodeError::InvalidEncoding)?;
    let not_after = reader
        .uint()
        .map_err(|_| NameRecordDecodeError::InvalidEncoding)?;
    let signature_owner = reader
        .fixed_bytes()
        .map_err(|_| NameRecordDecodeError::InvalidEncoding)?;
    Ok(OwnerSignedNameRecord {
        ver,
        network_id,
        identity,
        label,
        op,
        version,
        not_after,
        signature_owner,
    })
}

struct UnsignedNameWire<'a>(&'a OwnerSignedNameRecord);

impl Serialize for UnsignedNameWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let record = self.0;
        let mut array = serializer.serialize_tuple(7)?;
        array.serialize_element(&record.ver)?;
        array.serialize_element(&serde_bytes::Bytes::new(&record.network_id))?;
        array.serialize_element(&serde_bytes::Bytes::new(&record.identity))?;
        array.serialize_element(&record.label)?;
        array.serialize_element(&record.op.tag())?;
        array.serialize_element(&record.version)?;
        array.serialize_element(&record.not_after)?;
        array.end()
    }
}

struct OwnerNameWire<'a>(&'a OwnerSignedNameRecord);

impl Serialize for OwnerNameWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let record = self.0;
        let mut array = serializer.serialize_tuple(8)?;
        array.serialize_element(&record.ver)?;
        array.serialize_element(&serde_bytes::Bytes::new(&record.network_id))?;
        array.serialize_element(&serde_bytes::Bytes::new(&record.identity))?;
        array.serialize_element(&record.label)?;
        array.serialize_element(&record.op.tag())?;
        array.serialize_element(&record.version)?;
        array.serialize_element(&record.not_after)?;
        array.serialize_element(&serde_bytes::Bytes::new(&record.signature_owner))?;
        array.end()
    }
}

struct NetworkNameWire<'a>(&'a NameRecord);

impl Serialize for NetworkNameWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let record = self.0;
        let mut array = serializer.serialize_tuple(9)?;
        array.serialize_element(&record.ver)?;
        array.serialize_element(&serde_bytes::Bytes::new(&record.network_id))?;
        array.serialize_element(&serde_bytes::Bytes::new(&record.identity))?;
        array.serialize_element(&record.label)?;
        array.serialize_element(&record.op.tag())?;
        array.serialize_element(&record.version)?;
        array.serialize_element(&record.not_after)?;
        array.serialize_element(&serde_bytes::Bytes::new(&record.signature_owner))?;
        array.serialize_element(&serde_bytes::Bytes::new(&record.signature_network))?;
        array.end()
    }
}
