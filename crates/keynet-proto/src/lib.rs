#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::panic, clippy::unwrap_used, clippy::expect_used)]

//! Synchronous Keynet v0.4 address, identity-label, and local-conflict primitives.

use blake2::{
    Blake2sMac,
    digest::{
        KeyInit, Mac,
        consts::{U12, U15},
    },
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, ser::SerializeTuple};
use std::net::Ipv6Addr;

/// The Keynet address-format version defined by design section 13.6.
pub const ADDRESS_VERSION: u8 = 1;
const ADDRESS_KEY: &[u8] = b"keynet-addr-v1";
const IDENTITY_KEY: &[u8] = b"keynet-id-v1";
const ADDRESS_DIGEST_BYTES: usize = 15;
const IDENTITY_DIGEST_BYTES: usize = 12;
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A Keynet network identifier from design sections 3.2 and 13.6.
pub type NetworkId = [u8; 32];
/// A Keynet identity public key from design sections 3.2 and 13.4.
pub type Identity = [u8; 32];

/// An initialization failure for a fixed-size BLAKE2s derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerivationError {
    /// The requested BLAKE2s variable-output size was rejected by the implementation.
    InvalidOutputSize,
}

/// One normalized Keynet address group from design sections 3.2 and 3.4.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AddressGroup([u8; 16]);

impl AddressGroup {
    /// Normalizes an address into its group by clearing the final mode bit (§3.2).
    #[must_use]
    pub fn from_address_bytes(address: [u8; 16]) -> Self {
        Self(group_bytes(address))
    }
    /// Returns the native IPv6 service address with mode zero (§3.2).
    #[must_use]
    pub fn n6_bytes(self) -> [u8; 16] {
        self.0
    }
    /// Returns the translated IPv4-service address with mode one (§3.2).
    #[must_use]
    pub fn n4_bytes(self) -> [u8; 16] {
        n4_bytes_from_group(self.0)
    }
    /// Returns the native IPv6 service address as an `Ipv6Addr` (§3.2).
    #[must_use]
    pub fn n6(self) -> Ipv6Addr {
        Ipv6Addr::from(self.n6_bytes())
    }
    /// Returns the translated IPv4-service address as an `Ipv6Addr` (§3.2).
    #[must_use]
    pub fn n4(self) -> Ipv6Addr {
        Ipv6Addr::from(self.n4_bytes())
    }
    /// Returns the normalized sixteen-byte group representation (§3.2).
    #[must_use]
    pub fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Derives the address group for a network and identity using section 3.2.
pub fn derive_address_group(
    network_id: &NetworkId,
    identity: &Identity,
) -> Result<AddressGroup, DerivationError> {
    let mut input = [0_u8; 65];
    input[0] = ADDRESS_VERSION;
    input[1..33].copy_from_slice(network_id);
    input[33..].copy_from_slice(identity);
    let digest = address_digest(&input)?;
    let mut address = [0_u8; 16];
    address[0] = 0xfd;
    address[1..].copy_from_slice(&digest);
    Ok(AddressGroup::from_address_bytes(address))
}

/// Derives the mode-zero N6 address bytes for a network and identity (§3.2).
pub fn n6_bytes(network_id: &NetworkId, identity: &Identity) -> Result<[u8; 16], DerivationError> {
    Ok(derive_address_group(network_id, identity)?.n6_bytes())
}
/// Derives the mode-one N4 address bytes for a network and identity (§3.2).
pub fn n4_bytes(network_id: &NetworkId, identity: &Identity) -> Result<[u8; 16], DerivationError> {
    Ok(derive_address_group(network_id, identity)?.n4_bytes())
}
/// Derives the mode-zero N6 address for a network and identity (§3.2).
pub fn n6(network_id: &NetworkId, identity: &Identity) -> Result<Ipv6Addr, DerivationError> {
    Ok(derive_address_group(network_id, identity)?.n6())
}
/// Derives the mode-one N4 address for a network and identity (§3.2).
pub fn n4(network_id: &NetworkId, identity: &Identity) -> Result<Ipv6Addr, DerivationError> {
    Ok(derive_address_group(network_id, identity)?.n4())
}

/// Clears the mode bit of a raw sixteen-byte Keynet address (§3.2).
#[must_use]
pub fn group_bytes(mut address: [u8; 16]) -> [u8; 16] {
    address[15] &= !1;
    address
}
/// Clears the mode bit of an IPv6 Keynet address (§3.2).
#[must_use]
pub fn group_ipv6(address: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from(group_bytes(address.octets()))
}

/// Derives the immutable lowercase base32 identity label from section 7.1.
pub fn identity_label(identity: &Identity) -> Result<String, DerivationError> {
    let digest = identity_digest(identity)?;
    let mut label = String::with_capacity(20);
    for character_index in 0..20 {
        let mut value = 0_u8;
        for bit_index in 0..5 {
            let input_bit = character_index * 5 + bit_index;
            let bit = if input_bit < 96 {
                (digest[input_bit / 8] >> (7 - input_bit % 8)) & 1
            } else {
                0
            };
            value = (value << 1) | bit;
        }
        label.push(char::from(BASE32[usize::from(value)]));
    }
    Ok(label)
}

/// An address group together with its network and cryptographic owner (§3.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupOwner {
    /// The network that owns the group.
    pub network_id: NetworkId,
    /// The full identity that owns the group.
    pub identity: Identity,
    /// The normalized two-address group owned by the identity.
    pub group: AddressGroup,
}
/// A collision report identifying the already-configured owner (§3.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupConflict {
    /// The owner whose group conflicts with the candidate.
    pub conflicting_owner: GroupOwner,
}

/// Compares a candidate owner to every supplied owner for a group collision (§3.4).
///
/// When `allow_idempotent_owner` is true, the exact network-and-identity owner is skipped.
#[must_use]
pub fn compare_group_owners(
    candidate: GroupOwner,
    existing: &[GroupOwner],
    allow_idempotent_owner: bool,
) -> Option<GroupConflict> {
    for owner in existing {
        if candidate.group != owner.group {
            continue;
        }
        let idempotent = allow_idempotent_owner
            && candidate.network_id == owner.network_id
            && candidate.identity == owner.identity;
        if !idempotent {
            return Some(GroupConflict {
                conflicting_owner: *owner,
            });
        }
    }
    None
}
/// Checks a peer against all local and peer groups before installation (§3.4).
pub fn check_peer_group(
    candidate: GroupOwner,
    local_groups: &[GroupOwner],
    peer_groups: &[GroupOwner],
) -> Result<(), GroupConflict> {
    if let Some(conflict) = compare_group_owners(candidate, local_groups, false) {
        return Err(conflict);
    }
    if let Some(conflict) = compare_group_owners(candidate, peer_groups, true) {
        return Err(conflict);
    }
    Ok(())
}
/// Checks a newly joined local network group against every existing owner (§3.4).
pub fn check_new_local_group(
    candidate: GroupOwner,
    local_groups: &[GroupOwner],
    peer_groups: &[GroupOwner],
) -> Result<(), GroupConflict> {
    if let Some(conflict) = compare_group_owners(candidate, local_groups, false) {
        return Err(conflict);
    }
    if let Some(conflict) = compare_group_owners(candidate, peer_groups, false) {
        return Err(conflict);
    }
    Ok(())
}

fn n4_bytes_from_group(mut group: [u8; 16]) -> [u8; 16] {
    group[15] |= 1;
    group
}
fn address_digest(input: &[u8]) -> Result<[u8; ADDRESS_DIGEST_BYTES], DerivationError> {
    let mut hasher = <Blake2sMac<U15> as KeyInit>::new_from_slice(ADDRESS_KEY)
        .map_err(|_| DerivationError::InvalidOutputSize)?;
    hasher.update(input);
    let digest = hasher.finalize().into_bytes();
    let mut output = [0_u8; ADDRESS_DIGEST_BYTES];
    output.copy_from_slice(&digest);
    Ok(output)
}

fn identity_digest(input: &[u8]) -> Result<[u8; IDENTITY_DIGEST_BYTES], DerivationError> {
    let mut hasher = <Blake2sMac<U12> as KeyInit>::new_from_slice(IDENTITY_KEY)
        .map_err(|_| DerivationError::InvalidOutputSize)?;
    hasher.update(input);
    let digest = hasher.finalize().into_bytes();
    let mut output = [0_u8; IDENTITY_DIGEST_BYTES];
    output.copy_from_slice(&digest);
    Ok(output)
}

const KEY_BINDING_CONTEXT: &[u8] = b"keynet/key-binding/v1";
const KEY_BINDING_UNSIGNED_MIN_BYTES: usize = 107;
const KEY_BINDING_UNSIGNED_MAX_BYTES: usize = 131;
const KEY_BINDING_SIGNED_MIN_BYTES: usize = 173;
const KEY_BINDING_SIGNED_MAX_BYTES: usize = 197;

/// A version-one signed assertion of an identity's WireGuard key (§2.2, §§13.1-13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyBinding {
    /// The record version, which is one for this schema (§2.2).
    pub ver: u8,
    /// The network to which this binding belongs (§2.2).
    pub network_id: NetworkId,
    /// The Ed25519 public identity which signs this binding (§2.2).
    pub identity: Identity,
    /// The asserted WireGuard public key (§2.2).
    pub wireguard_key: [u8; 32],
    /// The monotonic per-identity binding generation (§2.2, §13.3).
    pub generation: u64,
    /// The inclusive Unix-second validity start (§2.2, §13.3).
    pub not_before: u64,
    /// The exclusive Unix-second validity end (§2.2, §13.3).
    pub not_after: u64,
    /// The Ed25519 signature of the prescribed seven-field preimage (§2.2, §13.2).
    pub signature: [u8; 64],
}

/// A failure to parse the canonical KeyBinding CBOR schema (§13.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyBindingDecodeError {
    /// The record was not the exact bounded canonical eight-field CBOR array.
    InvalidEncoding,
    /// The record used a version other than one.
    UnsupportedVersion,
}

/// A failure to create or verify a KeyBinding signature (§2.2, §13.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyBindingSignatureError {
    /// The in-memory record does not use the version-one KeyBinding schema.
    UnsupportedVersion,
    /// The supplied signing key does not have the record's identity public key.
    SignerIdentityMismatch,
    /// The identity bytes cannot be decoded as a strict Ed25519 public key.
    InvalidIdentityKey,
    /// The signature did not verify under the binding identity.
    InvalidSignature,
}

/// A KeyBinding interval failure (§13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyBindingTimeError {
    /// The interval is empty or inverted.
    InvalidInterval,
    /// The supplied Unix second is outside the half-open interval.
    NotCurrent,
}

/// A KeyBinding whose signature was verified but whose time interval was not yet considered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedKeyBinding(KeyBinding);

/// A KeyBinding verified cryptographically and current at an explicit Unix second.
///
/// The checked payload is private so callers cannot forge an installation-capable value.
///
/// ```compile_fail
/// let _ = keynet_proto::CurrentKeyBinding(unimplemented!());
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentKeyBinding(KeyBinding);

impl KeyBinding {
    /// Encodes this record as the canonical eight-field signed array (§2.2, §13.1-13.2).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(KEY_BINDING_SIGNED_MAX_BYTES);
        let result = ciborium::ser::into_writer(&SignedBindingWire(self), &mut encoded);
        debug_assert!(result.is_ok());
        debug_assert!(
            (KEY_BINDING_SIGNED_MIN_BYTES..=KEY_BINDING_SIGNED_MAX_BYTES).contains(&encoded.len())
        );
        encoded
    }

    /// Returns the canonical seven-field unsigned array signed by this record (§13.2).
    #[must_use]
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(KEY_BINDING_UNSIGNED_MAX_BYTES);
        let result = ciborium::ser::into_writer(&UnsignedBindingWire(self), &mut encoded);
        debug_assert!(result.is_ok());
        debug_assert!(
            (KEY_BINDING_UNSIGNED_MIN_BYTES..=KEY_BINDING_UNSIGNED_MAX_BYTES)
                .contains(&encoded.len())
        );
        encoded
    }

    /// Returns the exact Ed25519 message context and unsigned array (§2.2, §13.2).
    #[must_use]
    pub fn signing_preimage(&self) -> Vec<u8> {
        let unsigned = self.unsigned_bytes();
        let mut preimage = Vec::with_capacity(KEY_BINDING_CONTEXT.len() + unsigned.len());
        preimage.extend_from_slice(KEY_BINDING_CONTEXT);
        preimage.extend_from_slice(&unsigned);
        preimage
    }

    /// Signs this binding with its identity's caller-provided Ed25519 signing key (§2.2, §13.2).
    pub fn sign(&mut self, signer: &SigningKey) -> Result<(), KeyBindingSignatureError> {
        if self.ver != 1 {
            return Err(KeyBindingSignatureError::UnsupportedVersion);
        }
        if signer.verifying_key().to_bytes() != self.identity {
            return Err(KeyBindingSignatureError::SignerIdentityMismatch);
        }
        self.signature = signer.sign(&self.signing_preimage()).to_bytes();
        Ok(())
    }

    /// Decodes one strict canonical signed KeyBinding without performing verification (§2.2, §13.1).
    pub fn decode(encoded: &[u8]) -> Result<Self, KeyBindingDecodeError> {
        if !(KEY_BINDING_SIGNED_MIN_BYTES..=KEY_BINDING_SIGNED_MAX_BYTES).contains(&encoded.len()) {
            return Err(KeyBindingDecodeError::InvalidEncoding);
        }
        let mut reader = BindingCborReader::new(encoded);
        reader.array(8)?;
        let ver =
            u8::try_from(reader.uint()?).map_err(|_| KeyBindingDecodeError::InvalidEncoding)?;
        let network_id = reader.bytes()?;
        let identity = reader.bytes()?;
        let wireguard_key = reader.bytes()?;
        let generation = reader.uint()?;
        let not_before = reader.uint()?;
        let not_after = reader.uint()?;
        let signature = reader.signature()?;
        if !reader.finished() {
            return Err(KeyBindingDecodeError::InvalidEncoding);
        }
        if ver != 1 {
            return Err(KeyBindingDecodeError::UnsupportedVersion);
        }
        let binding = Self {
            ver,
            network_id,
            identity,
            wireguard_key,
            generation,
            not_before,
            not_after,
            signature,
        };
        let decoded: DecodedBindingWire = ciborium::de::from_reader(encoded)
            .map_err(|_| KeyBindingDecodeError::InvalidEncoding)?;
        if decoded.into_binding()? != binding {
            return Err(KeyBindingDecodeError::InvalidEncoding);
        }
        Ok(binding)
    }

    /// Verifies this binding's Ed25519 signature without considering its interval (§2.2, §13.2-13.3).
    pub fn verify(&self) -> Result<VerifiedKeyBinding, KeyBindingSignatureError> {
        if self.ver != 1 {
            return Err(KeyBindingSignatureError::UnsupportedVersion);
        }
        let verifying_key = VerifyingKey::from_bytes(&self.identity)
            .map_err(|_| KeyBindingSignatureError::InvalidIdentityKey)?;
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify_strict(&self.signing_preimage(), &signature)
            .map_err(|_| KeyBindingSignatureError::InvalidSignature)?;
        Ok(VerifiedKeyBinding(*self))
    }

    /// Decodes canonical CBOR before checking its signature, preserving rejection precedence (§13.1-13.2).
    pub fn decode_and_verify(
        encoded: &[u8],
    ) -> Result<VerifiedKeyBinding, KeyBindingVerificationError> {
        Self::decode(encoded)
            .map_err(KeyBindingVerificationError::Decode)?
            .verify()
            .map_err(KeyBindingVerificationError::Signature)
    }

    /// Checks that this record has a nonempty interval without consulting a clock (§13.3).
    pub fn validate_interval(&self) -> Result<(), KeyBindingTimeError> {
        if self.not_before >= self.not_after {
            return Err(KeyBindingTimeError::InvalidInterval);
        }
        Ok(())
    }
}

/// A parse-or-signature failure returned by [`KeyBinding::decode_and_verify`] (§13.1-13.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyBindingVerificationError {
    /// Canonical parsing failed before any signature operation.
    Decode(KeyBindingDecodeError),
    /// Signature verification failed after canonical parsing succeeded.
    Signature(KeyBindingSignatureError),
}

impl VerifiedKeyBinding {
    /// Returns the verified record without performing any interval validation (§13.3).
    #[must_use]
    pub fn binding(self) -> KeyBinding {
        self.0
    }

    /// Validates this verified record at an explicit Unix second (§13.3).
    pub fn validate_current(self, now: u64) -> Result<CurrentKeyBinding, KeyBindingTimeError> {
        self.0.validate_interval()?;
        if now < self.0.not_before || now >= self.0.not_after {
            return Err(KeyBindingTimeError::NotCurrent);
        }
        Ok(CurrentKeyBinding(self.0))
    }
}

impl CurrentKeyBinding {
    /// Returns the checked binding for a proposed installation (§2.2, §13.3).
    #[must_use]
    pub fn binding(self) -> KeyBinding {
        self.0
    }

    /// Evaluates an installation without mutating the supplied scoped state (§2.2, §13.3).
    pub fn installation_decision(
        self,
        state: &KeyBindingState,
    ) -> Result<InstallationDecision, KeyBindingTransitionError> {
        evaluate_key_binding_installation(state, self)
    }
}

/// A `(network_id, identity)` namespace for KeyBinding high-water state (§13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyBindingScope {
    /// The scoped network identifier.
    pub network_id: NetworkId,
    /// The scoped identity public key.
    pub identity: Identity,
}

/// The installed generation and WireGuard key for one scope (§13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedKeyBinding {
    /// The highest successfully installed generation.
    pub generation: u64,
    /// The installed WireGuard public key for that generation.
    pub wireguard_key: [u8; 32],
}

/// A latched equal-generation disagreement which disables its two keys (§2.2, §13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyBindingConflict {
    /// The disputed generation.
    pub generation: u64,
    /// The previously committed WireGuard key.
    pub first_key: [u8; 32],
    /// The authenticated conflicting WireGuard key.
    pub second_key: [u8; 32],
}

/// Caller-owned high-water and conflict information for one binding scope (§13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyBindingState {
    /// The scope to which all state in this value belongs.
    pub scope: KeyBindingScope,
    /// The optionally installed binding high-water and key.
    pub committed: Option<CommittedKeyBinding>,
    /// The optional inclusive revocation high-water.
    pub revoked_through: Option<u64>,
    /// The optional equal-generation conflict latch.
    pub conflict: Option<KeyBindingConflict>,
}

/// A proposed state replacement resulting from a successful install or conflict latch (§13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyBindingTransition {
    /// The complete replacement state; callers choose whether and when to commit it.
    pub next_state: KeyBindingState,
}

/// The pure installation outcome for a signature- and time-checked binding (§2.2, §13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationDecision {
    /// A new binding should be installed using the supplied state transition.
    Install(KeyBindingTransition),
    /// The candidate exactly matches an installed binding and needs no transition.
    Idempotent,
    /// An authenticated equal-generation different-key record should latch a conflict.
    LatchConflict(KeyBindingTransition),
}

/// A rejected KeyBinding state transition (§13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyBindingTransitionError {
    /// The candidate does not belong to the supplied state scope.
    ScopeMismatch,
    /// The candidate generation is below the committed high-water.
    Rollback,
    /// The candidate generation is at or below the inclusive revocation high-water.
    Revoked,
    /// A conflict remains latched until a strictly higher candidate is accepted.
    ConflictLatched,
}

/// Evaluates a checked KeyBinding installation without modifying caller-owned state (§2.2, §13.3).
pub fn evaluate_key_binding_installation(
    state: &KeyBindingState,
    candidate: CurrentKeyBinding,
) -> Result<InstallationDecision, KeyBindingTransitionError> {
    let binding = candidate.binding();
    if state.scope.network_id != binding.network_id || state.scope.identity != binding.identity {
        return Err(KeyBindingTransitionError::ScopeMismatch);
    }
    if state
        .revoked_through
        .is_some_and(|generation| binding.generation <= generation)
    {
        return Err(KeyBindingTransitionError::Revoked);
    }
    if let Some(conflict) = state.conflict {
        if binding.generation <= conflict.generation {
            return Err(KeyBindingTransitionError::ConflictLatched);
        }
        return Ok(InstallationDecision::Install(KeyBindingTransition {
            next_state: KeyBindingState {
                committed: Some(CommittedKeyBinding {
                    generation: binding.generation,
                    wireguard_key: binding.wireguard_key,
                }),
                conflict: None,
                ..*state
            },
        }));
    }
    if let Some(committed) = state.committed {
        if binding.generation < committed.generation {
            return Err(KeyBindingTransitionError::Rollback);
        }
        if binding.generation == committed.generation {
            if binding.wireguard_key == committed.wireguard_key {
                return Ok(InstallationDecision::Idempotent);
            }
            return Ok(InstallationDecision::LatchConflict(KeyBindingTransition {
                next_state: KeyBindingState {
                    committed: None,
                    conflict: Some(KeyBindingConflict {
                        generation: binding.generation,
                        first_key: committed.wireguard_key,
                        second_key: binding.wireguard_key,
                    }),
                    ..*state
                },
            }));
        }
    }
    Ok(InstallationDecision::Install(KeyBindingTransition {
        next_state: KeyBindingState {
            committed: Some(CommittedKeyBinding {
                generation: binding.generation,
                wireguard_key: binding.wireguard_key,
            }),
            conflict: None,
            ..*state
        },
    }))
}

struct UnsignedBindingWire<'a>(&'a KeyBinding);

impl Serialize for UnsignedBindingWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let binding = self.0;
        let mut array = serializer.serialize_tuple(7)?;
        array.serialize_element(&binding.ver)?;
        array.serialize_element(&serde_bytes::Bytes::new(&binding.network_id))?;
        array.serialize_element(&serde_bytes::Bytes::new(&binding.identity))?;
        array.serialize_element(&serde_bytes::Bytes::new(&binding.wireguard_key))?;
        array.serialize_element(&binding.generation)?;
        array.serialize_element(&binding.not_before)?;
        array.serialize_element(&binding.not_after)?;
        array.end()
    }
}

struct SignedBindingWire<'a>(&'a KeyBinding);

impl Serialize for SignedBindingWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let binding = self.0;
        let mut array = serializer.serialize_tuple(8)?;
        array.serialize_element(&binding.ver)?;
        array.serialize_element(&serde_bytes::Bytes::new(&binding.network_id))?;
        array.serialize_element(&serde_bytes::Bytes::new(&binding.identity))?;
        array.serialize_element(&serde_bytes::Bytes::new(&binding.wireguard_key))?;
        array.serialize_element(&binding.generation)?;
        array.serialize_element(&binding.not_before)?;
        array.serialize_element(&binding.not_after)?;
        array.serialize_element(&serde_bytes::Bytes::new(&binding.signature))?;
        array.end()
    }
}

#[derive(Deserialize)]
struct DecodedBindingWire(
    u8,
    serde_bytes::ByteBuf,
    serde_bytes::ByteBuf,
    serde_bytes::ByteBuf,
    u64,
    u64,
    u64,
    serde_bytes::ByteBuf,
);

impl DecodedBindingWire {
    fn into_binding(self) -> Result<KeyBinding, KeyBindingDecodeError> {
        Ok(KeyBinding {
            ver: self.0,
            network_id: fixed_array(&self.1)?,
            identity: fixed_array(&self.2)?,
            wireguard_key: fixed_array(&self.3)?,
            generation: self.4,
            not_before: self.5,
            not_after: self.6,
            signature: fixed_array(&self.7)?,
        })
    }
}

fn fixed_array<const N: usize>(
    bytes: &serde_bytes::ByteBuf,
) -> Result<[u8; N], KeyBindingDecodeError> {
    if bytes.len() != N {
        return Err(KeyBindingDecodeError::InvalidEncoding);
    }
    let mut fixed = [0_u8; N];
    fixed.copy_from_slice(bytes);
    Ok(fixed)
}

struct BindingCborReader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> BindingCborReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn array(&mut self, expected: u64) -> Result<(), KeyBindingDecodeError> {
        let (major, value) = self.head()?;
        if major != 4 || value != expected {
            return Err(KeyBindingDecodeError::InvalidEncoding);
        }
        Ok(())
    }

    fn uint(&mut self) -> Result<u64, KeyBindingDecodeError> {
        let (major, value) = self.head()?;
        if major != 0 {
            return Err(KeyBindingDecodeError::InvalidEncoding);
        }
        Ok(value)
    }

    fn bytes(&mut self) -> Result<[u8; 32], KeyBindingDecodeError> {
        self.fixed_bytes()
    }

    fn signature(&mut self) -> Result<[u8; 64], KeyBindingDecodeError> {
        self.fixed_bytes()
    }

    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], KeyBindingDecodeError> {
        let (major, length) = self.head()?;
        if major != 2 || length != N as u64 {
            return Err(KeyBindingDecodeError::InvalidEncoding);
        }
        let end = self
            .position
            .checked_add(N)
            .filter(|end| *end <= self.input.len())
            .ok_or(KeyBindingDecodeError::InvalidEncoding)?;
        let mut output = [0_u8; N];
        output.copy_from_slice(&self.input[self.position..end]);
        self.position = end;
        Ok(output)
    }

    fn head(&mut self) -> Result<(u8, u64), KeyBindingDecodeError> {
        let initial = self.take()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        let (value, width) = match additional {
            value @ 0..=23 => (u64::from(value), 0),
            24 => (u64::from(self.take()?), 1),
            25 => (
                u64::from(u16::from_be_bytes([self.take()?, self.take()?])),
                2,
            ),
            26 => (
                u64::from(u32::from_be_bytes([
                    self.take()?,
                    self.take()?,
                    self.take()?,
                    self.take()?,
                ])),
                4,
            ),
            27 => (
                u64::from_be_bytes([
                    self.take()?,
                    self.take()?,
                    self.take()?,
                    self.take()?,
                    self.take()?,
                    self.take()?,
                    self.take()?,
                    self.take()?,
                ]),
                8,
            ),
            _ => return Err(KeyBindingDecodeError::InvalidEncoding),
        };
        let minimal = match width {
            0 => true,
            1 => value >= 24,
            2 => value > u64::from(u8::MAX),
            4 => value > u64::from(u16::MAX),
            8 => value > u64::from(u32::MAX),
            _ => false,
        };
        if !minimal {
            return Err(KeyBindingDecodeError::InvalidEncoding);
        }
        Ok((major, value))
    }

    fn take(&mut self) -> Result<u8, KeyBindingDecodeError> {
        let value = self
            .input
            .get(self.position)
            .copied()
            .ok_or(KeyBindingDecodeError::InvalidEncoding)?;
        self.position += 1;
        Ok(value)
    }

    fn finished(&self) -> bool {
        self.position == self.input.len()
    }
}
