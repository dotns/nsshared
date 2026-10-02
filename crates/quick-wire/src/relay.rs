use crate::{
    CurrentKeyBinding, Identity, Intro, IntroAck, KeyBinding, NetworkId, RelayIdentifier,
    codec::CborReader,
};
use blake2::{
    Blake2sMac,
    digest::{KeyInit as BlakeKeyInit, Mac as BlakeMac, consts::U16},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::Hmac;
use serde::{Serialize, ser::SerializeTuple};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// The exact relay wire magic (§13.5).
pub const RELAY_MAGIC: [u8; 4] = *b"KNR1";
/// The exact relay header length (§13.5).
pub const RELAY_HEADER_BYTES: usize = 37;
/// The maximum complete relay datagram length (§§13.5-13.6).
pub const MAX_RELAY_DATAGRAM_BYTES: usize = 2048;
/// The maximum complete non-DATA relay datagram length (§§13.5-13.6).
pub const MAX_RELAY_CONTROL_BYTES: usize = 1200;
/// The maximum opaque DATA body length (§§13.5-13.6).
pub const MAX_RELAY_DATA_BYTES: usize = 2011;

const REGISTER_CONTEXT: &[u8] = b"keynet/relay-register/v1";
const SESSION_CONTEXT: &[u8] = b"keynet/relay-session/v1";
const CONTROL_CONTEXT: &[u8] = b"keynet/relay-ctl/v1";
const REPLY_CONTEXT: &[u8] = b"keynet/relay-reply/v1";
const SLOT_KEY: &[u8] = b"keynet-relay-slot-v1";

/// A sixteen-byte relay slot identifier (§§13.4-13.6).
pub type SlotId = [u8; 16];

/// Relay datagram type tags fixed by section 13.5.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelayType {
    /// REGISTER, node to relay.
    Register = 1,
    /// REGISTERED, relay to node.
    Registered = 2,
    /// PRESENCE, node to relay.
    Presence = 3,
    /// REFLECT, node to relay.
    Reflect = 4,
    /// REFLECTED, relay to node.
    Reflected = 5,
    /// INTRO, node to node.
    Intro = 6,
    /// INTRO_ACK, node to node.
    IntroAck = 7,
    /// DATA, node to node.
    Data = 8,
    /// STATUS, relay to node.
    Status = 9,
    /// REVOKE, node to relay.
    Revoke = 10,
}

impl TryFrom<u8> for RelayType {
    type Error = RelayDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Register),
            2 => Ok(Self::Registered),
            3 => Ok(Self::Presence),
            4 => Ok(Self::Reflect),
            5 => Ok(Self::Reflected),
            6 => Ok(Self::Intro),
            7 => Ok(Self::IntroAck),
            8 => Ok(Self::Data),
            9 => Ok(Self::Status),
            10 => Ok(Self::Revoke),
            _ => Err(RelayDecodeError::UnsupportedType),
        }
    }
}

/// The exact 37-byte KNR1 relay header (§13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayHeader {
    /// The relay datagram type.
    pub message_type: RelayType,
    /// The source slot, or zero for the relay.
    pub src: SlotId,
    /// The destination slot, or zero for the relay.
    pub dst: SlotId,
}

impl RelayHeader {
    /// Constructs a header only when its slot direction matches its type (§13.5).
    pub fn new(
        message_type: RelayType,
        src: SlotId,
        dst: SlotId,
    ) -> Result<Self, RelayEncodeError> {
        let header = Self {
            message_type,
            src,
            dst,
        };
        header.validate_direction()?;
        Ok(header)
    }

    /// Encodes the exact 37-byte KNR1 header (§13.5).
    pub fn encode(self) -> Result<[u8; RELAY_HEADER_BYTES], RelayEncodeError> {
        self.validate_direction()?;
        let mut output = [0; RELAY_HEADER_BYTES];
        output[..4].copy_from_slice(&RELAY_MAGIC);
        output[4] = self.message_type as u8;
        output[5..21].copy_from_slice(&self.src);
        output[21..].copy_from_slice(&self.dst);
        Ok(output)
    }

    /// Decodes exactly one canonical 37-byte KNR1 header (§13.5).
    pub fn decode(encoded: &[u8]) -> Result<Self, RelayDecodeError> {
        if encoded.len() != RELAY_HEADER_BYTES {
            return Err(RelayDecodeError::InvalidLength);
        }
        if encoded[..4] != RELAY_MAGIC {
            return Err(RelayDecodeError::InvalidMagic);
        }
        let mut src = [0; 16];
        src.copy_from_slice(&encoded[5..21]);
        let mut dst = [0; 16];
        dst.copy_from_slice(&encoded[21..37]);
        let header = Self {
            message_type: RelayType::try_from(encoded[4])?,
            src,
            dst,
        };
        header
            .validate_direction()
            .map_err(|_| RelayDecodeError::InvalidDirection)?;
        Ok(header)
    }

    fn validate_direction(self) -> Result<(), RelayEncodeError> {
        let src_zero = self.src == [0; 16];
        let dst_zero = self.dst == [0; 16];
        let valid = match self.message_type {
            RelayType::Register | RelayType::Presence | RelayType::Reflect | RelayType::Revoke => {
                !src_zero && dst_zero
            }
            RelayType::Registered | RelayType::Reflected | RelayType::Status => {
                src_zero && !dst_zero
            }
            RelayType::Intro | RelayType::IntroAck | RelayType::Data => !src_zero && !dst_zero,
        };
        if valid {
            Ok(())
        } else {
            Err(RelayEncodeError::InvalidDirection)
        }
    }
}

/// An observed UDP address encoded without IPv4 mapping (§13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedAddr {
    /// Four-byte IPv4 address and nonzero port.
    V4([u8; 4], u16),
    /// Sixteen-byte IPv6 address and nonzero port.
    V6([u8; 16], u16),
}

impl ObservedAddr {
    fn validate(self) -> Result<(), RelayEncodeError> {
        let port = match self {
            Self::V4(_, port) | Self::V6(_, port) => port,
        };
        if port == 0 {
            Err(RelayEncodeError::InvalidObservedAddress)
        } else {
            Ok(())
        }
    }
}

/// REGISTER body (§13.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Register {
    /// Complete signed KeyBinding.
    pub binding: KeyBinding,
    /// Per-relay, per-generation session incarnation.
    pub incarnation: u64,
    /// Unix-second registration timestamp.
    pub timestamp: u64,
    /// Node X25519 ephemeral public key.
    pub node_ephemeral: [u8; 32],
    /// Received relay name, preserved byte-for-byte as UTF-8.
    pub relay_name: String,
    /// Identity signature over the unsigned REGISTER.
    pub signature: [u8; 64],
}

/// REGISTERED body (§13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registered {
    /// Echoed session incarnation.
    pub incarnation: u64,
    /// Relay X25519 ephemeral public key.
    pub relay_ephemeral: [u8; 32],
    /// Presence time-to-live in seconds, inclusively 30 through 3600.
    pub presence_ttl_s: u32,
    /// UDP observation, or null on WSS.
    pub observed_addr: Option<ObservedAddr>,
    /// Zero for tentative setup, or the acknowledged PRESENCE sequence.
    pub ack_seq: u64,
    /// Relay reply MAC.
    pub mac: [u8; 32],
}

/// PRESENCE body (§13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Presence {
    /// Active session incarnation.
    pub incarnation: u64,
    /// Positive control sequence.
    pub seq: u64,
    /// Node control MAC.
    pub mac: [u8; 32],
}

/// REFLECT body (§13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reflect {
    /// Active session incarnation.
    pub incarnation: u64,
    /// Positive control sequence.
    pub seq: u64,
    /// Sixteen-byte reflection nonce.
    pub nonce: [u8; 16],
    /// Node control MAC.
    pub mac: [u8; 32],
}

/// REFLECTED body (§13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reflected {
    /// Active session incarnation.
    pub incarnation: u64,
    /// Echoed positive REFLECT sequence.
    pub seq: u64,
    /// Echoed sixteen-byte REFLECT nonce.
    pub nonce: [u8; 16],
    /// Required UDP observation.
    pub observed_addr: ObservedAddr,
    /// Relay reply MAC.
    pub mac: [u8; 32],
}

/// STATUS values fixed by section 13.5.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StatusCode {
    /// The requested destination is unavailable.
    NoDestination = 1,
    /// A processing or forwarding budget was exceeded.
    RateLimited = 2,
    /// The triggering datagram was too large.
    TooLarge = 3,
    /// The supplied generation or incarnation was stale.
    StaleGenerationOrIncarnation = 4,
    /// The input type is unsupported.
    UnsupportedType = 5,
    /// The sender is unregistered or its source does not match.
    SenderUnregisteredOrSourceMismatch = 6,
}

impl TryFrom<u8> for StatusCode {
    type Error = RelayDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::NoDestination),
            2 => Ok(Self::RateLimited),
            3 => Ok(Self::TooLarge),
            4 => Ok(Self::StaleGenerationOrIncarnation),
            5 => Ok(Self::UnsupportedType),
            6 => Ok(Self::SenderUnregisteredOrSourceMismatch),
            _ => Err(RelayDecodeError::InvalidBody),
        }
    }
}

/// STATUS body (§13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// The triggering type byte.
    pub type_in: u8,
    /// The triggering header destination.
    pub destination: SlotId,
    /// The failure status.
    pub status: StatusCode,
}

impl Status {
    /// Constructs STATUS header/body fields that echo a triggering header (§13.5).
    pub fn for_input(
        input: RelayHeader,
        status: StatusCode,
    ) -> Result<(RelayHeader, Self), RelayEncodeError> {
        input.validate_direction()?;
        if matches!(input.message_type, RelayType::Register | RelayType::Status) {
            return Err(RelayEncodeError::InvalidStatusTrigger);
        }
        let header = RelayHeader::new(RelayType::Status, [0; 16], input.src)?;
        Ok((
            header,
            Self {
                type_in: input.message_type as u8,
                destination: input.dst,
                status,
            },
        ))
    }

    /// Checks the exact STATUS destination/header echo relationship (§13.5).
    #[must_use]
    pub fn matches_input(self, header: RelayHeader, input: RelayHeader) -> bool {
        header.message_type == RelayType::Status
            && header.src == [0; 16]
            && header.dst == input.src
            && self.type_in == input.message_type as u8
            && self.destination == input.dst
    }
}

/// REVOKE reason values fixed by section 13.5.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RevokeReason {
    /// Key or session rotation.
    Rotation = 0,
    /// Graceful shutdown.
    Shutdown = 1,
}

impl TryFrom<u8> for RevokeReason {
    type Error = RelayDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Rotation),
            1 => Ok(Self::Shutdown),
            _ => Err(RelayDecodeError::InvalidBody),
        }
    }
}

/// REVOKE body (§13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Revoke {
    /// Active session incarnation.
    pub incarnation: u64,
    /// Positive control sequence.
    pub seq: u64,
    /// Rotation or shutdown reason.
    pub reason: RevokeReason,
    /// Node control MAC.
    pub mac: [u8; 32],
}

/// A typed relay body (§13.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayBody {
    /// REGISTER body.
    Register(Register),
    /// REGISTERED body.
    Registered(Registered),
    /// PRESENCE body.
    Presence(Presence),
    /// REFLECT body.
    Reflect(Reflect),
    /// REFLECTED body.
    Reflected(Reflected),
    /// Existing end-to-end INTRO body.
    Intro(Intro),
    /// Existing end-to-end INTRO_ACK body.
    IntroAck(IntroAck),
    /// Nonempty opaque WireGuard datagram.
    Data(Vec<u8>),
    /// STATUS body.
    Status(Status),
    /// REVOKE body.
    Revoke(Revoke),
}

impl RelayBody {
    /// Returns the exact type tag paired with this body.
    #[must_use]
    pub fn message_type(&self) -> RelayType {
        match self {
            Self::Register(_) => RelayType::Register,
            Self::Registered(_) => RelayType::Registered,
            Self::Presence(_) => RelayType::Presence,
            Self::Reflect(_) => RelayType::Reflect,
            Self::Reflected(_) => RelayType::Reflected,
            Self::Intro(_) => RelayType::Intro,
            Self::IntroAck(_) => RelayType::IntroAck,
            Self::Data(_) => RelayType::Data,
            Self::Status(_) => RelayType::Status,
            Self::Revoke(_) => RelayType::Revoke,
        }
    }
}

/// One complete bounded relay datagram (§13.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayDatagram {
    /// Exact KNR1 routing header.
    pub header: RelayHeader,
    /// Typed body matching the header type.
    pub body: RelayBody,
}

/// A relay encoding failure (§13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayEncodeError {
    /// Source and destination zero/nonzero rules do not match the type.
    InvalidDirection,
    /// Header and body types differ.
    TypeMismatch,
    /// A fixed body field, range, or count is invalid.
    InvalidBody,
    /// An observed address has a zero port or unsupported shape.
    InvalidObservedAddress,
    /// A relay name is outside the one-through-255-byte UTF-8 range.
    InvalidRelayName,
    /// A DATA body is empty or exceeds 2011 bytes.
    InvalidDataLength,
    /// A complete datagram exceeds its type budget.
    DatagramTooLarge,
    /// STATUS cannot be generated for REGISTER or STATUS.
    InvalidStatusTrigger,
}

/// A strict relay decoding failure (§§13.1, 13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayDecodeError {
    /// The complete input or exact header has an invalid length.
    InvalidLength,
    /// The magic is not KNR1.
    InvalidMagic,
    /// The type byte is not one through ten.
    UnsupportedType,
    /// Source and destination zero/nonzero rules do not match the type.
    InvalidDirection,
    /// The body is not its exact canonical schema.
    InvalidBody,
    /// The complete datagram exceeds its applicable bound.
    DatagramTooLarge,
}

impl RelayDatagram {
    /// Encodes exactly one complete bounded relay datagram (§13.5).
    pub fn encode(&self) -> Result<Vec<u8>, RelayEncodeError> {
        if self.header.message_type != self.body.message_type() {
            return Err(RelayEncodeError::TypeMismatch);
        }
        let header = self.header.encode()?;
        let body = encode_body(&self.body)?;
        let length = RELAY_HEADER_BYTES
            .checked_add(body.len())
            .ok_or(RelayEncodeError::DatagramTooLarge)?;
        let limit = if self.header.message_type == RelayType::Data {
            MAX_RELAY_DATAGRAM_BYTES
        } else {
            MAX_RELAY_CONTROL_BYTES
        };
        if length > limit {
            return Err(RelayEncodeError::DatagramTooLarge);
        }
        let mut output = Vec::with_capacity(length);
        output.extend_from_slice(&header);
        output.extend_from_slice(&body);
        Ok(output)
    }

    /// Decodes exactly one complete bounded relay datagram (§§13.1, 13.5).
    pub fn decode(encoded: &[u8]) -> Result<Self, RelayDecodeError> {
        if encoded.len() < RELAY_HEADER_BYTES {
            return Err(RelayDecodeError::InvalidLength);
        }
        if encoded.len() > MAX_RELAY_DATAGRAM_BYTES {
            return Err(RelayDecodeError::DatagramTooLarge);
        }
        let header = RelayHeader::decode(&encoded[..RELAY_HEADER_BYTES])?;
        if header.message_type != RelayType::Data && encoded.len() > MAX_RELAY_CONTROL_BYTES {
            return Err(RelayDecodeError::DatagramTooLarge);
        }
        let body = decode_body(header.message_type, &encoded[RELAY_HEADER_BYTES..])?;
        Ok(Self { header, body })
    }

    /// Decodes canonically before validating a REGISTER's cryptographic admission fields.
    pub fn decode_and_validate_register(
        encoded: &[u8],
        advertised_relay_name: &str,
        now: u64,
    ) -> Result<ValidatedRegister, RegisterInputError> {
        let datagram = Self::decode(encoded).map_err(RegisterInputError::Decode)?;
        let RelayBody::Register(register) = datagram.body else {
            return Err(RegisterInputError::Decode(RelayDecodeError::InvalidBody));
        };
        register
            .validate(datagram.header, advertised_relay_name, now)
            .map_err(RegisterInputError::Validation)
    }
}

/// A slot or relay-session cryptographic derivation failure (§§13.2, 13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayCryptoError {
    /// The keyed BLAKE2s setup failed.
    SlotDerivation,
    /// The derived slot is the reserved all-zero relay value.
    ReservedSlot,
    /// X25519 produced its forbidden all-zero shared secret.
    AllZeroSharedSecret,
    /// HKDF could not expand the requested fixed-size key.
    SessionKeyDerivation,
}

/// Derives the keyed BLAKE2s-16 slot id over complete owner inputs (§13.4).
pub fn derive_slot_id(
    network_id: &NetworkId,
    identity: &Identity,
) -> Result<SlotId, RelayCryptoError> {
    let mut mac = <Blake2sMac<U16> as BlakeKeyInit>::new_from_slice(SLOT_KEY)
        .map_err(|_| RelayCryptoError::SlotDerivation)?;
    BlakeMac::update(&mut mac, network_id);
    BlakeMac::update(&mut mac, identity);
    let slot: SlotId = BlakeMac::finalize(mac).into_bytes().into();
    if slot == [0; 16] {
        Err(RelayCryptoError::ReservedSlot)
    } else {
        Ok(slot)
    }
}

/// Computes X25519 and rejects its all-zero shared secret (§§13.2, 13.5).
pub fn derive_relay_shared_secret(
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
) -> Result<[u8; 32], RelayCryptoError> {
    let secret = StaticSecret::from(*local_private);
    let public = PublicKey::from(*remote_public);
    let shared = secret.diffie_hellman(&public).to_bytes();
    if shared == [0; 32] {
        Err(RelayCryptoError::AllZeroSharedSecret)
    } else {
        Ok(shared)
    }
}

/// Derives relay `sk` using the fixed HKDF transcript and field order (§§13.2, 13.5).
pub fn derive_relay_session_key(
    shared_secret: &[u8; 32],
    src_slot: &SlotId,
    incarnation: u64,
    node_ephemeral: &[u8; 32],
    relay_ephemeral: &[u8; 32],
    reg_hash: &[u8; 32],
) -> Result<[u8; 32], RelayCryptoError> {
    if src_slot == &[0; 16] {
        return Err(RelayCryptoError::ReservedSlot);
    }
    if shared_secret == &[0; 32] {
        return Err(RelayCryptoError::AllZeroSharedSecret);
    }
    let mut info = Vec::with_capacity(SESSION_CONTEXT.len() + 16 + 8 + 32 + 32 + 32);
    info.extend_from_slice(SESSION_CONTEXT);
    info.extend_from_slice(src_slot);
    info.extend_from_slice(&incarnation.to_be_bytes());
    info.extend_from_slice(node_ephemeral);
    info.extend_from_slice(relay_ephemeral);
    info.extend_from_slice(reg_hash);
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut output = [0; 32];
    hkdf.expand(&info, &mut output)
        .map_err(|_| RelayCryptoError::SessionKeyDerivation)?;
    Ok(output)
}

/// A REGISTER validation failure after canonical decoding (§13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterValidationError {
    /// The header is not a valid REGISTER header.
    InvalidHeader,
    /// The relay name differs or is outside the prescribed byte range.
    RelayNameMismatch,
    /// The timestamp is outside the inclusive 120-second window.
    TimestampOutsideWindow,
    /// The binding signature is invalid.
    InvalidBindingSignature,
    /// The binding is not current at the supplied Unix second.
    BindingNotCurrent,
    /// The header source is not the slot derived from the complete owner.
    SourceSlotMismatch,
    /// The REGISTER signature is invalid.
    InvalidSignature,
    /// The signer does not match the binding identity.
    SignerIdentityMismatch,
}

/// A canonical-decode or REGISTER-validation failure, in rejection order (§§13.1, 13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterInputError {
    /// Datagram decoding failed before any signature verification.
    Decode(RelayDecodeError),
    /// The decoded REGISTER failed stateless admission validation.
    Validation(RegisterValidationError),
}

/// A REGISTER whose binding, timestamp, source, relay name, and signatures are checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRegister {
    register: Register,
    binding: CurrentKeyBinding,
}

impl ValidatedRegister {
    /// Returns the checked REGISTER.
    #[must_use]
    pub fn register(&self) -> &Register {
        &self.register
    }

    /// Returns the signature- and time-checked nested binding.
    #[must_use]
    pub fn binding(&self) -> CurrentKeyBinding {
        self.binding
    }
}

impl Register {
    /// Returns the canonical unsigned five-field REGISTER array (§13.2).
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, RelayEncodeError> {
        validate_relay_name(&self.relay_name)?;
        Ok(serialize(&UnsignedRegisterWire(self)))
    }

    /// Returns the exact REGISTER Ed25519 preimage (§13.2).
    pub fn signing_preimage(&self) -> Result<Vec<u8>, RelayEncodeError> {
        let unsigned = self.unsigned_bytes()?;
        let mut output = Vec::with_capacity(REGISTER_CONTEXT.len() + unsigned.len());
        output.extend_from_slice(REGISTER_CONTEXT);
        output.extend_from_slice(&unsigned);
        Ok(output)
    }

    /// Signs the REGISTER with the nested binding identity (§13.2).
    pub fn sign(&mut self, signer: &SigningKey) -> Result<(), RegisterValidationError> {
        if signer.verifying_key().to_bytes() != self.binding.identity {
            return Err(RegisterValidationError::SignerIdentityMismatch);
        }
        let preimage = self
            .signing_preimage()
            .map_err(|_| RegisterValidationError::RelayNameMismatch)?;
        self.signature = signer.sign(&preimage).to_bytes();
        Ok(())
    }

    /// Returns SHA-256 of the canonical signed six-field REGISTER (§13.5).
    pub fn reg_hash(&self) -> Result<[u8; 32], RelayEncodeError> {
        let encoded = encode_register(self)?;
        Ok(Sha256::digest(encoded).into())
    }

    /// Validates the complete stateless REGISTER admission prerequisites (§13.5 rule 1).
    pub fn validate(
        &self,
        header: RelayHeader,
        advertised_relay_name: &str,
        now: u64,
    ) -> Result<ValidatedRegister, RegisterValidationError> {
        if header.message_type != RelayType::Register
            || header.dst != [0; 16]
            || header.src == [0; 16]
        {
            return Err(RegisterValidationError::InvalidHeader);
        }
        validate_relay_name(&self.relay_name)
            .map_err(|_| RegisterValidationError::RelayNameMismatch)?;
        RelayIdentifier::parse(&self.relay_name)
            .map_err(|_| RegisterValidationError::RelayNameMismatch)?;
        if self.relay_name.as_bytes() != advertised_relay_name.as_bytes() {
            return Err(RegisterValidationError::RelayNameMismatch);
        }
        if now.abs_diff(self.timestamp) > 120 {
            return Err(RegisterValidationError::TimestampOutsideWindow);
        }
        let expected_slot = derive_slot_id(&self.binding.network_id, &self.binding.identity)
            .map_err(|_| RegisterValidationError::SourceSlotMismatch)?;
        if header.src != expected_slot {
            return Err(RegisterValidationError::SourceSlotMismatch);
        }
        let verified = self
            .binding
            .verify()
            .map_err(|_| RegisterValidationError::InvalidBindingSignature)?;
        let current = verified
            .validate_current(now)
            .map_err(|_| RegisterValidationError::BindingNotCurrent)?;
        let key = VerifyingKey::from_bytes(&self.binding.identity)
            .map_err(|_| RegisterValidationError::InvalidSignature)?;
        let preimage = self
            .signing_preimage()
            .map_err(|_| RegisterValidationError::RelayNameMismatch)?;
        key.verify_strict(&preimage, &Signature::from_bytes(&self.signature))
            .map_err(|_| RegisterValidationError::InvalidSignature)?;
        Ok(ValidatedRegister {
            register: self.clone(),
            binding: current,
        })
    }
}

/// A relay control/reply authentication failure (§§13.2, 13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayMacError {
    /// The supplied header type does not match the body/MAC context.
    TypeMismatch,
    /// The supplied header violates its direction rules.
    InvalidHeader,
    /// A body range or counter is invalid.
    InvalidBody,
    /// The HMAC does not match in constant time.
    InvalidMac,
}

macro_rules! impl_mac_body {
    ($body:ty, $unsigned:ident, $type:expr, $context:expr, $validate:ident) => {
        impl $body {
            /// Returns the exact contextual relay MAC transcript (§§13.2, 13.5).
            pub fn mac_preimage(&self, header: RelayHeader) -> Result<Vec<u8>, RelayMacError> {
                $validate(self).map_err(|_| RelayMacError::InvalidBody)?;
                validate_mac_header(header, $type)?;
                let encoded = serialize(&MacTranscript {
                    header,
                    unsigned: &$unsigned(self),
                });
                let mut output = Vec::with_capacity($context.len() + encoded.len());
                output.extend_from_slice($context);
                output.extend_from_slice(&encoded);
                Ok(output)
            }

            /// Computes the relay control or reply HMAC (§§13.2, 13.5).
            pub fn authenticate(
                &mut self,
                key: &[u8; 32],
                header: RelayHeader,
            ) -> Result<(), RelayMacError> {
                self.mac = compute_hmac(key, &self.mac_preimage(header)?)?;
                Ok(())
            }

            /// Verifies the relay HMAC in constant time (§§13.2, 13.5).
            pub fn verify_mac(
                &self,
                key: &[u8; 32],
                header: RelayHeader,
            ) -> Result<(), RelayMacError> {
                verify_hmac(key, &self.mac_preimage(header)?, &self.mac)
            }
        }
    };
}

impl_mac_body!(
    Registered,
    UnsignedRegisteredWire,
    RelayType::Registered,
    REPLY_CONTEXT,
    validate_registered
);
impl_mac_body!(
    Presence,
    UnsignedPresenceWire,
    RelayType::Presence,
    CONTROL_CONTEXT,
    validate_presence
);
impl_mac_body!(
    Reflect,
    UnsignedReflectWire,
    RelayType::Reflect,
    CONTROL_CONTEXT,
    validate_reflect
);
impl_mac_body!(
    Reflected,
    UnsignedReflectedWire,
    RelayType::Reflected,
    REPLY_CONTEXT,
    validate_reflected
);
impl_mac_body!(
    Revoke,
    UnsignedRevokeWire,
    RelayType::Revoke,
    CONTROL_CONTEXT,
    validate_revoke
);

fn validate_mac_header(header: RelayHeader, expected: RelayType) -> Result<(), RelayMacError> {
    if header.message_type != expected {
        return Err(RelayMacError::TypeMismatch);
    }
    header
        .validate_direction()
        .map_err(|_| RelayMacError::InvalidHeader)
}

fn compute_hmac(key: &[u8; 32], message: &[u8]) -> Result<[u8; 32], RelayMacError> {
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key)
        .map_err(|_| RelayMacError::InvalidMac)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_hmac(key: &[u8; 32], message: &[u8], expected: &[u8; 32]) -> Result<(), RelayMacError> {
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key)
        .map_err(|_| RelayMacError::InvalidMac)?;
    mac.update(message);
    mac.verify_slice(expected)
        .map_err(|_| RelayMacError::InvalidMac)
}

fn encode_body(body: &RelayBody) -> Result<Vec<u8>, RelayEncodeError> {
    match body {
        RelayBody::Register(value) => encode_register(value),
        RelayBody::Registered(value) => {
            validate_registered(value)?;
            Ok(serialize(&SignedRegisteredWire(value)))
        }
        RelayBody::Presence(value) => {
            validate_presence(value)?;
            Ok(serialize(&SignedPresenceWire(value)))
        }
        RelayBody::Reflect(value) => {
            validate_reflect(value)?;
            Ok(serialize(&SignedReflectWire(value)))
        }
        RelayBody::Reflected(value) => {
            validate_reflected(value)?;
            Ok(serialize(&SignedReflectedWire(value)))
        }
        RelayBody::Intro(value) => value.encode().map_err(|_| RelayEncodeError::InvalidBody),
        RelayBody::IntroAck(value) => value.encode().map_err(|_| RelayEncodeError::InvalidBody),
        RelayBody::Data(value) => {
            if value.is_empty() || value.len() > MAX_RELAY_DATA_BYTES {
                Err(RelayEncodeError::InvalidDataLength)
            } else {
                Ok(value.clone())
            }
        }
        RelayBody::Status(value) => Ok(serialize(&StatusWire(value))),
        RelayBody::Revoke(value) => {
            validate_revoke(value)?;
            Ok(serialize(&SignedRevokeWire(value)))
        }
    }
}

fn decode_body(message_type: RelayType, encoded: &[u8]) -> Result<RelayBody, RelayDecodeError> {
    match message_type {
        RelayType::Register => decode_register(encoded).map(RelayBody::Register),
        RelayType::Registered => decode_registered(encoded).map(RelayBody::Registered),
        RelayType::Presence => decode_presence(encoded).map(RelayBody::Presence),
        RelayType::Reflect => decode_reflect(encoded).map(RelayBody::Reflect),
        RelayType::Reflected => decode_reflected(encoded).map(RelayBody::Reflected),
        RelayType::Intro => Intro::decode(encoded)
            .map(RelayBody::Intro)
            .map_err(|_| RelayDecodeError::InvalidBody),
        RelayType::IntroAck => IntroAck::decode(encoded)
            .map(RelayBody::IntroAck)
            .map_err(|_| RelayDecodeError::InvalidBody),
        RelayType::Data => {
            if encoded.is_empty() || encoded.len() > MAX_RELAY_DATA_BYTES {
                Err(RelayDecodeError::InvalidBody)
            } else {
                Ok(RelayBody::Data(encoded.to_vec()))
            }
        }
        RelayType::Status => decode_status(encoded).map(RelayBody::Status),
        RelayType::Revoke => decode_revoke(encoded).map(RelayBody::Revoke),
    }
}

fn validate_relay_name(name: &str) -> Result<(), RelayEncodeError> {
    if (1..=255).contains(&name.len()) {
        Ok(())
    } else {
        Err(RelayEncodeError::InvalidRelayName)
    }
}

fn validate_registered(value: &Registered) -> Result<(), RelayEncodeError> {
    if !(30..=3600).contains(&value.presence_ttl_s) {
        return Err(RelayEncodeError::InvalidBody);
    }
    if let Some(address) = value.observed_addr {
        address.validate()?;
    }
    Ok(())
}

fn validate_presence(value: &Presence) -> Result<(), RelayEncodeError> {
    if value.seq == 0 {
        Err(RelayEncodeError::InvalidBody)
    } else {
        Ok(())
    }
}

fn validate_reflect(value: &Reflect) -> Result<(), RelayEncodeError> {
    if value.seq == 0 {
        Err(RelayEncodeError::InvalidBody)
    } else {
        Ok(())
    }
}

fn validate_reflected(value: &Reflected) -> Result<(), RelayEncodeError> {
    if value.seq == 0 {
        return Err(RelayEncodeError::InvalidBody);
    }
    value.observed_addr.validate()
}

fn validate_revoke(value: &Revoke) -> Result<(), RelayEncodeError> {
    if value.seq == 0 {
        Err(RelayEncodeError::InvalidBody)
    } else {
        Ok(())
    }
}

fn decode_register(encoded: &[u8]) -> Result<Register, RelayDecodeError> {
    let mut reader = body_reader(encoded, 6)?;
    let value = Register {
        binding: reader.binding().map_err(body_error)?,
        incarnation: reader.uint().map_err(body_error)?,
        timestamp: reader.uint().map_err(body_error)?,
        node_ephemeral: reader.fixed_bytes().map_err(body_error)?,
        relay_name: reader.text().map_err(body_error)?,
        signature: reader.fixed_bytes().map_err(body_error)?,
    };
    finish_body(reader, encoded, &encode_register(&value)?)?;
    Ok(value)
}

fn decode_registered(encoded: &[u8]) -> Result<Registered, RelayDecodeError> {
    let mut reader = body_reader(encoded, 6)?;
    let value = Registered {
        incarnation: reader.uint().map_err(body_error)?,
        relay_ephemeral: reader.fixed_bytes().map_err(body_error)?,
        presence_ttl_s: u32::try_from(reader.uint().map_err(body_error)?)
            .map_err(|_| RelayDecodeError::InvalidBody)?,
        observed_addr: decode_optional_observed(&mut reader)?,
        ack_seq: reader.uint().map_err(body_error)?,
        mac: reader.fixed_bytes().map_err(body_error)?,
    };
    validate_registered(&value)?;
    finish_body(reader, encoded, &serialize(&SignedRegisteredWire(&value)))?;
    Ok(value)
}

fn decode_presence(encoded: &[u8]) -> Result<Presence, RelayDecodeError> {
    let mut reader = body_reader(encoded, 3)?;
    let value = Presence {
        incarnation: reader.uint().map_err(body_error)?,
        seq: reader.uint().map_err(body_error)?,
        mac: reader.fixed_bytes().map_err(body_error)?,
    };
    validate_presence(&value)?;
    finish_body(reader, encoded, &serialize(&SignedPresenceWire(&value)))?;
    Ok(value)
}

fn decode_reflect(encoded: &[u8]) -> Result<Reflect, RelayDecodeError> {
    let mut reader = body_reader(encoded, 4)?;
    let value = Reflect {
        incarnation: reader.uint().map_err(body_error)?,
        seq: reader.uint().map_err(body_error)?,
        nonce: reader.fixed_bytes().map_err(body_error)?,
        mac: reader.fixed_bytes().map_err(body_error)?,
    };
    validate_reflect(&value)?;
    finish_body(reader, encoded, &serialize(&SignedReflectWire(&value)))?;
    Ok(value)
}

fn decode_reflected(encoded: &[u8]) -> Result<Reflected, RelayDecodeError> {
    let mut reader = body_reader(encoded, 5)?;
    let value = Reflected {
        incarnation: reader.uint().map_err(body_error)?,
        seq: reader.uint().map_err(body_error)?,
        nonce: reader.fixed_bytes().map_err(body_error)?,
        observed_addr: decode_observed(&mut reader)?,
        mac: reader.fixed_bytes().map_err(body_error)?,
    };
    validate_reflected(&value)?;
    finish_body(reader, encoded, &serialize(&SignedReflectedWire(&value)))?;
    Ok(value)
}

fn decode_status(encoded: &[u8]) -> Result<Status, RelayDecodeError> {
    let mut reader = body_reader(encoded, 3)?;
    let value = Status {
        type_in: u8::try_from(reader.uint().map_err(body_error)?)
            .map_err(|_| RelayDecodeError::InvalidBody)?,
        destination: reader.fixed_bytes().map_err(body_error)?,
        status: StatusCode::try_from(
            u8::try_from(reader.uint().map_err(body_error)?)
                .map_err(|_| RelayDecodeError::InvalidBody)?,
        )?,
    };
    finish_body(reader, encoded, &serialize(&StatusWire(&value)))?;
    Ok(value)
}

fn decode_revoke(encoded: &[u8]) -> Result<Revoke, RelayDecodeError> {
    let mut reader = body_reader(encoded, 4)?;
    let value = Revoke {
        incarnation: reader.uint().map_err(body_error)?,
        seq: reader.uint().map_err(body_error)?,
        reason: RevokeReason::try_from(
            u8::try_from(reader.uint().map_err(body_error)?)
                .map_err(|_| RelayDecodeError::InvalidBody)?,
        )?,
        mac: reader.fixed_bytes().map_err(body_error)?,
    };
    validate_revoke(&value)?;
    finish_body(reader, encoded, &serialize(&SignedRevokeWire(&value)))?;
    Ok(value)
}

fn body_reader(encoded: &[u8], fields: u64) -> Result<CborReader<'_>, RelayDecodeError> {
    let mut reader = CborReader::new(encoded);
    reader.array(fields).map_err(body_error)?;
    Ok(reader)
}

fn finish_body(
    reader: CborReader<'_>,
    original: &[u8],
    canonical: &[u8],
) -> Result<(), RelayDecodeError> {
    if reader.finished() && original == canonical {
        Ok(())
    } else {
        Err(RelayDecodeError::InvalidBody)
    }
}

fn body_error(_: crate::codec::CborError) -> RelayDecodeError {
    RelayDecodeError::InvalidBody
}

impl From<RelayEncodeError> for RelayDecodeError {
    fn from(_: RelayEncodeError) -> Self {
        Self::InvalidBody
    }
}

fn decode_optional_observed(
    reader: &mut CborReader<'_>,
) -> Result<Option<ObservedAddr>, RelayDecodeError> {
    if reader.peek() == Some(0xf6) {
        reader.null().map_err(body_error)?;
        Ok(None)
    } else {
        decode_observed(reader).map(Some)
    }
}

fn decode_observed(reader: &mut CborReader<'_>) -> Result<ObservedAddr, RelayDecodeError> {
    reader.array(2).map_err(body_error)?;
    let address = match reader.peek() {
        Some(0x44) => ObservedAddr::V4(reader.fixed_bytes().map_err(body_error)?, 0),
        Some(0x50) => ObservedAddr::V6(reader.fixed_bytes().map_err(body_error)?, 0),
        _ => return Err(RelayDecodeError::InvalidBody),
    };
    let port = u16::try_from(reader.uint().map_err(body_error)?)
        .map_err(|_| RelayDecodeError::InvalidBody)?;
    let address = match address {
        ObservedAddr::V4(ip, _) => ObservedAddr::V4(ip, port),
        ObservedAddr::V6(ip, _) => ObservedAddr::V6(ip, port),
    };
    address.validate()?;
    Ok(address)
}

fn encode_register(value: &Register) -> Result<Vec<u8>, RelayEncodeError> {
    validate_relay_name(&value.relay_name)?;
    Ok(serialize(&SignedRegisterWire(value)))
}

fn serialize(value: &impl Serialize) -> Vec<u8> {
    let mut output = Vec::new();
    let result = ciborium::ser::into_writer(value, &mut output);
    debug_assert!(result.is_ok());
    output
}

struct UnsignedRegisterWire<'a>(&'a Register);
struct SignedRegisterWire<'a>(&'a Register);
struct UnsignedRegisteredWire<'a>(&'a Registered);
struct SignedRegisteredWire<'a>(&'a Registered);
struct UnsignedPresenceWire<'a>(&'a Presence);
struct SignedPresenceWire<'a>(&'a Presence);
struct UnsignedReflectWire<'a>(&'a Reflect);
struct SignedReflectWire<'a>(&'a Reflect);
struct UnsignedReflectedWire<'a>(&'a Reflected);
struct SignedReflectedWire<'a>(&'a Reflected);
struct StatusWire<'a>(&'a Status);
struct UnsignedRevokeWire<'a>(&'a Revoke);
struct SignedRevokeWire<'a>(&'a Revoke);
struct ObservedWire(ObservedAddr);

struct MacTranscript<'a, T> {
    header: RelayHeader,
    unsigned: &'a T,
}

impl<T: Serialize> Serialize for MacTranscript<'_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(5)?;
        array.serialize_element(&serde_bytes::Bytes::new(&RELAY_MAGIC))?;
        array.serialize_element(&(self.header.message_type as u8))?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.header.src))?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.header.dst))?;
        array.serialize_element(self.unsigned)?;
        array.end()
    }
}

fn register_fields<S>(value: &Register, array: &mut S) -> Result<(), S::Error>
where
    S: SerializeTuple,
{
    array.serialize_element(&crate::pairing::NestedBindingWire(&value.binding))?;
    array.serialize_element(&value.incarnation)?;
    array.serialize_element(&value.timestamp)?;
    array.serialize_element(&serde_bytes::Bytes::new(&value.node_ephemeral))?;
    array.serialize_element(&value.relay_name)
}

impl Serialize for UnsignedRegisterWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(5)?;
        register_fields(self.0, &mut array)?;
        array.end()
    }
}

impl Serialize for SignedRegisterWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(6)?;
        register_fields(self.0, &mut array)?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.signature))?;
        array.end()
    }
}

fn observed<S>(value: ObservedAddr, array: &mut S) -> Result<(), S::Error>
where
    S: SerializeTuple,
{
    array.serialize_element(&ObservedWire(value))
}

impl Serialize for ObservedWire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(2)?;
        match self.0 {
            ObservedAddr::V4(ip, port) => {
                array.serialize_element(&serde_bytes::Bytes::new(&ip))?;
                array.serialize_element(&port)?;
            }
            ObservedAddr::V6(ip, port) => {
                array.serialize_element(&serde_bytes::Bytes::new(&ip))?;
                array.serialize_element(&port)?;
            }
        }
        array.end()
    }
}

fn registered_fields<S>(value: &Registered, array: &mut S) -> Result<(), S::Error>
where
    S: SerializeTuple,
{
    array.serialize_element(&value.incarnation)?;
    array.serialize_element(&serde_bytes::Bytes::new(&value.relay_ephemeral))?;
    array.serialize_element(&value.presence_ttl_s)?;
    match value.observed_addr {
        Some(address) => observed(address, array)?,
        None => array.serialize_element(&Option::<u8>::None)?,
    }
    array.serialize_element(&value.ack_seq)
}

impl Serialize for UnsignedRegisteredWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(5)?;
        registered_fields(self.0, &mut array)?;
        array.end()
    }
}

impl Serialize for SignedRegisteredWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(6)?;
        registered_fields(self.0, &mut array)?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.mac))?;
        array.end()
    }
}

impl Serialize for UnsignedPresenceWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(2)?;
        array.serialize_element(&self.0.incarnation)?;
        array.serialize_element(&self.0.seq)?;
        array.end()
    }
}

impl Serialize for SignedPresenceWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(3)?;
        array.serialize_element(&self.0.incarnation)?;
        array.serialize_element(&self.0.seq)?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.mac))?;
        array.end()
    }
}

impl Serialize for UnsignedReflectWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(3)?;
        array.serialize_element(&self.0.incarnation)?;
        array.serialize_element(&self.0.seq)?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.nonce))?;
        array.end()
    }
}

impl Serialize for SignedReflectWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(4)?;
        array.serialize_element(&self.0.incarnation)?;
        array.serialize_element(&self.0.seq)?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.nonce))?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.mac))?;
        array.end()
    }
}

impl Serialize for UnsignedReflectedWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(4)?;
        array.serialize_element(&self.0.incarnation)?;
        array.serialize_element(&self.0.seq)?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.nonce))?;
        observed(self.0.observed_addr, &mut array)?;
        array.end()
    }
}

impl Serialize for SignedReflectedWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(5)?;
        array.serialize_element(&self.0.incarnation)?;
        array.serialize_element(&self.0.seq)?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.nonce))?;
        observed(self.0.observed_addr, &mut array)?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.mac))?;
        array.end()
    }
}

impl Serialize for StatusWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(3)?;
        array.serialize_element(&self.0.type_in)?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.destination))?;
        array.serialize_element(&(self.0.status as u8))?;
        array.end()
    }
}

impl Serialize for UnsignedRevokeWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(3)?;
        array.serialize_element(&self.0.incarnation)?;
        array.serialize_element(&self.0.seq)?;
        array.serialize_element(&(self.0.reason as u8))?;
        array.end()
    }
}

impl Serialize for SignedRevokeWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(4)?;
        array.serialize_element(&self.0.incarnation)?;
        array.serialize_element(&self.0.seq)?;
        array.serialize_element(&(self.0.reason as u8))?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.mac))?;
        array.end()
    }
}
