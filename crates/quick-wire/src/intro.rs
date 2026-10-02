use crate::{CurrentKeyBinding, Identity, KeyBinding, NetworkId};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Serialize, ser::SerializeTuple};
use sha2::Sha256;

use crate::{codec::CborReader, pairing::NestedBindingWire};

const INTRO_CONTEXT: &[u8] = b"keynet/intro/v1";
const INTRO_ACK_CONTEXT: &[u8] = b"keynet/intro-ack/v1";
const MAX_INTRO_BYTES: usize = 512;

/// A version-one INTRO body (§§7.5, 13.2, 13.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Intro {
    /// The selected local network.
    pub network_id: NetworkId,
    /// The full recipient identity sending the introduction.
    pub recipient: Identity,
    /// The recipient's signed current binding.
    pub binding: KeyBinding,
    /// SHA-256 of the selected canonical signed PairingToken.
    pub token_id: [u8; 32],
    /// A caller-generated live 32-byte nonce.
    pub nonce: [u8; 32],
    /// HMAC-SHA256 under the selected token secret.
    pub mac: [u8; 32],
}

/// A version-one INTRO_ACK body (§§7.5, 13.2, 13.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntroAck {
    /// The selected local network.
    pub network_id: NetworkId,
    /// The full issuer identity sending the acknowledgment.
    pub issuer: Identity,
    /// The issuer's signed current binding.
    pub binding: KeyBinding,
    /// The exact nonce echoed from the live INTRO.
    pub nonce: [u8; 32],
    /// HMAC-SHA256 under the selected token secret.
    pub mac: [u8; 32],
}

/// A strict INTRO or INTRO_ACK canonical decoding failure (§13.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntroductionDecodeError {
    /// The input is not the required bounded fixed-length canonical array.
    InvalidEncoding,
}

/// An INTRO or INTRO_ACK construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntroductionEncodeError {
    /// The binding does not name the surrounding sender and network.
    BindingScopeMismatch,
    /// The binding interval is empty or inverted.
    InvalidBindingInterval,
    /// Canonical serialization unexpectedly failed.
    Serialization,
    /// The vetted HMAC primitive rejected the fixed-width secret.
    MacInitialization,
}

/// An endpoint-validation failure for INTRO or INTRO_ACK (§§7.5, 13.2, 13.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntroductionValidationError {
    /// The body names a different local network.
    NetworkMismatch,
    /// The body names a different expected full sender identity.
    SenderMismatch,
    /// The binding does not name the sender and network in the body.
    BindingScopeMismatch,
    /// The binding interval is empty, inverted, or not current.
    BindingNotCurrent,
    /// The binding signature is invalid.
    InvalidBindingSignature,
    /// The INTRO names a different selected token.
    TokenMismatch,
    /// The ACK does not echo the exact live nonce.
    NonceMismatch,
    /// The HMAC-SHA256 value is invalid.
    InvalidMac,
}

/// A canonical-input error which preserves decode-before-MAC precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntroductionInputError {
    /// Canonical parsing failed before cryptographic work.
    Decode(IntroductionDecodeError),
    /// A canonical body failed endpoint validation.
    Validation(IntroductionValidationError),
}

/// A verified INTRO whose sender binding is current.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedIntro {
    body: Intro,
    binding: CurrentKeyBinding,
}

impl VerifiedIntro {
    /// Returns the authenticated INTRO body.
    #[must_use]
    pub fn body(&self) -> &Intro {
        &self.body
    }

    /// Returns the verified current recipient binding.
    #[must_use]
    pub fn binding(&self) -> CurrentKeyBinding {
        self.binding
    }
}

/// A verified INTRO_ACK whose sender binding and echoed nonce are current.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedIntroAck {
    body: IntroAck,
    binding: CurrentKeyBinding,
}

impl VerifiedIntroAck {
    /// Returns the authenticated INTRO_ACK body.
    #[must_use]
    pub fn body(&self) -> &IntroAck {
        &self.body
    }

    /// Returns the verified current issuer binding.
    #[must_use]
    pub fn binding(&self) -> CurrentKeyBinding {
        self.binding
    }
}

impl Intro {
    /// Returns the canonical five-field array covered by the INTRO MAC (§13.2).
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, IntroductionEncodeError> {
        self.validate_structure()?;
        serialize(&UnsignedIntroWire(self))
    }

    /// Returns the exact INTRO HMAC message (§13.2).
    pub fn mac_preimage(&self) -> Result<Vec<u8>, IntroductionEncodeError> {
        contextual_preimage(INTRO_CONTEXT, self.unsigned_bytes()?)
    }

    /// Computes the INTRO HMAC using the caller-selected token secret (§13.2).
    pub fn authenticate(&mut self, secret: &[u8; 32]) -> Result<(), IntroductionEncodeError> {
        self.mac = compute_mac(secret, &self.mac_preimage()?)?;
        Ok(())
    }

    /// Encodes the canonical six-field INTRO body (§13.5).
    pub fn encode(&self) -> Result<Vec<u8>, IntroductionEncodeError> {
        self.validate_structure()?;
        serialize(&SignedIntroWire(self))
    }

    /// Strictly decodes canonical INTRO bytes without performing MAC work (§13.1).
    pub fn decode(encoded: &[u8]) -> Result<Self, IntroductionDecodeError> {
        if encoded.len() > MAX_INTRO_BYTES {
            return Err(IntroductionDecodeError::InvalidEncoding);
        }
        let mut reader = CborReader::new(encoded);
        reader.array(6).map_err(decode_error)?;
        let body = Self {
            network_id: reader.fixed_bytes().map_err(decode_error)?,
            recipient: reader.fixed_bytes().map_err(decode_error)?,
            binding: reader.binding().map_err(decode_error)?,
            token_id: reader.fixed_bytes().map_err(decode_error)?,
            nonce: reader.fixed_bytes().map_err(decode_error)?,
            mac: reader.fixed_bytes().map_err(decode_error)?,
        };
        if !reader.finished() {
            return Err(IntroductionDecodeError::InvalidEncoding);
        }
        body.validate_structure().map_err(map_encode_decode)?;
        if body.encode().map_err(map_encode_decode)? != encoded {
            return Err(IntroductionDecodeError::InvalidEncoding);
        }
        Ok(body)
    }

    /// Validates token association, MAC, sender identity, scope, and current binding (§13.5).
    pub fn validate(
        &self,
        secret: &[u8; 32],
        expected_network: &NetworkId,
        expected_recipient: &Identity,
        expected_token_id: &[u8; 32],
        now: u64,
    ) -> Result<VerifiedIntro, IntroductionValidationError> {
        validate_sender(
            self.network_id,
            self.recipient,
            &self.binding,
            expected_network,
            expected_recipient,
        )?;
        if self.token_id != *expected_token_id {
            return Err(IntroductionValidationError::TokenMismatch);
        }
        verify_mac(
            secret,
            &self.mac_preimage().map_err(map_encode_validation)?,
            &self.mac,
        )?;
        let binding = validate_binding(&self.binding, now)?;
        Ok(VerifiedIntro {
            body: self.clone(),
            binding,
        })
    }

    /// Decodes canonical bytes before endpoint and MAC validation (§§13.1-13.2).
    pub fn decode_and_validate(
        encoded: &[u8],
        secret: &[u8; 32],
        expected_network: &NetworkId,
        expected_recipient: &Identity,
        expected_token_id: &[u8; 32],
        now: u64,
    ) -> Result<VerifiedIntro, IntroductionInputError> {
        Self::decode(encoded)
            .map_err(IntroductionInputError::Decode)?
            .validate(
                secret,
                expected_network,
                expected_recipient,
                expected_token_id,
                now,
            )
            .map_err(IntroductionInputError::Validation)
    }

    fn validate_structure(&self) -> Result<(), IntroductionEncodeError> {
        validate_structure(self.network_id, self.recipient, &self.binding)
    }
}

impl IntroAck {
    /// Returns the canonical four-field array covered by the ACK MAC (§13.2).
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, IntroductionEncodeError> {
        self.validate_structure()?;
        serialize(&UnsignedAckWire(self))
    }

    /// Returns the exact INTRO_ACK HMAC message (§13.2).
    pub fn mac_preimage(&self) -> Result<Vec<u8>, IntroductionEncodeError> {
        contextual_preimage(INTRO_ACK_CONTEXT, self.unsigned_bytes()?)
    }

    /// Computes the INTRO_ACK HMAC using the caller-selected token secret (§13.2).
    pub fn authenticate(&mut self, secret: &[u8; 32]) -> Result<(), IntroductionEncodeError> {
        self.mac = compute_mac(secret, &self.mac_preimage()?)?;
        Ok(())
    }

    /// Encodes the canonical five-field INTRO_ACK body (§13.5).
    pub fn encode(&self) -> Result<Vec<u8>, IntroductionEncodeError> {
        self.validate_structure()?;
        serialize(&SignedAckWire(self))
    }

    /// Strictly decodes canonical INTRO_ACK bytes without performing MAC work (§13.1).
    pub fn decode(encoded: &[u8]) -> Result<Self, IntroductionDecodeError> {
        if encoded.len() > MAX_INTRO_BYTES {
            return Err(IntroductionDecodeError::InvalidEncoding);
        }
        let mut reader = CborReader::new(encoded);
        reader.array(5).map_err(decode_error)?;
        let body = Self {
            network_id: reader.fixed_bytes().map_err(decode_error)?,
            issuer: reader.fixed_bytes().map_err(decode_error)?,
            binding: reader.binding().map_err(decode_error)?,
            nonce: reader.fixed_bytes().map_err(decode_error)?,
            mac: reader.fixed_bytes().map_err(decode_error)?,
        };
        if !reader.finished() {
            return Err(IntroductionDecodeError::InvalidEncoding);
        }
        body.validate_structure().map_err(map_encode_decode)?;
        if body.encode().map_err(map_encode_decode)? != encoded {
            return Err(IntroductionDecodeError::InvalidEncoding);
        }
        Ok(body)
    }

    /// Validates MAC, sender identity, scope, current binding, and exact live nonce (§13.5).
    pub fn validate(
        &self,
        secret: &[u8; 32],
        expected_network: &NetworkId,
        expected_issuer: &Identity,
        live_nonce: &[u8; 32],
        now: u64,
    ) -> Result<VerifiedIntroAck, IntroductionValidationError> {
        validate_sender(
            self.network_id,
            self.issuer,
            &self.binding,
            expected_network,
            expected_issuer,
        )?;
        if self.nonce != *live_nonce {
            return Err(IntroductionValidationError::NonceMismatch);
        }
        verify_mac(
            secret,
            &self.mac_preimage().map_err(map_encode_validation)?,
            &self.mac,
        )?;
        let binding = validate_binding(&self.binding, now)?;
        Ok(VerifiedIntroAck {
            body: self.clone(),
            binding,
        })
    }

    /// Decodes canonical bytes before endpoint and MAC validation (§§13.1-13.2).
    pub fn decode_and_validate(
        encoded: &[u8],
        secret: &[u8; 32],
        expected_network: &NetworkId,
        expected_issuer: &Identity,
        live_nonce: &[u8; 32],
        now: u64,
    ) -> Result<VerifiedIntroAck, IntroductionInputError> {
        Self::decode(encoded)
            .map_err(IntroductionInputError::Decode)?
            .validate(secret, expected_network, expected_issuer, live_nonce, now)
            .map_err(IntroductionInputError::Validation)
    }

    fn validate_structure(&self) -> Result<(), IntroductionEncodeError> {
        validate_structure(self.network_id, self.issuer, &self.binding)
    }
}

fn validate_structure(
    network_id: NetworkId,
    sender: Identity,
    binding: &KeyBinding,
) -> Result<(), IntroductionEncodeError> {
    if binding.network_id != network_id || binding.identity != sender {
        return Err(IntroductionEncodeError::BindingScopeMismatch);
    }
    binding
        .validate_interval()
        .map_err(|_| IntroductionEncodeError::InvalidBindingInterval)
}

fn validate_sender(
    network_id: NetworkId,
    sender: Identity,
    binding: &KeyBinding,
    expected_network: &NetworkId,
    expected_sender: &Identity,
) -> Result<(), IntroductionValidationError> {
    if network_id != *expected_network {
        return Err(IntroductionValidationError::NetworkMismatch);
    }
    if sender != *expected_sender {
        return Err(IntroductionValidationError::SenderMismatch);
    }
    if binding.network_id != network_id || binding.identity != sender {
        return Err(IntroductionValidationError::BindingScopeMismatch);
    }
    binding
        .validate_interval()
        .map_err(|_| IntroductionValidationError::BindingNotCurrent)
}

fn validate_binding(
    binding: &KeyBinding,
    now: u64,
) -> Result<CurrentKeyBinding, IntroductionValidationError> {
    binding
        .verify()
        .map_err(|_| IntroductionValidationError::InvalidBindingSignature)?
        .validate_current(now)
        .map_err(|_| IntroductionValidationError::BindingNotCurrent)
}

fn compute_mac(secret: &[u8; 32], preimage: &[u8]) -> Result<[u8; 32], IntroductionEncodeError> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret)
        .map_err(|_| IntroductionEncodeError::MacInitialization)?;
    mac.update(preimage);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_mac(
    secret: &[u8; 32],
    preimage: &[u8],
    expected: &[u8; 32],
) -> Result<(), IntroductionValidationError> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret)
        .map_err(|_| IntroductionValidationError::InvalidMac)?;
    mac.update(preimage);
    mac.verify_slice(expected)
        .map_err(|_| IntroductionValidationError::InvalidMac)
}

fn contextual_preimage(
    context: &[u8],
    unsigned: Vec<u8>,
) -> Result<Vec<u8>, IntroductionEncodeError> {
    let mut output = Vec::with_capacity(context.len() + unsigned.len());
    output.extend_from_slice(context);
    output.extend_from_slice(&unsigned);
    Ok(output)
}

fn serialize(value: &impl Serialize) -> Result<Vec<u8>, IntroductionEncodeError> {
    let mut output = Vec::with_capacity(MAX_INTRO_BYTES);
    ciborium::ser::into_writer(value, &mut output)
        .map_err(|_| IntroductionEncodeError::Serialization)?;
    if output.len() > MAX_INTRO_BYTES {
        return Err(IntroductionEncodeError::Serialization);
    }
    Ok(output)
}

fn decode_error(_: crate::codec::CborError) -> IntroductionDecodeError {
    IntroductionDecodeError::InvalidEncoding
}

fn map_encode_decode(error: IntroductionEncodeError) -> IntroductionDecodeError {
    match error {
        IntroductionEncodeError::BindingScopeMismatch
        | IntroductionEncodeError::InvalidBindingInterval
        | IntroductionEncodeError::MacInitialization
        | IntroductionEncodeError::Serialization => IntroductionDecodeError::InvalidEncoding,
    }
}

fn map_encode_validation(error: IntroductionEncodeError) -> IntroductionValidationError {
    match error {
        IntroductionEncodeError::BindingScopeMismatch => {
            IntroductionValidationError::BindingScopeMismatch
        }
        IntroductionEncodeError::InvalidBindingInterval => {
            IntroductionValidationError::BindingNotCurrent
        }
        IntroductionEncodeError::Serialization | IntroductionEncodeError::MacInitialization => {
            IntroductionValidationError::InvalidMac
        }
    }
}

struct UnsignedIntroWire<'a>(&'a Intro);
struct SignedIntroWire<'a>(&'a Intro);
struct UnsignedAckWire<'a>(&'a IntroAck);
struct SignedAckWire<'a>(&'a IntroAck);

fn intro_fields<S>(body: &Intro, array: &mut S) -> Result<(), S::Error>
where
    S: SerializeTuple,
{
    array.serialize_element(&serde_bytes::Bytes::new(&body.network_id))?;
    array.serialize_element(&serde_bytes::Bytes::new(&body.recipient))?;
    array.serialize_element(&NestedBindingWire(&body.binding))?;
    array.serialize_element(&serde_bytes::Bytes::new(&body.token_id))?;
    array.serialize_element(&serde_bytes::Bytes::new(&body.nonce))
}

fn ack_fields<S>(body: &IntroAck, array: &mut S) -> Result<(), S::Error>
where
    S: SerializeTuple,
{
    array.serialize_element(&serde_bytes::Bytes::new(&body.network_id))?;
    array.serialize_element(&serde_bytes::Bytes::new(&body.issuer))?;
    array.serialize_element(&NestedBindingWire(&body.binding))?;
    array.serialize_element(&serde_bytes::Bytes::new(&body.nonce))
}

impl Serialize for UnsignedIntroWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(5)?;
        intro_fields(self.0, &mut array)?;
        array.end()
    }
}

impl Serialize for SignedIntroWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(6)?;
        intro_fields(self.0, &mut array)?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.mac))?;
        array.end()
    }
}

impl Serialize for UnsignedAckWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(4)?;
        ack_fields(self.0, &mut array)?;
        array.end()
    }
}

impl Serialize for SignedAckWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(5)?;
        ack_fields(self.0, &mut array)?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.mac))?;
        array.end()
    }
}
