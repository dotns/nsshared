use crate::{
    CurrentKeyBinding, EndpointHint, Identity, InstallationDecision, KeyBinding, KeyBindingState,
    KeyBindingTransitionError, NetworkId, RelayIdentifier,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::{Serialize, ser::SerializeTuple};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::codec::CborReader;

const TOKEN_CONTEXT: &[u8] = b"keynet/pairing-token/v1";
const PSK_CONTEXT: &[u8] = b"keynet/psk/v1";
const TOKEN_TEXT_PREFIX: &str = "kn1";
const MAX_TEXT_FIELD_BYTES: usize = 255;
const MAX_TOKEN_TEXT_BYTES: usize = 1024;
const MAX_TOKEN_CBOR_BYTES: usize = 1536;

/// A version-one PairingToken bearer credential (§7.4, §§13.1-13.3).
#[derive(Clone, Eq, PartialEq)]
pub struct PairingToken {
    /// The record version, which is one.
    pub ver: u8,
    /// The v1 wire scope; default-context clients use `crate::DEFAULT_NETWORK_ID`.
    pub network_id: NetworkId,
    /// The legacy display name; default-context clients emit an empty string.
    pub net_name: String,
    /// The issuer identity public key.
    pub issuer: Identity,
    /// The issuer's signed current WireGuard-key binding.
    pub binding: KeyBinding,
    /// The optional issuer display name.
    pub issuer_name: Option<String>,
    /// The issuer's home relay identifier or host and port.
    pub relay: String,
    /// An optional direct endpoint hint.
    pub endpoint: Option<String>,
    /// The bearer secret used for introduction MACs and pair-PSK derivation.
    pub secret: [u8; 32],
    /// The exclusive Unix-second expiry.
    pub not_after: u64,
    /// The optional identity allowed to import this token.
    pub recipient: Option<Identity>,
    /// The issuer's Ed25519 signature over the unsigned token.
    pub signature: [u8; 64],
}

impl fmt::Debug for PairingToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingToken")
            .field("ver", &self.ver)
            .field("network_id", &self.network_id)
            .field("net_name", &self.net_name)
            .field("issuer", &self.issuer)
            .field("binding", &self.binding)
            .field("issuer_name", &self.issuer_name)
            .field("relay", &self.relay)
            .field("endpoint", &self.endpoint)
            .field("secret", &"[REDACTED]")
            .field("not_after", &self.not_after)
            .field("recipient", &self.recipient)
            .field("signature", &self.signature)
            .finish()
    }
}

/// A structural failure while encoding a PairingToken (§§13.1, 13.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingTokenEncodeError {
    /// The record version is not one.
    UnsupportedVersion,
    /// A text field exceeds 255 UTF-8 bytes.
    TextTooLong,
    /// The required relay is not a canonical section 13.5.1 identifier.
    InvalidRelay,
    /// The optional endpoint is not a canonical section 13.5.1 authority.
    InvalidEndpoint,
    /// The embedded binding does not name the token's issuer and network.
    BindingScopeMismatch,
    /// The embedded binding has an empty or inverted interval.
    InvalidBindingInterval,
    /// The canonical token cannot fit the 1024-byte text representation.
    TextRepresentationTooLong,
    /// Canonical serialization unexpectedly failed.
    Serialization,
}

/// A strict PairingToken CBOR decoding failure (§13.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingTokenDecodeError {
    /// The input is not the exact bounded canonical twelve-field array.
    InvalidEncoding,
    /// The record version is not one.
    UnsupportedVersion,
    /// A text field exceeds 255 UTF-8 bytes.
    TextTooLong,
    /// The received relay is not a canonical section 13.5.1 identifier.
    InvalidRelay,
    /// The received endpoint is not a canonical section 13.5.1 authority.
    InvalidEndpoint,
    /// The embedded binding does not name the token's issuer and network.
    BindingScopeMismatch,
    /// The embedded binding has an empty or inverted interval.
    InvalidBindingInterval,
}

/// A PairingToken text-form decoding failure (§§7.4, 13.3, 13.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingTokenTextError {
    /// The text exceeds the 1024-byte limit.
    TooLong,
    /// The `kn1` prefix or unpadded base64url body is invalid.
    InvalidText,
    /// The decoded bytes are not a canonical PairingToken.
    Token(PairingTokenDecodeError),
}

/// A PairingToken signature failure (§13.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingTokenSignatureError {
    /// The issuer bytes are not a strict Ed25519 public key.
    InvalidIssuerKey,
    /// The caller-provided signer does not match the issuer.
    SignerIdentityMismatch,
    /// The signature does not authenticate the token.
    InvalidSignature,
    /// The token is structurally invalid.
    InvalidToken(PairingTokenEncodeError),
}

/// A strict PairingToken acceptance failure (§§7.5, 13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingTokenAcceptanceError {
    /// The token is structurally invalid.
    InvalidToken(PairingTokenEncodeError),
    /// The token signature is invalid.
    InvalidSignature(PairingTokenSignatureError),
    /// The embedded KeyBinding signature is invalid.
    InvalidBindingSignature,
    /// The embedded KeyBinding is not current.
    BindingNotCurrent,
    /// The token has reached its exclusive expiry.
    Expired,
    /// The token names a different recipient.
    RecipientMismatch,
    /// Existing generation, revocation, scope, or conflict state rejects the binding.
    BindingState(KeyBindingTransitionError),
}

/// A decoded PairingToken which passed signature, scope, time, and recipient checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedPairingToken {
    token: PairingToken,
    binding: CurrentKeyBinding,
}

impl AcceptedPairingToken {
    /// Returns the accepted token.
    #[must_use]
    pub fn token(&self) -> &PairingToken {
        &self.token
    }

    /// Returns the verified, current issuer binding.
    #[must_use]
    pub fn binding(&self) -> CurrentKeyBinding {
        self.binding
    }

    /// Evaluates the embedded binding against caller-owned generation state without mutation.
    pub fn installation_decision(
        &self,
        state: &KeyBindingState,
    ) -> Result<InstallationDecision, KeyBindingTransitionError> {
        self.binding.installation_decision(state)
    }
}

impl PairingToken {
    /// Returns the canonical unsigned eleven-field CBOR array (§13.2).
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, PairingTokenEncodeError> {
        self.validate_structure()?;
        serialize(&UnsignedTokenWire(self))
    }

    /// Returns the canonical signed twelve-field CBOR array (§13.2).
    pub fn encode(&self) -> Result<Vec<u8>, PairingTokenEncodeError> {
        self.validate_structure()?;
        serialize(&SignedTokenWire(self))
    }

    /// Returns the exact ordinary-Ed25519 message for this token (§13.2).
    pub fn signing_preimage(&self) -> Result<Vec<u8>, PairingTokenEncodeError> {
        let unsigned = self.unsigned_bytes()?;
        let mut preimage = Vec::with_capacity(TOKEN_CONTEXT.len() + unsigned.len());
        preimage.extend_from_slice(TOKEN_CONTEXT);
        preimage.extend_from_slice(&unsigned);
        Ok(preimage)
    }

    /// Signs this token using its issuer's caller-supplied Ed25519 key (§13.2).
    pub fn sign(&mut self, signer: &SigningKey) -> Result<(), PairingTokenSignatureError> {
        if signer.verifying_key().to_bytes() != self.issuer {
            return Err(PairingTokenSignatureError::SignerIdentityMismatch);
        }
        let preimage = self
            .signing_preimage()
            .map_err(PairingTokenSignatureError::InvalidToken)?;
        self.signature = signer.sign(&preimage).to_bytes();
        Ok(())
    }

    /// Verifies the token signature without applying time or recipient policy (§13.2).
    pub fn verify_signature(&self) -> Result<(), PairingTokenSignatureError> {
        let preimage = self
            .signing_preimage()
            .map_err(PairingTokenSignatureError::InvalidToken)?;
        let key = VerifyingKey::from_bytes(&self.issuer)
            .map_err(|_| PairingTokenSignatureError::InvalidIssuerKey)?;
        key.verify_strict(&preimage, &Signature::from_bytes(&self.signature))
            .map_err(|_| PairingTokenSignatureError::InvalidSignature)
    }

    /// Strictly decodes one canonical signed token before any cryptographic work (§13.1).
    pub fn decode(encoded: &[u8]) -> Result<Self, PairingTokenDecodeError> {
        if encoded.len() > MAX_TOKEN_CBOR_BYTES {
            return Err(PairingTokenDecodeError::InvalidEncoding);
        }
        let mut reader = CborReader::new(encoded);
        reader.array(12).map_err(decode_error)?;
        let ver = u8::try_from(reader.uint().map_err(decode_error)?)
            .map_err(|_| PairingTokenDecodeError::InvalidEncoding)?;
        let token = Self {
            ver,
            network_id: reader.fixed_bytes().map_err(decode_error)?,
            net_name: reader.text().map_err(decode_error)?,
            issuer: reader.fixed_bytes().map_err(decode_error)?,
            binding: reader.binding().map_err(decode_error)?,
            issuer_name: reader.optional_text().map_err(decode_error)?,
            relay: reader.text().map_err(decode_error)?,
            endpoint: reader.optional_text().map_err(decode_error)?,
            secret: reader.fixed_bytes().map_err(decode_error)?,
            not_after: reader.uint().map_err(decode_error)?,
            recipient: reader.optional_bytes32().map_err(decode_error)?,
            signature: reader.fixed_bytes().map_err(decode_error)?,
        };
        if !reader.finished() {
            return Err(PairingTokenDecodeError::InvalidEncoding);
        }
        token.validate_decoded_structure()?;
        let canonical = token.encode().map_err(map_encode_decode)?;
        if canonical != encoded {
            return Err(PairingTokenDecodeError::InvalidEncoding);
        }
        Ok(token)
    }

    /// Encodes the exact `kn1` unpadded RFC 4648 base64url representation (§13.3).
    pub fn to_text(&self) -> Result<String, PairingTokenEncodeError> {
        let encoded = self.encode()?;
        let body = URL_SAFE_NO_PAD.encode(encoded);
        let length = TOKEN_TEXT_PREFIX.len() + body.len();
        if length > MAX_TOKEN_TEXT_BYTES {
            return Err(PairingTokenEncodeError::TextRepresentationTooLong);
        }
        let mut output = String::with_capacity(length);
        output.push_str(TOKEN_TEXT_PREFIX);
        output.push_str(&body);
        Ok(output)
    }

    /// Decodes the bounded strict `kn1` text form before parsing its CBOR (§13.3).
    pub fn from_text(text: &str) -> Result<Self, PairingTokenTextError> {
        if text.len() > MAX_TOKEN_TEXT_BYTES {
            return Err(PairingTokenTextError::TooLong);
        }
        let body = text
            .strip_prefix(TOKEN_TEXT_PREFIX)
            .filter(|body| !body.is_empty())
            .ok_or(PairingTokenTextError::InvalidText)?;
        if !body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(PairingTokenTextError::InvalidText);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| PairingTokenTextError::InvalidText)?;
        Self::decode(&decoded).map_err(PairingTokenTextError::Token)
    }

    /// Computes SHA-256 over the canonical signed twelve-field CBOR (§13.3).
    pub fn token_id(&self) -> Result<[u8; 32], PairingTokenEncodeError> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    /// Applies strict signature, binding, expiry, and recipient acceptance (§§7.5, 13.3).
    pub fn validate(
        &self,
        importing_identity: &Identity,
        now: u64,
    ) -> Result<AcceptedPairingToken, PairingTokenAcceptanceError> {
        self.validate_structure()
            .map_err(PairingTokenAcceptanceError::InvalidToken)?;
        self.verify_signature()
            .map_err(PairingTokenAcceptanceError::InvalidSignature)?;
        let verified_binding = self
            .binding
            .verify()
            .map_err(|_| PairingTokenAcceptanceError::InvalidBindingSignature)?;
        let binding = verified_binding
            .validate_current(now)
            .map_err(|_| PairingTokenAcceptanceError::BindingNotCurrent)?;
        if now >= self.not_after {
            return Err(PairingTokenAcceptanceError::Expired);
        }
        if self
            .recipient
            .is_some_and(|recipient| recipient != *importing_identity)
        {
            return Err(PairingTokenAcceptanceError::RecipientMismatch);
        }
        Ok(AcceptedPairingToken {
            token: self.clone(),
            binding,
        })
    }

    /// Performs strict import acceptance including caller-owned generation/revocation state.
    pub fn validate_for_import(
        &self,
        importing_identity: &Identity,
        now: u64,
        binding_state: &KeyBindingState,
    ) -> Result<(AcceptedPairingToken, InstallationDecision), PairingTokenAcceptanceError> {
        let accepted = self.validate(importing_identity, now)?;
        let decision = accepted
            .installation_decision(binding_state)
            .map_err(PairingTokenAcceptanceError::BindingState)?;
        Ok((accepted, decision))
    }

    /// Decodes canonical CBOR before applying strict acceptance checks (§§13.1-13.3).
    pub fn decode_and_validate(
        encoded: &[u8],
        importing_identity: &Identity,
        now: u64,
    ) -> Result<AcceptedPairingToken, PairingTokenInputError> {
        Self::decode(encoded)
            .map_err(PairingTokenInputError::Decode)?
            .validate(importing_identity, now)
            .map_err(PairingTokenInputError::Acceptance)
    }

    fn validate_structure(&self) -> Result<(), PairingTokenEncodeError> {
        if self.ver != 1 {
            return Err(PairingTokenEncodeError::UnsupportedVersion);
        }
        if [&self.net_name, &self.relay]
            .into_iter()
            .chain(self.issuer_name.iter())
            .chain(self.endpoint.iter())
            .any(|text| text.len() > MAX_TEXT_FIELD_BYTES)
        {
            return Err(PairingTokenEncodeError::TextTooLong);
        }
        RelayIdentifier::parse(&self.relay).map_err(|_| PairingTokenEncodeError::InvalidRelay)?;
        if let Some(endpoint) = &self.endpoint {
            EndpointHint::parse(endpoint).map_err(|_| PairingTokenEncodeError::InvalidEndpoint)?;
        }
        if self.binding.network_id != self.network_id || self.binding.identity != self.issuer {
            return Err(PairingTokenEncodeError::BindingScopeMismatch);
        }
        self.binding
            .validate_interval()
            .map_err(|_| PairingTokenEncodeError::InvalidBindingInterval)
    }

    fn validate_decoded_structure(&self) -> Result<(), PairingTokenDecodeError> {
        self.validate_structure().map_err(map_encode_decode)
    }
}

/// A decode-before-acceptance failure for canonical PairingToken input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingTokenInputError {
    /// Canonical parsing failed before signature verification.
    Decode(PairingTokenDecodeError),
    /// The canonical token failed cryptographic or endpoint acceptance.
    Acceptance(PairingTokenAcceptanceError),
}

/// Derives the pair PSK with issuer-before-recipient identity ordering (§§7.4, 13.2).
pub fn derive_pair_psk(
    secret: &[u8; 32],
    network_id: &NetworkId,
    issuer: &Identity,
    recipient: &Identity,
) -> [u8; 32] {
    let mut info = [0; 109];
    info[..PSK_CONTEXT.len()].copy_from_slice(PSK_CONTEXT);
    info[PSK_CONTEXT.len()..PSK_CONTEXT.len() + 32].copy_from_slice(network_id);
    info[PSK_CONTEXT.len() + 32..PSK_CONTEXT.len() + 64].copy_from_slice(issuer);
    info[PSK_CONTEXT.len() + 64..].copy_from_slice(recipient);
    let mut output = [0; 32];
    let result = Hkdf::<Sha256>::new(None, secret).expand(&info, &mut output);
    debug_assert!(result.is_ok());
    output
}

fn serialize(value: &impl Serialize) -> Result<Vec<u8>, PairingTokenEncodeError> {
    let mut output = Vec::with_capacity(MAX_TOKEN_CBOR_BYTES);
    ciborium::ser::into_writer(value, &mut output)
        .map_err(|_| PairingTokenEncodeError::Serialization)?;
    if output.len() > MAX_TOKEN_CBOR_BYTES {
        return Err(PairingTokenEncodeError::Serialization);
    }
    Ok(output)
}

fn decode_error(_: crate::codec::CborError) -> PairingTokenDecodeError {
    PairingTokenDecodeError::InvalidEncoding
}

fn map_encode_decode(error: PairingTokenEncodeError) -> PairingTokenDecodeError {
    match error {
        PairingTokenEncodeError::UnsupportedVersion => PairingTokenDecodeError::UnsupportedVersion,
        PairingTokenEncodeError::TextTooLong => PairingTokenDecodeError::TextTooLong,
        PairingTokenEncodeError::InvalidRelay => PairingTokenDecodeError::InvalidRelay,
        PairingTokenEncodeError::InvalidEndpoint => PairingTokenDecodeError::InvalidEndpoint,
        PairingTokenEncodeError::BindingScopeMismatch => {
            PairingTokenDecodeError::BindingScopeMismatch
        }
        PairingTokenEncodeError::InvalidBindingInterval => {
            PairingTokenDecodeError::InvalidBindingInterval
        }
        PairingTokenEncodeError::TextRepresentationTooLong
        | PairingTokenEncodeError::Serialization => PairingTokenDecodeError::InvalidEncoding,
    }
}

struct UnsignedTokenWire<'a>(&'a PairingToken);
struct SignedTokenWire<'a>(&'a PairingToken);

fn serialize_token_fields<S>(token: &PairingToken, array: &mut S) -> Result<(), S::Error>
where
    S: SerializeTuple,
{
    array.serialize_element(&token.ver)?;
    array.serialize_element(&serde_bytes::Bytes::new(&token.network_id))?;
    array.serialize_element(&token.net_name)?;
    array.serialize_element(&serde_bytes::Bytes::new(&token.issuer))?;
    array.serialize_element(&NestedBindingWire(&token.binding))?;
    array.serialize_element(&token.issuer_name)?;
    array.serialize_element(&token.relay)?;
    array.serialize_element(&token.endpoint)?;
    array.serialize_element(&serde_bytes::Bytes::new(&token.secret))?;
    array.serialize_element(&token.not_after)?;
    let recipient = token
        .recipient
        .as_ref()
        .map(|value| serde_bytes::Bytes::new(value));
    array.serialize_element(&recipient)
}

impl Serialize for UnsignedTokenWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(11)?;
        serialize_token_fields(self.0, &mut array)?;
        array.end()
    }
}

impl Serialize for SignedTokenWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(12)?;
        serialize_token_fields(self.0, &mut array)?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.signature))?;
        array.end()
    }
}

pub(crate) struct NestedBindingWire<'a>(pub(crate) &'a KeyBinding);

impl Serialize for NestedBindingWire<'_> {
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
