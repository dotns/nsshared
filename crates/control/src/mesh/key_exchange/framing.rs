use std::collections::BTreeSet;

use ciborium::value::Value;
use secrecy::{SecretBox, zeroize::Zeroize as _};

use super::{KeyGrant, KeyPeerBinding, KeyRequest, MAX_KEY_BODY, SensitiveValue};
use crate::envelope::ControlEnvelope;
use crate::mesh::{Error, SyncFrame, codec, decode_sync_length};

/// Complete, structurally decoded frame only. Live WG authority remains the owner's check.
pub enum WgPeerFrame {
    Sync(SyncFrame),
    Key(KeyEnvelope),
}

/// The contained envelope can carry a secret and is deliberately not exposed or cloned.
pub struct KeyEnvelope {
    envelope: ControlEnvelope,
}

impl std::fmt::Debug for KeyEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEnvelope")
            .field("api", &self.envelope.api)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

impl Drop for KeyEnvelope {
    fn drop(&mut self) {
        self.envelope.payload.as_mut_slice().zeroize();
    }
}

impl KeyEnvelope {
    pub fn from_envelope(envelope: ControlEnvelope) -> Result<Self, Error> {
        let result = Self { envelope };
        result.validate()?;
        let bytes = secrecy::zeroize::Zeroizing::new(
            result
                .envelope
                .to_cbor()
                .map_err(|_| Error::Payload("key envelope encoding"))?,
        );
        if bytes.len() > MAX_KEY_BODY {
            return Err(Error::TooLarge);
        }
        Ok(result)
    }

    pub fn api(&self) -> &str {
        &self.envelope.api
    }

    pub const fn nonce(&self) -> &[u8; 16] {
        &self.envelope.nonce
    }

    pub fn encode(&self) -> Result<SecretBox<Vec<u8>>, Error> {
        let body = secrecy::zeroize::Zeroizing::new(
            self.envelope
                .to_cbor()
                .map_err(|_| Error::Payload("key envelope encoding"))?,
        );
        if body.len() > MAX_KEY_BODY {
            return Err(Error::TooLarge);
        }
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(SecretBox::new(Box::new(frame)))
    }

    /// Signature and full declared binding only; caller checks current WG/member/version facts.
    pub fn verify_request(&self, grantor: &KeyPeerBinding, now: u64) -> Result<KeyRequest, Error> {
        if self.envelope.api != KeyRequest::API {
            return Err(Error::Payload("expected key request"));
        }
        self.envelope
            .verify_request(now)
            .map_err(|_| Error::Payload("key request signature"))?;
        let request = KeyRequest::decode(&self.envelope.payload)?;
        if request.requester.signing_pub != self.envelope.machine_key_pub
            || request.grantor != *grantor
        {
            return Err(Error::Payload("key request peer binding"));
        }
        Ok(request)
    }

    /// Does not consume a nonce or install a key. The single owner performs those transitions.
    pub fn verify_grant(
        &self,
        request: &KeyRequest,
        request_nonce: &[u8; 16],
        now: u64,
    ) -> Result<KeyGrant, Error> {
        if self.envelope.api != KeyGrant::API {
            return Err(Error::Payload("expected key grant"));
        }
        self.envelope
            .verify_response(now, &request.grantor.signing_pub)
            .map_err(|_| Error::Payload("key grant signature"))?;
        let grant = KeyGrant::decode(&self.envelope.payload)?;
        if grant.request() != request || grant.request_nonce() != request_nonce {
            return Err(Error::Payload("key grant request binding"));
        }
        Ok(grant)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.envelope.v != 1 || self.envelope.machine_id.is_some() {
            return Err(Error::Payload("key envelope identity"));
        }
        match self.envelope.api.as_str() {
            KeyRequest::API => {
                KeyRequest::decode(&self.envelope.payload)?;
            }
            KeyGrant::API => {
                KeyGrant::decode(&self.envelope.payload)?;
            }
            _ => return Err(Error::Payload("WG key API")),
        }
        Ok(())
    }
}

pub fn decode_wg_peer_frame(frame: &[u8]) -> Result<WgPeerFrame, Error> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(Error::Payload("frame prefix"))?
        .try_into()
        .map_err(|_| Error::Payload("frame prefix"))?;
    let length = decode_sync_length(prefix)?;
    if frame.len() != length + 4 {
        return Err(Error::Payload("frame length"));
    }
    let body = &frame[4..];
    // Select exactly once from the structured top-level keys, never by decoder failure.
    let mut input = body;
    let value = SensitiveValue(
        ciborium::de::from_reader(&mut input).map_err(|_| Error::Payload("WG frame CBOR"))?,
    );
    if !input.is_empty() {
        return Err(Error::Payload("WG frame trailing bytes"));
    }
    let Value::Map(fields) = &value.0 else {
        return Err(Error::Payload("WG frame map"));
    };
    if !fields.is_empty()
        && fields
            .iter()
            .all(|(key, _)| matches!(key, Value::Integer(_)))
    {
        return SyncFrame::decode_body(body).map(WgPeerFrame::Sync);
    }
    if fields.is_empty() || !fields.iter().all(|(key, _)| matches!(key, Value::Text(_))) {
        return Err(Error::Payload("WG frame mixed or unsupported keys"));
    }
    if body.len() > MAX_KEY_BODY {
        return Err(Error::TooLarge);
    }
    let mut names = BTreeSet::new();
    for (key, _) in fields {
        let Value::Text(name) = key else {
            return Err(Error::Payload("WG envelope field key"));
        };
        if !names.insert(name) {
            return Err(Error::Payload("duplicate envelope field"));
        }
    }
    let canonical =
        secrecy::zeroize::Zeroizing::new(codec::encode_with_limit(&value.0, MAX_KEY_BODY)?);
    if canonical.as_slice() != body {
        return Err(Error::Payload("noncanonical envelope"));
    }
    // Reuse the strict tree validator without treating envelope text keys as payload keys.
    let values = SensitiveValue(Value::Array(
        fields.iter().map(|(_, value)| value.clone()).collect(),
    ));
    let tree = secrecy::zeroize::Zeroizing::new(codec::encode_with_limit(&values.0, MAX_KEY_BODY)?);
    let _validated = SensitiveValue(codec::decode(&tree)?);
    let envelope = ControlEnvelope::from_cbor(body).map_err(|_| Error::Payload("key envelope"))?;
    KeyEnvelope::from_envelope(envelope).map(WgPeerFrame::Key)
}
