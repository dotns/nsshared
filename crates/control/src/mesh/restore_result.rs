use std::time::{SystemTime, UNIX_EPOCH};

use crate::envelope::{ControlEnvelope, ENVELOPE_VERSION};

use super::Error;
use super::codec::payload;

payload!(RestoreResult, "mesh.restore.result", {
    1_u64 => network_pub: [u8; 32],
    2_u64 => request_id: [u8; 16],
    3_u64 => uploader_pub: [u8; 32],
    4_u64 => anchor_seq: u64,
    5_u64 => state_digest: [u8; 32],
    6_u64 => phase: u64,
    7_u64 => chunk_index: Option<u64>,
    8_u64 => status: u64,
});

impl RestoreResult {
    pub const BEGIN: u64 = 0;
    pub const CHUNK: u64 = 1;
    pub const FINISH: u64 = 2;
    pub const ACCEPTED: u64 = 0;
    pub const INSTALLED: u64 = 1;
    pub const INCOMPLETE: u64 = 2;
    pub const CONFLICT: u64 = 3;
    pub const BUSY: u64 = 4;

    fn validate(&self) -> Result<(), Error> {
        let valid = match (self.phase, self.chunk_index) {
            (Self::BEGIN, None) => {
                matches!(self.status, Self::ACCEPTED | Self::CONFLICT | Self::BUSY)
            }
            (Self::CHUNK, Some(0..=2047)) => matches!(self.status, Self::ACCEPTED | Self::CONFLICT),
            (Self::FINISH, None) => matches!(
                self.status,
                Self::INSTALLED | Self::INCOMPLETE | Self::CONFLICT | Self::BUSY
            ),
            _ => false,
        };
        if !valid {
            return Err(Error::Payload("inconsistent restore result"));
        }
        Ok(())
    }

    /// Sign a result only after authenticating the uploader and candidate. The response echoes
    /// this request's nonce; it grants no membership or activity credit. Existing envelope APIs
    /// retain their random response nonces.
    pub fn sign_response<F>(
        &self,
        request_nonce: [u8; 16],
        relay_key: [u8; 32],
        sign: F,
    ) -> Result<ControlEnvelope, Error>
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        let mut envelope = ControlEnvelope {
            v: ENVELOPE_VERSION,
            api: Self::API.into(),
            ts: 0,
            nonce: request_nonce,
            machine_id: None,
            machine_key_pub: relay_key,
            payload: self.encode()?.into(),
            signature: [0; 64],
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crate::envelope::Error::ClockBeforeEpoch)?
            .as_secs();
        envelope.sign_response_at(now, request_nonce, sign);
        Ok(envelope)
    }
}
