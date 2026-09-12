use std::time::{SystemTime, UNIX_EPOCH};

use crate::envelope::{ControlEnvelope, ENVELOPE_VERSION};

use super::Error;
use super::codec::payload;

payload!(WinnerQuery, "mesh.winner.query", {
    1_u64 => network_pub: [u8; 32],
    2_u64 => request_id: [u8; 16],
    3_u64 => joiner_pub: [u8; 32],
    4_u64 => joiner_wg: [u8; 32],
});

impl WinnerQuery {
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}

payload!(WinnerResult, "mesh.winner.result", {
    1_u64 => network_pub: [u8; 32],
    2_u64 => request_id: [u8; 16],
    3_u64 => joiner_pub: [u8; 32],
    4_u64 => joiner_wg: [u8; 32],
    5_u64 => status: u64,
    6_u64 => author_pub: Option<[u8; 32]>,
    7_u64 => seq: Option<u64>,
    8_u64 => record_digest: Option<[u8; 32]>,
});

impl WinnerResult {
    pub const FOUND: u64 = 0;
    pub const UNAVAILABLE: u64 = 1;

    fn validate(&self) -> Result<(), Error> {
        let valid = match self.status {
            Self::FOUND => {
                self.author_pub.is_some()
                    && self.seq.is_some_and(|seq| seq > 0)
                    && self.record_digest.is_some()
            }
            Self::UNAVAILABLE => {
                self.author_pub.is_none() && self.seq.is_none() && self.record_digest.is_none()
            }
            _ => false,
        };
        if !valid {
            return Err(Error::Payload("inconsistent winner result"));
        }
        Ok(())
    }

    /// Sign only after checking current approval authority and the exact live carrier identity.
    /// This nonce-bound metadata is neither a receipt nor permission to repeat an approval.
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
