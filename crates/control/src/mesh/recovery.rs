use ed25519_dalek::{Signature, VerifyingKey};

use super::Error;
use super::codec::{Field, payload};

payload!(CommitQuery, "mesh.commit.query", {
    1_u64 => network_pub: [u8; 32],
    2_u64 => op_id: [u8; 16],
    3_u64 => record_digest: [u8; 32],
});
payload!(CommitAck, "mesh.commit.ack", {
    1_u64 => network_pub: [u8; 32],
    2_u64 => op_id: [u8; 16],
    3_u64 => record_digest: [u8; 32],
    4_u64 => seq: u64,
});
payload!(CommitReceipt, "", {
    1_u64 => network_pub: [u8; 32],
    2_u64 => op_id: [u8; 16],
    3_u64 => author_pub: [u8; 32],
    4_u64 => seq: u64,
    5_u64 => record_digest: [u8; 32],
    6_u64 => signature: [u8; 64],
});
payload!(CommitResult, "mesh.commit.result", {
    1_u64 => network_pub: [u8; 32],
    2_u64 => op_id: [u8; 16],
    3_u64 => author_pub: [u8; 32],
    4_u64 => status: u64,
    5_u64 => seq: Option<u64>,
    6_u64 => record_digest: [u8; 32],
    7_u64 => receipt: Option<CommitReceipt>,
});
payload!(RestoreBegin, "mesh.restore.begin", {
    1_u64 => network_pub: [u8; 32],
    2_u64 => request_id: [u8; 16],
    3_u64 => anchor_seq: u64,
    4_u64 => state_digest: [u8; 32],
    5_u64 => format_version: u64,
    6_u64 => total_bytes: u64,
    7_u64 => chunk_count: u64,
    8_u64 => network_proof: [u8; 64],
});
payload!(RestoreChunk, "mesh.restore.chunk", {
    1_u64 => network_pub: [u8; 32],
    2_u64 => request_id: [u8; 16],
    3_u64 => anchor_seq: u64,
    4_u64 => state_digest: [u8; 32],
    5_u64 => index: u64,
    6_u64 => bytes: Vec<u8>,
});
payload!(RestoreFinish, "mesh.restore.finish", {
    1_u64 => network_pub: [u8; 32],
    2_u64 => request_id: [u8; 16],
    3_u64 => anchor_seq: u64,
    4_u64 => state_digest: [u8; 32],
});

impl CommitQuery {
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}
impl RestoreFinish {
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}
impl CommitAck {
    fn validate(&self) -> Result<(), Error> {
        if self.seq == 0 {
            return Err(Error::Payload("management sequence starts at 1"));
        }
        Ok(())
    }
}

impl CommitReceipt {
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }

    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = b"nsmesh-receipt-v1\0".to_vec();
        self.network_pub.sign_into(&mut out);
        self.op_id.sign_into(&mut out);
        self.author_pub.sign_into(&mut out);
        self.seq.sign_into(&mut out);
        self.record_digest.sign_into(&mut out);
        out
    }

    pub fn verify(&self, relay_key: &[u8; 32]) -> Result<(), Error> {
        verify(relay_key, &self.signing_input(), &self.signature)
    }
}

impl CommitResult {
    pub const COMMITTED: u64 = 0;
    pub const RESULT_UNAVAILABLE: u64 = 1;
    pub const CONFLICT: u64 = 2;

    fn validate(&self) -> Result<(), Error> {
        match (self.status, self.seq, self.receipt.as_ref()) {
            (Self::COMMITTED, Some(seq), Some(receipt))
                if seq > 0
                    && receipt.network_pub == self.network_pub
                    && receipt.op_id == self.op_id
                    && receipt.author_pub == self.author_pub
                    && receipt.seq == seq
                    && receipt.record_digest == self.record_digest =>
            {
                Ok(())
            }
            (Self::RESULT_UNAVAILABLE | Self::CONFLICT, None, None) => Ok(()),
            _ => Err(Error::Payload("inconsistent commit result")),
        }
    }
}

impl RestoreBegin {
    fn validate(&self) -> Result<(), Error> {
        if self.format_version != 1
            || !(1..=1_048_576).contains(&self.total_bytes)
            || !(1..=2048).contains(&self.chunk_count)
            || self.chunk_count > self.total_bytes
            || self.total_bytes > self.chunk_count * 512
        {
            return Err(Error::Payload("restore dimensions"));
        }
        Ok(())
    }

    pub fn proof_input(&self, uploader: &[u8; 32], wg_pub: &[u8; 32]) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = b"nsmesh-restore-v1\0".to_vec();
        self.network_pub.sign_into(&mut out);
        self.request_id.sign_into(&mut out);
        self.anchor_seq.sign_into(&mut out);
        self.state_digest.sign_into(&mut out);
        self.format_version.sign_into(&mut out);
        self.total_bytes.sign_into(&mut out);
        self.chunk_count.sign_into(&mut out);
        uploader.sign_into(&mut out);
        wg_pub.sign_into(&mut out);
        Ok(out)
    }

    pub fn verify_proof(&self, uploader: &[u8; 32], wg_pub: &[u8; 32]) -> Result<(), Error> {
        verify(
            &self.network_pub,
            &self.proof_input(uploader, wg_pub)?,
            &self.network_proof,
        )
    }
}

impl RestoreChunk {
    fn validate(&self) -> Result<(), Error> {
        if self.index >= 2048 || self.bytes.is_empty() || self.bytes.len() > 512 {
            return Err(Error::Payload("restore chunk bounds"));
        }
        Ok(())
    }
}

pub(super) fn verify(key: &[u8; 32], input: &[u8], signature: &[u8; 64]) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| Error::Payload("signing key"))?;
    key.verify_strict(input, &Signature::from_bytes(signature))
        .map_err(|_| Error::Payload("signature"))
}
