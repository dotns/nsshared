use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use super::Error;

pub const COMPACT_FORMAT_VERSION: u16 = 1;
pub const MAX_COMPACT_BYTES: usize = 1_048_576;
pub const MAX_COMPACT_MEMBERS: usize = 32;
pub const MAX_RETAINED_IDENTITIES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactMember {
    pub wg_pub: [u8; 32],
    pub incarnation: u64,
}

/// Result state only. Original records, addresses, presence and policy are not serialized here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactState {
    pub network_pub: [u8; 32],
    pub seq: u64,
    pub members: BTreeMap<[u8; 32], CompactMember>,
    pub admins_revision: u64,
    pub admins: BTreeSet<[u8; 32]>,
    pub evicted_through: BTreeMap<[u8; 32], u64>,
}

impl CompactState {
    pub fn validate(&self) -> Result<(), Error> {
        if self.members.len() > MAX_COMPACT_MEMBERS
            || self.admins.len() > MAX_COMPACT_MEMBERS
            || self.evicted_through.len() > MAX_RETAINED_IDENTITIES
        {
            return Err(Error::Payload("compact state capacity"));
        }
        let identities: BTreeSet<_> = self
            .members
            .keys()
            .chain(self.admins.iter())
            .chain(self.evicted_through.keys())
            .collect();
        if identities.len() > MAX_RETAINED_IDENTITIES {
            return Err(Error::Payload("retained identity capacity"));
        }
        if self.admins_revision > self.seq || (self.admins_revision == 0 && !self.admins.is_empty())
        {
            return Err(Error::Payload("admin revision"));
        }
        let mut wg_keys = BTreeSet::new();
        for (key, member) in &self.members {
            if member.incarnation == 0
                || self
                    .evicted_through
                    .get(key)
                    .is_some_and(|watermark| member.incarnation <= *watermark)
                || !wg_keys.insert(member.wg_pub)
            {
                return Err(Error::Payload("compact member binding or incarnation"));
            }
        }
        if self
            .evicted_through
            .values()
            .any(|watermark| *watermark == 0)
        {
            return Err(Error::Payload("empty eviction watermark"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&COMPACT_FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network_pub);
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        count(&mut bytes, self.members.len())?;
        for (key, member) in &self.members {
            bytes.extend_from_slice(key);
            bytes.extend_from_slice(&member.wg_pub);
            bytes.extend_from_slice(&member.incarnation.to_be_bytes());
        }
        bytes.extend_from_slice(&self.admins_revision.to_be_bytes());
        count(&mut bytes, self.admins.len())?;
        for key in &self.admins {
            bytes.extend_from_slice(key);
        }
        count(&mut bytes, self.evicted_through.len())?;
        for (key, watermark) in &self.evicted_through {
            bytes.extend_from_slice(key);
            bytes.extend_from_slice(&watermark.to_be_bytes());
        }
        if bytes.len() > MAX_COMPACT_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_COMPACT_BYTES {
            return Err(Error::TooLarge);
        }
        let mut input = Input(bytes);
        if u16::from_be_bytes(input.take()?) != COMPACT_FORMAT_VERSION {
            return Err(Error::Payload("compact state version"));
        }
        let network_pub = input.take()?;
        let seq = input.u64()?;
        let mut members = BTreeMap::new();
        let mut previous = None;
        for _ in 0..input.count(MAX_COMPACT_MEMBERS)? {
            let key = input.ordered_key(&mut previous)?;
            members.insert(
                key,
                CompactMember {
                    wg_pub: input.take()?,
                    incarnation: input.u64()?,
                },
            );
        }
        let admins_revision = input.u64()?;
        let mut admins = BTreeSet::new();
        let mut previous = None;
        for _ in 0..input.count(MAX_COMPACT_MEMBERS)? {
            admins.insert(input.ordered_key(&mut previous)?);
        }
        let mut evicted_through = BTreeMap::new();
        let mut previous = None;
        for _ in 0..input.count(MAX_RETAINED_IDENTITIES)? {
            evicted_through.insert(input.ordered_key(&mut previous)?, input.u64()?);
        }
        if !input.0.is_empty() {
            return Err(Error::Payload("compact trailing data"));
        }
        let state = Self {
            network_pub,
            seq,
            members,
            admins_revision,
            admins,
            evicted_through,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn digest(&self) -> Result<[u8; 32], Error> {
        Ok(digest(&self.encode()?))
    }

    pub fn decode_for_anchor(
        bytes: &[u8],
        network: &[u8; 32],
        seq: u64,
        expected_digest: &[u8; 32],
    ) -> Result<Self, Error> {
        let state = Self::decode(bytes)?;
        if &state.network_pub != network || state.seq != seq || &digest(bytes) != expected_digest {
            return Err(Error::Payload("compact anchor mismatch"));
        }
        Ok(state)
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"nsmesh-membership-state-v1\0");
    hash.update(bytes);
    hash.finalize().into()
}

fn count(bytes: &mut Vec<u8>, count: usize) -> Result<(), Error> {
    let count = u32::try_from(count).map_err(|_| Error::TooLarge)?;
    bytes.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

struct Input<'a>(&'a [u8]);
impl Input<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (field, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(Error::Payload("truncated compact state"))?;
        self.0 = rest;
        Ok(*field)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.take()?))
    }
    fn count(&mut self, max: usize) -> Result<usize, Error> {
        let count =
            usize::try_from(u32::from_be_bytes(self.take()?)).map_err(|_| Error::TooLarge)?;
        if count > max {
            return Err(Error::Payload("compact count limit"));
        }
        Ok(count)
    }
    fn ordered_key(&mut self, previous: &mut Option<[u8; 32]>) -> Result<[u8; 32], Error> {
        let key = self.take()?;
        if previous.is_some_and(|previous| previous >= key) {
            return Err(Error::Payload("compact key ordering"));
        }
        *previous = Some(key);
        Ok(key)
    }
}
