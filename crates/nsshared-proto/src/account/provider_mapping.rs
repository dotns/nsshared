//! Pure provider mapping inventory; authentication belongs to the signed carrier.

use super::{MAX_BYTES, SubnetError, SubnetPrefix};
use crate::encoding::{CborReader, CborWriter};

/// Maximum entries in a complete eligible inventory.
pub const MAX_PROVIDER_MAPPINGS: usize = 256;

/// One eligible NSD mapping, without forwarding or allocation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderMapping {
    /// Nonzero NSD-allocated mapping identifier.
    pub subnet_id: u32,
    /// Exact real network, using the Subnet prefix contract.
    pub real_cidr: SubnetPrefix,
}

/// Complete inventory ordered strictly by mapping identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderMappings {
    /// Eligible mappings; empty removes eligibility in this collection only.
    pub mappings: Vec<ProviderMapping>,
}

impl ProviderMappings {
    fn validate(&self) -> Result<(), SubnetError> {
        if self.mappings.len() > MAX_PROVIDER_MAPPINGS {
            return Err(SubnetError::Bounds);
        }
        let mut previous = 0;
        for entry in &self.mappings {
            if entry.subnet_id <= previous {
                return Err(SubnetError::Scope);
            }
            entry.real_cidr.validate()?;
            previous = entry.subnet_id;
        }
        Ok(())
    }

    /// Encodes the canonical complete typed inventory.
    /// # Errors
    /// Refuses invalid ids, ordering, prefixes or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, SubnetError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(2).uint(1).array(self.mappings.len());
        for entry in &self.mappings {
            out.array(2).uint(u64::from(entry.subnet_id));
            entry.real_cidr.write(&mut out);
        }
        let bytes = out.into_bytes();
        if bytes.len() > MAX_BYTES {
            return Err(SubnetError::Bounds);
        }
        Ok(bytes)
    }

    /// Decodes without sorting, truncating or repairing received entries.
    /// # Errors
    /// Refuses malformed, noncanonical, oversized or invalid inventories.
    pub fn decode(bytes: &[u8]) -> Result<Self, SubnetError> {
        let mut input = CborReader::new(bytes, MAX_BYTES)?;
        input.array(2)?;
        if input.uint()? != 1 {
            return Err(SubnetError::Scope);
        }
        let count = input.array_up_to(MAX_PROVIDER_MAPPINGS)?;
        let mut mappings = Vec::with_capacity(count);
        for _ in 0..count {
            input.array(2)?;
            let subnet_id = u32::try_from(input.uint()?).map_err(|_| SubnetError::Scope)?;
            let real_cidr = SubnetPrefix::read(&mut input)?;
            mappings.push(ProviderMapping {
                subnet_id,
                real_cidr,
            });
        }
        input.finish()?;
        let value = Self { mappings };
        value.validate()?;
        Ok(value)
    }
}
