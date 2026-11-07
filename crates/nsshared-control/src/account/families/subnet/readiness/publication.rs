use super::{ExitProviderConfirmation, field};
use crate::account::{
    AccountError, MAX_BYTES,
    codec::{ascending_by, bounded, identity, reader, require},
};
use nsshared_codec::cbor::CborWriter;
use nsshared_identity::keys::IdentityKey;

/// Maximum positive confirmations in one complete consumer collection.
pub const MAX_EXIT_CONFIRMATIONS: usize = 32;

/// Complete observational replacement, separate from route and packet authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitReadinessPublication {
    /// Existing M6 NSD identifier.
    pub nsd_id: [u8; 16],
    /// Exact served Network.
    pub network_id: [u8; 16],
    /// Consumer receiving this complete set.
    pub recipient: IdentityKey,
    /// Positive version of this observational collection.
    pub revision: u64,
    /// Strict selection-ID order, at most one current generation for each ID.
    pub confirmations: Vec<ExitProviderConfirmation>,
}
impl ExitReadinessPublication {
    /// Encodes a complete positive set or explicit empty replacement.
    /// # Errors
    /// Refuses bounds, duplicate selections, mixed source/owner or scope disagreement.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        require(
            self.revision > 0
                && self.confirmations.len() <= MAX_EXIT_CONFIRMATIONS
                && ascending_by(&self.confirmations, |c| {
                    &c.context.receipt.command.selection_id
                }),
        )?;
        let first = self.confirmations.first().map(|c| &c.context);
        let mut out = CborWriter::default();
        out.array(7)
            .uint(1)
            .uint(4)
            .bytes(&self.nsd_id)
            .bytes(&self.network_id)
            .bytes(self.recipient.as_bytes())
            .uint(self.revision)
            .array(self.confirmations.len());
        for proof in &self.confirmations {
            let context = &proof.context;
            let source = &context.receipt.command.binding.binding;
            require(
                context.grant.resource.nsd_id == self.nsd_id
                    && context.grant.resource.network_id == self.network_id
                    && source.recipient == self.recipient,
            )?;
            if let Some(first) = first {
                require(
                    *source == first.receipt.command.binding.binding
                        && context.consumer_incarnation == first.consumer_incarnation
                        && context.nsd_incarnation == first.nsd_incarnation,
                )?;
            }
            out.bytes(&proof.canonical()?);
        }
        bounded(out.into_bytes())
    }
    /// Decodes an exact bounded set without acquiring source authority.
    /// # Errors
    /// Refuses noncanonical, malformed, duplicate or foreign-scoped proof.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 7)?;
        require(input.uint()? == 4)?;
        let nsd_id = input.fixed_bytes()?;
        let network_id = input.fixed_bytes()?;
        let recipient = identity(&mut input)?;
        let revision = input.uint()?;
        let count = input.array_up_to(MAX_EXIT_CONFIRMATIONS)?;
        let confirmations = (0..count)
            .map(|_| ExitProviderConfirmation::decode(input.bytes_up_to(MAX_BYTES).map_err(field)?))
            .collect::<Result<_, _>>()?;
        input.finish()?;
        let value = Self {
            nsd_id,
            network_id,
            recipient,
            revision,
            confirmations,
        };
        value.canonical()?;
        Ok(value)
    }
}
