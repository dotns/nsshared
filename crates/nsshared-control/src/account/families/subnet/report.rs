//! Pure ordinary-provider route reports and caller-owned custody comparisons.

use crate::{service::Id, service::ServiceRef};
use thiserror::Error;

use crate::{
    account::MAX_BYTES, account::control::BootstrapEnvelope, account::control::EnvelopeDirection,
    account::control::EnvelopeExpectation, account::publication::source_binding::MAX_SOURCE_BYTES,
    account::publication::source_binding::SignedSourceBinding,
    account::publication::source_binding::SourceError,
    account::publication::source_binding::nonzero, account::subnet::SubnetError,
    account::subnet::SubnetPrefix, account::subnet::SubnetSelection,
    account::subnet::views::read_set, account::subnet::views::validate_set,
    account::subnet::views::write_set,
};
use nsshared_codec::{cbor::CborError, cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;

/// Confidential ordinary Node provider report operation, in both directions.
pub const NODE_SUBNET_REPORT: &str = "node.subnet.report";
/// Maximum mappings in one complete report or response.
pub const MAX_SUBNET_OFFERS: usize = 256;

/// Invalid input never changes caller-owned generation, offers or allocations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SubnetReportError {
    /// Strict canonical encoding refusal.
    #[error(transparent)]
    Encoding(#[from] CborError),
    /// Source or authenticated carrier refusal.
    #[error(transparent)]
    Source(#[from] SourceError),
    /// Existing prefix/selection rules refused the input.
    #[error(transparent)]
    Subnet(#[from] SubnetError),
    /// Unsupported schema, zero generation or invalid ordered mapping ids.
    #[error("invalid Subnet report fields")]
    Fields,
    /// Encoded payload or entry bound exceeded.
    #[error("Subnet report bound exceeded")]
    Bounds,
    /// Binding is not the exact current nodes authority for the caller and Network.
    #[error("Subnet report source authority mismatch")]
    Authority,
    /// Mapping is missing, ambiguous, inactive or has incompatible ownership/destinations.
    #[error("Subnet report mapping authority mismatch")]
    Mapping,
    /// Equal generation carries different complete content.
    #[error("Subnet report generation conflict")]
    Conflict,
    /// Generation predates retained custody, even after complete withdrawal.
    #[error("stale Subnet report generation")]
    Stale,
    /// Allocation scope, mapping set or retained assignment disagrees.
    #[error("Subnet report allocation mismatch")]
    Allocation,
}

fn require(condition: bool, error: SubnetReportError) -> Result<(), SubnetReportError> {
    if condition { Ok(()) } else { Err(error) }
}
fn ids(values: impl Iterator<Item = u32>) -> Result<(), SubnetReportError> {
    let mut previous = 0;
    for id in values {
        require(id > previous, SubnetReportError::Fields)?;
        previous = id;
    }
    Ok(())
}
fn count(input: &mut CborReader<'_>) -> Result<usize, SubnetReportError> {
    input
        .array_up_to(MAX_SUBNET_OFFERS)
        .map_err(|error| match error {
            CborError::ArrayLength { .. } => SubnetReportError::Bounds,
            other => other.into(),
        })
}
fn mapping_id(input: &mut CborReader<'_>) -> Result<u32, SubnetReportError> {
    u32::try_from(input.uint()?).map_err(|_| SubnetReportError::Fields)
}
fn bounded(bytes: Vec<u8>) -> Result<Vec<u8>, SubnetReportError> {
    require(bytes.len() <= MAX_BYTES, SubnetReportError::Bounds)?;
    Ok(bytes)
}

/// Provider intent for an existing NSD mapping, never allocation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubnetRouteOffer {
    /// Nonzero NSD-allocated u32 mapping identity.
    pub subnet_id: u32,
    /// Exact existing explicit or default SubnetSelection representation.
    pub selection: SubnetSelection,
}

/// Complete offered set for one exact signed nodes source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeSubnetRouteReport {
    /// NSD-produced source binding; decoding does not establish authority.
    pub binding: SignedSourceBinding,
    /// Positive retained provider generation within this exact source.
    pub report_generation: u64,
    /// Ascending unique mappings; empty withdraws the complete live set.
    pub offers: Vec<SubnetRouteOffer>,
}
impl NodeSubnetRouteReport {
    /// Encodes exact intent without normalizing prefixes or mapping order.
    /// # Errors
    /// Refuses invalid source fields, counters, mapping ids, selections or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, SubnetReportError> {
        require(self.report_generation > 0, SubnetReportError::Fields)?;
        require(
            self.offers.len() <= MAX_SUBNET_OFFERS,
            SubnetReportError::Bounds,
        )?;
        ids(self.offers.iter().map(|offer| offer.subnet_id))?;
        let mut out = CborWriter::default();
        out.array(4)
            .uint(1)
            .bytes(&self.binding.canonical()?)
            .uint(self.report_generation)
            .array(self.offers.len());
        for offer in &self.offers {
            out.array(2).uint(u64::from(offer.subnet_id)).array(2);
            match &offer.selection {
                SubnetSelection::Default => {
                    out.uint(0).array(0);
                }
                SubnetSelection::Explicit(prefixes) => {
                    validate_set(prefixes)?;
                    out.uint(1);
                    write_set(prefixes, &mut out);
                }
            }
        }
        bounded(out.into_bytes())
    }

    /// Decodes bounded exact canonical bytes, without accepting source or mapping custody.
    /// # Errors
    /// Refuses unknown, malformed, noncanonical or over-bound forms.
    pub fn decode(bytes: &[u8]) -> Result<Self, SubnetReportError> {
        let mut input = CborReader::new(bytes, MAX_BYTES)?;
        input.array(4)?;
        require(input.uint()? == 1, SubnetReportError::Fields)?;
        let binding = SignedSourceBinding::decode(input.bytes_up_to(MAX_SOURCE_BYTES)?)?;
        let report_generation = input.uint()?;
        let size = count(&mut input)?;
        let mut offers = Vec::with_capacity(size);
        for _ in 0..size {
            input.array(2)?;
            let subnet_id = mapping_id(&mut input)?;
            input.array(2)?;
            let tag = input.uint()?;
            let prefixes = read_set(&mut input)?;
            let selection = match tag {
                0 if prefixes.is_empty() => SubnetSelection::Default,
                1 => SubnetSelection::Explicit(prefixes),
                _ => return Err(SubnetReportError::Fields),
            };
            offers.push(SubnetRouteOffer {
                subnet_id,
                selection,
            });
        }
        input.finish()?;
        let value = Self {
            binding,
            report_generation,
            offers,
        };
        value.canonical()?;
        Ok(value)
    }

    /// Authenticates the confidential request and exact current signed nodes source.
    /// Mapping and generation comparisons remain a separate pure decision.
    /// # Errors
    /// Refuses carrier trust, operation, caller, recipient, nonce or source mismatch.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
        authority: &SubnetReportAuthority<'_>,
    ) -> Result<Self, SubnetReportError> {
        envelope.verify(expected).map_err(SourceError::from)?;
        let value = Self::decode(&envelope.payload)?;
        nonzero(&envelope.nonce)?;
        authority.validate(&value.binding)?;
        require(
            envelope.direction == EnvelopeDirection::Request
                && envelope.kind == NODE_SUBNET_REPORT
                && envelope.signer == authority.caller
                && envelope.recipient == Some(authority.nsd)
                && expected.recipient == authority.nsd,
            SubnetReportError::Authority,
        )?;
        Ok(value)
    }
}

/// NSD-produced allocation association; shared code never chooses a reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubnetRouteAllocation {
    /// Exact reported nonzero mapping identity.
    pub subnet_id: u32,
    /// Existing canonical M6 resource identity.
    pub resource: ServiceRef,
}

/// Acknowledges committed offers, without granting selection or applied routing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeSubnetRouteReportResponse {
    /// Exact signed source of the pending report.
    pub binding: SignedSourceBinding,
    /// Exact generation of the pending report.
    pub report_generation: u64,
    /// Exactly the report's ids, in the same order.
    pub allocations: Vec<SubnetRouteAllocation>,
}
impl NodeSubnetRouteReportResponse {
    /// Encodes exact allocations using M6's own canonical reference codec.
    /// # Errors
    /// Refuses malformed source, generation, mapping order, reference or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, SubnetReportError> {
        require(self.report_generation > 0, SubnetReportError::Fields)?;
        require(
            self.allocations.len() <= MAX_SUBNET_OFFERS,
            SubnetReportError::Bounds,
        )?;
        ids(self
            .allocations
            .iter()
            .map(|allocation| allocation.subnet_id))?;
        let mut out = CborWriter::default();
        out.array(4)
            .uint(1)
            .bytes(&self.binding.canonical()?)
            .uint(self.report_generation)
            .array(self.allocations.len());
        for allocation in &self.allocations {
            let resource =
                nsshared_codec::cbor::value::encode_canonical(&allocation.resource.value())
                    .map_err(|_| SubnetReportError::Allocation)?;
            out.array(2)
                .uint(u64::from(allocation.subnet_id))
                .bytes(&resource);
        }
        bounded(out.into_bytes())
    }

    /// Decodes exact response bytes without authenticating or committing the result.
    /// # Errors
    /// Refuses malformed fields, M6 references, canonical encoding or bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, SubnetReportError> {
        let mut input = CborReader::new(bytes, MAX_BYTES)?;
        input.array(4)?;
        require(input.uint()? == 1, SubnetReportError::Fields)?;
        let binding = SignedSourceBinding::decode(input.bytes_up_to(MAX_SOURCE_BYTES)?)?;
        let report_generation = input.uint()?;
        let size = count(&mut input)?;
        let mut allocations = Vec::with_capacity(size);
        for _ in 0..size {
            input.array(2)?;
            let subnet_id = mapping_id(&mut input)?;
            let resource =
                nsshared_codec::cbor::value::decode_canonical(input.bytes_up_to(MAX_BYTES)?)
                    .map_err(|_| SubnetReportError::Allocation)?;
            let resource =
                ServiceRef::from_value(&resource).map_err(|_| SubnetReportError::Allocation)?;
            allocations.push(SubnetRouteAllocation {
                subnet_id,
                resource,
            });
        }
        input.finish()?;
        let value = Self {
            binding,
            report_generation,
            allocations,
        };
        value.canonical()?;
        Ok(value)
    }

    /// Compares a proposed result with exact pending intent and retained assignments.
    /// The caller supplies the last accepted generation/content and all prior
    /// allocations, including withdrawn mappings, retained across restart.
    /// # Errors
    /// Refuses stale source, changed mapping/generation or replaced/scoped references.
    pub fn compare(
        &self,
        pending: &NodeSubnetRouteReport,
        authority: &SubnetReportAuthority<'_>,
        retained: Option<&RetainedSubnetReport>,
    ) -> Result<(), SubnetReportError> {
        if let Some(prior) = retained {
            prior.validate(authority)?;
            compare_generation(pending, &prior.report)?;
        }
        self.compare_allocations(pending, authority, retained.map(|prior| &prior.allocations))
    }

    fn compare_allocations(
        &self,
        pending: &NodeSubnetRouteReport,
        authority: &SubnetReportAuthority<'_>,
        retained: Option<&SubnetAllocationHistory>,
    ) -> Result<(), SubnetReportError> {
        pending.canonical()?;
        self.canonical()?;
        authority.validate(&pending.binding)?;
        require(
            self.binding == pending.binding
                && self.report_generation == pending.report_generation
                && self.allocations.len() == pending.offers.len()
                && self
                    .allocations
                    .iter()
                    .zip(&pending.offers)
                    .all(|(allocation, offer)| allocation.subnet_id == offer.subnet_id),
            SubnetReportError::Allocation,
        )?;
        let retained = if let Some(history) = retained {
            require(
                history.binding == pending.binding,
                SubnetReportError::Authority,
            )?;
            authority.allocations(&history.allocations)?;
            history.allocations.as_slice()
        } else {
            &[]
        };

        authority.allocations(&self.allocations)?;
        for allocation in &self.allocations {
            for old in retained {
                require(
                    if old.subnet_id == allocation.subnet_id {
                        old.resource == allocation.resource
                    } else {
                        old.resource != allocation.resource
                    },
                    SubnetReportError::Allocation,
                )?;
            }
        }
        Ok(())
    }

    /// Authenticates an NSD response against retained pending request and current source.
    /// # Errors
    /// Refuses trust, recipient, operation, nonce, binding or allocation disagreement.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
        pending: &NodeSubnetRouteReport,
        pending_nonce: [u8; 16],
        authority: &SubnetReportAuthority<'_>,
        retained: Option<&RetainedSubnetReport>,
    ) -> Result<Self, SubnetReportError> {
        envelope.verify(expected).map_err(SourceError::from)?;
        nonzero(&pending_nonce)?;
        require(
            envelope.direction == EnvelopeDirection::Response
                && envelope.kind == NODE_SUBNET_REPORT
                && envelope.signer == authority.nsd
                && envelope.recipient == Some(authority.caller)
                && expected.recipient == authority.caller
                && envelope.nonce == pending_nonce,
            SubnetReportError::Authority,
        )?;
        let value = Self::decode(&envelope.payload)?;
        value.compare(pending, authority, retained)?;
        Ok(value)
    }
}

/// Independently committed source and M6 namespace facts, never taken from intent.
#[derive(Clone, Debug)]
pub struct SubnetReportAuthority<'a> {
    /// Trusted signing NSD identity.
    pub nsd: IdentityKey,
    /// Existing identity-bound M6 NSD identifier.
    pub nsd_id: Id,
    /// Exact committed Network, equal to the binding's served realm bytes.
    pub network_id: Id,
    /// Authenticated reporting provider Node.
    pub caller: IdentityKey,
    /// Exact current committed signed nodes binding; retired sources are excluded.
    pub current: &'a SignedSourceBinding,
}
impl SubnetReportAuthority<'_> {
    fn validate(&self, binding: &SignedSourceBinding) -> Result<(), SubnetReportError> {
        binding.verify(self.nsd)?;
        let source = &binding.binding;
        require(
            binding == self.current
                && source.scope == "nodes"
                && source.recipient == self.caller
                && source.source_node == self.caller
                && source.served_realm.as_bytes() == &self.network_id,
            SubnetReportError::Authority,
        )
    }
    fn allocations(&self, values: &[SubnetRouteAllocation]) -> Result<(), SubnetReportError> {
        ids(values.iter().map(|value| value.subnet_id))?;
        let mut references = std::collections::BTreeSet::new();
        for value in values {
            require(
                value.resource.nsd_id == self.nsd_id
                    && value.resource.network_id == self.network_id
                    && references.insert(value.resource),
                SubnetReportError::Allocation,
            )?;
        }
        Ok(())
    }
}

/// Committed mapping eligibility resolved by the caller within its transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubnetMappingAuthority {
    /// Existing NSD mapping identity.
    pub subnet_id: u32,
    /// Mapping's owning Network.
    pub network_id: Id,
    /// Full provider Node identity under current membership authority.
    pub provider: IdentityKey,
    /// Committed aligned real prefix; mapped-prefix custody remains with NSD.
    pub real: SubnetPrefix,
    /// Current membership and active-provider eligibility, resolved by the caller.
    pub active: bool,
}

/// Source-qualified caller-owned allocations retained through complete withdrawal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubnetAllocationHistory {
    /// Exact signed source owning every association, including withdrawn mappings.
    pub binding: SignedSourceBinding,
    /// Ascending unique mapping associations; lifetime history has no report-list bound.
    pub allocations: Vec<SubnetRouteAllocation>,
}

/// Caller-retained complete accepted report, result and all historical assignments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedSubnetReport {
    /// Last accepted generation and exact complete content, including empty withdrawal.
    pub report: NodeSubnetRouteReport,
    /// Exact allocation result for that content.
    pub response: NodeSubnetRouteReportResponse,
    /// Ascending unique retained mappings, including withdrawn offers.
    pub allocations: SubnetAllocationHistory,
}

/// Pure decision; committing replacement and choosing new references are external.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubnetReportDecision {
    /// Atomically replace the complete offered set; retain prior allocation custody.
    Replace,
    /// Return the exact retained allocation response without reapplying mutation.
    Retry,
}

/// Qualifies current source, mappings and complete generation against retained custody.
/// This function never modifies any supplied state or assigns a service id.
/// # Errors
/// Refuses stale sources/generations, conflicting retries, mapping or retained-state mismatch.
pub fn decide_subnet_report(
    report: &NodeSubnetRouteReport,
    authority: &SubnetReportAuthority<'_>,
    mappings: &[SubnetMappingAuthority],
    prior: Option<&RetainedSubnetReport>,
) -> Result<SubnetReportDecision, SubnetReportError> {
    report.canonical()?;
    authority.validate(&report.binding)?;
    for offer in &report.offers {
        let mut found = mappings
            .iter()
            .filter(|mapping| mapping.subnet_id == offer.subnet_id);
        let mapping = found.next().ok_or(SubnetReportError::Mapping)?;
        require(
            found.next().is_none()
                && mapping.active
                && mapping.network_id == authority.network_id
                && mapping.provider == authority.caller,
            SubnetReportError::Mapping,
        )?;
        mapping.real.validate()?;
        match &offer.selection {
            SubnetSelection::Default => {
                require(mapping.real.length == 0, SubnetReportError::Mapping)?
            }
            SubnetSelection::Explicit(prefixes) => require(
                prefixes.iter().all(|prefix| mapping.real.contains(*prefix)),
                SubnetReportError::Mapping,
            )?,
        }
    }
    if let Some(prior) = prior {
        prior.validate(authority)?;
        return compare_generation(report, &prior.report);
    }
    Ok(SubnetReportDecision::Replace)
}

impl RetainedSubnetReport {
    fn validate(&self, authority: &SubnetReportAuthority<'_>) -> Result<(), SubnetReportError> {
        self.response
            .compare_allocations(&self.report, authority, Some(&self.allocations))?;
        require(
            self.response
                .allocations
                .iter()
                .all(|allocation| self.allocations.allocations.contains(allocation)),
            SubnetReportError::Allocation,
        )
    }
}

fn compare_generation(
    report: &NodeSubnetRouteReport,
    prior: &NodeSubnetRouteReport,
) -> Result<SubnetReportDecision, SubnetReportError> {
    match report.report_generation.cmp(&prior.report_generation) {
        std::cmp::Ordering::Less => Err(SubnetReportError::Stale),
        std::cmp::Ordering::Equal => {
            require(report == prior, SubnetReportError::Conflict)?;
            Ok(SubnetReportDecision::Retry)
        }
        std::cmp::Ordering::Greater => Ok(SubnetReportDecision::Replace),
    }
}
