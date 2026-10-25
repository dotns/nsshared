use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{service::ContractError, service::Id, service::Identity, service::ServiceRef};
use thiserror::Error;

use crate::{account::MAX_BYTES, account::SCHEMA};
use nsshared_codec::{cbor::CborError, cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;

/// Maximum routes in a complete Subnet publication.
pub const MAX_SUBNET_ROUTES: usize = 256;
/// Maximum prefixes in each input selection, exclusion or bypass list.
pub const MAX_SUBNET_PREFIXES: usize = 256;
/// Maximum prefixes in the selected CIDR cover of one route.
pub const MAX_SELECTED_PREFIXES: usize = 32_768;

/// Family-neutral, network-aligned prefix; order is family, address, then length.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SubnetPrefix {
    /// Network address, with no host bits set.
    pub address: IpAddr,
    /// Prefix length within the address family's width.
    pub length: u8,
}

/// A route's logical default or explicitly named destination set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubnetSelection {
    /// Select the real /0 prefix; never combined with named prefixes.
    Default,
    /// Select these strictly ordered, nonoverlapping prefixes; empty selects none.
    Explicit(Vec<SubnetPrefix>),
}

/// One stable Subnet resource with exact real and mapped address views.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubnetRoute {
    /// Existing M6 resource identity, also the stable route identity.
    pub resource: ServiceRef,
    /// Family-neutral real network.
    pub real: SubnetPrefix,
    /// Exact /96+p mapping for real IPv4, or the same prefix for real IPv6.
    pub mapped: SubnetPrefix,
    /// Full provider identity, validated as an Ed25519 public key.
    pub provider: Identity,
    /// Full client identity, equal to the publication's recipient.
    pub client: Identity,
    /// Exact destination prefixes excluded from selection.
    pub exclusions: Vec<SubnetPrefix>,
    /// Exact bypass prefixes, retained separately from exclusions.
    pub bypasses: Vec<SubnetPrefix>,
    /// Explicit or default selection without host routing policy.
    pub selection: SubnetSelection,
}

/// Complete route publication within one authenticated NSD/network/recipient scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubnetPublication {
    /// Existing M6 identity-bound NSD identifier.
    pub nsd_id: Id,
    /// Existing M6 network identifier.
    pub network_id: Id,
    /// Full recipient identity.
    pub recipient: Identity,
    /// Positive revision within this scope; persistence remains with the caller.
    pub revision: u64,
    /// Routes ordered strictly by full M6 ServiceRef; empty withdraws all routes.
    pub routes: Vec<SubnetRoute>,
}

/// Explicit proxy coverage, independent of the prefix schema's address families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubnetProxyCoverage {
    /// TCP is covered only for nonempty selected real IPv4 destinations.
    pub tcp: bool,
    /// UDP is covered only for nonempty selected real IPv4 destinations.
    pub udp: bool,
    /// Echo is covered only for nonempty selected real IPv4 destinations.
    pub echo: bool,
}

/// Pure validation output. No local host binding or runtime route winner is present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedSubnetRoute {
    /// Exact validated route, including the distinct bypass and exclusion sets.
    pub route: SubnetRoute,
    /// Minimal sorted CIDR cover of selection minus exclusions.
    pub selected: Vec<SubnetPrefix>,
    /// Explicit protocol coverage; real IPv6 always has none.
    pub coverage: SubnetProxyCoverage,
}

/// Typed refusals; invalid input never means empty withdrawal.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SubnetError {
    /// Strict CBOR encoding failure, including nonminimal and trailing input.
    #[error(transparent)]
    Contract(#[from] crate::account::AccountError),
    /// M6's own codec or reference parser rejected embedded reference bytes.
    #[error("invalid M6 reference: {0}")]
    M6Reference(ContractError),
    /// Unsupported publication schema.
    #[error("unknown Subnet schema")]
    Schema,
    /// Unknown publication or prefix family.
    #[error("unknown Subnet family")]
    UnknownFamily,
    /// Unknown selection discriminant.
    #[error("unknown Subnet selection")]
    UnknownSelection,
    /// A prefix's length is outside its family's width.
    #[error("invalid Subnet prefix length")]
    InvalidPrefix,
    /// A prefix contains host bits.
    #[error("misaligned Subnet prefix")]
    MisalignedPrefix,
    /// Mapped prefix does not preserve the exact real network and length.
    #[error("Subnet mapped prefix mismatch")]
    MappedPrefix,
    /// Exclusion is outside the real prefix.
    #[error("Subnet exclusion outside real prefix")]
    OutsideExclusion,
    /// Bypass is outside the real prefix.
    #[error("Subnet bypass outside real prefix")]
    OutsideBypass,
    /// Explicit selection is outside the real prefix.
    #[error("Subnet selection outside real prefix")]
    OutsideSelection,
    /// Prefixes overlap within or across exclusion and bypass sets.
    #[error("overlapping Subnet prefixes")]
    Overlap,
    /// A route or prefix set is unsorted or contains duplicates.
    #[error("noncanonical Subnet set")]
    NonCanonicalSet,
    /// Default and explicit selection are mixed in one route.
    #[error("mixed default and explicit Subnet selection")]
    MixedSelection,
    /// Default selection requires a real /0 prefix.
    #[error("Subnet default selection requires a real default prefix")]
    InvalidDefault,
    /// Publication, input list or selected output exceeds its bound.
    #[error("Subnet bound exceeded")]
    Bounds,
    /// A full identity is not a valid Ed25519 key.
    #[error("invalid Subnet identity")]
    Identity,
    /// Resource/client scope disagrees or revision is zero.
    #[error("invalid Subnet publication scope")]
    Scope,
}

crate::account::contract_error!(SubnetError);

impl SubnetPrefix {
    fn width(self) -> u8 {
        if self.address.is_ipv4() { 32 } else { 128 }
    }

    fn number(self) -> u128 {
        match self.address {
            IpAddr::V4(address) => u128::from(u32::from(address)),
            IpAddr::V6(address) => u128::from(address),
        }
    }

    fn host_mask(self) -> u128 {
        let bits = self.width() - self.length;
        if bits == 128 {
            u128::MAX
        } else {
            (1_u128 << bits) - 1
        }
    }

    pub(in crate::account) fn validate(self) -> Result<(), SubnetError> {
        if self.length > self.width() {
            return Err(SubnetError::InvalidPrefix);
        }
        if self.number() & self.host_mask() != 0 {
            return Err(SubnetError::MisalignedPrefix);
        }
        Ok(())
    }

    pub(in crate::account) fn contains(self, other: Self) -> bool {
        self.address.is_ipv4() == other.address.is_ipv4()
            && self.length <= other.length
            && other.number() & !self.host_mask() == self.number()
    }

    fn overlaps(self, other: Self) -> bool {
        self.contains(other) || other.contains(self)
    }

    fn with_number(self, number: u128, length: u8) -> Self {
        let address = if self.address.is_ipv4() {
            // The caller preserves the original family's width when splitting or merging.
            let octets = number.to_be_bytes();
            IpAddr::V4(Ipv4Addr::new(
                octets[12], octets[13], octets[14], octets[15],
            ))
        } else {
            IpAddr::V6(Ipv6Addr::from(number))
        };
        Self { address, length }
    }

    pub(in crate::account) fn write(self, out: &mut CborWriter) {
        out.array(3);
        match self.address {
            IpAddr::V4(address) => {
                out.uint(4).bytes(&address.octets());
            }
            IpAddr::V6(address) => {
                out.uint(6).bytes(&address.octets());
            }
        }
        out.uint(u64::from(self.length));
    }

    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, SubnetError> {
        input.array(3)?;
        let address = match input.uint()? {
            4 => IpAddr::V4(Ipv4Addr::from(input.fixed_bytes::<4>()?)),
            6 => IpAddr::V6(Ipv6Addr::from(input.fixed_bytes::<16>()?)),
            _ => return Err(SubnetError::UnknownFamily),
        };
        let length = u8::try_from(input.uint()?).map_err(|_| SubnetError::InvalidPrefix)?;
        let value = Self { address, length };
        value.validate()?;
        Ok(value)
    }
}

pub(in crate::account) fn validate_set(values: &[SubnetPrefix]) -> Result<(), SubnetError> {
    if values.len() > MAX_SUBNET_PREFIXES {
        return Err(SubnetError::Bounds);
    }
    for value in values {
        value.validate()?;
    }
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(SubnetError::NonCanonicalSet);
    }
    if values.windows(2).any(|pair| pair[0].overlaps(pair[1])) {
        return Err(SubnetError::Overlap);
    }
    Ok(())
}

pub(in crate::account) fn write_set(values: &[SubnetPrefix], out: &mut CborWriter) {
    out.array(values.len());
    for value in values {
        value.write(out);
    }
}

fn read_count(input: &mut CborReader<'_>, maximum: usize) -> Result<usize, SubnetError> {
    input.array_up_to(maximum).map_err(|error| match error {
        CborError::ArrayLength { .. } => SubnetError::Bounds,
        other => other.into(),
    })
}

pub(in crate::account) fn read_set(
    input: &mut CborReader<'_>,
) -> Result<Vec<SubnetPrefix>, SubnetError> {
    let count = read_count(input, MAX_SUBNET_PREFIXES)?;
    (0..count).map(|_| SubnetPrefix::read(input)).collect()
}

fn validate_identity(value: &Identity) -> Result<(), SubnetError> {
    IdentityKey::from_bytes(value)
        .map(|_| ())
        .map_err(|_| SubnetError::Identity)
}

fn m6_error(error: impl Into<ContractError>) -> SubnetError {
    SubnetError::M6Reference(error.into())
}

impl SubnetRoute {
    fn validate(&self) -> Result<(), SubnetError> {
        self.real.validate()?;
        self.mapped.validate()?;
        let matches = match (self.real.address, self.mapped.address) {
            (IpAddr::V4(real), IpAddr::V6(mapped)) => {
                self.mapped.length == 96 + self.real.length
                    && mapped.octets()[12..] == real.octets()
            }
            (IpAddr::V6(_), IpAddr::V6(_)) => self.real == self.mapped,
            _ => false,
        };
        if !matches {
            return Err(SubnetError::MappedPrefix);
        }
        validate_identity(&self.provider)?;
        validate_identity(&self.client)?;
        validate_set(&self.exclusions)?;
        validate_set(&self.bypasses)?;
        if self
            .exclusions
            .iter()
            .any(|value| !self.real.contains(*value))
        {
            return Err(SubnetError::OutsideExclusion);
        }
        if self
            .bypasses
            .iter()
            .any(|value| !self.real.contains(*value))
        {
            return Err(SubnetError::OutsideBypass);
        }
        if self
            .exclusions
            .iter()
            .any(|left| self.bypasses.iter().any(|right| left.overlaps(*right)))
        {
            return Err(SubnetError::Overlap);
        }
        match &self.selection {
            SubnetSelection::Default if self.real.length != 0 => {
                return Err(SubnetError::InvalidDefault);
            }
            SubnetSelection::Default => {}
            SubnetSelection::Explicit(values) => {
                validate_set(values)?;
                if values.iter().any(|value| !self.real.contains(*value)) {
                    return Err(SubnetError::OutsideSelection);
                }
            }
        }
        Ok(())
    }

    fn write(&self, out: &mut CborWriter) -> Result<(), SubnetError> {
        let resource = nsshared_codec::cbor::value::encode_canonical(&self.resource.value())
            .map_err(m6_error)?;
        out.array(8).bytes(&resource);
        self.real.write(out);
        self.mapped.write(out);
        out.bytes(&self.provider).bytes(&self.client);
        write_set(&self.exclusions, out);
        write_set(&self.bypasses, out);
        out.array(2);
        match &self.selection {
            SubnetSelection::Default => {
                out.uint(0).array(0);
            }
            SubnetSelection::Explicit(values) => {
                out.uint(1);
                write_set(values, out);
            }
        }
        Ok(())
    }

    fn read(input: &mut CborReader<'_>) -> Result<Self, SubnetError> {
        input.array(8)?;
        let resource = nsshared_codec::cbor::value::decode_canonical(input.bytes_up_to(MAX_BYTES)?)
            .map_err(m6_error)?;
        let resource = ServiceRef::from_value(&resource).map_err(SubnetError::M6Reference)?;
        let real = SubnetPrefix::read(input)?;
        let mapped = SubnetPrefix::read(input)?;
        let provider = input.fixed_bytes()?;
        let client = input.fixed_bytes()?;
        let exclusions = read_set(input)?;
        let bypasses = read_set(input)?;
        input.array(2)?;
        let selection = match input.uint()? {
            0 => {
                if !read_set(input)?.is_empty() {
                    return Err(SubnetError::MixedSelection);
                }
                SubnetSelection::Default
            }
            1 => SubnetSelection::Explicit(read_set(input)?),
            _ => return Err(SubnetError::UnknownSelection),
        };
        Ok(Self {
            resource,
            real,
            mapped,
            provider,
            client,
            exclusions,
            bypasses,
            selection,
        })
    }

    fn selected(&self) -> Result<Vec<SubnetPrefix>, SubnetError> {
        let mut result = Vec::new();
        match &self.selection {
            SubnetSelection::Default => subtract(self.real, &self.exclusions, &mut result)?,
            SubnetSelection::Explicit(values) => {
                for value in values {
                    subtract(*value, &self.exclusions, &mut result)?;
                }
            }
        }
        result.sort_unstable();
        let mut merged: Vec<SubnetPrefix> = Vec::with_capacity(result.len());
        for value in result {
            merged.push(value);
            while merged.len() >= 2 {
                let right = merged[merged.len() - 1];
                let left = merged[merged.len() - 2];
                if left.length == 0 || left.length != right.length {
                    break;
                }
                let parent =
                    left.with_number(left.number() & !(left.host_mask() * 2 + 1), left.length - 1);
                if !parent.contains(right) {
                    break;
                }
                merged.truncate(merged.len() - 2);
                merged.push(parent);
            }
        }
        Ok(merged)
    }
}

fn subtract(
    prefix: SubnetPrefix,
    exclusions: &[SubnetPrefix],
    out: &mut Vec<SubnetPrefix>,
) -> Result<(), SubnetError> {
    if exclusions.iter().any(|excluded| excluded.contains(prefix)) {
        return Ok(());
    }
    if exclusions.iter().any(|excluded| prefix.contains(*excluded)) {
        // A contained, unequal exclusion proves this prefix can split within its width.
        let length = prefix.length + 1;
        let left = prefix.with_number(prefix.number(), length);
        let right = prefix.with_number(
            prefix.number() | (1_u128 << (prefix.width() - length)),
            length,
        );
        subtract(left, exclusions, out)?;
        subtract(right, exclusions, out)?;
    } else {
        if out.len() == MAX_SELECTED_PREFIXES {
            return Err(SubnetError::Bounds);
        }
        out.push(prefix);
    }
    Ok(())
}

impl SubnetPublication {
    fn validate(&self) -> Result<(), SubnetError> {
        if self.routes.len() > MAX_SUBNET_ROUTES {
            return Err(SubnetError::Bounds);
        }
        validate_identity(&self.recipient)?;
        if self.revision == 0 {
            return Err(SubnetError::Scope);
        }
        if !self
            .routes
            .windows(2)
            .all(|pair| pair[0].resource < pair[1].resource)
        {
            return Err(SubnetError::NonCanonicalSet);
        }
        for route in &self.routes {
            if route.resource.nsd_id != self.nsd_id
                || route.resource.network_id != self.network_id
                || route.client != self.recipient
            {
                return Err(SubnetError::Scope);
            }
            route.validate()?;
        }
        Ok(())
    }

    /// Encodes a complete publication without normalizing invalid fields or sets.
    ///
    /// # Errors
    /// Returns a typed refusal for invalid prefixes, mapping, identity, scope or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, SubnetError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(7)
            .uint(SCHEMA)
            .uint(4)
            .bytes(&self.nsd_id)
            .bytes(&self.network_id)
            .bytes(&self.recipient)
            .uint(self.revision)
            .array(self.routes.len());
        for route in &self.routes {
            route.write(&mut out)?;
        }
        let bytes = out.into_bytes();
        if bytes.len() > MAX_BYTES {
            return Err(SubnetError::Bounds);
        }
        Ok(bytes)
    }

    /// Decodes a present, complete canonical publication; empty bytes are an error.
    ///
    /// # Errors
    /// Refuses unknown discriminants, invalid contract fields, nonminimal or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SubnetError> {
        let mut input = CborReader::new(bytes, MAX_BYTES)?;
        input.array(7)?;
        if input.uint()? != SCHEMA {
            return Err(SubnetError::Schema);
        }
        if input.uint()? != 4 {
            return Err(SubnetError::UnknownFamily);
        }
        let nsd_id = input.fixed_bytes()?;
        let network_id = input.fixed_bytes()?;
        let recipient = input.fixed_bytes()?;
        let revision = input.uint()?;
        let count = read_count(&mut input, MAX_SUBNET_ROUTES)?;
        let routes = (0..count)
            .map(|_| SubnetRoute::read(&mut input))
            .collect::<Result<_, _>>()?;
        input.finish()?;
        let value = Self {
            nsd_id,
            network_id,
            recipient,
            revision,
            routes,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns exact validated routes with selected CIDR sets and explicit coverage.
    ///
    /// # Errors
    /// Refuses invalid constructed publications and any selected-output bound violation.
    pub fn selected_routes(&self) -> Result<Vec<SelectedSubnetRoute>, SubnetError> {
        // Apply the same field validation and encoded-size bound to values constructed without decoding.
        self.canonical()?;
        self.routes
            .iter()
            .map(|route| {
                let selected = route.selected()?;
                let covered = route.real.address.is_ipv4() && !selected.is_empty();
                Ok(SelectedSubnetRoute {
                    route: route.clone(),
                    selected,
                    coverage: SubnetProxyCoverage {
                        tcp: covered,
                        udp: covered,
                        echo: covered,
                    },
                })
            })
            .collect()
    }
}
