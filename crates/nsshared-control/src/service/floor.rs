//! Versioned whole-floor content for the existing M6 report carrier.

use std::net::IpAddr;

use nsshared_codec::cbor::value::{Value, decode_canonical, encode_canonical};

use super::contract::{boolean, exact_map, field, map, text, unsigned};
use super::{ContractError, Digest, ReportContent, domain_digest};

/// Maximum entries in each floor collection, including declarations.
pub const MAX_FLOOR_ITEMS: usize = 256;
/// Maximum UTF-8 bytes in a floor text field.
pub const MAX_FLOOR_TEXT: usize = 255;
/// Maximum encoded floor content size.
pub const MAX_FLOOR_BYTES: usize = 65_536;

/// Declaration metadata; references are local to the enclosing report scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FloorMetadata {
    /// Exact declaration key in this report.
    pub reference: String,
    /// Sorted capability observations, never permissions.
    pub capabilities: Vec<String>,
    /// Labels sorted by key, never authorization rules.
    pub policy_labels: Vec<(String, String)>,
}

/// Configured Exit selection, never traffic authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExitSelection {
    /// Default routing; requires compatible Default-aware floor consumers.
    Default,
    /// Canonical CIDR strings in strict UTF-8 byte order, without overlap.
    Explicit(Vec<String>),
}

/// An Exit declaration bound by reference to the enclosing report scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FloorExitProfile {
    /// Stable publisher-local profile reference.
    pub reference: String,
    /// Configured address scope.
    pub selection: ExitSelection,
    /// Local enabled intent, never traffic authority.
    pub enabled: bool,
    /// Sorted capability observations.
    pub capabilities: Vec<String>,
    /// Labels sorted by key.
    pub policy_labels: Vec<(String, String)>,
}

/// Version-one floor extension, retaining the unchanged legacy report type.
/// Empty extensions use the exact legacy report encoding and digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FloorContent {
    /// Unchanged scope and plain TCP/UDP declarations.
    pub report: ReportContent,
    /// Metadata in strict declaration-reference order; partial metadata is allowed.
    pub metadata: Vec<FloorMetadata>,
    /// Exit profiles in strict reference order.
    pub exit_profiles: Vec<FloorExitProfile>,
}

impl FloorContent {
    /// Encodes the complete canonical floor and its domain-separated digest.
    /// # Errors
    /// Refuses invalid references, CIDRs, ordering, text or collection bounds.
    pub fn canonical(&self) -> Result<(Vec<u8>, Digest), ContractError> {
        if self.metadata.is_empty() && self.exit_profiles.is_empty() {
            return self.report.canonical();
        }
        ordered(&self.metadata, |v| v.reference.as_str())?;
        ordered(&self.exit_profiles, |v| v.reference.as_str())?;
        bounded(self.report.declarations.len())?;
        let (report, _) = self.report.canonical()?;
        let metadata = self
            .metadata
            .iter()
            .map(|value| {
                if !self
                    .report
                    .declarations
                    .iter()
                    .any(|d| d.declaration_key == value.reference)
                {
                    return Err(ContractError::InvalidFloorBinding);
                }
                metadata_value(&value.reference, &value.capabilities, &value.policy_labels)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let profiles = self
            .exit_profiles
            .iter()
            .map(profile_value)
            .collect::<Result<Vec<_>, _>>()?;
        let encoded = encode_canonical(&map(vec![
            ("floor_version", Value::UInt(1)),
            ("report", Value::Bytes(report)),
            ("metadata", Value::Array(metadata)),
            ("exit_profiles", Value::Array(profiles)),
        ]))?;
        size(&encoded)?;
        let digest = domain_digest("ns.service.floor.v1", &encoded);
        Ok((encoded, digest))
    }

    /// Decodes legacy content or an explicitly versioned floor, without dropping fields.
    /// # Errors
    /// Refuses unknown versions, malformed input and noncanonical or invalid floors.
    pub fn decode(input: &[u8]) -> Result<Self, ContractError> {
        let value = decode_canonical(input)?;
        let Value::Map(fields) = &value else {
            return Err(ContractError::InvalidField);
        };
        if !fields.iter().any(|(key, _)| key == "floor_version") {
            return Ok(Self {
                report: ReportContent::decode(input)?,
                metadata: vec![],
                exit_profiles: vec![],
            });
        }
        size(input)?;
        let fields = exact_map(
            &value,
            &["floor_version", "report", "metadata", "exit_profiles"],
        )?;
        if unsigned(field(fields, "floor_version")?)? != 1 {
            return Err(ContractError::UnsupportedVersion);
        }
        let Value::Bytes(report) = field(fields, "report")? else {
            return Err(ContractError::InvalidField);
        };
        let report = ReportContent::decode(report)?;
        bounded(report.declarations.len())?;
        let metadata = array(field(fields, "metadata")?)?
            .iter()
            .map(|value| {
                let parts = tuple(value, 3)?;
                Ok(FloorMetadata {
                    reference: text(&parts[0])?.into(),
                    capabilities: texts(&parts[1])?,
                    policy_labels: labels(&parts[2])?,
                })
            })
            .collect::<Result<_, ContractError>>()?;
        let exit_profiles = array(field(fields, "exit_profiles")?)?
            .iter()
            .map(profile_read)
            .collect::<Result<_, _>>()?;
        let floor = Self {
            report,
            metadata,
            exit_profiles,
        };
        if floor.canonical()?.0 != input {
            return Err(ContractError::InvalidEncoding);
        }
        Ok(floor)
    }
}

fn size(bytes: &[u8]) -> Result<(), ContractError> {
    if bytes.len() > MAX_FLOOR_BYTES {
        Err(ContractError::FloorLimit)
    } else {
        Ok(())
    }
}
fn bounded(count: usize) -> Result<(), ContractError> {
    if count > MAX_FLOOR_ITEMS {
        Err(ContractError::FloorLimit)
    } else {
        Ok(())
    }
}
fn ordered<T>(items: &[T], key: impl Fn(&T) -> &str) -> Result<(), ContractError> {
    bounded(items.len())?;
    if items.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return Err(ContractError::InvalidFloorOrder);
    }
    Ok(())
}
fn data_text(value: &str, empty: bool) -> Result<(), ContractError> {
    if value.len() > MAX_FLOOR_TEXT {
        return Err(ContractError::FloorLimit);
    }
    if (!empty && value.is_empty()) || value.chars().any(char::is_control) {
        return Err(ContractError::InvalidField);
    }
    Ok(())
}
fn metadata_value(
    reference: &str,
    capabilities: &[String],
    labels: &[(String, String)],
) -> Result<Value, ContractError> {
    data_text(reference, false)?;
    ordered(capabilities, String::as_str)?;
    ordered(labels, |v| v.0.as_str())?;
    for capability in capabilities {
        data_text(capability, false)?;
    }
    for (key, value) in labels {
        data_text(key, false)?;
        data_text(value, true)?;
    }
    Ok(Value::Array(vec![
        Value::Text(reference.into()),
        Value::Array(capabilities.iter().cloned().map(Value::Text).collect()),
        Value::Array(
            labels
                .iter()
                .map(|(k, v)| Value::Array(vec![Value::Text(k.clone()), Value::Text(v.clone())]))
                .collect(),
        ),
    ]))
}
fn profile_value(profile: &FloorExitProfile) -> Result<Value, ContractError> {
    let Value::Array(mut parts) = metadata_value(
        &profile.reference,
        &profile.capabilities,
        &profile.policy_labels,
    )?
    else {
        return Err(ContractError::InvalidField);
    };
    let selection = match &profile.selection {
        ExitSelection::Default => Value::Array(vec![Value::UInt(0)]),
        ExitSelection::Explicit(prefixes) => {
            validate_prefixes(prefixes)?;
            Value::Array(vec![
                Value::UInt(1),
                Value::Array(prefixes.iter().cloned().map(Value::Text).collect()),
            ])
        }
    };
    parts.insert(1, selection);
    parts.insert(2, Value::Bool(profile.enabled));
    Ok(Value::Array(parts))
}
fn profile_read(value: &Value) -> Result<FloorExitProfile, ContractError> {
    let parts = tuple(value, 5)?;
    let selection = match array(&parts[1])? {
        [Value::UInt(0)] => ExitSelection::Default,
        [Value::UInt(1), prefixes] => ExitSelection::Explicit(texts(prefixes)?),
        _ => return Err(ContractError::InvalidFloorCidr),
    };
    Ok(FloorExitProfile {
        reference: text(&parts[0])?.into(),
        selection,
        enabled: boolean(&parts[2])?,
        capabilities: texts(&parts[3])?,
        policy_labels: labels(&parts[4])?,
    })
}
fn array(value: &Value) -> Result<&[Value], ContractError> {
    let Value::Array(items) = value else {
        return Err(ContractError::InvalidField);
    };
    bounded(items.len())?;
    Ok(items)
}
fn tuple(value: &Value, len: usize) -> Result<&[Value], ContractError> {
    let items = array(value)?;
    if items.len() != len {
        return Err(ContractError::InvalidField);
    }
    Ok(items)
}
fn texts(value: &Value) -> Result<Vec<String>, ContractError> {
    array(value)?.iter().map(|v| Ok(text(v)?.into())).collect()
}
fn labels(value: &Value) -> Result<Vec<(String, String)>, ContractError> {
    array(value)?
        .iter()
        .map(|v| {
            let parts = tuple(v, 2)?;
            Ok((text(&parts[0])?.into(), text(&parts[1])?.into()))
        })
        .collect()
}

fn validate_prefixes(prefixes: &[String]) -> Result<(), ContractError> {
    if prefixes.is_empty() {
        return Err(ContractError::InvalidFloorCidr);
    }
    ordered(prefixes, String::as_str)?;
    let mut ranges = Vec::with_capacity(prefixes.len());
    for prefix in prefixes {
        let (address, bits) = prefix
            .split_once('/')
            .ok_or(ContractError::InvalidFloorCidr)?;
        let address: IpAddr = address
            .parse()
            .map_err(|_| ContractError::InvalidFloorCidr)?;
        let bits: u32 = bits.parse().map_err(|_| ContractError::InvalidFloorCidr)?;
        let (width, start) = match address {
            IpAddr::V4(v) => (32, u128::from(u32::from(v))),
            IpAddr::V6(v) => (128, u128::from(v)),
        };
        if bits > width || prefix != &format!("{address}/{bits}") {
            return Err(ContractError::InvalidFloorCidr);
        }
        let host = width - bits;
        let mask = if host == 128 {
            u128::MAX
        } else {
            (1u128 << host) - 1
        };
        if start & mask != 0 {
            return Err(ContractError::InvalidFloorCidr);
        }
        let end = start | mask;
        if ranges
            .iter()
            .any(|&(w, lo, hi)| width == w && start <= hi && lo <= end)
        {
            return Err(ContractError::InvalidFloorCidr);
        }
        ranges.push((width, start, end));
    }
    Ok(())
}
