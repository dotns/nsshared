//! Pure observations and authenticated report operation dispatch.
use crate::{
    account::AccountError, account::MAX_BYTES, account::bounded,
    account::control::BootstrapEnvelope, account::control::EnvelopeDirection,
    account::control::EnvelopeExpectation, account::control::exchange::*,
    account::edge::EdgeMaterialAck, account::edge::EdgeServiceRequest,
    account::edge::EdgeServiceResponse, account::edge::MAX_EDGE_ITEMS, account::reader,
    account::require, account::usage::UsageAnswer, account::usage::UsageReport,
};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};

fn text(value: &str) -> Result<(), AccountError> {
    require(!value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control))
}
fn strings(out: &mut CborWriter, values: &[String], ordered: bool) -> Result<(), AccountError> {
    require(values.len() <= MAX_EDGE_ITEMS)?;
    if ordered {
        require(values.windows(2).all(|p| p[0] < p[1]))?;
    }
    out.array(values.len());
    for value in values {
        text(value)?;
        out.text(value);
    }
    Ok(())
}
fn read_strings(input: &mut CborReader<'_>) -> Result<Vec<String>, AccountError> {
    let count = input.array_up_to(MAX_EDGE_ITEMS)?;
    (0..count)
        .map(|_| Ok(input.text_up_to(256)?.into()))
        .collect()
}
fn optional_text(out: &mut CborWriter, value: &Option<String>) -> Result<(), AccountError> {
    if let Some(value) = value {
        text(value)?;
        out.text(value);
    } else {
        out.null();
    }
    Ok(())
}
fn read_text(input: &mut CborReader<'_>) -> Result<Option<String>, AccountError> {
    if input.take_null() {
        Ok(None)
    } else {
        Ok(Some(input.text_up_to(256)?.into()))
    }
}
fn optional_uint(out: &mut CborWriter, value: Option<u64>) {
    if let Some(value) = value {
        out.uint(value);
    } else {
        out.null();
    }
}
fn read_uint(input: &mut CborReader<'_>) -> Result<Option<u64>, AccountError> {
    if input.take_null() {
        Ok(None)
    } else {
        Ok(Some(input.uint()?))
    }
}

/// Process liveness observations, never authorization or applied-policy evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatRequest {
    /// Gateway-minted unique pending request id.
    pub request_id: [u8; 16],
    /// Process uptime in seconds.
    pub uptime_seconds: u64,
    /// Supplied IP literals, preserving order and valid empty distinctly.
    pub local_ips: Vec<String>,
    /// Last observed diagnostic policy counter, absent until received.
    pub policy_version: Option<u64>,
}
impl HeartbeatRequest {
    /// Encodes bounded observations without interpreting policy authority.
    /// # Errors
    /// Refuses invalid IP literals, text or list bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        require(
            self.local_ips
                .iter()
                .all(|value| value.parse::<std::net::IpAddr>().is_ok()),
        )?;
        let mut out = CborWriter::default();
        out.array(5)
            .uint(1)
            .bytes(&self.request_id)
            .uint(self.uptime_seconds);
        strings(&mut out, &self.local_ips, false)?;
        optional_uint(&mut out, self.policy_version);
        bounded(out.into_bytes())
    }
    /// Decodes exact canonical heartbeat bytes.
    /// # Errors
    /// Refuses malformed, noncanonical or oversized values.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 5)?;
        let value = Self {
            request_id: input.fixed_bytes()?,
            uptime_seconds: input.uint()?,
            local_ips: read_strings(&mut input)?,
            policy_version: read_uint(&mut input)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}
/// Exact heartbeat receipt and optional inert feature observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatResponse {
    /// Echo of the exact pending request id.
    pub request_id: [u8; 16],
    /// Ordered unique feature tokens; unknown tokens remain inert data.
    pub features: Vec<String>,
}
impl HeartbeatResponse {
    /// Encodes a receipt without creating permissions.
    /// # Errors
    /// Refuses invalid feature text, ordering or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        let mut out = CborWriter::default();
        out.array(3).uint(1).bytes(&self.request_id);
        strings(&mut out, &self.features, true)?;
        bounded(out.into_bytes())
    }
    /// Decodes canonical receipt bytes.
    /// # Errors
    /// Refuses malformed or noncanonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 3)?;
        let value = Self {
            request_id: input.fixed_bytes()?,
            features: read_strings(&mut input)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
    /// Correlates an authenticated receipt with its retained request.
    /// # Errors
    /// Refuses invalid content or a different request id.
    pub fn validate_for(&self, pending: &HeartbeatRequest) -> Result<(), AccountError> {
        self.canonical()?;
        pending.canonical()?;
        require(self.request_id == pending.request_id)
    }
}
/// Nonsecret certificate activation observations; never material-fetch authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayCertificateObservation {
    /// Exact certificate reference observation.
    pub id: String,
    /// Ordered unique covered hostnames.
    pub hostnames: Vec<String>,
    /// Opaque issuer observation.
    pub issuer: String,
    /// Observed certificate expiry in Unix seconds.
    pub not_after_seconds: u64,
    /// Opaque fingerprint observation, never a trust pin.
    pub fingerprint: String,
    /// Optional positive activation generation.
    pub ack_generation: Option<u64>,
    /// Optional explicit error code.
    pub last_error: Option<String>,
}
impl GatewayCertificateObservation {
    fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        text(&self.id)?;
        text(&self.issuer)?;
        text(&self.fingerprint)?;
        require(self.ack_generation.is_none_or(|value| value > 0))?;
        out.array(7).text(&self.id);
        strings(out, &self.hostnames, true)?;
        out.text(&self.issuer)
            .uint(self.not_after_seconds)
            .text(&self.fingerprint);
        optional_uint(out, self.ack_generation);
        optional_text(out, &self.last_error)
    }
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(7)?;
        Ok(Self {
            id: input.text_up_to(256)?.into(),
            hostnames: read_strings(input)?,
            issuer: input.text_up_to(256)?.into(),
            not_after_seconds: input.uint()?,
            fingerprint: input.text_up_to(256)?.into(),
            ack_generation: read_uint(input)?,
            last_error: read_text(input)?,
        })
    }
}
/// Gateway-local observations, distinct from accepted Node records and grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayReport {
    /// Gateway-minted unique pending observation id.
    pub request_id: [u8; 16],
    /// Optional exact software version.
    pub software_version: Option<String>,
    /// Optional exact source revision.
    pub source_revision: Option<String>,
    /// Legacy connection-count observation; absent means unknown, not zero.
    pub connections: Option<u32>,
    /// Optional local service termination intent.
    pub terminate_enabled: Option<bool>,
    /// Optional observed public HTTP port.
    pub public_http_port: Option<u16>,
    /// Optional observed internal HTTP port.
    pub internal_http_port: Option<u16>,
    /// Current local drain intent.
    pub draining: bool,
    /// Existing enrollment capability syntax, without grants.
    pub capabilities: Vec<String>,
    /// Ordered unique declared ingress scopes.
    pub public_ingress_scopes: Vec<String>,
    /// Nonsecret activation observations in supplied order.
    pub certificates: Vec<GatewayCertificateObservation>,
}
impl GatewayReport {
    /// Encodes observations, preserving missing values distinctly.
    /// # Errors
    /// Refuses invalid ports, text, capabilities or collection bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        require(self.certificates.len() <= MAX_EDGE_ITEMS)?;
        crate::account::node::enrollment::validate_capabilities(&self.capabilities)
            .map_err(|_| AccountError::Field)?;
        require(self.public_http_port != Some(0) && self.internal_http_port != Some(0))?;
        let mut out = CborWriter::default();
        out.array(12).uint(1).bytes(&self.request_id);
        optional_text(&mut out, &self.software_version)?;
        optional_text(&mut out, &self.source_revision)?;
        optional_uint(&mut out, self.connections.map(u64::from));
        if let Some(value) = self.terminate_enabled {
            out.boolean(value);
        } else {
            out.null();
        }
        optional_uint(&mut out, self.public_http_port.map(u64::from));
        optional_uint(&mut out, self.internal_http_port.map(u64::from));
        out.boolean(self.draining);
        strings(&mut out, &self.capabilities, true)?;
        strings(&mut out, &self.public_ingress_scopes, true)?;
        out.array(self.certificates.len());
        for value in &self.certificates {
            value.write(&mut out)?;
        }
        bounded(out.into_bytes())
    }
    /// Decodes canonical gateway observations with bounds before allocation.
    /// # Errors
    /// Refuses malformed fields, overflows or noncanonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 12)?;
        let request_id = input.fixed_bytes()?;
        let software_version = read_text(&mut input)?;
        let source_revision = read_text(&mut input)?;
        let connections = read_uint(&mut input)?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| AccountError::Field)?;
        let terminate_enabled = if input.take_null() {
            None
        } else {
            Some(input.boolean()?)
        };
        let public_http_port = read_uint(&mut input)?
            .map(u16::try_from)
            .transpose()
            .map_err(|_| AccountError::Field)?;
        let internal_http_port = read_uint(&mut input)?
            .map(u16::try_from)
            .transpose()
            .map_err(|_| AccountError::Field)?;
        let draining = input.boolean()?;
        let capabilities = read_strings(&mut input)?;
        let public_ingress_scopes = read_strings(&mut input)?;
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let certificates = (0..count)
            .map(|_| GatewayCertificateObservation::read(&mut input))
            .collect::<Result<_, _>>()?;
        input.finish()?;
        let value = Self {
            request_id,
            software_version,
            source_revision,
            connections,
            terminate_enabled,
            public_http_port,
            internal_http_port,
            draining,
            capabilities,
            public_ingress_scopes,
            certificates,
        };
        value.canonical()?;
        Ok(value)
    }
}
/// Receipt of one exact gateway observation id, without registration or readiness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayReportResponse {
    /// Exact pending request id.
    pub request_id: [u8; 16],
}
impl GatewayReportResponse {
    /// Encodes the exact receipt tuple.
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = CborWriter::default();
        out.array(2).uint(1).bytes(&self.request_id);
        out.into_bytes()
    }
    /// Decodes one receipt tuple.
    /// # Errors
    /// Refuses malformed, noncanonical or trailing input.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 2)?;
        let value = Self {
            request_id: input.fixed_bytes()?,
        };
        input.finish()?;
        Ok(value)
    }
    /// Compares the receipt to the retained observation.
    /// # Errors
    /// Refuses invalid observation or a different request id.
    pub fn validate_for(&self, pending: &GatewayReport) -> Result<(), AccountError> {
        pending.canonical()?;
        require(self.request_id == pending.request_id)
    }
}
/// Authority receipt of an exact material installation or rejection report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterialStatusResponse {
    /// Exact echoed report; a rejection does not become installation.
    pub report: EdgeMaterialAck,
}
impl MaterialStatusResponse {
    /// Encodes the exact accepted report without private configuration.
    /// # Errors
    /// Refuses invalid material/scope fields or oversized values.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        let mut out = CborWriter::default();
        out.array(2).uint(1).bytes(&self.report.canonical()?);
        bounded(out.into_bytes())
    }
    /// Decodes one exact material status receipt.
    /// # Errors
    /// Refuses malformed, noncanonical or invalid nested report bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 2)?;
        let value = Self {
            report: EdgeMaterialAck::decode(input.bytes_up_to(MAX_BYTES)?)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
    /// Matches realm, scope, request id, material reference, generation and status.
    /// # Errors
    /// Refuses any difference from the exact pending report.
    pub fn validate_for(&self, pending: &EdgeMaterialAck) -> Result<(), AccountError> {
        self.canonical()?;
        pending.canonical()?;
        require(&self.report == pending)
    }
}

/// Retained report operations, without a runtime dispatcher or private payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlReportOperation {
    /// Process heartbeat.
    Heartbeat,
    /// Gateway observations.
    Gateway,
    /// Existing complete M6 service and local Exit floor.
    Services,
    /// Immutable service or relay usage part.
    Usage,
    /// Exact material installation status.
    MaterialStatus,
}
impl ControlReportOperation {
    /// Selects one known operation; no unknown-operation fallback exists.
    /// # Errors
    /// Refuses names outside this report contract.
    pub fn parse(name: &str) -> Result<Self, AccountError> {
        match name {
            MACHINE_HEARTBEAT => Ok(Self::Heartbeat),
            GATEWAY_REPORT => Ok(Self::Gateway),
            GATEWAY_SERVICES_REPORT => Ok(Self::Services),
            GATEWAY_USAGE_REPORT => Ok(Self::Usage),
            GATEWAY_MATERIAL_STATUS => Ok(Self::MaterialStatus),
            _ => Err(AccountError::Field),
        }
    }
    /// Exact signed operation identifier, defined in the shared exchange constants.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Heartbeat => MACHINE_HEARTBEAT,
            Self::Gateway => GATEWAY_REPORT,
            Self::Services => GATEWAY_SERVICES_REPORT,
            Self::Usage => GATEWAY_USAGE_REPORT,
            Self::MaterialStatus => GATEWAY_MATERIAL_STATUS,
        }
    }
    /// Validates a canonical request or response payload without transport or I/O.
    /// # Errors
    /// Refuses malformed bytes or a payload outside the selected operation form.
    pub fn validate_payload(
        self,
        direction: EnvelopeDirection,
        bytes: &[u8],
    ) -> Result<(), AccountError> {
        match (self, direction) {
            (Self::Heartbeat, EnvelopeDirection::Request) => {
                HeartbeatRequest::decode(bytes)?;
            }
            (Self::Heartbeat, EnvelopeDirection::Response) => {
                HeartbeatResponse::decode(bytes)?;
            }
            (Self::Gateway, EnvelopeDirection::Request) => {
                GatewayReport::decode(bytes)?;
            }
            (Self::Gateway, EnvelopeDirection::Response) => {
                GatewayReportResponse::decode(bytes)?;
            }
            (Self::Services, EnvelopeDirection::Request) => {
                require(EdgeServiceRequest::decode(bytes)?.body.kind() == 1)?;
            }
            (Self::Services, EnvelopeDirection::Response) => {
                require(EdgeServiceResponse::decode(bytes)?.body_kind == 1)?;
            }
            (Self::Usage, EnvelopeDirection::Request) => {
                UsageReport::decode(bytes).map_err(|_| AccountError::Field)?;
            }
            (Self::Usage, EnvelopeDirection::Response) => {
                UsageAnswer::decode(bytes).map_err(|_| AccountError::Field)?;
            }
            (Self::MaterialStatus, EnvelopeDirection::Request) => {
                EdgeMaterialAck::decode(bytes)?;
            }
            (Self::MaterialStatus, EnvelopeDirection::Response) => {
                MaterialStatusResponse::decode(bytes)?;
            }
        }
        Ok(())
    }
    /// Authenticates the carrier before checking its report payload form.
    /// # Errors
    /// Refuses trust, expected direction/operation/recipient or invalid payloads.
    pub fn validate_envelope(
        self,
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
    ) -> Result<(), ExchangeError> {
        envelope.verify(expected)?;
        if envelope.kind != self.as_str() {
            return Err(crate::account::control::BootstrapError::Kind.into());
        }
        self.validate_payload(envelope.direction, &envelope.payload)?;
        if envelope.direction == EnvelopeDirection::Request {
            match self {
                Self::Services => require(
                    EdgeServiceRequest::decode(&envelope.payload)?.publisher == envelope.signer,
                )?,
                Self::Usage => require(
                    UsageReport::decode(&envelope.payload)
                        .map_err(|_| AccountError::Field)?
                        .reporter
                        == envelope.signer,
                )?,
                _ => {}
            }
        }
        Ok(())
    }
}
