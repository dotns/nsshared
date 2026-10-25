//! Correlated service requests and replies carrying exact existing M6 bytes.

use crate::{
    service::Declaration, service::Digest, service::ListenerIntent, service::ReportContent,
    service::domain_digest,
};

use crate::{
    account::AccountError, account::MAX_BYTES, account::bounded, account::edge::MAX_EDGE_ITEMS,
    account::identity, account::reader, account::require, account::subnet::SubnetSelection,
};
use nsshared_codec::cbor::CborReader;
use nsshared_codec::cbor::CborWriter;
use nsshared_identity::keys::IdentityKey;

/// Existing M6 object carried by a confidential service operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EdgeServiceBody {
    /// One private service declaration.
    Declaration(Declaration),
    /// Complete service declaration report.
    Report(ReportContent),
    /// Exact publisher listener intent.
    Listener(ListenerIntent),
}

impl EdgeServiceBody {
    /// Stable operation discriminator, without introducing another M6 message kind.
    #[must_use]
    pub const fn kind(&self) -> u64 {
        match self {
            Self::Declaration(_) => 0,
            Self::Report(_) => 1,
            Self::Listener(_) => 2,
        }
    }

    /// Returns unchanged M6 canonical bytes and their correlation digest.
    ///
    /// # Errors
    /// Rejects invalid nested M6 values.
    pub fn canonical(&self) -> Result<(Vec<u8>, Digest), AccountError> {
        match self {
            Self::Declaration(value) => {
                let bytes = value.canonical().map_err(|_| AccountError::Field)?;
                let digest = domain_digest("ns.account.declaration.v1", &bytes);
                Ok((bytes, digest))
            }
            Self::Report(value) => value.canonical().map_err(|_| AccountError::Field),
            Self::Listener(value) => value.canonical().map_err(|_| AccountError::Field),
        }
    }
}

/// Complete service operation context retained until an authenticated reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeServiceRequest {
    /// Stable request identity.
    pub request_id: [u8; 16],
    /// Full publisher identity, never an address or display name.
    pub publisher: IdentityKey,
    /// Exact M6 NSD identifier.
    pub nsd_id: [u8; 16],
    /// Exact M6 Network identifier.
    pub network_id: [u8; 16],
    /// Positive content revision.
    pub revision: u64,
    /// Existing object and its exact serializer.
    pub body: EdgeServiceBody,
    /// Exact metadata for every report declaration; absent for other body kinds.
    pub metadata: Vec<EdgeServiceMetadata>,
    /// Complete non-authoritative local Exit floor; absent for other body kinds.
    pub exit_profiles: Vec<EdgeExitProfile>,
}

impl EdgeServiceRequest {
    /// Encodes scope and correlation metadata around unchanged M6 bytes.
    ///
    /// # Errors
    /// Rejects invalid bodies, mismatched ownership/scope/revision or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        require(self.revision > 0)?;
        match &self.body {
            EdgeServiceBody::Declaration(_) => {}
            EdgeServiceBody::Report(value) => require(
                value.publisher_identity == *self.publisher.as_bytes()
                    && value.nsd_id == self.nsd_id
                    && value.network_id == self.network_id,
            )?,
            EdgeServiceBody::Listener(value) => require(
                value.publisher_identity == *self.publisher.as_bytes()
                    && value.service_ref.nsd_id == self.nsd_id
                    && value.service_ref.network_id == self.network_id
                    && value.listener_revision == self.revision,
            )?,
        }
        let (bytes, _) = self.body.canonical()?;
        let digest = self.content_digest()?;
        if let EdgeServiceBody::Report(report) = &self.body {
            require(self.metadata.len() == report.declarations.len())?;
            for (metadata, declaration) in self.metadata.iter().zip(&report.declarations) {
                require(metadata.reference == declaration.declaration_key)?;
            }
        } else {
            require(self.metadata.is_empty() && self.exit_profiles.is_empty())?;
        }
        let mut out = CborWriter::default();
        out.array(if self.body.kind() == 1 { 11 } else { 9 })
            .uint(1)
            .bytes(&self.request_id)
            .bytes(self.publisher.as_bytes())
            .bytes(&self.nsd_id)
            .bytes(&self.network_id)
            .uint(self.revision)
            .uint(self.body.kind())
            .bytes(&bytes);
        if self.body.kind() == 1 {
            self.write_floor(&mut out)?;
        }
        out.bytes(&digest);
        bounded(out.into_bytes())
    }

    /// Decodes and validates metadata and delegates the body to its M6 decoder.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical values, ownership or digest mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = CborReader::new(bytes, MAX_BYTES)?;
        let arity = input.array_up_to(11)?;
        require(input.uint()? == 1)?;
        let request_id = input.fixed_bytes()?;
        let publisher = identity(&mut input)?;
        let nsd_id = input.fixed_bytes()?;
        let network_id = input.fixed_bytes()?;
        let revision = input.uint()?;
        let kind = input.uint()?;
        let raw = input.bytes_up_to(MAX_BYTES)?;
        let body = match kind {
            0 => EdgeServiceBody::Declaration(
                Declaration::decode(raw).map_err(|_| AccountError::Field)?,
            ),
            1 => EdgeServiceBody::Report(
                ReportContent::decode(raw).map_err(|_| AccountError::Field)?,
            ),
            2 => EdgeServiceBody::Listener(
                ListenerIntent::decode(raw).map_err(|_| AccountError::Field)?,
            ),
            _ => return Err(AccountError::Field),
        };
        require(arity == if kind == 1 { 11 } else { 9 })?;
        let (metadata, exit_profiles) = if kind == 1 {
            (read_metadata(&mut input)?, read_exits(&mut input)?)
        } else {
            (Vec::new(), Vec::new())
        };
        let digest: Digest = input.fixed_bytes()?;
        input.finish()?;
        let value = Self {
            request_id,
            publisher,
            nsd_id,
            network_id,
            revision,
            body,
            metadata,
            exit_profiles,
        };
        require(value.content_digest()? == digest)?;
        value.canonical()?;
        Ok(value)
    }
}

/// Authenticated service response and ACK, without listener-readiness semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeServiceResponse {
    /// Correlated pending operation.
    pub request_id: [u8; 16],
    /// Exact publisher.
    pub publisher: IdentityKey,
    /// Exact M6 NSD scope.
    pub nsd_id: [u8; 16],
    /// Exact M6 Network scope.
    pub network_id: [u8; 16],
    /// Exact accepted/rejected revision.
    pub revision: u64,
    /// Request body discriminator, 0 declaration, 1 report, 2 listener.
    pub body_kind: u64,
    /// Exact request digest, unchanged for M6 report/listener bodies.
    pub digest: Digest,
    /// True means content accepted, false explicitly rejected.
    pub accepted: bool,
    /// Exact per-reference report outcomes; absent for declaration/listener bodies.
    pub outcomes: Option<EdgeFloorOutcomes>,
}

impl EdgeServiceResponse {
    /// Encodes an explicit scoped response with no default status.
    ///
    /// # Errors
    /// Rejects zero revisions, unknown body kinds and oversized input.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        require(self.revision > 0 && self.body_kind <= 2)?;
        let mut out = CborWriter::default();
        out.array(9)
            .uint(1)
            .bytes(&self.request_id)
            .bytes(self.publisher.as_bytes())
            .bytes(&self.nsd_id)
            .bytes(&self.network_id)
            .uint(self.revision)
            .uint(self.body_kind)
            .bytes(&self.digest);
        if self.body_kind == 1 {
            let outcomes = self.outcomes.as_ref().ok_or(AccountError::Field)?;
            require(self.accepted == outcomes.rejected.is_empty())?;
            outcomes.write(&mut out)?;
        } else {
            require(self.outcomes.is_none())?;
            out.uint(u64::from(!self.accepted));
        }
        bounded(out.into_bytes())
    }

    /// Decodes an exact explicit accepted/rejected service response.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical metadata and unknown discriminants.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 9)?;
        let request_id = input.fixed_bytes()?;
        let publisher = identity(&mut input)?;
        let nsd_id = input.fixed_bytes()?;
        let network_id = input.fixed_bytes()?;
        let revision = input.uint()?;
        let body_kind = input.uint()?;
        let digest = input.fixed_bytes()?;
        let (accepted, outcomes) = if body_kind == 1 {
            let outcomes = EdgeFloorOutcomes::read(&mut input)?;
            (outcomes.rejected.is_empty(), Some(outcomes))
        } else {
            (
                match input.uint()? {
                    0 => true,
                    1 => false,
                    _ => return Err(AccountError::Field),
                },
                None,
            )
        };
        input.finish()?;
        let value = Self {
            request_id,
            publisher,
            nsd_id,
            network_id,
            revision,
            body_kind,
            digest,
            accepted,
            outcomes,
        };
        value.canonical()?;
        Ok(value)
    }

    /// Matches every correlation field against an externally retained request.
    ///
    /// # Errors
    /// Rejects mismatched request, scope, ownership, kind, revision or digest.
    /// Explicit rejection is a matching response whose accepted flag stays false.
    pub fn validate_request(
        &self,
        request: &EdgeServiceRequest,
    ) -> Result<(), EdgeServiceAckError> {
        self.canonical()?;
        request.canonical()?;
        require(
            self.request_id == request.request_id
                && self.publisher == request.publisher
                && self.nsd_id == request.nsd_id
                && self.network_id == request.network_id
                && self.revision == request.revision
                && self.body_kind == request.body.kind()
                && self.digest == request.content_digest()?,
        )?;
        if let Some(outcomes) = &self.outcomes {
            outcomes.validate_for(request)?;
        }
        Ok(())
    }
}

/// Local floor metadata attached to an unchanged M6 declaration key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeServiceMetadata {
    /// Exact publisher-local declaration key.
    pub reference: String,
    /// Declared capabilities, never permissions.
    pub capabilities: Vec<String>,
    /// Ordered local policy label key/value observations.
    pub policy_labels: Vec<(String, String)>,
}

fn data_text(value: &str) -> Result<(), AccountError> {
    require(!value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control))
}

fn labels_write(values: &[(String, String)], out: &mut CborWriter) -> Result<(), AccountError> {
    require(values.len() <= MAX_EDGE_ITEMS && values.windows(2).all(|p| p[0].0 < p[1].0))?;
    out.array(values.len());
    for (key, value) in values {
        data_text(key)?;
        require(value.len() <= 256 && !value.chars().any(char::is_control))?;
        out.array(2).text(key).text(value);
    }
    Ok(())
}
fn labels_read(input: &mut CborReader<'_>) -> Result<Vec<(String, String)>, AccountError> {
    let count = input.array_up_to(MAX_EDGE_ITEMS)?;
    (0..count)
        .map(|_| {
            input.array(2)?;
            Ok((input.text_up_to(256)?.into(), input.text_up_to(256)?.into()))
        })
        .collect()
}
fn ordered_data_write(values: &[String], out: &mut CborWriter) -> Result<(), AccountError> {
    require(values.len() <= MAX_EDGE_ITEMS && values.windows(2).all(|p| p[0] < p[1]))?;
    out.array(values.len());
    for value in values {
        data_text(value)?;
        out.text(value);
    }
    Ok(())
}
fn strings_read(input: &mut CborReader<'_>) -> Result<Vec<String>, AccountError> {
    let count = input.array_up_to(MAX_EDGE_ITEMS)?;
    (0..count)
        .map(|_| Ok(input.text_up_to(256)?.into()))
        .collect()
}
impl EdgeServiceMetadata {
    fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        data_text(&self.reference)?;
        crate::account::node::enrollment::validate_capabilities(&self.capabilities)
            .map_err(|_| AccountError::Field)?;
        out.array(3).text(&self.reference);
        ordered_data_write(&self.capabilities, out)?;
        labels_write(&self.policy_labels, out)
    }
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(3)?;
        Ok(Self {
            reference: input.text_up_to(256)?.into(),
            capabilities: strings_read(input)?,
            policy_labels: labels_read(input)?,
        })
    }
}

/// A local Exit profile declaration; it supplies no route or grant authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeExitProfile {
    /// Stable local profile reference.
    pub reference: String,
    /// Existing Subnet default or explicit prefix selection semantics.
    pub selection: SubnetSelection,
    /// Local enabled intent, never an authorization decision.
    pub enabled: bool,
    /// Observed profile capabilities.
    pub capabilities: Vec<String>,
    /// Local policy label metadata.
    pub policy_labels: Vec<(String, String)>,
}
impl EdgeExitProfile {
    fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        data_text(&self.reference)?;
        crate::account::node::enrollment::validate_capabilities(&self.capabilities)
            .map_err(|_| AccountError::Field)?;
        out.array(5).text(&self.reference);
        match &self.selection {
            SubnetSelection::Default => {
                out.array(1).uint(0);
            }
            SubnetSelection::Explicit(prefixes) => {
                crate::account::subnet::views::validate_set(prefixes)
                    .map_err(|_| AccountError::Field)?;
                out.array(2).uint(1);
                crate::account::subnet::views::write_set(prefixes, out);
            }
        }
        out.boolean(self.enabled);
        ordered_data_write(&self.capabilities, out)?;
        labels_write(&self.policy_labels, out)
    }
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(5)?;
        let reference = input.text_up_to(256)?.into();
        let arity = input.array_up_to(2)?;
        let selection = match (arity, input.uint()?) {
            (1, 0) => SubnetSelection::Default,
            (2, 1) => SubnetSelection::Explicit(
                crate::account::subnet::views::read_set(input).map_err(|_| AccountError::Field)?,
            ),
            _ => return Err(AccountError::Field),
        };
        Ok(Self {
            reference,
            selection,
            enabled: input.boolean()?,
            capabilities: strings_read(input)?,
            policy_labels: labels_read(input)?,
        })
    }
}
fn read_metadata(input: &mut CborReader<'_>) -> Result<Vec<EdgeServiceMetadata>, AccountError> {
    let count = input.array_up_to(MAX_EDGE_ITEMS)?;
    (0..count)
        .map(|_| EdgeServiceMetadata::read(input))
        .collect()
}
fn read_exits(input: &mut CborReader<'_>) -> Result<Vec<EdgeExitProfile>, AccountError> {
    let count = input.array_up_to(MAX_EDGE_ITEMS)?;
    (0..count).map(|_| EdgeExitProfile::read(input)).collect()
}
impl EdgeServiceRequest {
    fn write_floor(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        require(
            self.metadata.len() <= MAX_EDGE_ITEMS
                && self
                    .metadata
                    .windows(2)
                    .all(|p| p[0].reference < p[1].reference),
        )?;
        require(
            self.exit_profiles.len() <= MAX_EDGE_ITEMS
                && self
                    .exit_profiles
                    .windows(2)
                    .all(|p| p[0].reference < p[1].reference),
        )?;
        out.array(self.metadata.len());
        for value in &self.metadata {
            value.write(out)?;
        }
        out.array(self.exit_profiles.len());
        for value in &self.exit_profiles {
            value.write(out)?;
        }
        Ok(())
    }
    /// Commits the entire submitted floor while preserving nested M6 bytes.
    /// # Errors
    /// Refuses invalid M6 objects or floor metadata.
    pub fn content_digest(&self) -> Result<Digest, AccountError> {
        let (bytes, digest) = self.body.canonical()?;
        if self.body.kind() != 1 {
            return Ok(digest);
        }
        let mut out = CborWriter::default();
        out.array(3).bytes(&bytes);
        self.write_floor(&mut out)?;
        Ok(domain_digest(
            "ns.account.service-floor.v1",
            &out.into_bytes(),
        ))
    }
}

/// A rejected exact submitted reference and the producer's reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeFloorRejection {
    /// 0 service or 1 Exit profile.
    pub kind: u64,
    /// Exact submitted reference of that kind.
    pub reference: String,
    /// Explicit nonempty diagnostic reason.
    pub reason: String,
}
/// Complete per-reference outcomes for one correlated floor report.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EdgeFloorOutcomes {
    /// Accepted submitted M6 declaration keys.
    pub accepted_services: Vec<String>,
    /// Accepted submitted local Exit references.
    pub accepted_exit_profiles: Vec<String>,
    /// Explicit rejected references with their reasons.
    pub rejected: Vec<EdgeFloorRejection>,
}
/// Correlation failures never imply acknowledgement.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EdgeServiceAckError {
    /// Malformed fields or mismatched complete request context.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// A submitted reference has no outcome.
    #[error("missing floor reference outcome")]
    MissingReference,
    /// An outcome does not name a submitted reference of its exact kind.
    #[error("unknown floor reference outcome")]
    UnknownReference,
    /// A reference is both accepted and rejected.
    #[error("contradictory floor reference outcome")]
    ContradictoryReference,
}
impl EdgeFloorOutcomes {
    fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        out.array(3);
        ordered_data_write(&self.accepted_services, out)?;
        ordered_data_write(&self.accepted_exit_profiles, out)?;
        require(
            self.rejected.len() <= MAX_EDGE_ITEMS
                && self
                    .rejected
                    .windows(2)
                    .all(|p| (p[0].kind, &p[0].reference) < (p[1].kind, &p[1].reference)),
        )?;
        out.array(self.rejected.len());
        for value in &self.rejected {
            require(value.kind <= 1)?;
            data_text(&value.reference)?;
            data_text(&value.reason)?;
            out.array(3)
                .uint(value.kind)
                .text(&value.reference)
                .text(&value.reason);
        }
        Ok(())
    }
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(3)?;
        let accepted_services = strings_read(input)?;
        let accepted_exit_profiles = strings_read(input)?;
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let rejected = (0..count)
            .map(|_| {
                input.array(3)?;
                Ok(EdgeFloorRejection {
                    kind: input.uint()?,
                    reference: input.text_up_to(256)?.into(),
                    reason: input.text_up_to(256)?.into(),
                })
            })
            .collect::<Result<_, AccountError>>()?;
        Ok(Self {
            accepted_services,
            accepted_exit_profiles,
            rejected,
        })
    }
    fn validate_for(&self, request: &EdgeServiceRequest) -> Result<(), EdgeServiceAckError> {
        let EdgeServiceBody::Report(report) = &request.body else {
            return Err(AccountError::Field.into());
        };
        let services: Vec<_> = report
            .declarations
            .iter()
            .map(|v| v.declaration_key.as_str())
            .collect();
        let exits: Vec<_> = request
            .exit_profiles
            .iter()
            .map(|v| v.reference.as_str())
            .collect();
        let kinds = [
            (0, &services, &self.accepted_services),
            (1, &exits, &self.accepted_exit_profiles),
        ];
        for (kind, submitted, accepted) in kinds {
            if accepted.iter().any(|v| !submitted.contains(&v.as_str()))
                || self
                    .rejected
                    .iter()
                    .filter(|v| v.kind == kind)
                    .any(|v| !submitted.contains(&v.reference.as_str()))
            {
                return Err(EdgeServiceAckError::UnknownReference);
            }
        }
        for (kind, submitted, accepted) in kinds {
            let rejected: Vec<_> = self
                .rejected
                .iter()
                .filter(|v| v.kind == kind)
                .map(|v| v.reference.as_str())
                .collect();
            for reference in submitted {
                let yes = accepted.iter().any(|v| v == reference);
                let no = rejected.contains(reference);
                if yes && no {
                    return Err(EdgeServiceAckError::ContradictoryReference);
                }
                if !yes && !no {
                    return Err(EdgeServiceAckError::MissingReference);
                }
            }
        }
        Ok(())
    }
}
