//! Additive adapter for versioned content in the existing report.replace message.

use nsshared_codec::cbor::value::Value;

use super::contract::{Envelope, bytes, exact_map, field, map, unsigned};
use super::{ContractError, FloorContent, FloorExitProfile, FloorMetadata, Message, MessageBody};

/// Versioned content body for the existing ReportReplace wire operation.
/// The legacy [`super::ReportReplace`] structure remains unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FloorReportReplace {
    /// Positive report revision, checked by the enclosing M6 message.
    pub report_revision: u64,
    /// Complete canonical floor content.
    pub report: FloorContent,
}

/// Complete floor request using the unchanged M6 envelope and report.replace kind.
/// The legacy message API deliberately refuses nonempty floor extensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FloorReportMessage {
    message: Message,
    report: FloorReportReplace,
}

impl Message {
    /// Attaches canonical floor data to a legacy ReportReplace request.
    /// # Errors
    /// Refuses other message kinds or any invalid complete floor or runtime context.
    pub fn with_floor(
        self,
        metadata: Vec<FloorMetadata>,
        exit_profiles: Vec<FloorExitProfile>,
    ) -> Result<FloorReportMessage, ContractError> {
        let MessageBody::ReportReplace(body) = &self.body else {
            return Err(ContractError::InvalidField);
        };
        let report = FloorReportReplace {
            report_revision: body.report_revision,
            report: FloorContent {
                report: body.report.clone(),
                metadata,
                exit_profiles,
            },
        };
        let result = FloorReportMessage {
            message: self,
            report,
        };
        result.encode()?;
        Ok(result)
    }
}

impl FloorReportMessage {
    /// The exact complete versioned report and its revision.
    #[must_use]
    pub const fn report(&self) -> &FloorReportReplace {
        &self.report
    }

    /// Envelope context and legacy declaration projection, not the full wire payload.
    /// Use `encode` for transport and `validate_accepted` for content correlation.
    #[must_use]
    pub const fn context(&self) -> &Message {
        &self.message
    }

    /// Encodes report.replace with the complete canonical content digest.
    /// # Errors
    /// Refuses invalid floor content, scope or Node runtime fence.
    pub fn encode(&self) -> Result<Vec<u8>, ContractError> {
        let mut raw = Envelope::decode(&self.message.encode()?)?;
        let (content, digest) = self.report.report.canonical()?;
        raw.body = map(vec![
            ("report_revision", Value::UInt(self.report.report_revision)),
            ("report_digest", bytes(digest)),
            ("report_content", Value::Bytes(content)),
        ]);
        raw.encode()
    }

    /// Decodes legacy or versioned report.replace without discarding floor content.
    /// # Errors
    /// Refuses any wrong message kind, canonical content, digest or runtime context.
    pub fn decode(input: &[u8]) -> Result<Self, ContractError> {
        let mut raw = Envelope::decode(input)?;
        if raw.kind != "report.replace" {
            return Err(ContractError::InvalidField);
        }
        let fields = exact_map(
            &raw.body,
            &["report_revision", "report_digest", "report_content"],
        )?;
        let Value::Bytes(content) = field(fields, "report_content")? else {
            return Err(ContractError::InvalidField);
        };
        let report = FloorReportReplace {
            report_revision: unsigned(field(fields, "report_revision")?)?,
            report: FloorContent::decode(content)?,
        };
        let (content, digest) = report.report.report.canonical()?;
        raw.body = map(vec![
            ("report_revision", Value::UInt(report.report_revision)),
            ("report_digest", bytes(digest)),
            ("report_content", Value::Bytes(content)),
        ]);
        let message = Message::decode(&raw.encode()?)?;
        Ok(Self { message, report })
    }

    /// Compares ReportAccepted with this pending report's entire content and context.
    /// Authentication and independently persisted custody remain caller responsibilities.
    /// # Errors
    /// Refuses any scope, runtime, authority, request, revision or digest mismatch.
    pub fn validate_accepted(&self, reply: &Message) -> Result<(), ContractError> {
        reply.encode()?;
        let request = &self.message;
        let MessageBody::ReportAccepted(result) = &reply.body else {
            return Err(ContractError::InvalidField);
        };
        if request.nsd_id != reply.nsd_id
            || request.network_id != reply.network_id
            || request.subject_identity != reply.subject_identity
            || request.request_id != reply.request_id
            || request.runtime_generation != reply.runtime_generation
            || request.runtime_id != reply.runtime_id
            || request.authority_epoch != reply.authority_epoch
            || request.session_seq != reply.session_seq
            || result.accepted_revision != self.report.report_revision
            || result.report_digest != Some(self.report.report.canonical()?.1)
        {
            return Err(ContractError::DigestConflict);
        }
        Ok(())
    }
}
