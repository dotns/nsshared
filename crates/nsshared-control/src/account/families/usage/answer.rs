use crate::{
    account::MAX_IDENTITIES, account::SCHEMA, account::identity,
    account::node::ReporterIncarnation, account::reader, account::relay::ParticipantRosterScope,
    account::relay::RosterVersion, account::usage::UsageError, account::usage::UsageProfile,
    account::usage::UsageReport, account::usage::UsageRows, account::usage::report::field,
};
use nsshared_codec::cbor::CborWriter;
use nsshared_identity::{identity::NodeId, keys::IdentityKey};

/// Conflict metadata preserves missing, malformed and valid zero distinctly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageWatermark {
    /// No accepted-through value was supplied.
    Absent,
    /// A supplied accepted-through value was invalid.
    Malformed,
    /// Highest contiguous accepted sequence, including a valid zero.
    Present(u64),
}

/// Permanent rejection classes; neither acknowledges a report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum UsageRejection {
    /// Captured ownership or reporter authority was forbidden.
    Forbidden,
    /// The report shape was permanently invalid.
    InvalidRequest,
}

/// Typed receiver outcome. Authentication and delivery remain caller-owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsageOutcome {
    /// Durable contiguous acknowledgement, also used for an identical duplicate.
    Accepted {
        /// Highest contiguous accepted sequence in this exact reporter domain.
        accepted_through: u64,
    },
    /// Sequence/window conflict, never an acknowledgement.
    Conflict(UsageWatermark),
    /// Permanent rejection, never an acknowledgement.
    Permanent(UsageRejection),
    /// Unknown historical mapping requiring repair, never a guessed owner.
    UnknownMapping {
        /// Original roster issuer/participant domain.
        scope: ParticipantRosterScope,
        /// Captured roster version.
        epoch: RosterVersion,
        /// Endpoint whose retained historical mapping is missing.
        node: NodeId,
    },
}

/// Exact correlation with an immutable report part, independent of transport status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageAnswer {
    /// Original authenticated reporter identity.
    pub reporter: IdentityKey,
    /// Original reporter lifecycle.
    pub incarnation: ReporterIncarnation,
    /// Original independent quantity profile.
    pub profile: UsageProfile,
    /// Original part sequence.
    pub sequence: u64,
    /// Original zero-based part index.
    pub part_index: u64,
    /// Original part commitment.
    pub part_digest: [u8; 32],
    /// Durable acceptance or typed refusal/repair.
    pub outcome: UsageOutcome,
}

impl UsageAnswer {
    fn validate(&self) -> Result<(), UsageError> {
        field(self.sequence > 0 && self.part_index < MAX_IDENTITIES as u64)?;
        match &self.outcome {
            UsageOutcome::Accepted { accepted_through } => {
                field(*accepted_through >= self.sequence)
            }
            UsageOutcome::UnknownMapping { scope, epoch, .. } => {
                field(self.profile == UsageProfile::Relay && epoch.0 > 0)?;
                if scope.recipient != self.reporter {
                    return Err(UsageError::Scope);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Encodes a correlated outcome without advancing local custody or watermarks.
    ///
    /// # Errors
    /// Refuses invalid correlation fields, stale acceptance and malformed repair scope.
    pub fn canonical(&self) -> Result<Vec<u8>, UsageError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(8)
            .uint(SCHEMA)
            .bytes(self.reporter.as_bytes())
            .bytes(&self.incarnation.0)
            .text(self.profile.as_str())
            .uint(self.sequence)
            .uint(self.part_index)
            .bytes(&self.part_digest);
        match &self.outcome {
            UsageOutcome::Accepted { accepted_through } => {
                out.array(2).uint(0).uint(*accepted_through);
            }
            UsageOutcome::Conflict(watermark) => {
                out.array(2).uint(1);
                match watermark {
                    UsageWatermark::Absent => {
                        out.null();
                    }
                    UsageWatermark::Malformed => {
                        out.array(1).uint(0);
                    }
                    UsageWatermark::Present(value) => {
                        out.array(2).uint(1).uint(*value);
                    }
                }
            }
            UsageOutcome::Permanent(reason) => {
                out.array(2).uint(2).uint(*reason as u64);
            }
            UsageOutcome::UnknownMapping { scope, epoch, node } => {
                out.array(5)
                    .uint(3)
                    .bytes(scope.issuer.as_bytes())
                    .bytes(scope.recipient.as_bytes())
                    .uint(epoch.0)
                    .bytes(node.as_bytes());
            }
        }
        Ok(out.into_bytes())
    }

    /// Decodes canonical typed acceptance/conflict/rejection/repair bytes.
    ///
    /// # Errors
    /// Refuses malformed arrays, fields, profiles, widths or unknown outcomes.
    pub fn decode(bytes: &[u8]) -> Result<Self, UsageError> {
        let mut input = reader(bytes, 8)?;
        let reporter = identity(&mut input)?;
        let incarnation = ReporterIncarnation(input.fixed_bytes()?);
        let profile = UsageProfile::read(&mut input)?;
        let sequence = input.uint()?;
        let part_index = input.uint()?;
        let part_digest = input.fixed_bytes()?;
        let arity = input.array_up_to(5)?;
        let outcome = match input.uint()? {
            0 if arity == 2 => UsageOutcome::Accepted {
                accepted_through: input.uint()?,
            },
            1 if arity == 2 => {
                let watermark = if input.take_null() {
                    UsageWatermark::Absent
                } else {
                    let count = input.array_up_to(2)?;
                    match (count, input.uint()?) {
                        (1, 0) => UsageWatermark::Malformed,
                        (2, 1) => UsageWatermark::Present(input.uint()?),
                        _ => return Err(UsageError::Field),
                    }
                };
                UsageOutcome::Conflict(watermark)
            }
            2 if arity == 2 => UsageOutcome::Permanent(match input.uint()? {
                0 => UsageRejection::Forbidden,
                1 => UsageRejection::InvalidRequest,
                _ => return Err(UsageError::Field),
            }),
            3 if arity == 5 => UsageOutcome::UnknownMapping {
                scope: ParticipantRosterScope {
                    issuer: identity(&mut input)?,
                    recipient: identity(&mut input)?,
                },
                epoch: RosterVersion(input.uint()?),
                node: NodeId::from_bytes(input.fixed_bytes()?),
            },
            _ => return Err(UsageError::Field),
        };
        input.finish()?;
        let value = Self {
            reporter,
            incarnation,
            profile,
            sequence,
            part_index,
            part_digest,
            outcome,
        };
        value.validate()?;
        Ok(value)
    }

    /// Correlates an authenticated answer with the complete immutable pending part.
    /// The returned outcome is borrowed; errors never become acknowledgements.
    ///
    /// # Errors
    /// Refuses wrong identity, lifecycle, profile, sequence, part or digest, and repair
    /// metadata that does not name an endpoint in this report's original roster scope.
    pub fn validate_for<'a>(
        &'a self,
        pending: &UsageReport,
    ) -> Result<&'a UsageOutcome, UsageError> {
        self.validate()?;
        pending.canonical()?;
        if self.reporter != pending.reporter
            || self.incarnation != pending.incarnation
            || self.profile != pending.profile
            || self.sequence != pending.sequence
            || self.part_index != pending.part_index
            || self.part_digest != pending.part_digest
        {
            return Err(UsageError::Scope);
        }
        if let UsageOutcome::UnknownMapping { scope, epoch, node } = &self.outcome {
            let UsageRows::Relay(rows) = &pending.rows else {
                return Err(UsageError::Scope);
            };
            if !rows.iter().any(|row| {
                row.scope == *scope
                    && row.epoch == *epoch
                    && (row.source == *node || row.destination == *node)
            }) {
                return Err(UsageError::Scope);
            }
        }
        Ok(&self.outcome)
    }
}
