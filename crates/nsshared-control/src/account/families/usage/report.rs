use crate::{
    account::AccountError, account::MAX_BYTES, account::MAX_IDENTITIES, account::SCHEMA,
    account::codec::bounded, account::codec::identity, account::codec::reader,
    account::domains::USAGE_PART_DOMAIN, account::grants::GrantError,
    account::grants::ServiceGrant, account::grants::grant as grants,
    account::node::ReporterIncarnation, account::usage::RelayUsage,
    account::usage::ServiceBoundary, account::usage::ServiceDirection,
    account::usage::ServiceUsage, service::ServiceRef, service::domain_digest,
};
use thiserror::Error;

use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;

/// Typed usage refusal; no error is an acknowledgement.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UsageError {
    /// Strict canonical contract refusal.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// Invalid embedded M6 reference or grant.
    #[error(transparent)]
    Grant(#[from] GrantError),
    /// Unsupported profile, part, operation or interval.
    #[error("invalid usage field")]
    Field,
    /// Reporter or immutable pending part differs.
    #[error("usage scope mismatch")]
    Scope,
    /// Captured service ownership differs from the historical grant.
    #[error("historical service grant mismatch")]
    HistoricalGrant,
    /// Historical relay mapping is unavailable or inconsistent; repair is required.
    #[error("unknown historical relay mapping")]
    UnknownMapping,
    /// Digest does not commit the supplied immutable part.
    #[error("usage part digest mismatch")]
    Digest,
    /// Changed bytes reused an already delivered part's ownership key.
    #[error("conflicting usage delivery")]
    Conflict,
}

crate::account::contract_error!(UsageError);

pub(in crate::account) fn field(condition: bool) -> Result<(), UsageError> {
    if condition {
        Ok(())
    } else {
        Err(UsageError::Field)
    }
}

/// Independent reporter quantity profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageProfile {
    /// Completed I/O bytes, never echo message quantities.
    Service,
    /// Whole encoded accepted DATA bytes.
    Relay,
}

impl UsageProfile {
    /// Exact profile identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "l8-completed-io-v1",
            Self::Relay => "l8-relay-data-v1",
        }
    }

    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, UsageError> {
        match input.text_up_to(32)? {
            "l8-completed-io-v1" => Ok(Self::Service),
            "l8-relay-data-v1" => Ok(Self::Relay),
            _ => Err(UsageError::Field),
        }
    }
}

/// Successful operation metadata; the service quantity is always completed bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum ServiceOperation {
    /// Actual completed TCP write length, including partial progress.
    TcpWrite,
    /// Actual completed UDP datagram send length.
    UdpSend,
    /// Completed echo probe send, excluding IP headers.
    EchoProbeSend,
    /// Completed synthetic client reply send, excluding IP headers.
    EchoReplySend,
    /// Existing public-ingress quantity, without changing its boundary.
    PublicIngress,
}

/// Captured resource/client/provider context for one service quantity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceUsageRow {
    /// Existing M6 reference, without an alternate service identifier.
    pub resource: ServiceRef,
    /// Original authorized client.
    pub client: IdentityKey,
    /// Original service provider.
    pub provider: IdentityKey,
    /// Operation whose byte completion was observed.
    pub operation: ServiceOperation,
    /// Captured payer, direction, incarnations, bytes and loss window.
    pub unit: ServiceUsage,
}

impl ServiceUsageRow {
    fn validate(&self) -> Result<(), UsageError> {
        match self.operation {
            ServiceOperation::PublicIngress => {
                field(self.unit.boundary == ServiceBoundary::PublicIngress)
            }
            ServiceOperation::EchoProbeSend => field(
                self.unit.boundary == ServiceBoundary::CompletedHostWritesAndSends
                    && self.unit.direction == ServiceDirection::ClientToProvider,
            ),
            ServiceOperation::EchoReplySend => field(
                self.unit.boundary == ServiceBoundary::CompletedHostWritesAndSends
                    && self.unit.direction == ServiceDirection::ProviderToClient,
            ),
            _ => field(self.unit.boundary == ServiceBoundary::CompletedHostWritesAndSends),
        }
    }

    fn write(&self, out: &mut CborWriter) -> Result<(), UsageError> {
        self.validate()?;
        out.array(5);
        grants::write_reference(&self.resource, out)?;
        out.bytes(self.client.as_bytes())
            .bytes(self.provider.as_bytes())
            .uint(self.operation as u64)
            .bytes(&self.unit.canonical());
        Ok(())
    }

    fn read(input: &mut CborReader<'_>) -> Result<Self, UsageError> {
        input.array(5)?;
        let resource = grants::read_reference(input)?;
        let client = identity(input)?;
        let provider = identity(input)?;
        let operation = match input.uint()? {
            0 => ServiceOperation::TcpWrite,
            1 => ServiceOperation::UdpSend,
            2 => ServiceOperation::EchoProbeSend,
            3 => ServiceOperation::EchoReplySend,
            4 => ServiceOperation::PublicIngress,
            _ => return Err(UsageError::Field),
        };
        Ok(Self {
            resource,
            client,
            provider,
            operation,
            unit: ServiceUsage::decode(input.bytes_up_to(MAX_BYTES)?)?,
        })
    }

    /// Compares captured ownership with a retained historical grant.
    /// Current expiry and user/Node identity are not substituted for that history.
    ///
    /// # Errors
    /// Refuses invalid payer cardinality or any resource/client/provider/payer/incarnation mismatch.
    pub fn validate_grant(&self, historical: &ServiceGrant) -> Result<(), UsageError> {
        let payer = historical.payer()?;
        if self.resource != historical.resource
            || self.client != historical.client
            || self.provider != historical.provider
            || self.unit.grant != historical.incarnation
            || self.unit.payer_realm != payer.realm
            || self.unit.payer_subject != payer.subject
        {
            return Err(UsageError::HistoricalGrant);
        }
        Ok(())
    }
}

/// Exactly one quantity family per independent report part.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsageRows {
    /// Completed service I/O with captured grants.
    Service(Vec<ServiceUsageRow>),
    /// Accepted relay ingress DATA with captured roster attribution.
    Relay(Vec<RelayUsage>),
}

/// A complete immutable part. Authentication and durable custody remain caller-owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageReport {
    /// Full reporter identity from its independent credential domain.
    pub reporter: IdentityKey,
    /// Reporter lifecycle, independent of grant and roster generations.
    pub incarnation: ReporterIncarnation,
    /// Explicit quantity profile.
    pub profile: UsageProfile,
    /// Positive sequence within this reporter/incarnation/profile domain.
    pub sequence: u64,
    /// Inclusive start of the report window, in Unix seconds.
    pub start_unix: u64,
    /// Exclusive end of the report window, in Unix seconds.
    pub end_unix: u64,
    /// Zero-based index in the sealed partition.
    pub part_index: u64,
    /// Positive sealed partition size.
    pub part_count: u64,
    /// SHA-256 commitment of the domain-separated eleven-field preimage.
    pub part_digest: [u8; 32],
    /// Frozen quantities; empty is a sequence probe.
    pub rows: UsageRows,
}

impl UsageReport {
    fn validate(&self) -> Result<(), UsageError> {
        field(
            self.sequence > 0
                && self.start_unix < self.end_unix
                && self.part_count > 0
                && self.part_count <= MAX_IDENTITIES as u64
                && self.part_index < self.part_count,
        )?;
        let count = match &self.rows {
            UsageRows::Service(rows) => {
                field(self.profile == UsageProfile::Service)?;
                for row in rows {
                    if row.unit.reporter != self.incarnation || row.provider != self.reporter {
                        return Err(UsageError::Scope);
                    }
                }
                rows.len()
            }
            UsageRows::Relay(rows) => {
                field(self.profile == UsageProfile::Relay)?;
                for row in rows {
                    row.canonical()?;
                    if row.reporter != self.incarnation || row.scope.recipient != self.reporter {
                        return Err(UsageError::Scope);
                    }
                }
                rows.len()
            }
        };
        if count > MAX_IDENTITIES {
            return Err(AccountError::Bounds.into());
        }
        Ok(())
    }

    fn encode(&self, include_digest: bool) -> Result<Vec<u8>, UsageError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(if include_digest { 12 } else { 11 })
            .uint(SCHEMA)
            .uint(9)
            .uint(u64::from(self.profile == UsageProfile::Relay))
            .bytes(self.reporter.as_bytes())
            .bytes(&self.incarnation.0)
            .text(self.profile.as_str())
            .uint(self.sequence)
            .array(2)
            .uint(self.start_unix)
            .uint(self.end_unix)
            .uint(self.part_index)
            .uint(self.part_count);
        if include_digest {
            out.bytes(&self.part_digest);
        }
        match &self.rows {
            UsageRows::Service(rows) => {
                out.array(rows.len());
                for row in rows {
                    row.write(&mut out)?;
                }
            }
            UsageRows::Relay(rows) => {
                out.array(rows.len());
                for row in rows {
                    out.bytes(&row.canonical()?);
                }
            }
        }
        Ok(bounded(out.into_bytes())?)
    }

    /// Computes the digest without mutating the report or persisting custody.
    ///
    /// # Errors
    /// Refuses invalid scope, profile, fields, references or bounds.
    pub fn computed_digest(&self) -> Result<[u8; 32], UsageError> {
        Ok(domain_digest(USAGE_PART_DOMAIN, &self.encode(false)?))
    }

    /// Encodes a report whose digest commits all its exact fields.
    ///
    /// # Errors
    /// Refuses invalid fields, bounds and digest mismatch.
    pub fn canonical(&self) -> Result<Vec<u8>, UsageError> {
        if self.computed_digest()? != self.part_digest {
            return Err(UsageError::Digest);
        }
        self.encode(true)
    }

    /// Decodes one exact bounded report and validates its full commitment.
    ///
    /// # Errors
    /// Refuses malformed CBOR, invalid units, scope, fields, bounds or digest.
    pub fn decode(bytes: &[u8]) -> Result<Self, UsageError> {
        let mut input = reader(bytes, 12)?;
        field(input.uint()? == 9)?;
        let kind = input.uint()?;
        let reporter = identity(&mut input)?;
        let incarnation = ReporterIncarnation(input.fixed_bytes()?);
        let profile = UsageProfile::read(&mut input)?;
        field(kind == u64::from(profile == UsageProfile::Relay))?;
        let sequence = input.uint()?;
        input.array(2)?;
        let start_unix = input.uint()?;
        let end_unix = input.uint()?;
        let part_index = input.uint()?;
        let part_count = input.uint()?;
        let part_digest = input.fixed_bytes()?;
        let count = input.array_up_to(MAX_IDENTITIES)?;
        let rows = match profile {
            UsageProfile::Service => UsageRows::Service(
                (0..count)
                    .map(|_| ServiceUsageRow::read(&mut input))
                    .collect::<Result<_, _>>()?,
            ),
            UsageProfile::Relay => UsageRows::Relay(
                (0..count)
                    .map(|_| Ok(RelayUsage::decode(input.bytes_up_to(MAX_BYTES)?)?))
                    .collect::<Result<_, UsageError>>()?,
            ),
        };
        input.finish()?;
        let value = Self {
            reporter,
            incarnation,
            profile,
            sequence,
            start_unix,
            end_unix,
            part_index,
            part_count,
            part_digest,
            rows,
        };
        value.canonical()?;
        Ok(value)
    }

    /// Checks a duplicate against the exact previously retained immutable part.
    /// This comparison stores no state and advances no watermark.
    ///
    /// # Errors
    /// Refuses a different ownership key or changed duplicate bytes.
    pub fn validate_duplicate(&self, previous: &Self) -> Result<(), UsageError> {
        self.canonical()?;
        previous.canonical()?;
        if self.reporter != previous.reporter
            || self.incarnation != previous.incarnation
            || self.profile != previous.profile
            || self.sequence != previous.sequence
            || self.part_index != previous.part_index
        {
            return Err(UsageError::Scope);
        }
        if self != previous {
            return Err(UsageError::Conflict);
        }
        Ok(())
    }
}
