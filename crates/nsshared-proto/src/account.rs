//! Pure L8 account payload candidate; see `docs/l8-account-payload-profile.md`.
//!
//! M6 objects and their bytes remain in `nsshared-service-control`. This module
//! adds no runtime or transport and reads no clock or filesystem.

pub use crate::{RealmId, RealmIdError};

mod bootstrap;
mod bootstrap_envelope;
pub mod confidential_auth;
pub mod confidential_material;
pub mod control_exchange;
pub mod control_reports;
pub mod directory_binding;
mod edge_declaration;
mod edge_material;
mod enrollment;
mod grants;
mod l3;
mod l3_authority;
mod lifecycle;
pub mod machine_token;
pub mod node_l3_status;
mod participant_roster;
pub mod participant_session;
mod policy_auth;
mod policy_subject;
mod profile_publications;
mod provider_mapping;
pub mod provider_subnet_report;
mod public_edge;
mod publication;
pub mod publication_snapshot_request;
pub mod publication_subscription;
mod realm_peers;
mod registry;
mod roster;
pub mod route_command;
pub mod service_control;
mod signed_request;
pub mod source_binding;
pub mod source_publication;
mod subject_policy;
mod subnet;
mod usage;
mod usage_answer;
mod usage_relay;
mod usage_report;

pub use bootstrap::{
    BootstrapDiscovery, BootstrapEndpoint, BootstrapError, ConfidentialCarrier, ControlBoundary,
    EnvelopePins, MAX_BOOTSTRAP_BYTES, MAX_CONTROL_BODY, MAX_CONTROL_HEADERS,
    MAX_CONTROL_NOISE_FRAME, MAX_CONTROL_NOISE_PAYLOAD, MAX_ENCODED_SUBSCRIPTION,
    validate_control_input,
};
pub use bootstrap_envelope::{
    ACCOUNT_REQUEST_DOMAIN, ACCOUNT_RESPONSE_DOMAIN, BootstrapEnvelope, CONTROL_CLOCK_SKEW_SECONDS,
    CONTROL_REPLAY_WINDOW_SECONDS, EnvelopeDirection, EnvelopeExpectation,
};
pub use edge_declaration::{
    EdgeExitProfile, EdgeFloorOutcomes, EdgeFloorRejection, EdgeServiceAckError, EdgeServiceBody,
    EdgeServiceMetadata, EdgeServiceRequest, EdgeServiceResponse,
};
pub use edge_material::{
    EdgeAuth, EdgeJwtAuthority, EdgeMaterialAck, EdgeMaterialKind, EdgeMaterialRef, MAX_EDGE_ITEMS,
};
pub use enrollment::{
    Enrollment, EnrollmentDecision, EnrollmentError, MAX_CAPABILITIES, MAX_CAPABILITY_BYTES,
    NODE_LOCAL_NAMES_V1, RebindAuthorization, decide_enrollment,
};
pub use grants::{
    GrantClaim, GrantDetails, GrantDiscriminator, GrantError, GrantPublication, Payer,
    PayerBinding, PayerBindings, ResourceAuthority, RetiredGrant, ServiceGrant,
};
pub use l3::{L3Rule, L3Scope, NodeL3, TransportProtocol};
pub use l3_authority::{L3Binding, NodeL3Authority};
pub use lifecycle::{
    GrantIncarnation, Lifecycle, MembershipIdentityVersion, NodeBinding, RecordGeneration,
    ReporterIncarnation, Transition,
};
pub use participant_roster::{
    ParticipantRosterError, ParticipantRosterGeneration, ParticipantRosterScope,
    ParticipantRosterStatus, participant_roster_status, verify_participant_roster,
};
pub use policy_auth::{AdminScope, AdminTokenClaims, JwtSubjectBinding, SignedSubjectHeaderPolicy};
pub use policy_subject::{PolicySubject, SubjectAnchor, SubjectBinding};
pub use profile_publications::{
    NodeControlProfilePublication, ProfilePublicationPayload, UsageProfilePublication,
};
pub use provider_mapping::{MAX_PROVIDER_MAPPINGS, ProviderMapping, ProviderMappings};
pub use public_edge::{
    EdgeProtocol, EdgeRealm, EdgeRoute, EdgeRouteOptions, EdgeSourceIp, EdgeTransport,
    EdgeUpstreamTls, PublicEdge,
};
pub use publication::{
    AcceptedPublication, MAX_PUBLICATION_BYTES, PUBLICATION_SIGNATURE_DOMAIN, PublicationChannel,
    PublicationContent, PublicationDecision, PublicationError, PublicationEvent,
    PublicationExpectation, PublicationKey, PublicationOutcome, PublicationScope,
    PublicationSnapshot, decide_publication, decide_publication_snapshot, encode_publication,
    publication_channel,
};
pub use realm_peers::{
    MAX_PEER_REALMS, MAX_POLICY_VERSION_BYTES, PolicyVersion, RealmContribution, RealmMember,
    RealmPeers,
};
pub use registry::{
    FAMILIES, FamilyId, FamilyRegistration, FamilyRegistry, M6Reuse, ReplacementRule,
};
pub use roster::{
    AdmissionSnapshot, IdentityClass, MIN_ROSTER_VALIDITY_MS, ROSTER_SIGNATURE_DOMAIN, Roster,
    RosterEntry, RosterVersion, SignedRoster, validate_snapshot,
};
pub use signed_request::{SignedAccountRequest, SignedUrlScope};
pub use subject_policy::{SubjectGroup, SubjectPolicy, SubjectRule, SubjectSelector};
pub use subnet::{
    MAX_SELECTED_PREFIXES, MAX_SUBNET_PREFIXES, MAX_SUBNET_ROUTES, SelectedSubnetRoute,
    SubnetError, SubnetPrefix, SubnetProxyCoverage, SubnetPublication, SubnetRoute,
    SubnetSelection,
};
pub use usage::{BatchLossWindow, Direction, ServiceBoundary, ServiceUsage};
pub use usage_answer::{UsageAnswer, UsageOutcome, UsageRejection, UsageWatermark};
pub use usage_relay::{RelayBilling, RelayDirection, RelayUsage};
pub use usage_report::{
    ServiceOperation, ServiceUsageRow, USAGE_PART_DOMAIN, UsageError, UsageProfile, UsageReport,
    UsageRows,
};

use crate::{
    IdentityKey,
    encoding::{CborError, CborReader},
};
use thiserror::Error;

/// Candidate CBOR schema version. Local admission JSON has its own schema 2.
pub const SCHEMA: u64 = 1;
/// Maximum encoded candidate or local snapshot size, in bytes.
pub const MAX_BYTES: usize = 1_048_576;
/// Maximum identities in a complete admission roster.
pub const MAX_IDENTITIES: usize = 8_192;

/// A rejected candidate contract. Invalid content never represents withdrawal.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AccountError {
    /// Noncanonical membership realm text.
    #[error(transparent)]
    Realm(#[from] RealmIdError),
    /// Malformed or noncanonical CBOR.
    #[error(transparent)]
    Cbor(#[from] CborError),
    /// JSON shape, required field or field type is invalid.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Unsupported schema or invalid contract fields.
    #[error("invalid account contract field")]
    InvalidField,
    /// Input or a collection exceeds its contract bound.
    #[error("account contract bound exceeded")]
    Bounds,
    /// The signature is invalid.
    #[error("invalid participant roster signature")]
    Signature,
    /// Issuer, recipient, version or time does not match the caller's authority.
    #[error("participant roster authority or freshness mismatch")]
    Authority,
}

fn require(condition: bool) -> Result<(), AccountError> {
    if condition {
        Ok(())
    } else {
        Err(AccountError::InvalidField)
    }
}

fn identity(reader: &mut CborReader<'_>) -> Result<IdentityKey, AccountError> {
    IdentityKey::from_bytes(&reader.fixed_bytes()?).map_err(|_| AccountError::InvalidField)
}

fn reader(input: &[u8], arity: u64) -> Result<CborReader<'_>, AccountError> {
    let mut reader = CborReader::new(input, MAX_BYTES)?;
    reader.array(arity)?;
    require(reader.uint()? == SCHEMA)?;
    Ok(reader)
}

fn bounded(bytes: Vec<u8>) -> Result<Vec<u8>, AccountError> {
    if bytes.len() > MAX_BYTES {
        Err(AccountError::Bounds)
    } else {
        Ok(bytes)
    }
}
