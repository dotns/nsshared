//! Signed publication events and snapshots, the family registry, source bindings and source publications, subscriptions and snapshot requests.

pub(in crate::account) mod envelope;
pub(in crate::account) mod registry;
pub(in crate::account) mod snapshot_request;
pub(in crate::account) mod source_binding;
pub(in crate::account) mod source_publication;
pub(in crate::account) mod subscription;

pub use envelope::{
    AcceptedPublication, PUBLICATION_SIGNATURE_DOMAIN, PublicationChannel, PublicationContent,
    PublicationDecision, PublicationError, PublicationEvent, PublicationExpectation,
    PublicationKey, PublicationOutcome, PublicationScope, PublicationSnapshot, decide_publication,
    decide_publication_snapshot, encode_publication, publication_channel,
};
pub use registry::{
    FAMILIES, FamilyId, FamilyRegistration, FamilyRegistry, M6Reuse, ReplacementRule,
};
pub use snapshot_request::{
    MAX_SNAPSHOT_REQUEST_BYTES, MAX_SNAPSHOT_SCOPES, PublicationSnapshotRequest,
    SnapshotRequestError,
};
pub use source_binding::{
    DeliveryContext, MAX_SOURCE_BYTES, SOURCE_BINDING_DOMAIN, SignedSourceBinding, SourceBinding,
    SourceEnrollmentExpectation, SourceError, SourceProfile,
};
pub use source_publication::{
    SOURCE_PUBLICATION_DOMAIN, SourcePublication, decide_source_publication,
    decide_source_snapshot, decide_source_snapshot_scopes, encode_source_publication,
    source_publication_signing_input,
};
pub use subscription::{
    MAX_SUBSCRIPTION_BYTES, MAX_SUBSCRIPTION_SCOPES, PublicationSubscriptionRequest,
    SubscriptionScope,
};
