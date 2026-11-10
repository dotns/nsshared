//! Family 8: admission rosters, participant rosters, participant sessions and directory bindings.

pub(in crate::account) mod directory;
pub(in crate::account) mod epoch;
pub(in crate::account) mod participant_roster;
pub(in crate::account) mod roster;
pub(in crate::account) mod session;

pub use directory::{BindingDecision, BindingError, DirectoryBinding, SignedDirectoryBinding};
pub use epoch::{EpochOutcome, EpochRequest, EpochResult, PendingEpochResponse};
pub use participant_roster::{
    ParticipantRosterError, ParticipantRosterGeneration, ParticipantRosterScope,
    ParticipantRosterStatus, participant_roster_status, verify_participant_roster,
};
pub use roster::{
    AdmissionSnapshot, AdmissionSnapshotEntry, IdentityClass, MIN_ROSTER_VALIDITY_MS, Roster,
    RosterEntry, RosterVersion, SignedRoster, validate_admission_snapshot,
};
pub use session::{
    Authorization, EnrollmentProvision, Frame, FrameKind, MAX_FRAME_BODY, PendingResponse,
    SessionError, credential_deadline, exporter_context, proof_input, retained_credential_deadline,
    validate_header,
};
