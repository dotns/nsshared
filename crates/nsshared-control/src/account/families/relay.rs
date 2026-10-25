//! Family 8: admission rosters, participant rosters, participant sessions and directory bindings.

pub(in crate::account) mod directory;
pub(in crate::account) mod participant_roster;
pub(in crate::account) mod roster;
pub(in crate::account) mod session;

pub use directory::{
    BindingDecision, BindingError, DIRECTORY_BINDING_DOMAIN, DirectoryBinding,
    SignedDirectoryBinding,
};
pub use participant_roster::{
    ParticipantRosterError, ParticipantRosterGeneration, ParticipantRosterScope,
    ParticipantRosterStatus, participant_roster_status, verify_participant_roster,
};
pub use roster::{
    AdmissionSnapshot, IdentityClass, MIN_ROSTER_VALIDITY_MS, ROSTER_SIGNATURE_DOMAIN, Roster,
    RosterEntry, RosterVersion, SignedRoster, validate_snapshot,
};
pub use session::{
    ANSWER, AUTHENTICATE, AUTHENTICATED, Authorization, ENROLL, ENROLLED, EXPORTER_LABEL,
    EnrollmentProvision, Frame, MAX_FRAME_BODY, PROOF_DOMAIN, PendingResponse, REFUSED, RENEW,
    RENEWED, REPORT, ROSTER, SessionError, credential_deadline, exporter_context, proof_input,
    retained_credential_deadline, validate_header,
};
