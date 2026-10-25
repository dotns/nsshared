//! Relay packets v2: header, bodies, REGISTER, session key, MACs and admission checks
//! (quick-v2 §8, quick-protocol §5.2.1 and §12.5), and relay identifiers (quick-v2 §8.6).
//! Relay budget defaults are in [`budget`]. Defined in `nsshared-relay` and
//! `nsshared-identity`.

pub use nsshared_identity::relay_id::{MAX_RELAY_ID_BYTES, RelayId, RelayIdError};
pub use nsshared_relay::{
    BadRegisterSignature, DataRejection, MAX_RELAY_NAME_BYTES, ObservedAddr, Presence, RELAY_SLOT,
    Reflect, Reflected, Register, RegisterCandidate, RegisterRejection, Registered, RelayBody,
    RelayDirection, RelayHeader, RelayMacError, RelayPacket, RelayPacketError, RelayType, Revoke,
    RevokeReason, SessionKey, SignerMismatch, Status, StatusCode, VerifiedRegister,
    WIREGUARD_HANDSHAKE_INITIATION, ZeroSharedSecret, accept_relayed_data, budget, check_register,
    derive_session_key, ephemeral_public, is_handshake_initiation,
};
