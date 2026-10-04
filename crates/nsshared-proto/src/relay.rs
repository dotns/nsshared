//! Relay packets v2: header, bodies, REGISTER, session key, MACs and admission checks
//! (quick-v2 §8, quick-protocol §5.2.1 and §12.5), and relay identifiers (quick-v2 §8.6).
//! Relay budget defaults are in [`budget`].

pub mod budget;
mod crypto;
mod data;
mod packet;
mod register;

pub use crate::identifier::{MAX_RELAY_ID_BYTES, RelayId, RelayIdError};
pub use crypto::{
    RelayMacError, SessionKey, ZeroSharedSecret, derive_session_key, ephemeral_public,
};
pub use data::{
    DataRejection, WIREGUARD_HANDSHAKE_INITIATION, accept_relayed_data, is_handshake_initiation,
};
pub use packet::{
    BadRegisterSignature, MAX_RELAY_NAME_BYTES, ObservedAddr, Presence, RELAY_SLOT, Reflect,
    Reflected, Register, Registered, RelayBody, RelayDirection, RelayHeader, RelayPacket,
    RelayPacketError, RelayType, Revoke, RevokeReason, SignerMismatch, Status, StatusCode,
};
pub use register::{RegisterCandidate, RegisterRejection, VerifiedRegister, check_register};
