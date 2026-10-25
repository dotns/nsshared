#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! NS shared relay packets v2: header, bodies, REGISTER, session key, MACs and admission
//! checks (quick-v2 §8, quick-protocol §5.2.1 and §12.5). Relay identifiers are
//! `nsshared_identity::relay_id`.
//!
//! The packet, crypto, DATA and REGISTER items are at the crate root; budget defaults are
//! in [`budget`] and relay constants in [`constants`]. Every public item has one path.
//! Pure: no I/O; callers pass time, randomness and keys.

pub mod budget;
pub mod constants;
mod crypto;
mod data;
mod packet;
mod register;

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
