//! Shared Mesh control framing and credential validation.

mod codec;
mod compact;
mod discovery;
mod framing;
mod genesis;
mod handshake;
mod history;
mod identity;
mod key_exchange;
mod mailbox;
mod membership;
mod owner;
mod recovery;
mod restore_result;
mod sync;
mod validity;
mod winner;

pub use compact::*;
pub use discovery::*;
pub use framing::*;
pub use genesis::*;
pub use handshake::*;
pub use history::*;
pub use identity::*;
pub use key_exchange::*;
pub use mailbox::*;
pub use membership::*;
pub use owner::*;
pub use recovery::*;
pub use restore_result::*;
pub use sync::*;
pub use validity::*;
pub use winner::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid Mesh payload: {0}")]
    Payload(&'static str),
    #[error("invalid Mesh framing")]
    Framing,
    #[error("Mesh message exceeds its transport limit")]
    TooLarge,
    #[error("Mesh envelope carries a managed identity or an invalid API")]
    Identity,
    #[error("invalid Mesh credential lifetime")]
    Lifetime,
    #[error("Mesh credential is not live")]
    Expired,
    #[error("invalid Mesh envelope: {0}")]
    Envelope(#[from] crate::envelope::Error),
}
