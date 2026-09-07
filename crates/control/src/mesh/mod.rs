//! Shared Mesh control framing and credential validation.

mod codec;
mod framing;
mod handshake;
mod mailbox;
mod recovery;
mod validity;

pub use framing::*;
pub use handshake::*;
pub use mailbox::*;
pub use recovery::*;
pub use validity::*;

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
