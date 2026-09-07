//! Shared Mesh control framing and credential validation.

mod codec;
mod compact;
mod framing;
mod handshake;
mod history;
mod identity;
mod mailbox;
mod owner;
mod recovery;
mod validity;

pub use compact::*;
pub use framing::*;
pub use handshake::*;
pub use history::*;
pub use identity::*;
pub use mailbox::*;
pub use owner::*;
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
