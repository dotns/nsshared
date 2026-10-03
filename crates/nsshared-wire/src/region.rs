//! Relay region member protocol v2: frame codec, channel rules, snapshot chunking and the
//! monotone mark merge (quick-v2 §8.5, quick-protocol §12.8).
//!
//! # Extension point for types 10-12
//!
//! Types 10 RENDEZVOUS_REQUEST, 11 RENDEZVOUS_RESPONSE and 12 REGISTRY_RECORD (quick-v2
//! §7.1, §8.5) are carried only on the control connection. Their bodies are defined by the
//! rendezvous v2 messages in `nsshared_rendezvous::region`; [`RegionFrame`] does not model them,
//! so [`RegionFrame::decode`] rejects them with [`RegionFrameError::UnknownType`].
//! `nsshared_rendezvous::region` builds on [`decode_region_envelope`], which checks the framing,
//! the canonical envelope, the version and the type byte and yields the raw body bytes, and
//! on [`encode_region_envelope`].
//!
//! Frame size limits depend on the channel and the type: on the control connection the
//! length prefix may be up to 20480 ([`crate::MAX_REGION_RENDEZVOUS_FRAME_BYTES`]) and a
//! decoded frame above 4096 bytes is accepted only for types 10 and 11; every other frame,
//! and every frame on the data connection, keeps the 4096-byte limit
//! ([`MAX_REGION_FRAME_BYTES`]). See [`max_region_frame_bytes`] and
//! [`max_region_frame_bytes_for`].

mod frame;
mod marks;
mod snapshot;

pub use frame::*;
pub use marks::*;
pub use snapshot::*;
