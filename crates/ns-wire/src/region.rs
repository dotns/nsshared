//! Relay region member protocol v2: frame codec, channel rules, snapshot chunking and the
//! monotone mark merge (quick-v2 §8.5, quick-protocol §12.8).
//!
//! # Extension point for types 10-12
//!
//! Types 10 RENDEZVOUS_REQUEST, 11 RENDEZVOUS_RESPONSE and 12 REGISTRY_RECORD are reserved
//! by quick-v2 §8.5. Their bodies, any body size limit beyond the 4096-byte frame limit and
//! the channel of type 12 are owned by the rendezvous v2 messages; until those exist,
//! [`RegionFrame::decode`] rejects these types with [`RegionFrameError::UnknownType`],
//! exactly like any other unknown type. The rendezvous workstream builds on
//! [`decode_region_envelope`], which checks the framing, the canonical envelope, the version
//! and the type byte and yields the raw body bytes, and on [`encode_region_envelope`]; the
//! envelope and the typed bodies of types 1-9 do not change when those bodies are added.

mod frame;
mod marks;
mod snapshot;

pub use frame::*;
pub use marks::*;
pub use snapshot::*;
