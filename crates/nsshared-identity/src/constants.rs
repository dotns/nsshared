//! Identity and node record constants, derivation labels and the record signature
//! context (quick-v2 §2.2, §12.2-§12.3).

/// NodeRecord format version (quick-v2 §12.3).
pub const NODE_RECORD_VERSION: u8 = 2;
/// Maximum encoded NodeRecord length in bytes (quick-v2 §12.3).
pub const MAX_NODE_RECORD_BYTES: usize = 600;
/// Maximum record service period `expires - issued_at` in seconds (quick-v2 §12.3).
pub const MAX_RECORD_SERVICE_SECONDS: u64 = 604_800;

/// Raw node ID length in bytes (quick-v2 §2.2, §12.3).
pub const NODE_ID_BYTES: usize = 12;
/// Node ID text length in lowercase unpadded base32 characters (quick-v2 §2.2, §12.3).
pub const NODE_ID_TEXT_LEN: usize = 20;

/// First byte of every node address, `fd` in `fd ‖ g ‖ m` (quick-v2 §2.2, §12.3).
pub const ADDRESS_PREFIX: u8 = 0xfd;
/// Prefix length of a node address group (quick-v2 §2.2, §12.3).
pub const ADDRESS_GROUP_PREFIX_LEN: u8 = 127;

/// Keyed BLAKE2s label for the node ID (quick-v2 §2.2).
pub const NODE_ID_LABEL: &[u8] = b"ns-node-id-v2";
/// Keyed BLAKE2s label for the address group (quick-v2 §2.2).
pub const NODE_ADDR_LABEL: &[u8] = b"ns-node-addr-v2";

/// Signature context for NodeRecord, signed by `I` (quick-v2 §12.2).
pub const NODE_RECORD_CONTEXT: &[u8] = b"ns/node-record/v2";
