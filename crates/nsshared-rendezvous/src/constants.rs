//! Registry shard constants (quick-v2 §12.3).

/// Registry shard replica count (quick-v2 §12.3).
pub const REGISTRY_SHARD_REPLICAS: usize = 2;
/// Maximum registry nodes asked per lookup (quick-v2 §12.3).
pub const REGISTRY_LOOKUP_MAX: usize = 4;
