//! Bounds shared by several account contracts.

/// Maximum bytes of a bounded text field.
pub(in crate::account) const MAX_TEXT_BYTES: usize = 256;
/// Maximum entries of a bounded text or value list.
pub(in crate::account) const MAX_ITEMS: usize = 256;
/// Canonical RealmId text length.
pub(in crate::account) const REALM_TEXT_BYTES: usize = 26;
/// Maximum bytes of a DNS hostname.
pub(in crate::account) const MAX_HOSTNAME_BYTES: usize = 253;
/// Maximum bytes of a credential, token or signed request component.
pub(in crate::account) const MAX_CREDENTIAL_BYTES: usize = 16_384;
