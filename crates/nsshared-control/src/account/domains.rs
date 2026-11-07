//! Domain separation strings of the account contracts. Each signature covers the domain
//! followed by the canonical signed bytes; every signature domain ends with a zero
//! separator. The digest domain is text for `service::domain_digest`, which appends the
//! separator itself. Exit observation digests use the explicit byte domains below,
//! including their zero separators, followed directly by canonical CBOR.

/// Confidential carrier request signature domain.
pub const ACCOUNT_REQUEST_DOMAIN: &[u8] = b"ns.account.call.request.v1\0";
/// Confidential carrier response signature domain.
pub const ACCOUNT_RESPONSE_DOMAIN: &[u8] = b"ns.account.call.response.v1\0";
/// Publication event signature domain.
pub const PUBLICATION_DOMAIN: &[u8] = b"ns.account.publication.v1\0";
/// Source binding signature domain.
pub const SOURCE_BINDING_DOMAIN: &[u8] = b"ns.account.source-binding.v1\0";
/// Source publication signature domain.
pub const SOURCE_PUBLICATION_DOMAIN: &[u8] = b"ns.account.source-publication.v1\0";
/// Admission roster signature domain.
pub const ROSTER_DOMAIN: &[u8] = b"ns.account.roster.v1\0";
/// Directory binding signature domain.
pub const DIRECTORY_BINDING_DOMAIN: &[u8] = b"ns.account.directory-binding.v1\0";
/// Participant connection proof signature domain.
pub const PARTICIPANT_PROOF_DOMAIN: &[u8] = b"nsgw-participant-candidate-v1\0";
/// Usage report part digest domain, for `service::domain_digest`, which appends the
/// zero separator.
pub const USAGE_PART_DIGEST_DOMAIN: &str = "ns.account.usage.part.v1";
/// Completed-handshake TLS exporter label of a participant connection, including
/// resumed handshakes.
pub const PARTICIPANT_EXPORTER_LABEL: &[u8] = b"EXPORTER-nsgw-participant-candidate-v1";

/// Retention seal content domain for `service::domain_digest`.
pub const RETENTION_SEAL_DIGEST_DOMAIN: &str = "ns.account.retention.seal.v1";

/// Canonical per-grant SHA-256 domain, including the zero separator.
pub const EXIT_GRANT_DIGEST_DOMAIN: &[u8] = b"ns-exit-grant-v1\0";
/// Exact installation challenge SHA-256 domain, including the zero separator.
pub const EXIT_CONTEXT_DIGEST_DOMAIN: &[u8] = b"ns-exit-context-v1\0";
/// Installation observation SHA-256 domain, including the zero separator.
pub const EXIT_OBSERVATION_DIGEST_DOMAIN: &[u8] = b"ns-exit-observation-v1\0";
