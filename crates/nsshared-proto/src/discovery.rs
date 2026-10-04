//! Public DNS discovery of node records (quick-v2 §11.2).
//!
//! A registry operator's authoritative DNS publishes an opted-in record as
//! `<node id>.n.ns.io. AAAA N6(I)` plus `TXT "v=ns2 r=<record>"`, where `<record>` is the
//! unpadded base64url of the whole `NodeRecord`, split into character-strings of at most
//! 255 bytes. Neither the resolver nor the authoritative server is trusted: a client
//! accepts the answer only when the record is valid and unexpired, its node ID is the
//! queried one and the AAAA is its `N6`. DNS I/O, TTLs and the choice to publish belong
//! to the caller; the result is discovery, not authorization (feed it through
//! [`crate::record::RecordMarks`] and the caller's source policy).

use crate::{
    NodeId, NodeRecord,
    constants::MAX_NODE_RECORD_BYTES,
    encoding::{decode_base64url, encode_base64url},
    identity::AddressGroup,
    record::{NodeRecordError, RecordExpired},
};
use std::net::Ipv6Addr;
use thiserror::Error;

/// DNS zone of public node names (quick-v2 §11).
pub const NODE_DNS_ZONE: &str = "n.ns.io";
/// Prefix of the TXT record value (quick-v2 §11.2).
pub const DNS_TXT_PREFIX: &str = "v=ns2 r=";
/// Maximum length of one DNS character-string in bytes (RFC 1035 §3.3).
pub const MAX_DNS_STRING_BYTES: usize = 255;
/// Maximum concatenated TXT value: the prefix and a 600-byte record in base64url.
pub const MAX_DNS_TXT_BYTES: usize = DNS_TXT_PREFIX.len() + (MAX_NODE_RECORD_BYTES * 4).div_ceil(3);

/// Returns the public DNS name `<node id>.n.ns.io` of a node (quick-v2 §11.2).
#[must_use]
pub fn node_dns_name(node_id: &NodeId) -> String {
    format!("{node_id}.{NODE_DNS_ZONE}")
}

/// Encodes the TXT value of `record` as character-strings of at most 255 bytes, in
/// order (quick-v2 §11.2).
#[must_use]
pub fn encode_dns_txt(record: &NodeRecord) -> Vec<String> {
    let text = format!("{DNS_TXT_PREFIX}{}", encode_base64url(record.as_bytes()));
    // The value is ASCII, so byte chunks are character boundaries.
    text.as_bytes()
        .chunks(MAX_DNS_STRING_BYTES)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect()
}

/// A rejected DNS answer (quick-v2 §11.2).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum DnsAnswerError {
    /// A character-string is longer than 255 bytes.
    #[error("TXT character-string longer than 255 bytes")]
    StringLength,
    /// The concatenated TXT value is longer than any valid record allows.
    #[error("TXT value too long")]
    TooLong,
    /// The value does not start with `v=ns2 r=`.
    #[error("TXT value does not start with `v=ns2 r=`")]
    Prefix,
    /// The record field is not strict unpadded base64url.
    #[error("TXT record field is not strict base64url")]
    Encoding,
    /// The record is invalid.
    #[error(transparent)]
    Record(#[from] NodeRecordError),
    /// The record has expired.
    #[error(transparent)]
    Expired(#[from] RecordExpired),
    /// The record belongs to another node ID than the queried one.
    #[error("record node ID differs from the queried name")]
    NodeId,
    /// The companion AAAA is not the record's `N6`.
    #[error("AAAA differs from the record's N6")]
    Address,
}

/// Verifies one DNS answer for `queried`: the character-strings of ONE TXT record, in
/// order, and the companion AAAA, at `now` (quick-v2 §11.2). Any mismatch rejects the
/// whole answer.
///
/// # Errors
///
/// [`DnsAnswerError`] naming the first failed check, in this order: string length,
/// total length, prefix, encoding, record validity, expiry, node ID, address.
pub fn verify_dns_answer(
    queried: &NodeId,
    aaaa: Ipv6Addr,
    txt: &[&[u8]],
    now: u64,
) -> Result<NodeRecord, DnsAnswerError> {
    if txt.iter().any(|string| string.len() > MAX_DNS_STRING_BYTES) {
        return Err(DnsAnswerError::StringLength);
    }
    let total: usize = txt.iter().map(|string| string.len()).sum();
    if total > MAX_DNS_TXT_BYTES {
        return Err(DnsAnswerError::TooLong);
    }
    let value = txt.concat();
    let field = value
        .strip_prefix(DNS_TXT_PREFIX.as_bytes())
        .ok_or(DnsAnswerError::Prefix)?;
    let field = std::str::from_utf8(field).map_err(|_| DnsAnswerError::Encoding)?;
    let bytes =
        decode_base64url(field, MAX_NODE_RECORD_BYTES).map_err(|_| DnsAnswerError::Encoding)?;
    let record = NodeRecord::decode(&bytes)?;
    record.check_not_expired(now)?;
    if record.node_id() != *queried {
        return Err(DnsAnswerError::NodeId);
    }
    if AddressGroup::derive(record.identity()).n6() != aaaa {
        return Err(DnsAnswerError::Address);
    }
    Ok(record)
}
