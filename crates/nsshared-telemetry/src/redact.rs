//! Sensitive field names and the [`Redacted`] wrapper.
//!
//! Policy: the fields in [`SENSITIVE_FIELDS`] identify a user, a peer, an
//! address or a single flow. They are never metric labels (they are
//! unbounded and identifying). When one is recorded as
//! a log or span field, the value goes through [`redacted`]
//! (`remote_ip = %redacted(&addr)`) so the field stays visible while the
//! value does not. The list follows the forbidden labels of NS
//! `telemetry/src/labels.rs`.

use std::fmt;

/// The text printed in place of a redacted value.
pub const REDACTED: &str = "[redacted]";

/// Field names whose values must not reach logs, spans or metric labels in
/// clear.
pub const SENSITIVE_FIELDS: &[&str] = &[
    "remote_ip",
    "src_ip",
    "dst_ip",
    "peer_key",
    "connection_id",
    "flow_id",
    "fqid",
];

/// A value whose `Debug` and `Display` print [`REDACTED`].
#[derive(Clone, Copy)]
pub struct Redacted<T>(T);

/// Wraps `value` so that formatting it prints [`REDACTED`].
pub const fn redacted<T>(value: T) -> Redacted<T> {
    Redacted(value)
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}
