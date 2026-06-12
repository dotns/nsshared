//! Label key constants and value enums for metric and span attributes.
//!
//! Every label NSN emits is declared here so the label vocabulary is
//! finite and code-reviewable. Adding a new label requires editing this
//! file, which makes accidental high-cardinality labels (remote IP,
//! connection ID, peer key) visible in PRs.
//!
//! Cardinality contract — upper bound per instrument:
//!
//! | label       | expected domain size            |
//! |-------------|---------------------------------|
//! | transport   | 4 values (udp, wss, noise, quic)|
//! | path        | 3 values (tun, userspace, wss)  |
//! | protocol    | 2 values (tcp, udp)             |
//! | result      | 4 values (ok, denied, timeout, error) |
//! | reason      | 3 values (ttl, lru, cap_overflow)|
//! | service     | from services.toml — tens       |
//! | gateway     | from connector config — small N |
//! | event_type  | small fixed enum                |
//! | task        | from [`crate::spawn`] names — small fixed set |
//!
//! Labels **forbidden by convention** (add a lint to review time):
//! `remote_ip`, `src_ip`, `dst_ip`, `peer_key`, `connection_id`,
//! `flow_id`, `fqid`. Use span fields for per-request tracing instead.

/// Transport in use for a given tunnel or control-plane connection.
pub const LABEL_TRANSPORT: &str = "transport";

/// Data-plane code path the byte traversed.
pub const LABEL_PATH: &str = "path";

/// Service name from `services.toml` (never the FQID — the hostname is
/// already on the node identity).
pub const LABEL_SERVICE: &str = "service";

/// L4 protocol. Always `"tcp"` or `"udp"`.
pub const LABEL_PROTOCOL: &str = "protocol";

/// Gateway identifier from the connector config.
pub const LABEL_GATEWAY: &str = "gateway";

/// Classified outcome of an instrumented operation.
pub const LABEL_RESULT: &str = "result";

/// Reason an entry was removed from a bounded table (conntrack eviction).
/// Domain: `ttl`, `lru`, `cap_overflow` (small fixed enum).
pub const LABEL_REASON: &str = "reason";

/// Event type for SSE delivery / control plane events.
pub const LABEL_EVENT_TYPE: &str = "event_type";

/// Supervised task name used by [`crate::spawn::spawn_supervised`].
pub const LABEL_TASK: &str = "task";

/// Logical control-plane API identifier (the `ControlEnvelope::api` field).
/// Bounded enum: `info.get`, `machine.register`, `machine.heartbeat`,
/// `services.report`, `config.stream`, `gateway.report`. Never carries a
/// nonce / token / thumbprint.
pub const LABEL_API: &str = "api";

/// Binary outcome of a control-plane call: `ok` or `error`. Distinct from
/// [`LABEL_RESULT`] which carries the 4-value [`Outcome`] enum.
pub const LABEL_STATUS: &str = "status";

// ── Value enums ───────────────────────────────────────────────────────────────
// `as_str` returns a `&'static str` so call sites can feed it to
// `KeyValue::new(...)` without allocation.

/// Data-plane path a byte flows through inside NSN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// Kernel TUN device (requires `CAP_NET_ADMIN`).
    Tun,
    /// User-space smoltcp + ServiceRouter + proxy.
    Userspace,
    /// WSS fallback relay.
    Wss,
}

impl Path {
    pub fn as_str(self) -> &'static str {
        match self {
            Path::Tun => "tun",
            Path::Userspace => "userspace",
            Path::Wss => "wss",
        }
    }
}

/// Transport used for a control plane or data plane tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Wss,
    Noise,
    Quic,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Wss => "wss",
            Transport::Noise => "noise",
            Transport::Quic => "quic",
        }
    }
}

/// L4 protocol label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// Normalised outcome for every instrumented operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Denied,
    Timeout,
    Error,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Denied => "denied",
            Outcome::Timeout => "timeout",
            Outcome::Error => "error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_key_constants_are_lowercase_snake_case() {
        for k in [
            LABEL_TRANSPORT,
            LABEL_PATH,
            LABEL_SERVICE,
            LABEL_PROTOCOL,
            LABEL_GATEWAY,
            LABEL_RESULT,
            LABEL_EVENT_TYPE,
            LABEL_TASK,
            LABEL_API,
            LABEL_STATUS,
        ] {
            assert!(k.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    #[test]
    fn enums_round_trip_through_as_str() {
        assert_eq!(Path::Tun.as_str(), "tun");
        assert_eq!(Path::Userspace.as_str(), "userspace");
        assert_eq!(Path::Wss.as_str(), "wss");

        assert_eq!(Transport::Udp.as_str(), "udp");
        assert_eq!(Transport::Wss.as_str(), "wss");
        assert_eq!(Transport::Noise.as_str(), "noise");
        assert_eq!(Transport::Quic.as_str(), "quic");

        assert_eq!(Protocol::Tcp.as_str(), "tcp");
        assert_eq!(Protocol::Udp.as_str(), "udp");

        assert_eq!(Outcome::Ok.as_str(), "ok");
        assert_eq!(Outcome::Denied.as_str(), "denied");
        assert_eq!(Outcome::Timeout.as_str(), "timeout");
        assert_eq!(Outcome::Error.as_str(), "error");
    }
}
