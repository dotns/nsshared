//! Global OTel facade for tunnel (WireGuard + WSS) metrics.
//!
//! These instruments are labeled by `{gateway, transport}` and aggregate
//! byte counts, handshake counts, and the last-handshake timestamp across
//! all sessions.
//!
//! - `nsn_tunnel_handshakes_total{gateway, transport}` — successful
//!   handshake completions.
//! - `nsn_tunnel_rx_bytes_total{gateway, transport}` — bytes decrypted from
//!   the tunnel.
//! - `nsn_tunnel_tx_bytes_total{gateway, transport}` — bytes encrypted to
//!   the tunnel.
//! - `nsn_tunnel_last_handshake_timestamp_seconds{gateway, transport}` —
//!   unix timestamp (seconds) of the last successful handshake.
//!
//! Cardinality: `gateway` from connector config (small N, tens at most),
//! `transport` from [`crate::labels::Transport`] (4 values).

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Gauge, Histogram};

use crate::labels::{LABEL_GATEWAY, LABEL_RESULT, LABEL_TRANSPORT, Outcome, Transport};
use crate::meter::{counter_u64, histogram_seconds, meter};

struct Instruments {
    handshakes: Counter<u64>,
    rx_bytes: Counter<u64>,
    tx_bytes: Counter<u64>,
    last_handshake: Gauge<u64>,
    unknown_peer: Counter<u64>,
    handshake_duration: Histogram<f64>,
}

fn instruments() -> &'static Instruments {
    static INST: OnceLock<Instruments> = OnceLock::new();
    INST.get_or_init(|| {
        let m = meter("nsn.tunnel");
        Instruments {
            handshakes: counter_u64(
                &m,
                "nsn_tunnel_handshakes_total",
                "Successful tunnel handshake completions",
            ),
            rx_bytes: counter_u64(
                &m,
                "nsn_tunnel_rx_bytes_total",
                "Bytes decrypted from the tunnel",
            ),
            tx_bytes: counter_u64(
                &m,
                "nsn_tunnel_tx_bytes_total",
                "Bytes encrypted to the tunnel",
            ),
            last_handshake: m
                .u64_gauge("nsn_tunnel_last_handshake_timestamp_seconds")
                .with_description("Unix timestamp of the last successful handshake")
                .with_unit("s")
                .build(),
            unknown_peer: counter_u64(
                &m,
                "nsn_tunnel_unknown_peer_total",
                "UAPI Get returned a peer whose pubkey matched no configured peer",
            ),
            handshake_duration: histogram_seconds(
                &m,
                "nsn_wg_handshake_duration_seconds",
                "Latency from handshake initiation to first completed handshake",
            ),
        }
    })
}

fn gw_tp_labels(gateway: &str, transport: Transport) -> [KeyValue; 2] {
    [
        KeyValue::new(LABEL_GATEWAY, gateway.to_owned()),
        KeyValue::new(LABEL_TRANSPORT, transport.as_str()),
    ]
}

/// Record a successful handshake on `{gateway, transport}`.  Also updates
/// the last-handshake timestamp gauge.
pub fn record_handshake(gateway: &str, transport: Transport) {
    let labels = gw_tp_labels(gateway, transport);
    instruments().handshakes.add(1, &labels);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    instruments().last_handshake.record(now, &labels);
}

/// Record `n` bytes decrypted from the tunnel.
pub fn record_rx_bytes(gateway: &str, transport: Transport, n: u64) {
    instruments()
        .rx_bytes
        .add(n, &gw_tp_labels(gateway, transport));
}

/// Record `n` bytes encrypted to the tunnel.
pub fn record_tx_bytes(gateway: &str, transport: Transport, n: u64) {
    instruments()
        .tx_bytes
        .add(n, &gw_tp_labels(gateway, transport));
}

/// Record the latency (seconds) of a WireGuard handshake, from initiation to
/// the first observed completion, labeled by `{gateway, result}`.
///
/// Taken once per probe / handshake attempt (not per packet). `result` is
/// `ok` on success or `timeout` when the handshake did not complete in budget.
pub fn record_handshake_duration(gateway: &str, outcome: Outcome, secs: f64) {
    instruments().handshake_duration.record(
        secs,
        &[
            KeyValue::new(LABEL_GATEWAY, gateway.to_owned()),
            KeyValue::new(LABEL_RESULT, outcome.as_str()),
        ],
    );
}

/// Record a status-poll observation of a UAPI peer whose public key matched
/// no configured peer.  Unlabeled: the peer is unknown, so neither gateway
/// nor transport can be attributed, and the pubkey itself is unbounded
/// cardinality.  See LIVE-003: distinguishes a genuine pubkey-representation
/// mismatch from the gotatun `last_handshake_time_sec` surface gap.
pub fn record_unknown_peer() {
    instruments().unknown_peer.add(1, &[]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_handshake_does_not_panic() {
        record_handshake("gw-1", Transport::Udp);
        record_handshake("gw-2", Transport::Wss);
        record_handshake("gw-3", Transport::Noise);
        record_handshake("gw-4", Transport::Quic);
    }

    #[test]
    fn record_bytes_accepts_zero_and_large_values() {
        record_rx_bytes("gw-1", Transport::Udp, 0);
        record_rx_bytes("gw-1", Transport::Udp, u64::MAX);
        record_tx_bytes("gw-1", Transport::Wss, 0);
        record_tx_bytes("gw-1", Transport::Wss, 1_000_000);
    }

    #[test]
    fn record_unknown_peer_does_not_panic() {
        record_unknown_peer();
        record_unknown_peer();
    }

    #[test]
    fn record_handshake_duration_accepts_outcomes() {
        record_handshake_duration("gw-1", Outcome::Ok, 0.05);
        record_handshake_duration("gw-2", Outcome::Timeout, 5.0);
    }

    #[test]
    fn label_helper_builds_two_labels() {
        let labels = gw_tp_labels("gw-test", Transport::Udp);
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].key.as_str(), LABEL_GATEWAY);
        assert_eq!(labels[1].key.as_str(), LABEL_TRANSPORT);
        assert_eq!(labels[1].value.as_str(), "udp");
    }
}
