# CTRL-016 Add config-stream idle read deadline and control-socket TCP keepalive

- **status**: implemented
- **priority**: P1
- **owner**: control workstream (PLAN-011)
- **createdAt**: 2026-07-03 06:55

## Description

Design-review finding DR-H3 (`nsiod-docs/_design-review-2026-07-03.md`, high,
security/robustness): the config-stream client has no idle read deadline and
no TCP keepalive, so a half-open / black-holed control path (NAT idle-drop,
silent middlebox, NSD OOM-killed without RST) is never detected. The node
keeps its last-pushed `acl_config` and honors stale ALLOW rules indefinitely,
because the fail-closed `ExplicitEmpty` / `FetchFailed` signal can only arrive
on a live stream. This task adds client-side enforcement of the NSD 15s SSE
keepalive contract (a byte-level idle deadline) plus TCP keepalive on the
control socket. This file records the investigation and the proposal; the
implement phase starts only after the proposal is accepted.

## Investigation

### Read path: the established stream has no deadline

`next_message_from_stream` (`crates/control/src/sse.rs:421-455`) loops
"drain framer, then read more bytes" with an unbounded read:

```rust
// crates/control/src/sse.rs:441-450
let mut chunk = [0u8; 4096];
let n = stream
    .read(&mut chunk)
    .await
    .map_err(|e| Error::Sse(e.to_string()))?;

if n == 0 {
    *sse_stream = None;
    return Err(Error::Sse("stream ended".to_string()));
}
```

Disconnection is detected only on clean EOF (`n == 0`) or an explicit socket
error surfaced by `read`. A black-holed path produces neither, so the await
never completes.

Both `ControlStream` flavours delegate to this helper —
`SseControl::next_message` (`crates/control/src/sse.rs:307-315`) and
`NoiseControl::next_message` (`crates/control/src/sse.rs:395-403`) — and
`make_control_stream` (`crates/control/src/lib.rs:742-758`) maps transport
`"sse"` to `SseControl` and noise/quic to `NoiseControl`. One fix in the
helper therefore covers all three transports.

Connect-time is already bounded elsewhere: `connect_active_endpoint` applies
`endpoint_attempt_timeout` (`crates/control/src/lib.rs:498,770-771`, from
`nsd_endpoint_attempt_timeout_secs`, default 8s), and the test
`established_stream_outlives_endpoint_attempt_timeout`
(`crates/control/src/lib.rs:2332-2356`) pins that this timeout must not apply
after connect. The gap is exclusively the established-stream read path.

### Server keepalives never surface as messages

`SseFramer::parse_event` skips SSE comment lines
(`crates/control/src/sse.rs:122-124`: `if line.starts_with(':') { continue; }`)
and returns `Ok(None)` for events without a `data` field
(`crates/control/src/sse.rs:143-145`). Per
`nsiod-docs/control-plane/02-transport-sse.md`, NSD emits `: keepalive\n\n` as
the first stream item and then an axum `KeepAlive` comment every 15s when idle
(`KEEPALIVE_INTERVAL` = 15s).

Consequence: a healthy-but-quiet stream delivers *bytes* at least every 15s
but may never deliver a `ControlMessage`. Any deadline at message granularity
(wrapping `next_message()` from the driver, or a `select!` idle arm keyed on
message arrival) would false-positive on healthy idle streams. The deadline
must sit at byte granularity — around the `stream.read()` call.

### Driver loop: no idle arm; heartbeat health != stream health

`drive_connected_stream` (`crates/control/src/lib.rs:615-688`) selects over
exactly two arms: the message future (`:623`) and the heartbeat tick (`:652`,
interval default 60s, `:387,445-448`). There is no idle arm.

Stream errors already funnel into the right transition:

```rust
// crates/control/src/lib.rs:646-649
Err(e) => {
    warn!(error = %e, "SSE error, reconnecting");
    return Ok(LiveStreamExit::Disconnected);
}
```

Heartbeat failures do not: the generic arm only logs
(`crates/control/src/lib.rs:681-683`, `warn!(error = %e, "heartbeat failed")`),
`Unauthorized` only logs (`:675-680`), and only `MachineUnknown` with a
successful recovery returns `Disconnected` (`:657-659`). The heartbeat is a
separate unary call, not traffic on the stream socket, so heartbeat health
says nothing about stream liveness in either direction.

### Why a black-holed stream never reaches fail-closed today

1. The path dies without FIN/RST → the `read` at
   `crates/control/src/sse.rs:442-445` never completes.
2. `next_message()` never returns; the only other `select!` arm (heartbeat)
   warns on failure and loops. `drive_connected_stream` never returns.
3. `run()` therefore never reaches the `Disconnected` branch
   (`crates/control/src/lib.rs:479-486`), never sends
   `status_tx.send(false)`, never backs off or reconnects.
4. The fail-closed machinery is keyed on exactly those signals:
   `MultiControlPlane` synthesizes `AclConfig::fetch_failed` on a
   `connected=false` status event (`crates/control/src/multi.rs:321-355`) or
   on terminal plane exit (`:522-546`). Neither fires.
5. The merger keeps that NSD's last `Loaded` ACL layer pinned;
   `last_good_max_age` (`crates/control/src/multi.rs:103-104,250-253`) only
   ages the last-good cache after a `FetchFailed` is recorded, so it never
   engages either. Stale ALLOW rules are honored indefinitely. DR-H3
   confirmed end to end.

### Exact change set (implement phase)

1. `crates/control/src/sse.rs` — add
   `const CONFIG_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(45);`
   next to `next_message_from_stream`; wrap the `stream.read()` at
   `:442-445` in `tokio::time::timeout(CONFIG_STREAM_IDLE_TIMEOUT, ..)`; on
   expiry mirror the EOF path (clear `*sse_stream`, return
   `Err(Error::Sse(..))`). No signature or type changes; reuses
   `Error::Sse(String)`.
2. `crates/control/src/transport/mod.rs` — add
   `pub(crate) fn set_control_tcp_keepalive(tcp: &tokio::net::TcpStream) -> std::io::Result<()>`
   plus the keepalive parameter constants.
3. `crates/control/src/transport/sse.rs` — call the helper right after
   `TcpStream::connect` in `SseTransport::connect` (`:80-82`). This covers
   the plaintext (`:90-93`) and TLS (`:99-104`) paths (both wrap the same
   socket), and `connect_stream` / `call` reuse `self.connect`
   (`:134`, `:116`).
4. `crates/control/src/transport/noise.rs` — same call in
   `NoiseTransport::connect` (`:419-421`); `connect_stream` reuses it
   (`:410`).
5. `crates/control/src/transport/quic.rs` — no change: QUIC runs over UDP
   (`quinn::Endpoint::client`, `:217`), so TCP keepalive does not apply; the
   idle deadline from change 1 covers QUIC streams via `NoiseControl`.
6. `crates/control/Cargo.toml`, workspace `Cargo.toml`, `Cargo.lock` — add
   `socket2` as a direct dependency (below).

### Keepalive mechanism and dependency

- tokio's `TcpStream` exposes no keepalive API, and
  `tokio::net::TcpSocket::set_keepalive(bool)` only toggles `SO_KEEPALIVE`,
  leaving kernel defaults (Linux `tcp_keepalive_time` = 7200s) — useless at
  control-plane timescales.
- The standard mechanism is the `socket2` crate:
  `SockRef::from(&tcp).set_tcp_keepalive(&TcpKeepalive::new()...)` applies to
  a connected `tokio::net::TcpStream` in place.
- A new **direct** dependency is required:
  `socket2 = { version = "0.6", features = ["all"] }` in
  `[workspace.dependencies]` and in `control`'s `[dependencies]` (the `all`
  feature exposes the full `TcpKeepalive` builder and the getters used by
  tests). This is not a new crate in the graph: the committed lockfile
  already resolves `socket2 0.6.4` transitively (tokio, quinn), so the
  supply-chain delta is a direct edge only, with no version movement.

### Test seams

- `control` dev-deps already enable tokio `test-util`
  (`crates/control/Cargo.toml:40-43`), so
  `#[tokio::test(start_paused = true)]` with auto-advancing virtual time
  works out of the box.
- Mock harness to mirror: `MockTransport::with_stream_event` returning a
  `duplex()` client end (`crates/control/src/sse.rs:587-609`) and the burst
  test `config_stream_snapshot_burst_skips_unknown_and_delivers_known`
  (`:1373-1411`). A server end that writes a keepalive comment and then goes
  silent models the black-hole exactly.
- Driver-level seam: `established_stream_outlives_endpoint_attempt_timeout`
  (`crates/control/src/lib.rs:2332-2356`) drives `drive_connected_stream`
  with a boxed mock stream and a manual heartbeat interval. It uses its own
  `PendingStream` mock, so a timeout inside `next_message_from_stream` does
  not affect it; it must stay green unmodified.
- Keepalive helper: connect to a localhost listener, apply the helper, read
  the values back through `socket2` getters (`keepalive()`,
  `tcp_keepalive_time()`); the transport test modules already run against
  local sockets (`crates/control/src/transport/sse.rs:710+`).

### Wire-format impact: none

The change is client read behavior plus socket options. No type in
`messages.rs` / `api.rs` / `envelope.rs` changes, no endpoint path or event
schema changes, and the `ControlStream` trait is untouched. ns / nsd / nsgw
consume ns-shared as a live path dependency and simply recompile; the NSD
server already emits the 15s keepalive that this task starts enforcing.

## Proposal

### Idle deadline value: 45s (3x the server keepalive)

`CONFIG_STREAM_IDLE_TIMEOUT = 45s`, i.e. 3x the NSD `KEEPALIVE_INTERVAL`
(15s, fixed server-side; `nsiod-docs/control-plane/02-transport-sse.md`).
Expiry requires three consecutive keepalives to be lost or late. 2x (30s)
would disconnect after a single lost keepalive plus modest jitter — too
aggressive on lossy links; more than 3x only widens the stale-ALLOW window.
Typical detection latency for a black-holed stream becomes <= 45s (bounded
worst case under Risks).

### Placement: per-read timeout inside `next_message_from_stream`

Wrap only the `stream.read()` call (`crates/control/src/sse.rs:442-445`):

```rust
let n = tokio::time::timeout(CONFIG_STREAM_IDLE_TIMEOUT, stream.read(&mut chunk)).await
// Err(Elapsed)  -> idle expiry: clear the stream, return Error::Sse(..)
// Ok(Err(e))    -> existing socket-error path, unchanged
// Ok(Ok(n))     -> existing EOF / feed path, unchanged
```

- Any bytes — keepalive comments included — complete the read and reset the
  window, which is precisely "enforce keepalive arrival".
- One change covers `SseControl` and `NoiseControl`, i.e. all three
  transports (sse / noise / quic), and also bounds connect-to-first-byte
  (the server's first stream item is a keepalive comment).
- Rejected alternatives: a timeout around `next_message()` in the driver, or
  a new `select!` idle arm in `drive_connected_stream`. Both operate at
  message granularity and false-positive on healthy idle streams, because
  keepalives never yield a `ControlMessage` (see Investigation); fixing that
  would require plumbing byte-activity timestamps up through the framer —
  more coupling for no benefit.

### Expiry semantics: exact EOF parity

On timeout expiry: set `*sse_stream = None`, then return
`Err(Error::Sse("config stream idle: no bytes in 45s (server keepalive 15s)"))`
— byte-for-byte the EOF path (`crates/control/src/sse.rs:447-450`) with a
distinct message. The driver then takes the existing transition chain,
unchanged: `Err` → `warn!` + `LiveStreamExit::Disconnected`
(`crates/control/src/lib.rs:646-649`) → `status_tx.send(false)` + exponential
backoff 1s→60s + reconnect (`:479-486`) → `MultiControlPlane` synthesizes
`AclConfig::fetch_failed` for that NSD (`crates/control/src/multi.rs:329-342`)
→ merger degrades to last-good and then fail-closed per `last_good_max_age`.
No new exit variant, no driver changes, no new state.

The existing `Error::Timeout` variant is deliberately not reused: it carries
HTTP 408 unary semantics (`crates/control/src/transport/sse.rs:161`) and
would lose the diagnostic detail.

Failover interaction (`multi.rs`): expiry on one NSD degrades only that
NSD's ACL slot; layers from other live NSDs keep serving, and the per-plane
backoff bounds reconnect churn.

### TCP keepalive: time=30s, interval=10s, retries=3, set at connect

In `SseTransport::connect` and `NoiseTransport::connect`, immediately after
`TcpStream::connect` succeeds and before the TLS / Noise handshake:

```rust
socket2::SockRef::from(&tcp).set_tcp_keepalive(
    &TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10))
        .with_retries(3), // where the platform supports it; target is Linux
)
```

Kernel-level dead-path teardown lands at roughly 30 + 3x10 = 60s. Role:
OS-level backstop that also fails pending *writes* on half-open sockets and
covers the short-lived unary `call()` sockets; the 45s read deadline remains
the primary detector. On setter failure: `warn!` and continue — the deadline
mechanism is infallible, and refusing to connect over a sockopt failure would
trade a robustness feature for an availability regression.

### Config surface: hardcoded constants, no new config field

Recommend constants (`CONFIG_STREAM_IDLE_TIMEOUT` in `sse.rs`; keepalive
parameters in `transport/mod.rs`), each documented against the server
contract. Justification: (1) the value derives from NSD's fixed
`KEEPALIVE_INTERVAL = 15s` — an operator knob invites
deadline-below-server-interval misconfiguration, i.e. self-inflicted
reconnect storms; (2) a new `ConnectorConfig` field ripples into the ns /
nsd / nsgw config surfaces with no identified operational need; (3) tests use
paused virtual time and need no injection. Revisit only if the server
interval ever becomes configurable — that is a protocol change that would
land in ns-shared first anyway.

### Acceptance criteria (implement phase)

1. Paused-time unit test (`sse.rs`): a mock stream delivers one keepalive
   comment then goes silent → `next_message()` returns `Err(Error::Sse(..))`
   whose message mentions the idle deadline, after 45s of virtual time, and
   the client reports `is_connected() == false` afterwards.
2. Paused-time unit test: keepalive comments every 15s keep the stream up
   across at least three deadline windows (no error), and a subsequent real
   signed event still decodes to `Ok(msg)`.
3. Regression: the full existing `control` suite stays green unmodified,
   including `established_stream_outlives_endpoint_attempt_timeout` and the
   SSE replay / burst tests.
4. Unix unit test: after `SseTransport::connect` / `NoiseTransport::connect`
   to a localhost listener, `SO_KEEPALIVE` is enabled and
   `tcp_keepalive_time` reads back 30s via `socket2` getters.
5. Wire freeze: no diff under `crates/control/src/messages.rs`, `api.rs`,
   `envelope.rs`; `cargo fmt`, `clippy`, and `cargo test -p control --locked`
   green against the committed lockfile.

### Risks and mitigations

- **False-positive disconnects on slow or lossy links** — expiry needs three
  consecutive missed keepalives; the cost is one reconnect cycle under the
  existing 1s→60s backoff, and the merger dedups identical re-pushed configs
  (`crates/control/src/multi.rs:584-585`). Accepted.
- **Reconnect storms across NSDs after a shared outage** — deadlines anchor
  to per-stream last-byte times, not wall clock, and each plane backs off
  independently; if churn is observed in practice, add ±10% jitter to the
  deadline as a follow-up (not in the initial scope).
- **Detection-latency inflation via `select!` cancellation** — when the
  heartbeat arm (60s) wins, the in-flight `next_message` future is dropped
  and the per-read window restarts on the next loop iteration; bounded worst
  case ≈ 45s + 60s ≈ 105s, versus unbounded today. Carrying a deadline
  across calls would remove this but adds cross-call state for little value.
  Accepted.
- **Coupling to the server keepalive interval** — the constant's doc comment
  must reference `KEEPALIVE_INTERVAL = 15s` (`02-transport-sse`); an NSD-side
  interval change must revisit this constant in the same review.
- **`setsockopt` platform gaps** — warn-and-continue; the application-level
  deadline is the guaranteed detector.

## ActiveForm

Adding config-stream idle read deadline and control-socket TCP keepalive

## Dependencies

- **plan**: PLAN-011 (control-stream stale-policy detection)
- **blocked by**: approval of the proposal above (implement must not start
  before acceptance)
- **relates**: CTRL-017 (cross-repo stale-policy design decision under the
  same plan)

## Notes

- 2026-07-03: investigation and proposal recorded from design-review finding
  DR-H3 (`nsiod-docs/_design-review-2026-07-03.md`). No source changes in
  this task.
- 2026-07-04: proposal accepted by the campaign coordinator on 2026-07-03;
  implemented in this task.
