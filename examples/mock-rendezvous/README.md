# nsshared-mock-rendezvous

A single-instance mock of the NS rendezvous v2 relay (`wss://{host:port}/quick/v2`,
subprotocol `ns-quick-v2`) for ns development and tests. `publish = false`.

It serves, over TLS WebSocket:

- the connection `challenge` and actor `hello` (docs `ns/rendezvous.md` §3, §4);
- the mailbox broker: `open`, `lookup`, `join`, `admit`, `reject`, `send`, `recv`
  with its long poll, `close`, expiry and inactivity sweeps (§5);
- `directory`: the mock's own entry, announcing `mailbox` and `registry`, or a
  configured directory (§5.4);
- the node registry: `publish` and `lookup_node` with §3.3 ordering and the
  conflict latch (`ns/quick-v2.md` §7);
- every §6 and quick-v2 §7.4 limit and rate limit, configurable through `Limits`,
  and the §7 error codes.

It is one instance: no region, owner epochs, forwarding or replication (region
frames 10-12 are not served), and its registry domain is its own single entry,
so every node ID is in its shard. Encodings, validation, phase rules, proofs
and record acceptance all come from `nsshared-rendezvous`; the mock adds only
storage, randomness, clocks, rate limits and I/O. State is in memory and lost
on exit.

## Binary

```sh
cargo run -p nsshared-mock-rendezvous -- --listen 127.0.0.1:8443 --write-cert /tmp/mock-rendezvous.pem
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen <ip:port>` | `127.0.0.1:8443` | Listen address; its port is the advertised port |
| `--host <name>` | `localhost` | TLS host name of the relay entry; the authority is `host:port` |
| `--advertise-ip <ip>` | the listen IP | Directory IP of the entry, repeatable |
| `--relay-id <u16>` | `1` | Directory relay id |
| `--code <XX>` | `MK` | Two-letter directory code |
| `--cert <pem> --key <pem>` | self-signed | Present this certificate chain and key |
| `--write-cert <path>` | — | Write the presented certificate PEM to `path` |
| `--directory <json>` | single entry | Serve this directory; it must list the mock's entry |

On startup it prints `authority <host:port>` and `directory <json>`, then runs
until Ctrl-C.

## Pointing ns at it

Dial the printed authority, e.g. `localhost:8443`: TLS goes to the advertised IP
with SNI = `--host`, so the host must resolve to (or be configured with) that
IP. Both the ns overlay registry client and Quick pairing connect this way.

The self-signed certificate covers `--host` and the advertised IPs. Trust it
by giving the client the PEM written by `--write-cert` as the relay's trust
store (ns accepts a per-relay PEM trust store), or pass your own
`--cert`/`--key` issued by a CA the client already trusts. Never install the
self-signed certificate system-wide.

## Library

Tests embed the server directly:

```rust
use nsshared_mock_rendezvous::{Config, Limits, RendezvousServer};

let config = Config {
    listen: "127.0.0.1:0".parse()?,
    limits: Limits { opens_per_ip_per_minute: 2, ..Limits::default() },
    ..Config::default()
};
let (server, listener) = RendezvousServer::bind(config).await?;
tokio::spawn({
    let server = server.clone();
    async move { server.serve(listener).await }
});
// Trust `server.certificate_pem()`, dial `server.relay_entry()`, then:
server.shutdown();
```

Port 0 picks a free port that the entry announces. Another server can embed
it with `handle_tcp`, `handle_stream` or `handle_websocket` plus
`run_sweeper`. `tests/support/mod.rs` is an ns-style client (tokio-tungstenite
and rustls with aws-lc-rs) driving it end to end.
