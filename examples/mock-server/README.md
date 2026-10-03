# nsshared-mock-server

One process, one `host:port`, one certificate: the relay v2 mock
(`nsshared-mock-relay`) and the rendezvous mock (`nsshared-mock-rendezvous`)
behind a single authority, for ns development and tests. Library
(`MockServer`) and binary (`nsshared-mock-server`).

It serves, on the listen port:

- relay v2 UDP (one relay packet per datagram), bound on the same port as TCP;
- one TCP+TLS listener that routes each WebSocket upgrade by path:
  - `wss://host:port/ns/v2` (subprotocol `ns-relay-v2`) to the relay mock,
  - `wss://host:port/rendezvous/v1` (subprotocol `ns-rendezvous-v1`) to the rendezvous
    mock (mailbox broker, `directory`, registry `publish` / `lookup_node`),
  - any other path gets 404, a missing subprotocol 400.

The served directory lists the server itself (`--relay-id`, `--code`, `--host`,
`--advertise-ip`, the listen port) announcing `mailbox`, `registry`, `udp` and
`wss`; the `/rendezvous/v1` challenge announces the same set. The relay handshake
reply (REGISTERED) announces `udp` and `wss`, the tokens `nsshared-mock-relay`
emits.

Everything the two mocks leave out still applies: single instance (no region,
mesh replication or owner fencing), in memory only, simple limits.

## Run

```sh
cargo run -p nsshared-mock-server -- --listen 127.0.0.1:8443 --write-cert /tmp/mock-server.pem
```

On start it prints `authority host:port` and `directory {...}` (the served
directory JSON). Ctrl-C shuts both services down.

| Flag | Meaning |
| ---- | ------- |
| `--listen ip:port` | TCP (TLS) and UDP listen address (default `127.0.0.1:8443`; port 0 picks a port free for both) |
| `--host name` | TLS host name and authority host (default `localhost`) |
| `--advertise-ip ip` | Directory IP of the entry, repeatable (default the listen IP) |
| `--relay-id u16` | Directory relay id (default 1) |
| `--code XX` | Directory code (default `MK`) |
| `--cert pem`, `--key pem` | Certificate chain and key; default a self-signed certificate for `--host` and the advertised IPs |
| `--write-cert path` | Writes the presented certificate PEM (the trust anchor) |
| `--directory json` | Serves this directory instead of the single-entry default; it must list this server |

## Pointing ns at it

ns uses one identifier `host:port` for everything: UDP to that port,
`wss://host:port/ns/v2` for the relay WSS carrier and `wss://host:port/rendezvous/v1`
for the registry and the mailbox, dialling the directory entry's `ips` and
verifying `host`.

1. Relay: list the printed authority (`localhost:8443` by default) as the relay
   identifier in the node configuration; ns signs it into REGISTER unchanged,
   so it must match exactly.
2. Registry and rendezvous: use the printed directory (or its single entry) as
   ns's relay directory. The entry's `ips` must be reachable from ns: when ns
   runs elsewhere (another container or host), listen on `0.0.0.0:8443` and
   pass the reachable address with `--advertise-ip`, and a `--host` name that
   ns can verify.
3. Trust the certificate: `--write-cert` writes the PEM trust anchor. ns takes
   its TLS policy from a `TlsConfigProvider` (an `Arc<rustls::ClientConfig>`
   is one). Build the `ClientConfig` with an explicit provider, e.g.
   `rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))`,
   and a root store holding that PEM. The self-signed certificate names
   `--host` and every advertised IP.

## Library

`MockServer::bind(Config)` (the rendezvous mock's `Config`) binds TCP and UDP on
one port and returns the server with its listener; `serve(listener)` accepts
until `shutdown().await`. `route(stream, remote)` upgrades and routes one
decrypted stream; `relay()` and `rendezvous()` expose the two services.
`tests/combined.rs` drives a node through both paths and UDP on one port.
