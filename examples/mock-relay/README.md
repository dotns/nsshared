# nsshared-mock-relay

A single-instance, in-memory relay v2 mock (ns/quick-v2 §8) for tests, as a library
(`MockRelay`) and a binary (`nsshared-mock-relay`).

It is **not** a production relay:

- one instance only: no region, mesh replication or owner fencing;
- everything lives in memory and is lost on exit;
- only simple per-node limits (sessions, provisional registrations per IP, DATA and
  handshake budgets, WSS connections per IP) instead of the production budgets.

## Run

```sh
cargo run -p nsshared-mock-relay -- --listen 127.0.0.1:4433 --write-cert /tmp/mock-relay.pem
```

On start it logs the relay identifier, the bound UDP and WSS addresses and the written
certificate path. Ctrl-C shuts it down. `RUST_LOG` sets the log filter (default `info`).

| Flag | Meaning |
| ---- | ------- |
| `--relay-id host:port` | Relay identifier nodes sign and list; default: the bound address (`127.0.0.1:<port>` for an unspecified IP) |
| `--listen addr` | Shared UDP and WSS listen address (default `127.0.0.1:0`; port 0 picks one free port for both) |
| `--udp-listen addr`, `--wss-listen addr` | Separate UDP / WSS listen addresses instead of `--listen` |
| `--tls-cert pem`, `--tls-key pem` | WSS certificate chain and key; default: a self-signed certificate |
| `--cert-names a,b` | Extra self-signed names; the identifier host is always included (default extras: `localhost`, `127.0.0.1`) |
| `--write-cert path` | Writes the self-signed certificate as PEM |
| `--presence-ttl s` | Presence TTL, 30..=3600 (default 90) |
| `--no-udp`, `--no-wss` | Disables a carrier and drops its capability token |
| `--max-sessions`, `--provisional-per-ip`, `--wss-connections-per-ip` | Basic limits |

## Carriers

- UDP: one relay packet per datagram; datagrams over 2048 bytes are dropped.
- WSS: `wss://host:port/ns/v2` with subprotocol `ns-relay-v2` (other paths get 404, a
  missing subprotocol gets 400); one relay packet per binary message, no compression; a
  text message closes with code 1003, a message over 2048 bytes with 1009.
- WSS is TLS only. The ns WSS carrier always dials `wss://` with a rustls client
  configuration, so the mock offers no plain `ws://`.

## Pointing ns at the mock

1. Use the mock's relay identifier `host:port` (logged on start, or fixed with
   `--relay-id`) in the node record's relay list. ns signs it into REGISTER unchanged, so
   it must match exactly.
2. UDP and WSS share that port: ns sends UDP to `host:port` and opens
   `wss://host:port/ns/v2`. Keep the default shared port; separate listen addresses only
   help behind a port mapping that restores it.
3. Trust the certificate. ns overlay takes its TLS policy from a `TlsConfigProvider`
   (an `Arc<rustls::ClientConfig>` works as one). Build that `ClientConfig` with an
   explicit provider, e.g.
   `rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))`,
   with a root store holding the `--write-cert` PEM. rustls verifies the identifier host
   name, which the self-signed certificate always contains (IP literals as IP names).
4. Capabilities: the tentative REGISTERED announces `udp` and `wss`, minus any carrier
   disabled with `--no-udp` / `--no-wss`. The library's
   `MockRelayConfig::extra_capabilities` appends further tokens after them.

## Library

`MockRelay::start(MockRelayConfig)` binds and spawns the tasks; `relay_id()`,
`udp_addr()`, `wss_addr()` and `generated_cert()` (DER and PEM) describe it; `sessions()`
and `counters()` inspect the core; `shutdown().await` stops every task and releases the
sockets.

## Embedding behind a shared listener (combined server)

`/rendezvous/v1` rides the relay's TLS listener (same authority), so a combined server owns the
single TCP+TLS listener and hands `/ns/v2` to the relay. Set
`MockRelayConfig::external_wss`: the mock then binds no TCP listener and generates no
certificate (`wss_addr()` and `generated_cert()` are `None`), but still announces `wss`
and binds UDP on `udp_listen` or `listen`. Give it the listener's port, because ns uses
the identifier port for both carriers.

Per connection, either:

- `relay.handle_stream(tls, remote).await`: the relay runs the WebSocket handshake itself
  (404 for a path other than `/ns/v2`, 400 without `ns-relay-v2`), or
- upgrade in the router with `relay_websocket_config()` and `accept_relay_request` in the
  `accept_hdr_async` callback, then `relay.handle_websocket(ws, remote).await`.

Both resolve when the connection ends, count toward the per-IP WSS limit, disconnect the
session on close, and are closed with 1001 by `shutdown()`. `S` only needs
`AsyncRead + AsyncWrite + Unpin`; share the relay as `Arc<MockRelay>` to spawn them.

```rust
let listener = TcpListener::bind("127.0.0.1:4433").await?;
let relay = Arc::new(MockRelay::start(MockRelayConfig {
    listen: listener.local_addr()?, // UDP on the same port
    external_wss: true,
    ..MockRelayConfig::default()
}).await?);
loop {
    let (tcp, remote) = listener.accept().await?;
    let (acceptor, relay) = (acceptor.clone(), Arc::clone(&relay));
    tokio::spawn(async move {
        let Ok(tls) = acceptor.accept(tcp).await else { return };
        let mut quick = false;
        let callback = |request: &Request, response: Response| {
            if request.uri().path() == "/rendezvous/v1" {
                quick = true;
                return quick_v2_accept(request, response); // the rendezvous check
            }
            accept_relay_request(request, response) // 404 unless /ns/v2
        };
        // One config for both paths: the larger rendezvous limit. The relay still
        // closes a message over 2048 bytes with 1009; a relay-only router would pass
        // relay_websocket_config() instead.
        let config = Some(RendezvousServer::websocket_config());
        let Ok(ws) = accept_hdr_async_with_config(tls, callback, config).await else { return };
        if quick {
            rendezvous.handle_websocket(ws, remote.ip()).await;
        } else {
            relay.handle_websocket(ws, remote).await;
        }
    });
}
```

`handle_websocket` expects `relay_websocket_config()` (2048-byte messages and frames);
with a larger limit the relay itself still closes any message over 2048 bytes with 1009.
When the router already knows the path some other way, `relay.handle_stream(tls, remote)`
skips the router-side upgrade for `/ns/v2`. `relay.shutdown().await` takes `&self`.
