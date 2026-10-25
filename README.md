# nsshared

Shared Rust crates for the generic protocols and tools that two or more NSIO
components encode or use. Application protocols (the ns app channel, pairing,
file transfer) and component-internal architecture (node address planning,
in-tunnel control, relay regions) stay with their owners. The scope is defined
on the docs site (`ns-shared/index.md`).

It contains these library crates (all pure: no I/O, async runtime or TLS):

| Crate | Contents |
| --- | --- |
| `nsshared-codec` | Canonical CBOR in two profiles (the NS array profile, `cbor::CborReader` / `cbor::CborWriter`, and the M6 value profile, `cbor::value`) and strict base64url / base64 |
| `nsshared-identity` | Identities and typed keys (generation, canonical text and binary forms, node ID, `node6` / `node4`), canonical realm ids, relay ids, `NodeRecord` and its ordering rules, public DNS discovery of records (quick-v2 §11.2) |
| `nsshared-relay` | Relay packets v2: header and bodies, REGISTER, session key, MACs, DATA admission, budget defaults (docs `ns/quick-v2.md` §8) |
| `nsshared-rendezvous` | The `/rendezvous/v1` messages: transport, capabilities, actor `hello`, relay directory v2, mailbox phase rules, node registry (docs `ns/rendezvous.md`) |
| `nsshared-control` | `service`: the M6 private service control contract; `node_control`: Node-control v2 messages; `account`: the account payload contracts by layer and family (specifications in `docs/spec/`) |
| `nsshared-telemetry` | `tracing` subscriber setup (text or JSON, env filter with a default) and redaction helpers; no exporter |
| `nsshared-proto` | Deprecated facade: the 0.6 module paths (`keys`, `identity`, `record`, `discovery`, `encoding`, `constants`, `relay`, `rendezvous`, `node_control` and the root types), re-exported from the crates above |
| `nsshared-service-control` | Deprecated facade: the M6 contract at its existing paths, re-exported from `nsshared-control` |

Development and test support (`publish = false`):

- `nsshared-testkit` — the `.vec` fixture reader, hex helpers and seeded fixture
  authorities used by the integration tests (a development dependency only)
- `nsshared-mock-relay` (`examples/mock-relay`) — in-memory relay v2 mock over UDP
  and WSS for tests, as a library and a binary
- `nsshared-mock-rendezvous` (`examples/mock-rendezvous`) — single-instance
  `/rendezvous/v1` mock (mailbox broker, directory, node registry) over TLS
  WebSocket for ns development and tests
- `nsshared-mock-server` (`examples/mock-server`) — both mocks on one `host:port`
  and certificate (UDP, `/ns/v2`, `/rendezvous/v1`)

`tools/vectors` is an independent Python generator of the conformance vectors in
`crates/<crate>/tests/vectors/` (`just vectors`, `just vectors-check`). Spec
coverage: `docs/spec-coverage/quick-v2.md`, `docs/spec-coverage/rendezvous.md`.

The v1 workspace (`control`, `common`, `acl`, `tunnel-ws`, `telemetry`) is
archived at tag `archive/v1-20261002`; see `docs/design/v1-crate-analysis.md`.

## Status: maintenance

Since `v0.6.0` (2026-10-10) nsshared is a foundation library in maintenance.
It takes only:

- fixes: bugs, specification mismatches, security issues;
- dependency and toolchain updates;
- new contracts that a consumer migration needs, each as a new module or crate
  in a minor release, specified first: the control resource and session
  protocol (when the gateway protocol is chosen), the account payload contracts
  (including the serialized policy contract) and short names with the relay to
  authoritative DNS feed.

It does not take features of a single component (relay mailbox storage, the
node relay client, policy compilation for one consumer) or application
protocols. `v1.0.0` follows once ns and the relay v2 server pass their interop
tests on one implementation. See
`docs/plan/20261010-1200-nsshared-maintenance.md`.

## Consuming

Consumers use Cargo git dependencies pinned by tag. The public mirror needs no
credentials:

```toml
nsshared-identity = { git = "https://github.com/dotns/nsshared", tag = "<tag>" }
```

Existing dependencies on `nsshared-proto` and `nsshared-service-control` keep
building through the facades; move each import to the defining crate.

Use this exact URL (no `.git` suffix): Cargo treats URL spellings as
different sources, so a `[patch]` only applies when it matches the consumer's
dependency. `https://git.pvv.cc/nsiod/nsshared.git` is the primary remote with
the same refs.

For local development against a sibling checkout, add an uncommitted override
in the consumer's `.cargo/config.toml`:

```toml
[patch."https://github.com/dotns/nsshared"]
nsshared-identity = { path = "../nsshared/crates/nsshared-identity" }
```

See `docs/decisions/2026-10-02-ns-shared-next-baseline.md`.

## Versioning

Tags `vX.Y.Z` mark releases. While in 0.x, a minor bump may break the API and
a patch bump must not; from 1.0, semver applies. `just semver` enforces this
against the previous tag for every library crate that exists at that tag:
cargo-semver-checks for the crates that define their items, and
`scripts/api_surface.py` for the facades, whose items live in other workspace
crates. Wire
formats change only with a new protocol version or context string, never
silently within one.

## Development

```sh
just dev-check   # fmt + clippy
just qa          # full quality gate
```
