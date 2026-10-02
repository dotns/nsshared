# ns-shared

Shared Rust crates for the contracts that two or more NSIO components encode
or enforce. The scope is defined on the docs site (`ns-shared/index.md`).

This is the `next` workspace, rebuilt around the Quick protocol. It contains:

- `ns-wire` — NS protocol v2 wire formats: identities, node records, relay
  packets, region and in-tunnel control messages (normative source: docs
  `ns/quick-v2.md`)
- `quick-rendezvous` — invitation locators, identity proofs and encrypted
  handoffs (target: rendezvous v2, docs `ns/rendezvous.md`)

The previous workspace (`control`, `common`, `acl`, `tunnel-ws`, `telemetry`)
is archived at tag `archive/v1-20261002`; those crates return one at a time
after a per-crate analysis.

## Consuming

Consumers use Cargo git dependencies pinned by tag:

```toml
ns-wire = { git = "https://git.pvv.cc/nsiod/ns-shared.git", tag = "v0.1.0" }
```

For local development against a sibling checkout, add an uncommitted override
in the consumer's `.cargo/config.toml`:

```toml
[patch."https://git.pvv.cc/nsiod/ns-shared.git"]
ns-wire = { path = "../ns-shared/crates/ns-wire" }
```

See `docs/decisions/2026-10-02-ns-shared-next-baseline.md`.

## Development

```sh
just dev-check   # fmt + clippy
just qa          # full quality gate
```
