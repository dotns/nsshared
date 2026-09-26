# ns-shared

Shared Rust crates for the NSIO control and transport stack.

This workspace currently contains:

- `common`
- `telemetry`
- `acl`
- `control`
- `tunnel-ws`
- `keynet-proto`
- `keynet-quick` — short invitation locators, identity proofs and encrypted handoffs

Consumers should pin source dependencies by an immutable tag or commit. This
workspace is configured with `publish = false`; during local development,
sibling checkouts use path dependencies such as `../ns-shared/crates/common`.
