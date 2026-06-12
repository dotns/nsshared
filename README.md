# ns-shared

Shared Rust crates for the NSIO control and transport stack.

This workspace currently contains:

- `common`
- `telemetry`
- `acl`
- `control`
- `tunnel-ws`

Consumers should pin this repository by an immutable tag or commit when it is
published. During local development, sibling checkouts can use path
dependencies such as `../ns-shared/crates/common`.
