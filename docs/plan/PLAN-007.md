# PLAN-007 Canonical internal DNS helpers

- **status**: completed
- **createdAt**: 2026-06-17 11:27
- **approvedAt**: 2026-06-17 11:38
- **completedAt**: 2026-06-17 11:51
- **relatedTask**: DNS-001

## Context

`ns-shared` currently has the behavior owner for service FQID formatting in
`crates/common/src/services.rs::ServiceDef::fqid()`, where the service name is
formatted as `"{name}.{node_id}.n.ns"`. Machine state documentation and tests in
`crates/common/src/state.rs` still use `{machine_id}.n.ns`, while NSD register
responses already use `{machine_id}.m.ns.io`.

Consumers in `ns`, `nsd`, and `nsgw` depend on the `common` crate through path
dependencies. This makes `common` the right place to own DNS suffix constants
and helpers.

The requested migration is a hard cut: no legacy `.n.ns` alias emission is
required.

## Proposal

Add a `dns_names` module in `crates/common/src/dns_names.rs` and re-export its
canonical constants and helpers from `crates/common/src/lib.rs`.

Minimum API:

```rust
pub const SERVICE_DNS_SUFFIX: &str = "n.ns.io";
pub const MACHINE_DNS_SUFFIX: &str = "m.ns.io";
pub const GATEWAY_DNS_SUFFIX: &str = "gw.ns.io";

pub fn service_fqdn(service: &str, site: &str) -> String;
pub fn machine_fqdn(machine_id: &str) -> String;
pub fn gateway_fqdn(gateway_id: &str) -> String;
pub fn is_service_fqdn(name: &str) -> bool;
pub fn is_machine_fqdn(name: &str) -> bool;
pub fn is_gateway_fqdn(name: &str) -> bool;
```

Use the canonical helpers in `ServiceDef::fqid()`. Update focused tests and
docstrings to the new canonical service and machine names.

Do not add legacy `.n.ns` alias generation or compatibility resolution in this
implementation.

## Risks

- Any remaining hard-coded `.n.ns` service name in downstream behavior paths
  will diverge from NSD's canonical projection.
- Existing local state files may contain old `domain_base` values. This field is
  informational and should not block the hard cut, but tests must assert new
  registration output.

## Scope

Touch only `crates/common` API, tests, and PMA tracking files. No dependency
changes are required.

## Alternatives

- Keep constants in each repository: rejected because it preserves the current
  drift problem.
- Emit both canonical and legacy service names: rejected by product direction for
  this change.

## Annotations

- 2026-06-17 11:27: Plan created after investigation. User clarified that legacy
  `.n.ns` compatibility is not required.
- 2026-06-17 11:38: Implementation approved for the hard-cut canonical scope:
  service `n.ns.io`, machine `m.ns.io`, gateway `gw.ns.io`; no legacy alias
  generation or compatibility resolution.
- 2026-06-17 11:51: Implemented by BKD worker `sd8cx1z2/415znys3`; coordinator
  verification passed.

## Outcome

- Added `crates/common/src/dns_names.rs` with canonical service, machine, and
  gateway suffix constants.
- Added shared FQDN generators and canonical FQDN shape checks.
- Re-exported the DNS helper API from `crates/common/src/lib.rs`.
- Updated `ServiceDef::fqid()` to call the shared service helper and produce
  `<service>.<site>.n.ns.io`.
- Updated machine-state docs/tests to align with `<machine_id>.m.ns.io`.

## Verification

- `PATH="$HOME/.cargo/bin:$PATH" cargo fmt --all -- --check`
- `PATH="$HOME/.cargo/bin:$PATH" cargo check -p common`
- `PATH="$HOME/.cargo/bin:$PATH" cargo test -p common`
