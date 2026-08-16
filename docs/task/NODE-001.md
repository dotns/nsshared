# NODE-001 Define unified node capability and subnet-route contracts

- **status**: review — shared slice complete; must merge with the nsd/nsgw arms, not ahead of them
- **priority**: P0
- **owner**: ns-shared/NODE-001
- **createdAt**: 2026-08-16 06:06 UTC
- **relatedPlan**: PLAN-015

## Description

Implement the additive capability vocabulary, bounded route-advertisement
report, and authoritative approved-subnet-route projection selected by
PLAN-015 without changing existing service or capture-route semantics.

## Acceptance criteria

- Capability constants and route types have one shared implementation owner.
- IPv4 prefix, route-count, encoded-size, identity, and generation validation
  is deterministic and bounded.
- Overlay-reserved range rejection takes NSD's effective `vip_pool` /
  `tunnel_ip_pool` as an input. A validator pinned to the default CIDRs is a
  defect: both pools are operator-configurable, so a deployment that overrides
  either would accept a prefix swallowing the overlay's own address space.
- Full-snapshot withdrawal and stale-generation behavior is explicit.
- Old/new round trips and cross-repository fixtures prove compatibility.
- Unknown capabilities and advertisements never grant route authority.
- ns-shared locked QA plus focused ns/nsd/nsgw compatibility gates pass.

## Dependencies

- **blocked by**: PLAN-015 approval
- **blocks**: ns PLAN-124 S2-S4, nsd PLAN-129, nsgw PLAN-123

## Implementation

Landed on `bkd/495p47u1` as `6f0b4b399c41f8b80bf2ab4dbc51506a253ba35e`, based on
main `8c49dcd2b1c20ecac54bcb48b99ddb67f7c641ef`.

| PLAN-015 item | Where it landed |
|---------------|-----------------|
| 1, 2 — capability vocabulary | `crates/common/src/node_capability.rs` |
| 3 — advertisement (intent) | `NodeSubnetRouteReport`, envelope api `node.subnet_routes.report.v1` |
| 4 — approved projection (authority) | `SubnetRouteConfig`, control message `subnet_route_config.v1` |
| 5 — snapshot / withdrawal | `supersedes`, `withdrawn_route_ids` on both shapes |
| 6 — byte-for-byte preservation | `crates/control/tests/node_contract_fixtures.rs` |
| 7 — `AuthPayload` leg role | `control::types::WssLegRole`, `AuthPayload::leg_role` |

Items 3-5 live in the new `crates/control/src/subnet_route.rs`. Report and
projection are separate types with separate wire tags and separate validators;
there is no conversion between them, so an advertisement cannot authorize
itself.

`OverlayReservedRanges` takes the effective `vip_pool` / `tunnel_ip_pool` as a
constructor input and deliberately has no `Default`, because a default would
reintroduce the pinning defect the acceptance criteria call out.

## Evidence

### Locked ns-shared QA

Run stage by stage so a passing gate cannot be inferred from the last command's
exit code:

```text
cargo fmt --all -- --check                                  EXIT=0
cargo clippy --workspace --all-targets --locked -- -D warnings  EXIT=0
cargo nextest run --workspace --locked                      EXIT=0
cargo deny --locked check                                   EXIT=0
cargo shear --locked                                        EXIT=0
typos                                                       EXIT=0
```

`cargo nextest run --workspace --locked` reports
`Summary [1.813s] 681 tests run: 681 passed, 0 skipped`. The same command on
base `8c49dcd` reports `606 tests run: 606 passed, 0 skipped`, so this slice
adds 75 executed tests: 47 in `subnet_route::tests`, 21 in
`node_contract_fixtures`, 5 in `node_capability::tests`, 2 in `auth`.

### RED proofs

Each mutation was applied on top of the committed slice, shown failing, then
reverted with `git checkout --`; the working tree was verified clean after each.

| Mutation | Result |
|----------|--------|
| `OverlayReservedRanges::conflict` pinned to `100.64.0.0/10` / `10.100.0.0/24` instead of its input | `an_overridden_vip_pool_...` and `an_overridden_tunnel_ip_pool_...` — `0 passed; 2 failed` |
| decode-time route-count check removed from `BoundedSeq::visit_seq` | `a_report_carrying_more_routes_than_the_limit_fails_during_decoding` and the config twin — `0 passed; 1 failed` each |
| `skip_serializing_if` dropped from `AuthPayload::leg_role` | `a_legacy_auth_payload_is_unchanged_on_the_wire` failed: left `{"purpose":"wss","leg_role":null}`, right `{"purpose":"wss"}` |

### Cascade

Consumers were built in throwaway worktrees under
`/workspace/nsiod/worktrees/node001-cascade/` whose `../ns-shared` resolves to
this exact candidate. Consumer checkouts were not modified.

| Consumer | Commit | `cargo check --workspace --all-targets --locked` |
|----------|--------|--------------------------------------------------|
| `ns` | `a527c8fa20b7817be44ea5e0ed06e38e66313f4c` | EXIT=0 — no source change needed |
| `nsd` | `3098dac54d168daa75ff35cfa02d6693997ba15a` | EXIT=101 — 2 sites |
| `nsgw` | `63debe00002a293e9482840e32a9f26d0d3cb733` | EXIT=101 — 3 sites |

All three were green against base `8c49dcd` before the change, so every failure
below is attributable to this slice. The exact surface, measured by patching
the throwaway tree until it compiled and then discarding the patch:

- `nsd/crates/nsd-api/src/sse/filter.rs:109` — `VariantKind::from_message`,
  whose doc comment already states the match is intentionally exhaustive so a
  new upstream variant must fail compilation. This is the change surface nsd
  PLAN-129 names.
- `nsd/crates/nsd-api/tests/envelope.rs:1322` — `AuthPayload` struct literal.
- `nsgw/crates/nsgw-control/src/auth.rs:236` — `AuthPayload` struct literal.
- `nsgw/crates/nsgw-control/src/config_stream.rs:737` — dispatch match.
- `nsgw/crates/nsgw-control/src/config_stream.rs:926` —
  `ConfigStreamChannelRequirement::for_message`.

Five edits across four files bring both consumers back to EXIT=0. The breaks
are the intended cascade PLAN-015 acceptance describes: the shared crate must
land inside one merge window with the nsd PLAN-129 and nsgw PLAN-123 arms, not
ahead of them.

With those five edits applied in the throwaway tree, every consumer suite runs
green against this candidate — no runtime wire regression:

| Consumer | Command | Result |
|----------|---------|--------|
| `ns` | `cargo nextest run --workspace --locked` | EXIT=0 — `1010 tests run: 1010 passed, 1 skipped` |
| `nsd` | `cargo nextest run --workspace --locked` | EXIT=0 — `1081 tests run: 1081 passed (2 slow), 0 skipped` |
| `nsgw` | `cargo nextest run --workspace --all-features --locked --no-tests=pass` | EXIT=0 — `1511 tests run: 1511 passed, 8 skipped` |

The `ns` run is the cleanest signal of the three: `ns` needed no scaffolding at
all, so its 1010 tests exercised unmodified consumer source against the new
shared crate.

`ns` and `nsgw` advanced while this slice was verified — `ns` to `38aaaed` and
`nsgw` to `6396a53`. Both deltas are documentation-only
(`ns` `docs/plan/PLAN-124.md`; `nsgw` `docs/plan/PLAN-123.md` plus the NODE-001
audit finding), so no consumer source moved and the results above still
describe the current consumer mains. The throwaway worktrees were removed after
measurement; the consumer checkouts were left untouched.

## Notes

- 2026-08-16 06:06 UTC: Proposal task created pending approval; unclaimed.
- 2026-08-16 06:27 UTC: Plan review applied — overlay-reserved range rejection
  now takes NSD's effective pool configuration as an input instead of pinning
  the default CIDRs.
- 2026-08-16 12:05 UTC: Implemented PLAN-015 items 1-7 and the Bounds and
  validation section. Locked QA green with 681 executed tests. Cascade measured:
  `ns` compiles and tests green unchanged; `nsd` and `nsgw` need five arm/field
  edits that belong to their own plans, after which all three suites are green.
  Moved to review — this slice must not merge ahead of those consumer arms.
