# 20261025-0802-nsshared-restructure Restructure the shared crates and apply the review revisions

- **status**: implementing
- **createdAt**: 2026-10-25 08:02
- **approvedAt**: 2026-10-25 08:02
- **relatedTask**: 20261025-0802-nsshared-restructure

## Context

Base: `1bc1d39ef51d3e60a88a01d67244afc68ebd795c` (account profile candidate). Branch
`refactor/nsshared-restructure`. Baseline `just qa` at the base passes (542 tests).

Current crates:

- `nsshared-proto` (about 25k source lines with tests): `codec` (array-only canonical
  CBOR reader and writer), `encoding` (base64 and the CBOR re-export), `constants`,
  `identifier` (`RelayId`), `identity`, `keys`, `realm_id`, `record`, `discovery`,
  `relay/`, `rendezvous/`, `node_control`, `account/` (42 files, about 14k lines).
- `nsshared-service-control` (M6, about 2.9k lines): its own map-capable CBOR value
  codec (`cbor.rs`), contract, message, snapshot.
- `nsshared-telemetry`, three mock example crates.

Module dependencies inside proto (checked): `encoding` -> `codec`; `identity` ->
`constants`; `keys` -> `identity`, `record::WireGuardKey`; `record` -> `codec`,
`constants`, `identifier`, `identity`; `discovery` -> `record`, `encoding`,
`identity`; `relay` -> `codec`, `constants`, `identifier`, `identity`, `record`;
`rendezvous` -> `constants`, `RelayId`; `node_control` -> `encoding`, `record`,
`RelayIdError`; `account` -> `encoding`, `identity`, `RealmId`, `IdentityKey`,
M6 (`ServiceRef`, `Id`, `Identity`, canonical value codec, public-edge
`Declaration`/`ListenerIntent`/`ReportContent`/`domain_digest`, carrier
`Message`/`MessageBody`), `idna` (bootstrap host check only).

Consumers pin `aba1c5d5` (nsd, nsgw) and `24ae9ef` (ns); none uses `account`.
Their main lines use `nsshared_proto::{keys, identity, record, discovery, encoding,
constants, relay, rendezvous, node_control}` plus the root re-exports, and
`nsshared_service_control` root items. ns also depends on the mock crates by package
name.

Review findings at the base (`review-1bc1d39e.md`) were re-verified against the code
before each change; each phase lists what was confirmed.

Phase A findings (confirmed):

- A1: `Cursor::item` reserved `Vec::with_capacity(length)` and
  `HashSet::with_capacity(length)` from the declared count (up to 16 384) before
  reading members. The NS array profile has the same pattern after `array_up_to`, but
  every such count is bounded by a small per-field maximum, so it is left unchanged.
- A2: three scope rules existed: publication content (non-empty, at most 256 bytes),
  subscription, snapshot request, source binding and authentication source selection
  (also no control characters), public-edge, material and confidential configuration
  (`policy_subject::text`: also no whitespace). The family specifications state
  "without control characters". One rule now applies everywhere: the strictest one,
  so no previously refused input becomes accepted. Node L3 status scopes equal their
  source binding's scope and inherit the rule.
- A3: the disposition table said every row was `prepared` although the status
  recorded delivery on 2026-10-25.
- A4: the profile named `41149fe1`, the review request and handoff `958da3f9`; content
  after `958da3f9` (registration placeholders) was not marked.

## Proposal

### Target crates

```
nsshared-codec       canonical CBOR: shared head rules, NS array profile
                     (CborReader/CborWriter) and M6 map profile (Value tree);
                     strict base64 text encodings                    (no cryptography)
nsshared-identity    keys, identity, realm id, RelayId, record, discovery,
                     identity and record constants                   -> codec
nsshared-relay       relay v2 packets, REGISTER, MACs, data, budget,
                     relay constants                                 -> identity, codec
nsshared-rendezvous  /rendezvous/v1 messages, registry constants     -> identity, codec
nsshared-control     service (M6), node_control, account             -> identity, codec
nsshared-testkit     vector reader, fixture identities (dev-only)
nsshared-proto       facade: old public paths of every module except account
nsshared-service-control  facade: re-exports nsshared_control::service
nsshared-telemetry   unchanged
```

Facade decisions:

- `nsshared-proto` keeps `keys`, `identity`, `record`, `discovery`, `encoding`,
  `constants`, `relay`, `rendezvous`, `node_control` and the root re-exports
  (`NodeId`, `IdentityKey`, `IdentitySecret`, `WgSessionKey`, `WgSessionSecret`,
  `RealmId`, `RealmIdError`, `NodeRecord`, `RelayId`). It does **not** re-export
  `account`: the account API was never released (absent from `v0.6.0` and from every
  consumer pin), it is re-pathed in this change anyway, and new users should depend on
  `nsshared-control` directly instead of a facade that is scheduled for removal.
- `nsshared-service-control` re-exports `nsshared_control::service` with the old
  module paths (`cbor`, `contract`, `message`, `snapshot`) and root items.
- The mock example crates keep their package names (ns depends on them) and stay
  examples; `nsshared-testkit` holds the vector reader and fixture identities only.
  This deviates from the plan draft, which put the mocks into the testkit; the mocks
  run I/O and the testkit must stay a pure dev dependency.
- Rust `#[deprecated]` has no effect on re-exports, so the facades are marked
  deprecated in their crate documentation and description, not with the attribute.

### Phases and gates

Every phase ends with the gates below and a commit series of conventional commits.

| Phase | Content |
| --- | --- |
| P0 | This plan and the task entry |
| A | Review section A: A1 decoder allocation bound with regression test and vector; A2 one scope-text validator with refusal vectors; A3 review-request disposition rows `sent`; A4 one revision pointer |
| P1 | `nsshared-codec` with both profiles; proto and M6 use it |
| P2 | `nsshared-identity` with the constants split; proto re-exports |
| P3 | `nsshared-relay`, `nsshared-rendezvous`; proto re-exports |
| P4 | `nsshared-control`: `service` (M6 merged on the codec map profile), `node_control`, `account` by layer and family; review section B; `nsshared-service-control` becomes a facade |
| P5 | `nsshared-testkit`; tests grouped by area; vectors renamed per crate and family; generator duplication removed; vector headers separate the external docs pin from in-repo specifications |
| P6 | Facades final; crate descriptions, `lib.rs` tables, README; semver recipe covers every library crate |
| D | Documentation: per-family specifications under `docs/spec/`, profile reduced to registry, placement and shared rules, review and handoff state moved out of product specifications, process vocabulary removed |

Gates after every phase:

1. `just qa` exits 0.
2. `just vectors-check` exits 0, and the case-by-case comparison against
   `1bc1d39e` (every old case found at its mapped path with identical lines; every new
   case listed as an intended addition) exits 0.
3. API compatibility of the facades: `scripts/api_surface.py check` on `nsshared-proto`
   against `v0.6.0`, `aba1c5d5` (consumer pin) and `1bc1d39e` (account excluded), and on
   `nsshared-service-control` against `aba1c5d5` and `1bc1d39e`, reports no missing line
   other than the intended deltas listed under Risks. cargo-semver-checks reports
   every item re-exported from another workspace crate as removed, so it cannot check
   the facades; it still checks every other library crate in `just semver`.
   In addition the `1bc1d39e` integration tests of both facades (account tests
   excluded: 30 files, 287 tests) are compiled and run against the branch.
4. A scratch crate outside the repository that imports every `nsshared_proto` and
   `nsshared_service_control` item used by the consumer main lines builds against the
   branch.

Gate tools (in [this plan's directory](20261025-0802-nsshared-restructure/)):

- `vector_cases.py BASE vector-map.json` compares every case of every fixture at
  `BASE` with the working tree through the `moves` map and the listed `added` cases.
- `consumer_paths.py OUT SHARED CONSUMER...` collects the `nsshared_proto` and
  `nsshared_service_control` paths used by consumer sources and writes a crate that
  imports each one. At the consumer pin `aba1c5d5` all 238 collected paths resolve.

### Account layout inside nsshared-control (P4, as implemented)

```
account.rs      AccountError, SCHEMA, MAX_BYTES, MAX_IDENTITIES, contract_error! macro
account/
  codec.rs      private: require/ensure, ascending/ascending_by, reader, bounded, identity,
                realm, token and data text rules, text lists, optional texts and integers,
                M6 references, hostname, issuer URL, hex, JWK thumbprint
  limits.rs     private: MAX_TEXT_BYTES, MAX_ITEMS, REALM_TEXT_BYTES, MAX_HOSTNAME_BYTES,
                MAX_CREDENTIAL_BYTES
  signing.rs    private: signing_input and strict verify, used by every signed contract
  domains.rs    public: every signature and digest domain (bytes unchanged)
  node/         lifecycle, enrollment, l3, l3_authority
  control/      bootstrap, envelope, signed_request, exchange, methods, machine_token,
                reports, route_command, node_l3_status, service_control
  publication/  envelope, payloads, registry, source_binding, source_publication,
                subscription, snapshot_request
  families/     (private directory; areas are re-exported at account::)
    realm/      peers, subject, rules, claims
    grants/     grant, payer, authority
    subnet/     views, mapping, report
    edge/       routing, declaration, material, material_request, auth, auth/values
    relay/      roster, participant_roster, session, directory
    usage/      service, report, answer, relay, catalog
```

Export rule: every public item has exactly one path. Area modules (`account::node`,
`account::control`, `account::publication`, `account::realm`, `account::grants`,
`account::subnet`, `account::edge`, `account::relay`, `account::usage`) re-export the
public items of their private files; `account::domains` and the account root hold the
shared items. The same rule holds in every new crate (`nsshared_relay` flattens its
private files into the root beside the public `budget` and `constants` modules).

Section B changes: every account error enum is `#[non_exhaustive]`; shared refusals are
`Contract(AccountError)` and one macro implements the CBOR conversion (grants and Node
L3 authority keep a separate `Encoding(CborError)` because their vectors distinguish
outer encoding from embedded policy refusals; bootstrap keeps its bound
classification); variant names `Field`, `Stale`, `Signature`, `Issuer`, `Recipient`;
`RouteError` and `L3AuthorityError` replace borrowed variants; `AccountError` messages
no longer name the participant roster; `validate_admission_snapshot`,
`ServiceDirection`, `FrameKind`.

### Tests and vectors (P5, as implemented)

- One integration test binary per crate area: `nsshared-codec/tests/codec`,
  `nsshared-identity/tests/identity`, `nsshared-relay/tests/relay`,
  `nsshared-rendezvous/tests/rendezvous`, `nsshared-control/tests/{account,node_control,service}`.
- A test module that checks vectors reads `crates/<crate>/tests/vectors/<module path>.vec`
  through `nsshared_testkit::vectors!` or `vector_fields!`; its producer is
  `tools/vectors/nsvec/producers/<crate>/<module path>.py`. Example:
  `account::edge::routing` ↔ `tests/vectors/account/edge/routing.vec` ↔
  `producers/control/account/edge/routing.py`.
- `account.vec` is split by producer into `account/profile`, `account/control/envelope`,
  `account/node/enrollment`, `account/relay/participant-roster`,
  `account/subnet/selection` and `account/publication/envelope`.
- The M6 vectors are `nsshared-control/tests/vectors/service/canonical.json`, produced by
  `producers/control/service/canonical.py` on the shared CBOR module (`encode_value`).
- `vector-map.json` maps every base fixture to its new path; `vector_cases.py` proves every
  base case unchanged.

### Module mapping

| Current | Target |
| --- | --- |
| `proto::codec`, `proto::encoding`; M6 `cbor` | `nsshared-codec` (`cbor`, `cbor::value`, `base64`) |
| `proto::{keys, identity, realm_id, identifier, record, discovery}`; identity and record constants | `nsshared-identity` |
| `proto::relay`; relay constants | `nsshared-relay` |
| `proto::rendezvous`; presence and registry constants | `nsshared-rendezvous` |
| `proto::{account, node_control}`; all of `nsshared-service-control` | `nsshared-control` |
| `tests/support/vectors.rs` and the per-test hex and vector parsers | `nsshared-testkit` |

## Risks

- Byte equality: guarded by the existing vectors, the case comparison and the
  decoders' re-encode checks.
- Intended public API deltas (to be confirmed by semver-checks, none on paths used
  by the consumers):
  - `nsshared-service-control`: `CborError` and `ContractError` become
    `#[non_exhaustive]` (review B).
  - `nsshared-proto`: `account` is no longer exported (unreleased).
  - A2: scope text in publication content is checked by the shared scope-text rule
    (behaviour change, recorded in the changelog and the review request).
- Paths cited by the review package change in P4, P5 and D; the review request is
  updated in the same phase.

## Scope

All crates, `tools/vectors`, `justfile`, docs. Out of scope: nsd, ns, nsgw; removing
the facades; moving the external quick-v2 and rendezvous specifications; releases and
tags.

## Alternatives

- Keep M6 as its own crate on `nsshared-codec` (plan fallback): rejected by the owner
  decision to merge now.
- Re-export `account` from the `nsshared-proto` facade: rejected, see Facade
  decisions.

## Annotations

Owner decisions (2026-10-25) approve this scope: separate worktree branch from
`1bc1d39e`; review sections A and B; plan phases P1-P6; M6 merged into
`nsshared-control` as `service`; account reorganized freely; facades keep the
existing consumer paths; wire bytes unchanged except the stricter A2 scope text; no
push, merge or tag without the owner's word.

Owner decisions (2026-10-25, after phase A): phase A and the design calls are
accepted (no `account` re-export from `nsshared-proto`; mocks stay examples under
their package names, the testkit gets the vector reader and fixture identities;
facades deprecated in documentation and description only; A2 uses the strictest
rule). Continue P1-P6 and D without waiting between phases.

Implementation notes:

- cargo-semver-checks cannot follow re-exports into other workspace crates and
  reports every moved item as removed. `scripts/api_surface.py` lists public paths,
  signatures, fields, variants and trait impls from rustdoc JSON across workspace
  crates; `just semver` uses it for the facades.
- Grants and Node L3 authority keep a separate `Encoding(CborError)` variant: their
  vectors classify outer encoding refusals apart from embedded policy refusals.

## Progress

| Phase | Status | Head | Notes |
| --- | --- | --- | --- |
| P0 | done | ab9c885 | plan and task |
| A | done | 4f623d3 | A1-A4; gates: qa 0, vectors-check 0, cases 0 (2714 unchanged, 9 added), semver 0 x5, consumer paths 0 |
| P1 | done | 42c4810 | qa 0, vectors 0, cases 0, api_surface proto 0 x3, service-control 2 missing lines = intended `#[non_exhaustive]` on `CborError`, consumer paths 0, base tests 287/287 |
| P2 | done | dc7e9ff | qa 0 (after dropping proto's unused `getrandom`), vectors 0, cases 0, api_surface proto 0 x3, service-control: only the 2 intended lines, consumer paths 0, base tests 287/287; `RecordMarks::write`/`read` became public for the registry state |
| P3 | done | 97b8da4 | qa 0, vectors 0, cases 0, api_surface proto 0 x3, service-control: only the 2 intended lines, consumer paths 0, base tests 287/287 |
| P4 | done | df723a4 | qa 0, vectors 0, cases 0 (account fixtures moved to nsshared-control), api_surface proto 0 x3, service-control: 4 missing lines = intended `#[non_exhaustive]` on `CborError` and `ContractError` (two paths each), consumer paths 0, base tests 287/287 |
| P5 | done | 859d199 | qa 0, vectors 0 (42 files), cases 0 (all 2714 base cases at mapped paths, 9 additions), api_surface proto 0 x3, service-control: only the 4 intended lines, consumer paths 0, base tests 287/287; 545 tests in 7 binaries (was 75) |
| P6 | done | e5830e0 | qa 0 (`just semver`: proto api_surface 0 missing vs v0.6.0, telemetry semver-checks clean, new crates skipped), vectors 0, cases 0, api_surface proto 0 x3, service-control: only the 4 intended lines, consumer paths 0, base tests 287/287; mocks build on the defining crates |
| D | pending | | |
