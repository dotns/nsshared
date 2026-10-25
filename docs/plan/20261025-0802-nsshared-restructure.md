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
3. `cargo semver-checks` on `nsshared-proto` against `v0.6.0` and against `aba1c5d5`
   (consumer pin), and on `nsshared-service-control` against `aba1c5d5`, reports no
   breaking change other than the intended deltas listed under Risks.
4. A scratch crate outside the repository that imports every `nsshared_proto` and
   `nsshared_service_control` item used by the consumer main lines builds against the
   branch.

Gate tools (in [this plan's directory](20261025-0802-nsshared-restructure/)):

- `vector_cases.py BASE vector-map.json` compares every case of every fixture at
  `BASE` with the working tree through the `moves` map and the listed `added` cases.
- `consumer_paths.py OUT SHARED CONSUMER...` collects the `nsshared_proto` and
  `nsshared_service_control` paths used by consumer sources and writes a crate that
  imports each one. At the consumer pin `aba1c5d5` all 238 collected paths resolve.

### Account layout inside nsshared-control (P4)

```
account/
  mod.rs        error type, flat re-exports of the public contract types
  codec.rs      private: reader/writer helpers, ordered sets, optional fields,
                ServiceRef round trip, bounded text
  limits.rs     private: shared bounds
  methods.rs    method names and paths of the control exchange
  signing.rs    private: one domain-separated sign and verify helper
  domains.rs    signature domains (bytes unchanged)
  node/         lifecycle, enrollment, l3, l3 authority
  control/      bootstrap, envelope, signed request, exchange, machine token,
                reports, route command, node L3 status, service control carrier
  publication/  envelope, registry, source binding, source publication,
                subscription, snapshot request
  families/
    realm/      peers, policy subject, subject rules, policy claims
    grants/     grants, payers, resource authority
    subnet/     views, provider mapping, provider subnet report
    edge/       routing, declaration, material, confidential auth, certificate
    relay/      roster, participant roster, participant session, directory binding
    usage/      usage, report, answer, relay usage, profile publications
```

Exact module names are settled during P4 and recorded here.

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

## Progress

| Phase | Status | Head | Notes |
| --- | --- | --- | --- |
| P0 | done | ab9c885 | plan and task |
| A | done | 4f623d3 | A1-A4; gates: qa 0, vectors-check 0, cases 0 (2714 unchanged, 9 added), semver 0 x5, consumer paths 0 |
| P1 | pending | | |
| P2 | pending | | |
| P3 | pending | | |
| P4 | pending | | |
| P5 | pending | | |
| P6 | pending | | |
| D | pending | | |
