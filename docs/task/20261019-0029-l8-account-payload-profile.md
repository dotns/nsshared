# L8 account payload profile

- **status**: completed
- **priority**: P1
- **owner**: account-contract
- **createdAt**: 2026-10-19 00:29

## Description

Deliver the candidate account frame: family registry, lifecycle distinctions,
Node L3 form, service usage units and both admission roster carriers. Detailed
family payloads follow separately. Candidate ownership for all registry entries
belongs to this record; detailed payload ownership will replace it as those
contracts are specified.

## ActiveForm

Specifying and validating the account payload candidate

## Dependencies

- **blocked by**: (none)
- **blocks**: detailed account payload contracts

## Investigation

`nsshared-proto::encoding` exposes strict array CBOR and canonical key text.
M6 already owns service declarations, references, listener intents, snapshots,
labels and messages. Its fixture bytes remain the reference. A local roster
must retain byte/count/freshness bounds while adding a required version and class.

## Proposal

Implement the [account specification](../l8-account-payload-profile.md) and
independent fixtures. Check decoding, signatures, scope ordering, incarnation
semantics, empty complete sets, malformed inputs and snapshot bounds.

## Acceptance

- Registry identifies all eleven families, replacement scopes, ownership and M6 reuse.
- Independent CBOR fixtures cover lifecycle, L3 rules, service units and signed roster.
- Local JSON accepts complete identity/class entries and refuses missing version,
  missing class, unknown fields, oversized content and duplicate identities.
- Static checks, fixture drift checks and scoped self-check pass.

## Notes

- The specification preceded implementation and is linked from `docs/architecture.md`.
- The candidate adds eleven typed registry entries, scoped replacement rules,
  separate membership/record counters and opaque grant/reporter incarnations,
  canonical L3 scopes/rules and explicit service byte and loss-window units.
- Both roster carriers publish full identity and class atomically, with the
  roster version serving as the attribution epoch. Signed validation checks
  issuer, recipient, monotonic version, validity and Ed25519 signature; local
  validation checks JSON shape, freshness, bounds and duplicate identities.
- The first `cargo test -p nsshared-proto --test account_vectors --locked`
  exited 101 with `could not find account in nsshared_proto` before the module
  existed. The independent fixtures subsequently passed all six integration tests.
- A refusal vector for object-shaped class content first failed in
  `strict_local_roster_vectors`: the derived enum admitted a JSON object.
  Parsing the raw class as a required string fixed the contract violation;
  the same vector passes in the complete check.
- `account.vec` contains 50 independent vectors. The Python signer checks an
  RFC 8032 known-answer case before producing signed roster bytes. Rust tests
  decode and re-encode candidate bytes, reject invalid forms and verify the
  independently generated signature. Count tests accept 8,192 identities and
  reject 8,193; byte vectors accept exactly 1 MiB and reject one byte more.
- `just fmt-check lint` passed before positive tests. The initial candidate
  `just self-check feat/l8-account-profile` selected `just qa` because vectors
  and their generator changed, and exited 0: 399 tests passed, 0 skipped;
  10 check-selection tests passed; 1 documentation test passed. Formatting,
  lint, supply-chain checks, spelling, both vector checks, API compatibility
  and documentation generation passed. API checks required no semver update.
- All nine existing service-control tests passed. Its source, generator and
  fixture bytes remain unchanged. The account registry references their
  existing definitions and bytes; no dependency or parallel M6 type was added.
- Source and fixtures match the passing check; only this acceptance record
  and the linked plan were updated afterward.

## Named-object validation correction

The derived JSON structs accepted positional arrays as well as objects. A root
array could therefore decode to an empty withdrawal, and an entry array could
supply a class without named fields. Require object-only deserialization at both
boundaries while forwarding the original map entries to the existing derives,
preserving duplicate/unknown-field rejection and all semantic validation.
Keep the named-field regression controls and array refusals, audit equivalent
JSON entry points, then run static checks, regression tests and the self-check.

The correction is complete in source commit
`e46d8481e8b32cbca07febb989734b60fd3dbeb4`:

- `JsonObject<T>` uses `deserialize_map` and forwards the original `MapAccess`
  through `MapAccessDeserializer` to the existing named-field derives. Both the
  root `JsonSnapshot` and every nested `JsonEntry` require actual objects.
  There is no intermediate map/value representation that can collapse keys.
- `snapshot_requires_named_roster_fields.rs` retains both valid-object controls,
  missing-field checks and positional-array refusals. Before the fix, both
  array assertions failed with successful admission results (exit 101).
  Additional raw-JSON cases preserve duplicate identity/class/version and
  unknown-field rejection at root and entry levels.
- `just fmt-check lint` passed before each test invocation. After the fix,
  `cargo test -p nsshared-proto --test snapshot_requires_named_roster_fields
  --test account_vectors --locked` exited 0: all 3 named-field tests and all
  6 candidate vector tests passed, with no ignored or filtered tests.
- `just self-check feat/l8-account-profile` on the source commit exited 0 and
  selected complete QA: 402 tests passed, 0 skipped; 10 check-selection tests
  and 1 documentation test passed. Static checks, both vector checks, API
  compatibility and documentation generation passed.
- The same-shape audit found only these two unprotected candidate boundaries.
  Rendezvous request/response envelopes and object payloads already require
  objects; directory/relay fields and nested waiting/message entries use their
  existing `Object<T>` wrapper. The mock executable directory readers consume
  the protected `Directory` type. No additional affected parsing site was found.
- Identity/class validation, byte/count bounds and freshness retain their
  existing checks. Canonical CBOR arrays remain intentional and unchanged;
  all nine M6 tests pass, and its sources, generator and fixtures are unchanged.
- Only this acceptance record and the linked plan changed after the passing
  source check. Documentation publication and reviewed candidate revision
  recording remain open below.

## Open work

- Publish the specification to the documentation site.
- Record the reviewed integration commit as the candidate revision when available.
