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
- `just fmt-check lint` passed before positive tests. The final
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

## Open work

- Publish the specification to the documentation site.
- Record the reviewed integration commit as the candidate revision when available.
- Add shared index and changelog entries when integrating this change.
