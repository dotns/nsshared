# Shared Node-control codec

- **status**: completed
- **createdAt**: 2026-10-20 12:30
- **approvedAt**: 2026-10-20 12:30
- **relatedTask**: 20261020-1230-node-control-codec

## Context

The account registry names NodeControl but the canonical codec remains in consumers.
The immutable node source at `50f8e3fd95fac8bbc72aea9b132459103c3b206a`
contains ten test functions. The gateway fixture contains nine message encodings.

## Proposal

Specify the unchanged version-two messages, generate independent Python vectors,
then port the codec and all predecessor tests into a pure public module.
Preserve registry bytes and tie the module to FamilyId::NodeControl.

## Risks

Changing error order, ACK meaning or selection would break consumers. Preserve
all original validation and use independent byte comparisons.

## Scope

Proto module, consumer tests, vector producer, specification and coverage docs.

## Alternatives

Keeping duplicate consumer codecs risks drift. Runtime remains consumer-owned.

## Acceptance

The shared implementation preserves the predecessor production logic, with
import relocation and contract documentation only. All ten predecessor tests,
independent vector conformance, pinned gateway byte equivalence and byte-budget
selection passed. Repository self-check passed at
`52ac36af5e2565c41f33054a91d90820535b1735`: 429 tests passed, zero skipped,
with static, compatibility and documentation checks. No dependencies changed.
