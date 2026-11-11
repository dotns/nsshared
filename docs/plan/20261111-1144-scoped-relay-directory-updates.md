# 20261111-1144-scoped-relay-directory-updates Network-scoped relay directory update contract

- **status**: completed
- **createdAt**: 2026-11-11 11:44
- **approvedAt**: 2026-11-11 11:44
- **relatedTask**: 20261111-1144-scoped-relay-directory-updates

## Context

`directory::check_update` requires every old relay to remain. NSD Network projections can remove a relay while the global directory still retains its permanent ID and code.

## Proposal

Add a separate stateful Account projection validator in nsshared. It enforces monotonic versions and permanent ID/code ownership over all accepted revisions, including removed entries. Leave the Quick validator unchanged. Update the rendezvous coverage and tests. Consumer PRs will persist the validator history and use it only for Account projections.

## Risks

Existing receiver state has no historical code map; seed from its retained current directory. A relay removed before receiver upgrade cannot be reconstructed from old local state, so NSD must retain global ID/code immutability.

## Scope

nsshared directory contract and tests, plus spec coverage. NSGW and NS consume this contract in separate PRs.

## Alternatives

Applying the removal exception to `check_update` would relax Quick's append-only rule, so keep separate validators.

## Annotations

The user directed B+C implementation and receiver-first deployment in the ongoing cross-repository delivery.
