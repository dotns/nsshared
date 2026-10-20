# Service grant and Node authority contracts

- **status**: implementing
- **createdAt**: 2026-10-20 15:09
- **approvedAt**: 2026-10-20 15:09
- **relatedTask**: 20261020-1509-grant-authority

## Context

The registry names grants, payer and withdrawal but has no corresponding payload codecs. Existing Node L3 scopes and rules contain full identities without authorized transport keys. Subnet selection already validates route references and exact prefix arithmetic. Service usage still has its predecessor subject type and is revised separately.

## Proposal

Add bounded, canonical pure grant publications, payer bindings and resource authority snapshots. Reuse canonical M6 ServiceRef bytes and existing Subnet publications. Require exactly one explicit realm-local 16-byte UserId payer. Keep retired tokens as caller-supplied validated data and validate successor snapshots without owning state. Add a Node L3 authority wrapper with explicit identity-to-key bindings, preserving existing policy bytes. Define independent accepted and refused vectors before implementation.

## Risks

Missing and ambiguous payer must not become inferred authority. Retired tokens must survive replacement, including identical-content regrant. Missing membership, binding or policy must deny. An authority wrapper grants no transport installation or authenticated issuer trust by itself.

## Scope

Account contracts, independent producer and consumer fixtures, profile and review request. No runtime, session, usage wire revision or duplicate M6 codec.

## Verification

Run the consumer first to establish failure, then format/lint and focused contract tests. Run the prescribed self-check before marking completed. Independent fixtures describe candidate authority, not live producer interoperability.
