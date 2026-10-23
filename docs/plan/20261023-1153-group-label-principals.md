# Refuse group labels as principals

- **status**: implementing
- **createdAt**: 2026-10-23 11:53
- **approvedAt**: 2026-10-23 11:53
- **relatedTask**: 20261023-1153-group-label-principals

## Context

The profile excludes group labels from credential principals, but six anonymous public-edge matching rows classify them as verified and three admit them. The fixture consumer compares them directly with selectors. The existing verified Node row already demonstrates explicit group membership independently of the qualified user.

## Proposal

Clarify the matching table, classify the six group-label rows as refused input, and reject group subjects before selector matching. Add regression assertions against both the consumer and generated outcomes. Regenerate fixtures with the independent producer.

## Risks

The change corrects fixture semantics only. Preserve every existing selector and policy byte, group membership, credential binding, and admin claim.

## Scope

The account payload profile, anonymous public-edge producer, generated fixture, and matching consumer tests.

## Alternatives

Retaining verified-group terminology risks treating a selector as a credential principal; use group-label instead.
