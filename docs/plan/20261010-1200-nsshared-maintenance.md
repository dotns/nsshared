# 20261010-1200-nsshared-maintenance Put nsshared in maintenance after v0.6.0

- **status**: completed
- **createdAt**: 2026-10-10 12:00
- **approvedAt**: 2026-10-10 12:00
- **relatedPlan**: 20261004-0900-nsshared-api-stability

## Context

Every request from the consumers' current plans is delivered: the nsgw
next-architecture draft (docs `27a794d`) marks L10 delivered in `v0.6.0` and
asks nothing of nsshared for R0, R1 and R2. The remaining requests are new
contracts tied to later milestones. nsplane 0.11 (`v0.11.0`, `d788269`) makes
the data plane business-agnostic; nsshared does not depend on nsplane, so the
release needs no change here.

## Proposal

nsshared becomes a foundation library in maintenance. It takes fixes,
dependency and toolchain updates, and milestone contracts added as new modules
or crates in minor releases, docs first:

| # | Contract | Trigger |
| --- | --- | --- |
| L11 | Control resource and session protocol | Gateway protocol chosen (nsgw G9, G11 to G13) |
| L8 | M6 payload profiles, including the serialized policy contract | R3 / M6 |
| L9 | Short-name application and the relay to authoritative DNS feed | R4 / M8 |

`v1.0.0` follows once ns and the relay v2 server pass their interop tests on
one implementation.

## Decisions on open questions

- **Mailbox export and restore** (nsgw draft, R1 row): not in nsshared. Mailbox
  state is private to the relay (rendezvous §5.3), held by one owner per epoch
  and never replicated between members, so only one component reads it; it
  belongs to `nsgw-rendezvous`. Registry state differs: members merge it and
  nodes apply the same §3.3 rules, which is why L10 is here.
- **Node relay v2 client** (nsplane 0.11 migration notes, §6): in ns, not
  nsshared. It is node runtime state (sessions, attempts, liveness); ns
  `overlay` already holds `RelayClient`. nsshared keeps the packet codecs and
  admission rules both ends use.
- **Policy documents and source labels moved out of nsplane 0.11**: the label
  text is local to each process and stays with ns and nsgw. The NSD policy
  document that ns and the gateway both read is a v1 contract kept by its
  consumers until M6 (nsgw G4, G5); its redesigned form is part of L8.

## Annotations

- 2026-10-10: Owner asked to record the maintenance rules after reviewing the
  docs.
