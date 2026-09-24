# Explicit relay PIN handoff

- **status**: completed
- **createdAt**: 2026-09-24 12:28
- **approvedAt**: 2026-09-24
- **relatedTask**: 20260924-1228-quick-explicit-relay-pin

## Context

URI invitations duplicate information already supplied by --relay and make
custom-relay handoff harder to read. Removal was explicitly requested.

## Plan

1. Replace URI parsing/formatting in both shared-crate copies with bare PINs.
2. Require one explicit relay for a bare PIN; reject ambiguous or conflicting
   selectors before connecting. Keep directory routing for prefixed codes.
3. Print a complete copyable command, retain private input and fingerprint
   confirmation, and synchronize customer-facing terminal examples.
4. Test parser and routing edges plus isolated default/custom-relay pairing
   and cleanup. Review security boundaries and record actual results.

## Boundaries

No legacy URI parser, no relay scanning, no weakened confirmation, no change
to account mode or temporary-state lifecycle. No public deployment/release.

Canonical crate implementation and focused validation are complete. NS CLI
integration and real executable checks remain tracked in NS, not claimed here.
