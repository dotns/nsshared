# Candidate handoff

- **status**: implementing
- **createdAt**: 2026-10-24 11:15
- **approvedAt**: 2026-10-24 11:15
- **relatedTask**: 20261024-1115-candidate-handoff

## Context

The selected package is 50dc9db5fe106536d0a7d8b113b5bb4a3e210368.
The earlier review package remains historical. Existing QA regenerates independent
vectors, checks dependencies and compares public APIs against the previous release.
It does not compare another repository's immutable manifests and lockfiles.
The specified current gateway inputs agree on the selected package; frozen r1
inputs are historical. NSD and ns adoption and producer review remain unresolved.

## Proposal

Document every delivered shared contract and its independent consumer vectors,
subsequent corrections, external obligations and ownership. Add a read-only
comparison of exact gateway manifest/lock inputs with the selected revision and
of local package, lock, API source and vector inputs with that revision. Reuse
existing QA rather than duplicating vector generation or API compatibility checks.

## Scope

Handoff and review documentation, one comparison tool and its focused test.

## Risks

A pin is delivery evidence only for the specified inputs. It does not establish
producer agreement, runtime interoperability or release approval. Consumer lock
files resolve their own dependency graphs and need not equal the shared lockfile.

## Alternatives

Documentation alone cannot detect changed source or a mismatched lock resolution.
Running another full QA inside the comparison would duplicate existing checks.
