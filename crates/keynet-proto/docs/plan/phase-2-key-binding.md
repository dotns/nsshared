# Phase 2 KeyBinding

- **status**: completed
- **designRevision**: keynet v0.6, docs commit `0f56552`, SHA-256 `494c50a12112aa88fe6fa084c0be9a14a2ca66415244ff202b72d89e08190fc1`

Implement the version-one KeyBinding model, canonical bounded CBOR profile,
ordinary Ed25519 signature profile, explicit interval checks, and pure scoped
high-water installation decisions from design sections 2.2 and 13.1-13.3.

The implementation remains synchronous and data-only. Callers provide signing
keys and explicit Unix seconds, retain state, and choose whether to commit a
returned transition proposal.

Acceptance against the active pin passed the focused KeyBinding suite, literal
vectors, authentication and codec refutations, crate nextest, crate doctests,
and the full repository quality gate.
