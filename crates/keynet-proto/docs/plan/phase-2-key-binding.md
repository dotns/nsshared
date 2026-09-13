# Phase 2 KeyBinding

Implement the version-one KeyBinding model, canonical bounded CBOR profile,
ordinary Ed25519 signature profile, explicit interval checks, and pure scoped
high-water installation decisions from design sections 2.2 and 13.1-13.3.

The implementation remains synchronous and data-only. Callers provide signing
keys and explicit Unix seconds, retain state, and choose whether to commit a
returned transition proposal.
