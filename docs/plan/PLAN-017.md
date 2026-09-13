# PLAN-017 Keynet-proto wire and derivation primitives for keynet v0.4

- **status**: approved
- **createdAt**: 2026-09-13 03:55 UTC
- **approvedAt**: 2026-09-13 04:09 UTC
- **campaign**: cmp-202609130355
- **designRevision**: `/workspace/nsiod/docs/docs/ns/keynet.md`, SHA-256 `7c99ffb2e03c0728128da7270754aa065148e263fdc7c3aef233ff9696fa8a9f`

## Context

The repository needs an independent `keynet-proto` workspace crate containing
the pure wire, cryptographic derivation, validation and fixture primitives for
keynet v0.4. It must not depend on existing internal crates, an async runtime,
networking or production filesystem access.

The authoritative design is the English keynet document named above. Its
normative section 13, Wire Profile, controls every byte-level question where
it differs from earlier prose. Builders do not edit the external design
checkout. Each implementation phase and the final fixture manifest pin the
same revision digest until an explicitly approved later revision replaces it.

## Approved decisions

1. Add the smallest root workspace lint table: `warnings` is denied and
   `unsafe_code` is forbidden. Only `keynet-proto` opts into it; existing
   member manifests and root quality-gate configuration remain unchanged.
   The new crate enforces missing documentation and runtime
   panic/unwrap/expect restrictions locally.
2. Keep implementation-facing plan and task tracking in
   `crates/keynet-proto/docs/plan/` and `crates/keynet-proto/docs/task/`.
   The root plan index links to the campaign plan only.
3. KeyBinding uses ordinary Ed25519 over `keynet/key-binding/v1` immediately
   followed by the canonical unsigned seven-field CBOR array. Validity is
   `not_before <= now < not_after`; generation state is scoped by
   `(network_id, I)` and uses committed generation plus optional
   revoked-through state. Equal generation with a distinct key latches a
   conflict.
4. PairingToken uses the normative twelve-field profile, including optional
   `issuer_name` directly after the binding. Its signature is ordinary
   Ed25519 over `keynet/pairing-token/v1` followed by the canonical unsigned
   eleven-field array. HKDF has absent salt; token text is capped at 1024
   bytes and each text field at 255 bytes.
5. INTRO uses a caller-supplied 32-byte nonce and the section 13 transcript.
   INTRO_ACK is the normative five-field array with its separate
   `keynet/intro-ack/v1` MAC context. Token lookup, nonce generation and
   replay storage remain caller responsibilities.
6. H22, alias candidates and label normalization follow section 13.4. The
   PairingToken `issuer_name` supplies the device name used by the default
   nickname behavior.
7. NameRecord uses the section 13.2 owner and network signature contexts,
   fixed operation tags, and its specified equal-version behavior.
8. Relay frames use sections 13.5 and 13.6: a four-byte big-endian body
   length, a 65536-byte body cap, and the normative type, payload, decoding
   and bounds profile. X25519 proof computation is a pure helper over supplied
   keys; connection handling remains outside this crate.
9. This document and the fixture suite use the pinned authoritative revision;
   a later revision requires a recorded approval and a replacement digest.

## Roadmap

| Phase | Name | Depends | Manager | Status |
|---|---|---|---|---|
| 1 | Independent crate and address/name derivation foundation | None | vkd2enid | Working |
| 2 | Canonical KeyBinding and generation decisions | 1 | — | Pending |
| 3 | PairingToken, PSK and INTRO | 1, 2 | — | Pending |
| 4 | Labels, alias candidates and NameRecord | 1, 2, 3 | — | Pending |
| 5 | Bounded typed relay frames | 1, 2, 3, 4 | — | Pending |
| 6 | Interoperability fixture release and final acceptance | 1, 2, 3, 4, 5 | — | Pending |

Each phase is refuted before its Architect review. Only one phase runs at a
time because build capacity is constrained. A phase is merged automatically
only after a passing review, a completed refutation report, no unresolved
blocker or major finding, no still-failing finding and a successful merged-tree
quality gate.

## Scope and acceptance

The crate provides only pure functions, strict bounded codecs and tests that
read committed fixture data. It covers address derivation and group conflict
checks, KeyBinding, PairingToken, PSK, INTRO/INTRO_ACK, names, labels, alias
candidates, NameRecord, relay frames and byte-exact interoperability vectors.

The crate does not add networking, I/O beyond test fixtures, persistence,
async runtimes, existing internal-crate dependencies, runtime key generation,
connection handling, DNS services, relay services or changes to existing
crates. `just qa`, crate-focused nextest and crate doctests are required at
the applicable phase boundaries. All public functions document their keynet
design section; all code forbids unsafe code.

## Campaign settings

- Merge gate: automatic when the documented refutation and review conditions
  are met.
- Parallel phase limit: one.
- Debug escalation threshold: two unresolved normal attempts.

## Phase status

Manager identifiers, merge bases, branch heads, refutation outcomes and final
quality-gate evidence are recorded here as phases are dispatched and merged.
