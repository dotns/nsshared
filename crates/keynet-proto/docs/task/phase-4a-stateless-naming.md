# Phase 4A stateless naming primitives task

## Status

Implemented against keynet v0.6 at docs commit `0f56552`, SHA-256
`494c50a12112aa88fe6fa084c0be9a14a2ca66415244ff202b72d89e08190fc1`.
The stateless subset is complete; full phase 4 remains deferred.

## Delivered boundary

- The existing H96 identity label remains the exact keyed BLAKE2s-12 and
  lowercase unpadded RFC 4648 base32 derivation, with fixed last-character
  unused bits.
- H22 exposes the upper 22 bits of the keyed BLAKE2s-3 digest and the ordered
  sixteen-candidate sequence for caller-supplied checked IPv4 pools. It does
  not deduplicate, allocate, filter routes, or retain state.
- Label normalization and received-label validation implement the ASCII byte
  rules, 63-byte limit, and reserved labels.
- NameRecord exposes canonical owner-signed and network-countersigned CBOR,
  exact ordinary Ed25519 contexts, strict decoding, signature checks, scope
  checks, and exclusive currentness. Its checked wrapper grants no version or
  installation decision.

Default nickname construction and collision handling are absent. NameRecord
version high-water, installation, idempotence, and conflict decisions are
absent. Alias allocation, route filtering, persistence, tombstones, user
aliases, exported mappings, resolver behavior, and naming runtime behavior are
absent.

## RED evidence and assertion mapping

The pre-implementation focused command, using the installed Cargo binary, was:

`env -u RUSTC_WRAPPER CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 /home/alan/.cargo/bin/cargo test -p keynet-proto --test naming --locked`

It failed with exit code 101 and `E0432`: `AliasPool`, `NameOperation`,
`NameRecord`, `alias_candidate`, `alias_candidates`, `normalize_label`, and
`validate_label` were unresolved imports from `keynet_proto`.

- The missing public derivation and validation surface maps to
  `p4a_public_surface_is_present`.
- H96 byte, alphabet, length, and zero-unused-bit assertions map to
  `identity_labels_have_exact_literal_bits_and_alphabet` and the pre-existing
  identity fixture test.
- H22 transcript, order, modulo, duplicate, kind, index, and checked-pool
  assertions map to `alias_vectors_are_literal_ordered_and_not_deduplicated`
  and `alias_input_and_checked_pool_boundaries_are_enforced`.
- Label byte rules and boundaries map to
  `label_normalization_and_validation_follow_ascii_byte_rules`.
- Exact two-layer NameRecord bytes and signatures map to
  `name_record_fixture_pins_both_canonical_signature_layers`.
- Operation tags, signature substitution, tampering, signer, scope, expiry,
  canonical-CBOR, hostile-length, and panic assertions map to the remaining
  focused NameRecord tests in `tests/naming.rs`.
- Empty, duplicate, missing, corrupted, and unlisted fixture behavior maps to
  `manifest_integrity_and_inventory_are_enforced` and
  `p4a_duplicate_missing_and_unlisted_cases_must_be_rejected`.

## Fixture evidence

The alias vectors were constructed independently with Python standard-library
keyed BLAKE2s. The NameRecord vector was constructed with a manual RFC 8949
encoder and independently signed Ed25519 keys. Production code does not
generate expected fixture data. `manifest.txt` fixes the complete inventory
and SHA-256 of every data file.

- `aliases.vec`: `0406dd0e60de7133e92323cdb3c391a17235b747cdd95a5167fb3d02ed6f3916`
- `labels.vec`: `2b0328e0c3fc700929d58dee51a1a3fbda48518f9304200a2ce3773fa86f5330`
- `name_records.vec`: `74584e2e68f2eaf382a63d4829b4ea9e92346bd37239208bba6a6e063d3a03e2`

## Verification evidence

- Focused naming tests: 11 passed.
- Existing vector tests: 5 passed.
- Fixture inventory/refutation tests: 11 passed.
- Crate nextest suite: 54 passed, 0 skipped.
- Crate documentation tests: 1 passed.
- Crate all-target Clippy: passed.
- Repository `just qa`: passed, including 763 nextest cases with the phase 4A
  naming cases present.
- `git diff --check`: passed.
- No direct dependency or lockfile change was required.
- Available space changed from 103,533,416 KiB before the expensive checks to
  102,737,108 KiB after final verification. Cgroup `oom_kill` remained 14;
  anonymous memory changed from 2,684,354,560 bytes to 5,019,852,800 bytes.
