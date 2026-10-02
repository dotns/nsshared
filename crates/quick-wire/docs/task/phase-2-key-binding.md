# Phase 2 KeyBinding task

## Red test evidence

`cargo test -p keynet-proto --test key_binding --locked` initially failed with
`E0432`: `keynet_proto::KeyBinding` was not exported. The retained test now
checks the canonical eight-field version-one schema.

During the v0.6 acceptance resume, the same focused command failed in
`installation_is_scoped_pure_and_handles_conflicts`: the conflict transition
returned `committed: None` instead of retaining the authenticated committed
generation and key required by section 13.3.

## Wire and signature profile

The active design pin is keynet v0.6 at docs commit `0f56552`, SHA-256
`494c50a12112aa88fe6fa084c0be9a14a2ca66415244ff202b72d89e08190fc1`.

The parser only accepts the fixed eight-field definite CBOR array and bounds
the complete and unsigned forms to 173-197 and 107-131 bytes respectively.
It performs no CBOR tree allocation. Parsing completes before signature
verification. Ed25519 uses the exact ASCII `keynet/key-binding/v1` context
immediately followed by the canonical seven-field array.

## State transitions

Cryptographic verification, explicit interval validation, and installation
decisions are separate. `CurrentKeyBinding` has private authenticated content
and is constructed only by `VerifiedKeyBinding::validate_current`; a raw
`KeyBinding` has no time-only route to installation. Installation accepts only
that checked current binding, returns a replacement-state proposal, and does
not mutate caller state.
Generation zero is valid for an empty scope; equal-key replay is idempotent;
an equal-generation different-key record latches a conflict until a strictly
higher valid current nonrevoked record recovers it. The conflict latch retains
the committed generation and key as high-water state while disabling both
same-generation candidates.

## Original-to-current assertion mapping

- The original missing-export RED maps to
  `key_binding_encodes_the_eight_field_v1_schema` and the literal vector codec
  assertions in `key_binding_vectors_are_literal_and_independently_verified`.
- Canonical schema and decode-before-verify rejection map to
  `canonical_decoder_rejects_malformed_data_before_signature_verification`.
- Signature context and authenticated-field coverage map to
  `signatures_cover_every_authenticated_field_and_the_exact_context` and the
  independent literal signature checks.
- Half-open validity and integer-width boundaries map to
  `widths_sizes_and_intervals_are_exact` and the literal boundary inventory.
- Scoped generation, revocation, idempotence, conflict retention, and
  higher-generation recovery map to
  `installation_is_scoped_pure_and_handles_conflicts`.
- The authenticated installation boundary maps to
  `only_checked_current_bindings_can_be_installed_and_scopes_are_independent`
  and `refutation_authentication`.

## Fixture rationale

The committed KeyBinding vectors contain public fixed signing seeds, literal
canonical unsigned arrays, complete preimages, signatures, signed arrays,
sizes, explicit current times, scoped state inputs, decisions, and rejection
outcomes. They include all CBOR integer-width boundaries and conflict and
invalid-signature cases. Tests independently verify literal preimages and
signatures before exercising the crate API, compare resulting typed state, and
retain missing, duplicate, unlisted, empty, and corruption defenses.

## Green and acceptance evidence

- `cargo test -p keynet-proto --test key_binding --locked`: 6 passed.
- `cargo test -p keynet-proto --test vectors --locked`: 4 passed.
- `cargo test -p keynet-proto --test refutation_authentication --locked`: 4
  passed.
- `python3 crates/keynet-proto/tests/refutation_cbor_dependency.py`: passed.
- `python3 -m unittest crates/keynet-proto/tests/refutation_literal_coverage.py`:
  3 passed.
- `cargo nextest run -p keynet-proto --locked`: 23 passed, 0 skipped.
- `cargo test -p keynet-proto --doc --locked`: 1 passed.
- `just qa`: 732 passed, 0 skipped; the output included all `keynet-proto`
  KeyBinding, vector, authentication, and inventory tests. Formatting, clippy,
  dependency policy, unused-dependency, and typo checks also passed.
- `/workspace` had 105-106 GiB free around the Rust checks and `oom_kill`
  remained 11.
