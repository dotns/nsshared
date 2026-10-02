# Phase 3 PairingToken, PSK, and introduction task

## Status

Completed against keynet v0.6 at docs commit `0f56552`, SHA-256
`494c50a12112aa88fe6fa084c0be9a14a2ca66415244ff202b72d89e08190fc1`.

## Red test evidence

On the integrated phase-2 tree, the first focused command was:

`cargo test -p keynet-proto --test pairing_token --locked`

It failed with `E0432` because `keynet_proto::PairingToken` and
`keynet_proto::derive_pair_psk` did not exist. The final public test suite
retains that behavior boundary and exercises the implementation directly.

## Implemented behavior

- PairingToken uses the exact canonical twelve-field signed array and nested
  signed KeyBinding. Ordinary Ed25519 authenticates the context
  `keynet/pairing-token/v1` immediately followed by the eleven-field array.
- Strict decoding rejects noncanonical CBOR before signature work. Import
  acceptance checks issuer and network scope, both signatures, current binding,
  exclusive token expiry, recipient restriction, and caller-owned binding marks
  without mutating state.
- The `kn1` form is strict unpadded base64url with its 1024-byte pre-allocation
  gate. SHA-256 identifies canonical signed CBOR, not presentation text.
- Pair PSKs use HKDF-SHA256 with absent salt and fixed issuer-before-recipient
  ordering.
- INTRO and INTRO_ACK use their normative fixed arrays and separate
  HMAC-SHA256 contexts. Checked results require exact network and sender,
  binding scope/currentness, selected token association, and the live ACK nonce.
  HMAC verification uses the vetted primitive's constant-time verification.
- All operations are synchronous, caller-keyed, bounded, and free of runtime
  randomness, persistence, networking, timers, and replay storage.

## Original-to-current assertion mapping

- The missing-export RED maps to
  `signed_twelve_field_token_round_trips_all_optional_combinations` and
  `token_id_uses_signed_cbor_and_psk_identity_order_is_fixed`.
- Exact field order, nested binding shape, optional null/text/bytes forms, and
  signature transcript map to
  `signed_twelve_field_token_round_trips_all_optional_combinations`,
  `signature_covers_every_unsigned_token_field`, and
  `pairing_and_introduction_vectors_are_literal`.
- The 255/256 UTF-8 limits and 1024/1025 token-text limits map to
  `text_and_token_bounds_are_enforced`.
- Padding, whitespace, alphabet, unused-bit, and trailing-data rejection map to
  `text_form_rejects_padding_whitespace_alphabet_and_trailing_bits` and
  `token_text_refutes_nonzero_unused_bits_and_trailing_data`.
- CBOR indefinite lengths, non-shortest integers, wrong major types, wrong
  counts, invalid UTF-8, wrong widths, nested byte-string substitution, and
  trailing bytes map to `malformed_cbor_is_rejected_before_signature_acceptance`,
  `token_decoder_refutes_noncanonical_shapes_and_widths`,
  `malformed_cbor_is_rejected_before_mac_validation`, and
  `introduction_decoder_refutes_wrong_counts_types_widths_and_trailing_bytes`.
- Signature failure, field tampering, binding mismatch/invalidity/staleness,
  expiry equality, recipient mismatch, generation/revocation rejection, and
  unchanged caller state map to
  `strict_acceptance_checks_signature_binding_time_scope_and_recipient`,
  `signature_covers_every_unsigned_token_field`, and
  `rejected_input_proposes_no_state_transition`.
- Exact PSK derivation and identity-order sensitivity map to the literal PSK
  vector and `token_id_uses_signed_cbor_and_psk_identity_order_is_fixed`.
- Exact INTRO/INTRO_ACK arrays, independent literal MAC verification, separate
  contexts, all-field tampering, token-id coverage, exact live nonce, expected
  sender/network, and stale/invalid bindings map to the tests in `intro.rs`,
  `intro_mac_refutes_token_id_omission`, and the introduction literal vector.

## Fixture evidence

The committed pairing and introduction vectors were generated independently
with Python `cryptography` 43.0.0, Python standard-library HMAC/SHA-256, a
manual RFC 8949 encoder, and manual RFC 5869 expansion. They contain literal
unsigned and signed CBOR, signature, text bytes, token id, PSK, INTRO and ACK
preimages, MACs, and complete bodies. Rust tests independently verify the
Ed25519 signature and HMACs before checking the public API. The manifest pins
both files by SHA-256 and requires their case inventories.

## Verification evidence

- `cargo test -p keynet-proto --test pairing_token --locked`: 8 passed.
- `cargo test -p keynet-proto --test intro --locked`: 5 passed.
- `cargo test -p keynet-proto --test refutation_pairing_wire --locked`: 4 passed.
- `cargo test -p keynet-proto --test vectors --locked`: 5 passed.
- `cargo clippy -p keynet-proto --all-targets --locked`: passed.
- `cargo nextest run -p keynet-proto --locked`: 42 passed, 0 skipped.
- `cargo test -p keynet-proto --doc --locked`: 1 passed.
- `just qa`: 751 passed, 0 skipped; format, workspace Clippy, dependency policy,
  unused-dependency, and typo gates passed. The output included the actual phase-3
  pairing, introduction, refutation, and vector tests.
- `git diff --check`: passed.
- Incremental Rust review: PASS with no high-confidence findings.

The first repository QA attempt passed all 751 tests and dependency checks but
failed because the typo collector interpreted random letters inside the literal
base64url token as prose. The text literal is now stored as hexadecimal text
bytes and reconstructed by the vector test; the protocol value is unchanged.
The final repository QA run passed.

Before and after expensive checks, `/workspace` had 104-105 GiB free and
`oom_kill` remained 11.
