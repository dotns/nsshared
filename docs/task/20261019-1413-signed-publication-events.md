# Signed publication events

- **status**: in_progress
- **priority**: P1
- **owner**: (assigned)
- **createdAt**: 2026-10-19 14:13

## Description

Define and implement pure signed per-scope/kind publication validation, owning-channel separation, atomic snapshot validation and pre-decode measured 1 MiB event bounds. Preserve the registry and all existing vectors. Prepare producer confirmation questions.

## ActiveForm

Awaiting complete repository verification after implementing signed publication decisions.

## Dependencies

- **blocked by**: none
- **blocks**: none

## Notes

Investigation: bootstrap carrier, immutable registry, service-control snapshot/message interfaces and independent vector conventions inspected. Decoder and writer public interfaces are reused; no new dependency is required.

Acceptance: publication_decoder_vectors consumes fixture decisions, canonical signed bytes and supplied clocks for replacement/withdrawal/absence/typed failure/unknown/wrong-channel/refusal, atomic snapshots, exact and over-limit events and malformed lengths. Generator check must match every committed vector. Formatting and lint precede passing tests; the scoped self-check validates the final source tree.

## Implementation and verification

- Added borrowed canonical publication decoding, independent issuer/recipient/scope checks, owning-channel decisions, positive per-key versions, actual exclusive validity, typed ACL failure denial and complete empty withdrawal. Oversized stream input returns termination before decoding; snapshots validate all events and key order before exposing decisions.
- Added 95 independently signed Python publication vectors, with supplied clocks, explicit decisions and expected retained versions. Existing fixture bytes and the immutable registry remain unchanged.
- Extended Q08 and Q21 while retaining prepared disposition. NSD producer confirmation and independent NSD output remain external requirements.
- Failing-first command: `cargo test -p nsshared-proto --test publication_decoder_vectors --locked`; compilation failed with `error[E0432]: unresolved imports` for the absent publication API before implementation.
- `just fmt-check` and `just lint` passed. `python3 tools/vectors/generate.py --check` reported nine fixture files up to date. Service-control vectors, dependency policy, spelling and API compatibility checks passed within the repository self-check.
- Final focused command: `cargo test -p nsshared-proto --test publication_decoder_vectors --test account_vectors --locked`; seven tests passed, zero failed or ignored. The publication test consumes all 95 fixtures and checks exact received encoded lengths, bounded borrowed payloads, noncanonical encodings, scope/version isolation and atomic rejection.
- The first repository self-check exposed generic account dispatch rejecting the newly added fixture kinds. Its two dispatch lists now defer those kinds to the dedicated publication consumer; that consumer checks trailing and nonminimal encodings for every decodable event and accepted snapshot, preserving the original assertions.
- Final `just self-check feat/l8-account-profile` exited 100 in the unrelated `external_mode_announces_wss_without_a_tcp_listener` test: `examples/mock-relay/tests/external.rs:269` returned `AddrInUse` (OS error 98). The test run reported 33 passed, one failed and zero skipped before cancellation. No mock-relay source was changed and no retry was used to obtain a passing result.

Implementation and focused acceptance are complete. Status remains in progress because complete repository verification is blocked by the mock-relay listener test.
