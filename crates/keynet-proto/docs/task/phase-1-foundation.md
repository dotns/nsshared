# Phase 1 foundation task

## Red test evidence

`cargo nextest run -p keynet-proto --locked` initially failed as intended:
`phase_one_address_derivation_is_not_implemented_yet` asserted `0 == 1`.

## Dependency rationale

`blake2` 0.10.6 was already locked and provides fixed-output keyed BLAKE2s;
it is the only production dependency. `sha2` 0.10.9 was already locked and is
test-only for fixture-manifest SHA-256 verification.
