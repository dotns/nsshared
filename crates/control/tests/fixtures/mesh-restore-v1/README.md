# Mesh restore result v1 vectors

Authority: NS PLAN-218-mesh-contract C2, commit `b5afb9b5` (2026-09-11).

`vectors.json` freezes all nine legal phase/status combinations. Fields use
synthetic repeated bytes; the Relay Ed25519 test seed is 32 bytes of `0x0d`.
Timestamp is 1000, request/response nonce is 16 bytes of `0x05`, anchor sequence
is `u64::MAX`, and chunk index is 2047. No deployment secrets are included.

The initial bytes were produced independently using a Python definite-length
CBOR encoder and OpenSSL Ed25519 signing, without importing the product codec.
The Rust integration test independently reconstructs the response-domain input
and verifies the fixed signature, payload, complete envelope, UDP and WSS bytes.
All fields, including null key 7 for non-chunk results, are frozen explicitly.
Maximum UDP size is 357 bytes; no control frame limit is increased.

A must consume these same bytes when mirroring the shared API in NS. A valid
signature is insufficient alone: clients must match the outstanding request's
nonce, candidate identity, phase/index and pinned Relay key before using a result.
