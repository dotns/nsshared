# Phase 2 KeyBinding task

## Red test evidence

`cargo test -p keynet-proto --test key_binding --locked` initially failed with
`E0432`: `keynet_proto::KeyBinding` was not exported. The retained test now
checks the canonical eight-field version-one schema.

## Wire and signature profile

The pinned design file SHA-256 was checked as
`7c99ffb2e03c0728128da7270754aa065148e263fdc7c3aef233ff9696fa8a9f`.

The parser only accepts the fixed eight-field definite CBOR array and bounds
the complete and unsigned forms to 173-197 and 107-131 bytes respectively.
It performs no CBOR tree allocation. Parsing completes before signature
verification. Ed25519 uses the exact ASCII `keynet/key-binding/v1` context
immediately followed by the canonical seven-field array.

## State transitions

Cryptographic verification, explicit interval validation, and installation
decisions are separate. Installation accepts only a checked current binding,
returns a replacement-state proposal, and does not mutate caller state.
Generation zero is valid for an empty scope; equal-key replay is idempotent;
an equal-generation different-key record latches a conflict until a strictly
higher valid current nonrevoked record recovers it.

## Fixture rationale

The committed KeyBinding vectors contain public fixed signing seeds, literal
canonical unsigned arrays, complete preimages, signatures, signed arrays,
sizes, explicit current times, state inputs, decisions, and error outcomes.
Tests independently verify the literal preimages and signatures with
ed25519-dalek before exercising the crate API. The shared fixture loader also
requires the KeyBinding case inventory and preserves missing, duplicate,
unlisted, empty, and corruption defenses.
