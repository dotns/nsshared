# Define the Keynet default context

Scope: publish the shared public identifier, record the selected profile and
add independent derivation vectors without changing the sealed wire v1 suite.
Baseline: `dd2783b` on `feat/keynet`; implementation branch:
`feat/keynet-default-context`.

- [x] Export a stable identifier with no shared signing key.
- [x] Verify address/slot vectors independently and device-signed pairing.
- [x] Preserve the existing v1 fixture manifest and vectors exactly.
- [x] Pass the shared workspace quality gate.

Client migration, public JSON, DNS and real TUN acceptance are coordinated in
the client task and are not closed by this task.

The initial QA passed 795 tests but failed the pre-existing
`RUSTSEC-2026-0285` advisory for rustls 0.23.41. The minimal lockfile update uses
rustls 0.23.45 and its required rustls-webpki 0.103.15; no advisory is ignored.

Validation (Linux, 2026-09-16, locally checked): `just qa` passed with all 795
tests, format, clippy, deny, shear and typos. The Python vector generator's
`--check` passed, and `git diff --exit-code` confirmed no changes in the sealed
fixture directory or `release_inventory.rs`. The focused default-context tests
also passed independently before the full gate.
