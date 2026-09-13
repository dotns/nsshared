# Phase 5A stable relay wire and Revocation primitives task

## Status

Completed against keynet v0.6 at docs commit `0f56552`, SHA-256
`494c50a12112aa88fe6fa084c0be9a14a2ca66415244ff202b72d89e08190fc1`.
This released portion is unchanged in v0.7.

## Delivery boundary

- Implement the exact KNR1 header and all section 13.5 datagram bodies,
  direction rules, bounds, signatures, derivations, and MAC transcripts.
- Implement the six-field signed Revocation record and pure high-water
  decision behavior from sections 13.2 and 13.3.
- Preserve received relay names as UTF-8 text of 1 through 255 bytes.
- Defer relay identifier grammar and canonicalization, section 13.7 in-band
  control codecs, and constants introduced only in v0.7 to phase 5B.

Sockets, timers, relay state, persistence, forwarding, listeners, and
WebSocket behavior remain outside this pure crate.

## RED and GREEN evidence

The initial focused compile failed with `E0432` because the public relay and
Revocation codec and cryptographic APIs did not exist. The completed focused
suite exercises those production APIs and passes 11 adversarial tests.

The assertions cover every datagram family, exact header and datagram bounds,
direction and zero-slot rules, canonical CBOR rejection, field widths and
ranges, observed addresses, relay-name bytes, REGISTER admission, fixed
derivations and MACs, STATUS and REVOKE values, and Revocation authentication
and high-water decisions.

## Literal fixtures

`relay_revocation.vec` contains fixed bytes for all ten relay datagram
families, REGISTER unsigned bytes and signature, slot id, both ephemeral
public keys, X25519 shared secret, registration hash, session key, all five
relay control/reply MACs, and the unsigned and signed Revocation record. The
values were produced independently with a manual deterministic CBOR encoder
and independent signing, hashing, HMAC, HKDF, and X25519 calculations rather
than by the production codec.

- `relay_revocation.vec`: `4f36ef6e4e5f07cdb778aea2855f0ffbd9b1597f35f1530ad69dcc092bbe345a`
- `manifest.txt`: `fbeedb6c691da5e1fd6d1cdc1a4e225f4e34656bcadee16a276b9ebadae67e3b`

## Verification and resources

- Focused relay and Revocation suite: 11 passed.
- Focused fixture and inventory suites: 17 passed.
- Crate nextest: 66 passed, 0 skipped.
- Crate doctests: 1 passed.
- Crate all-target linting with warnings denied: passed.
- Repository quality gate: passed, including 775 tests with none skipped;
  dependency policy, unused-dependency, spelling, formatting, and lint checks
  passed. The gate retained its pre-existing yanked-dependency warning.
- Formatting and diff checks: passed.
- Available workspace space changed from 107,132,252 KiB before focused RED
execution to 106,725,244 KiB after repository verification.
- Cgroup `oom_kill` remained 15 throughout nontrivial checks.

No phase 5B codec, identifier rule, network behavior, or v0.7-only limit was
implemented.
