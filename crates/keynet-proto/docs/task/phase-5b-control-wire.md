# Phase 5B relay identifiers and in-band control wire task

## Status

Completed against keynet v0.7 at docs commit `4ae04faa`, SHA-256
`ceeca74ab6dad33f34df36ef789c1d32014679c9592655439210c169b0bebce6`.

## Delivery boundary

- Implement the exact section 13.5.1 relay-identifier and endpoint grammar,
  including strict received-text rejection and explicit local canonicalization.
- Implement all eight section 13.7 in-band control records as exact canonical
  version-one CBOR arrays.
- Export the v0.7 limits and pure candidate/relay ordering and bounded-selection
  primitives needed by protocol consumers.
- Add independently produced fixed literal vectors and adversarial focused tests.

Timers, persistence, sockets, path selection, relay resolution, and runtime state
remain outside this pure crate. Existing fixtures and phase 1 through phase 5A
behavior remain unchanged except where v0.7 makes relay identifiers strict.

## Acceptance evidence

- RED: the initial focused `control_wire` test failed with unresolved public
  imports for `ControlRecord`, `EndpointHint`, and `RelayIdentifier`.
- GREEN: strict identifier parsing and local canonicalization cover DNS, IPv4,
  bracketed IPv6, short IDs, endpoints, exact size/port/label boundaries, and
  hostile signed text. Pairing-token and REGISTER admission reject
  noncanonical signed relay text before signature verification while the
  existing relay datagram fixture continues to round-trip byte-for-byte.
- Exact control assertions cover all type tags 0 through 7, canonical outer and
  body shapes, ACK BLAKE2s-16, BINDING cutover equality, nested records, legacy
  type-1 separation, candidate and relay ordering, selection/count/datagram
  caps, revision exhaustion, nonce widths, wrong versions/types/counts/widths,
  noncanonical integers, trailing data, and every v0.7 constant in crate scope.
- Original-to-current mapping: the absent public wire surface now has strict
  typed codecs; the former text-length-only PairingToken checks now enforce the
  section 13.5.1 grammar; the v0.6 REGISTER bytes remain decodable but strict
  admission now rejects their noncanonical example; the prior fixture inventory
  is preserved and extended with independently produced fixed identifier and
  control-record vectors.
- Fixture SHA-256: `control_records.vec`
  `661917e7611dbebfa2e629e405f8a0877b7209a79677e03fa2355adb02c01160`;
  `relay_identifiers.vec`
  `a5caf3b6317654663e28bcd403837261b003c6ddc457facc162cb66600711e9b`;
  `manifest.txt`
  `c339c0707fefb1e5a157419ff871af2ea624e330c6ff05cf10cdce84b24030fc`.
- Focused tests, crate tests, 80-test crate nextest run with zero skipped,
  doctest, clippy with warnings denied, rustfmt, documentation build, and diff
  checks passed. The final repository quality gate passed 789 tests with zero
  skipped; formatting, clippy, dependency policy, unused-dependency, and typo
  checks also passed. The dependency policy retained its existing duplicate,
  wildcard, and yanked `chacha20 0.10.1` warnings. No acceptance check was
  skipped. Before/after the final gate, anonymous memory was 3494002688 /
  6480814080 bytes, `oom_kill` remained 15, and `/workspace` had 100803916 /
  100673316 KiB available.
