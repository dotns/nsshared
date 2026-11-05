# 20261105-1239-ordinary-node-l3-echo Ordinary Node L3 Echo authorization

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-11-05 12:39

## Description

Define fixed IPv4 and IPv6 Echo authorization in the Node L3 contract while preserving exact authority boundaries, TCP/UDP bytes, non-Node refusal and fail-closed consumer enablement.

## ActiveForm

Implementing and validating the Node-only Echo contract.

## Dependencies

- **blocked by**: none for the shared contract
- **blocks**: compatible producer and consumer integration

## Investigation

The Node L3 codec currently uses the TCP/UDP-only TransportProtocol shared with Service grants and Realm rules. Both protocol decoding and nonzero port validation refuse Echo. The existing canonical six-field rule and exact namespace/identity authority wrapper must remain intact. A distinct L3Protocol can add fixed Echo selectors without widening unrelated authority. The public Node module needs only a re-export of that type.

## Approved implementation

See [the implementation plan](../plan/20261105-1239-ordinary-node-l3-echo.md). The authorized public module change is limited to exporting L3Protocol. Runtime support declarations require authenticated exact custody; decoding support alone is insufficient.

## Acceptance

- Canonical Echo forms and legacy TCP/UDP round-trip through actual codecs; malformed fields and unknown protocols fail.
- Complete authority retains namespace, identity/key and direction boundaries and default deny; unrelated families refuse Echo.
- Normative request/reply, capability and version rules supply a precise immutable integration contract while retaining the released enforcement prerequisite.

## Notes

The initial focused decoder test failed on protocol 1 with `AccountError::Field`. Standalone formatting and lint checks passed before that run. The implementation adds the distinct Node protocol type and zero-slot validation; the existing non-Node decoders remain unchanged.


## Acceptance results

- `ordinary_node_echo_canonical_protocol_forms` first failed with `protocol 1 must decode: Field`. The actual Node L3 decoder refused the new selector before implementation.
- Canonical protocol 1 and 58 now round-trip with two zero slots. Existing TCP/UDP fixtures retain their exact bytes and inclusive nonzero ranges. The profile tests refuse unknown protocols, type/code operands, malformed arities, nonzero Echo slots, invalid transport ranges, duplicate rules and ordering violations.
- `ordinary_node_echo_exact_authority_boundaries` validates complete authority encoding and preserves issuer, recipient, namespace membership and identity/key bindings. Its fixture rule interpretation checks request direction, missing rules, other identities, namespaces and IP families. Invalid, absent and repeated keys are refused by actual authority validation.
- Route-admission codec forms construct both selectors with fixture client/provider identities. Existing mapped-route admission vectors retain their original independent selection checks. Service, Realm and public-edge codecs explicitly reject Node-only Echo values.
- Standalone `just fmt-check lint` passed before the failing test and after implementation. The focused selection passed all 32 selected tests. The final self-check selected full QA and passed 70 script tests, 422 default-feature nextest tests and 588 account-feature nextest tests. Both nextest runs had zero skips. Formatting, lint, supply-chain, unused-dependency, spelling, vectors, API compatibility, doctests and documentation checks passed; each doctest configuration retained its existing single ignored example.
- Local review found no unresolved contract, scope or compatibility defects. Only the public L3Protocol re-export changes the Node module surface. Other families retain TransportProtocol and their existing TCP/UDP-only decoders.
- The normative specification records fixed request/reply types and code zero, exact authenticated runtime capability custody, complete unsupported-runtime TCP/UDP projection and old-decoder refusal. Packet enforcement and reply-state delivery remain unqualified until a compatible immutable released code-zero-before-state path is verified. No runtime support is advertised by this contract change.

## Final validation

- [ ] Run the complete integration check on the composed source.
