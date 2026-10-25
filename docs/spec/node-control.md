# Node-control

The Node-control v2 codec (`nsshared_control::node_control`, re-exported as
`nsshared_proto::node_control`) encodes the ordinary Node-control messages of account
registry family 10 (`FamilyId::NodeControl`, see [the family registry](account/profile.md#family-registry-and-replacement)).
The registry publication is version 1; the control wire `VERSION` is independently 2
and `CONTROL_PORT` is 47900 at both ends. External specification: `ns/quick-v2.md`
§9 and §12.1. The codec is pure: transport, acceptance ordering, persistence,
retransmission, sessions and probe correlation belong to consumers.

## Messages

The canonical CBOR message is `[2, kind, body]`, at most 1200 encoded bytes
(`MAX_MESSAGE_BYTES`). Every array has exact arity and all integers use shortest
unsigned encoding.

| Kind | Body |
| --- | --- |
| 0 ACK | `[type_in_u8, hash_16]` |
| 1 ENDPOINTS | `[revision_u64, candidates, relays]` |
| 2 RECORD | `[NodeRecord]`, embedding the canonical signed array directly |
| 3 PROBE_REQUEST | `[nonce_32]` |
| 4 PROBE_REPLY | `[nonce_32]` |

ACK means **at least accepted**. A receiver that persists before ACK conforms; the
codec adds no durability or retransmission requirement. The hash is the unkeyed
BLAKE2s digest configured for 16-byte output over the entire encoded acknowledged
message, not a truncated 32-byte digest. Every u8 `type_in` is representable,
including unknown message kinds.

## Endpoints

ENDPOINTS contains at most eight candidates and four relay identifiers. A candidate
is `[ip_bytes, port, kind]`: exactly 4 or 16 IP bytes, port 1–65535, and kind 0
local, 1 reflected, or 2 configured. Relay strings use the canonical RelayId parser
(`nsshared_identity::relay_id`) and at most 255 UTF-8 bytes. Revision zero and
duplicate or unsorted input entries are wire-representable.

`Endpoints::select` sorts by IP byte length, IP bytes, port and kind, deduplicates
candidates and relays, places a listed home relay first, then the other relays in
byte order. It greedily adds candidates before relays subject to the count and total
byte limits. Its omitted count covers rejected unique entries, not duplicates.

## Refusals

Decoding rejects oversize input first, then malformed or noncanonical CBOR, a wrong
version, an unknown kind, malformed bodies and trailing bytes, in reading order.
Candidate and relay array-head errors map to `TooMany`. Candidate IP strings over
16 bytes produce CBOR string-length errors; other invalid IP lengths, ports or kinds
produce `Candidate`. ACK type overflow preserves `Type(0)`. Invalid relay syntax
produces `Relay`; embedded signed record validation produces `Record` after its
structural CBOR is read. Encoding preserves the supplied order and rejects excess
counts, zero candidate ports and messages over 1200 bytes.

## Conformance

The byte contract is the node codec at `50f8e3fd95fac8bbc72aea9b132459103c3b206a`.
The independent producer `tools/vectors/nsvec/producers/control/node_control/messages.py`
writes `crates/nsshared-control/tests/vectors/node_control/messages.vec`: the nine
gateway fixtures (gateway source `a00e6d61b5f0f635e740337131eb35514adbc46f`), both
known-byte examples and the empty-input ACK hash. The test module
`node_control::codec` keeps the ten predecessor test functions; `node_control::messages`
checks the independent bytes and rejections, and the predecessor fixture
`crates/nsshared-control/tests/vectors/node_control/predecessor.json`.
