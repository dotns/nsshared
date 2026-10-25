"""Independent Node-control v2 contract and predecessor fixture encodings."""

import hashlib
import ipaddress

from nsvec import cbor, ed25519
from nsvec.producers.identity import record as node_records

CRATE = "nsshared-control"
GROUP = "node_control/messages"
TITLE = "Node-control v2 messages"
SPEC = "docs/spec/node-control.md"
EXTERNAL = "ns/quick-v2.md §9, §12.1"


def message(kind, body):
    return cbor.encode([2, kind, body])


def digest(encoded):
    return hashlib.blake2s(encoded, digest_size=16).digest()


def vectors():
    seed = bytes([2]) * 32
    identity = ed25519.public_key(seed)
    fields = node_records.body(identity, bytes([9]) * 32, 1, 10, 20, ["relay.example:443"])
    record = fields + [ed25519.sign(seed, node_records.signing_message(fields))]
    endpoints = [7, [[ipaddress.ip_address("192.0.2.1").packed, 51820, 0],
                     [ipaddress.ip_address("2001:db8::1").packed, 4500, 1]], ["relay.example:443"]]
    endpoint_bytes = message(1, endpoints)
    record_bytes = message(2, [record])
    messages = {
        "ack": message(0, [2, bytes([3]) * 16]),
        "ack_endpoints": message(0, [1, digest(endpoint_bytes)]),
        "ack_record": message(0, [2, digest(record_bytes)]),
        "endpoints": endpoint_bytes,
        "known_ack": message(0, [2, bytes(16)]),
        "known_probe_reply": message(4, [bytes([0xaa]) * 32]),
        "probe_reply": message(4, [bytes([0xaa]) * 32]),
        "probe_request": message(3, [bytes([0xaa]) * 32]),
        "record": record_bytes,
    }
    out = [[("name", name), ("encoded", encoded), ("ack_hash", digest(encoded))]
           for name, encoded in messages.items()]
    # Both producer families share the immutable predecessor source revision.
    out.append([("name", "empty-ack-hash"), ("hash_input", "empty"),
                ("ack_hash", digest(b""))])
    negatives = {
        "version": message(3, [bytes(32)]).replace(b"\x83\x02", b"\x83\x01", 1),
        "type": message(5, [bytes(32)]),
        "ack-type-overflow": message(0, [256, bytes(16)]),
        "non-shortest": b"\x83\x18\x02" + messages["probe_request"][2:],
        "indefinite": b"\x9f" + messages["probe_request"][1:],
        "trailing": messages["probe_request"] + b"\x00",
        "truncated": messages["endpoints"][:-1],
        "nonce-length": message(3, [bytes(31)]),
        "hash-length": message(0, [1, bytes(15)]),
        "outer-arity": cbor.encode([2, 3]),
        "body-arity": message(3, []),
        "oversize": bytes(1201),
        "candidate-count": message(1, [1, [[bytes(4), 1, 0]] * 9, []]),
        "relay-count": message(1, [1, [], ["relay.example:443"] * 5]),
        "candidate-ip": message(1, [1, [[bytes(5), 1, 0]], []]),
        "candidate-ip-bound": message(1, [1, [[bytes(17), 1, 0]], []]),
        "candidate-port-zero": message(1, [1, [[bytes(4), 0, 0]], []]),
        "candidate-port-overflow": message(1, [1, [[bytes(4), 65536, 0]], []]),
        "candidate-kind": message(1, [1, [[bytes(4), 1, 3]], []]),
        "relay": message(1, [1, [], ["relay.example:0"]]),
        "relay-length": message(1, [1, [], ["a" * 256]]),
        "record-signature": record_bytes[:-1] + bytes([record_bytes[-1] ^ 1]),
    }
    out.extend([[("name", name), ("encoded", encoded), ("expect", "reject"), ("reason", name)]
                for name, encoded in negatives.items()])
    return out
