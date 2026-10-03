"""Registry publish proofs and HRW shard placement (quick-v2 §7.1, §7.2, §12.2; registry
domain from the relay directory of rendezvous §3.1, §5.4)."""

import hashlib
import ipaddress

from .. import derive, ed25519
from ..kdf import keyed_blake2s
from . import node_records
from . import rendezvous_common as common

CRATE = common.CRATE
GROUP = "registry"
TITLE = "NS rendezvous registry publish proofs and shard order, valid and rejected"
SECTIONS = "ns/quick-v2.md §7.1, §7.2, §12.2; ns/rendezvous.md §3.1, §5.4"

PUBLISH_CONTEXT = b"ns/registry-publish/v2"
SHARD_LABEL = b"ns-registry-shard-v2"
SHARD_REPLICAS = 2
LOOKUP_MAX = 4
CODE_LETTERS = "ABCDEFGHJKLMNPQRSTUVWXYZ"

DIRECTORY_VERSION = 3
# (id, code, host, ips, port, capabilities); entries 3, 5 and 8 lack `registry`.
RELAYS = [
    (1, "HK", "hkg-a1.relay.ns.io", ["203.0.113.1"], 443, ["udp", "wss", "mailbox", "registry"]),
    (2, "FR", "fra-b2.relay.ns.io", ["203.0.113.2", "2001:db8::2"], 443, ["udp", "wss", "mailbox", "registry"]),
    (3, "SJ", "sjc-c3.relay.ns.io", ["203.0.113.3"], 443, ["udp", "wss"]),
    (4, "NR", "nrt-d4.relay.ns.io", ["203.0.113.4"], 8443, ["udp", "wss", "mailbox", "registry"]),
    (5, "AM", "ams-e5.relay.ns.io", ["203.0.113.5"], 443, ["udp", "mailbox"]),
    (6, "SG", "sin-f6.relay.ns.io", ["203.0.113.6"], 443, ["udp", "wss", "mailbox", "registry"]),
    (7, "LA", "lax-g7.relay.ns.io", ["2001:db8::7"], 443, ["udp", "registry"]),
    (8, "SY", "syd-h8.relay.ns.io", ["203.0.113.8"], 443, ["wss", "mailbox"]),
    (9, "GR", "gru-j9.relay.ns.io", ["203.0.113.9"], 443, ["udp", "wss", "mailbox", "registry"]),
    (10, "BM", "bom.relay.ns.io", ["203.0.113.10", "203.0.113.11"], 443, ["udp", "region", "registry"]),
    (300, "ZR", "zrh-k1.relay.ns.io", ["203.0.113.30"], 443, ["wss", "mailbox", "registry", "x-future.1"]),
]


def directory_value():
    """Relay directory v2 in spec field order (rendezvous §5.4)."""
    ids, codes, hosts = set(), set(), set()
    relays = []
    for rid, code, host, ips, port, capabilities in RELAYS:
        assert 0 < rid < 2**16 and 0 < port < 2**16
        assert len(code) == 2 and all(c in CODE_LETTERS for c in code)
        assert 1 <= len(ips) <= 4 and all(str(ipaddress.ip_address(ip)) == ip for ip in ips)
        assert rid not in ids and code not in codes and host not in hosts
        ids.add(rid)
        codes.add(code)
        hosts.add(host)
        relays.append({"id": rid, "code": code, "host": host, "ips": ips, "port": port, "capabilities": capabilities})
    return {"version": DIRECTORY_VERSION, "relays": relays}


def registry_domain():
    """Directory entries that announce `registry` (quick-v2 §7.1)."""
    return [rid for rid, *_, capabilities in RELAYS if "registry" in capabilities]


def shard_weight(node_id, relay_id):
    """`w = BLAKE2s(out = 8, key = "ns-registry-shard-v2")(node_id ‖ e.id_be16)` (quick-v2 §7.1)."""
    return keyed_blake2s(SHARD_LABEL, node_id + relay_id.to_bytes(2, "big"), 8)


def shard_order(node_id, domain):
    """Descending `w`, ties by ascending `id` (quick-v2 §7.1)."""
    return sorted(domain, key=lambda rid: (-int.from_bytes(shard_weight(node_id, rid), "big"), rid))


def proof_message(nonce, authority, record, dns):
    """`"ns/registry-publish/v2" ‖ challenge.nonce ‖ authority ‖ SHA-256(record) ‖ dns_u8`
    (quick-v2 §7.2)."""
    return PUBLISH_CONTEXT + nonce + authority.encode("ascii") + hashlib.sha256(record).digest() + bytes([int(dns)])


def publish_value(record, dns, proof):
    """`publish {record, dns, proof}` payload (rendezvous §5.2)."""
    return {"record": common.b64u(record), "dns": dns, "proof": common.b64u(proof)}


def check_publish(record, dns, proof, nonce, authority, now):
    """Returns None for an accepted publish or why it is `invalid_message` (quick-v2 §7.2)."""
    reason = node_records.validate(record)
    if reason is not None:
        return f"record_{reason}"
    expires = node_records.cbor.decode(record)[5]
    if now >= expires:
        return "record_expired"
    identity = node_records.cbor.decode(record)[1]
    if not ed25519.verify(identity, proof_message(nonce, authority, record, dns), proof):
        return "bad_proof"
    return None


def shard_vector(name, label, domain):
    identity = derive.identity(derive.seed(label))
    node_id = derive.node_id(identity)
    order = shard_order(node_id, domain)
    weights = [shard_weight(node_id, rid) for rid in domain]
    assert len(set(weights)) == len(weights), "an HRW tie needs a Rust unit test instead"
    vector = [("name", name), ("node_seed_label", label), ("identity", identity), ("node_id", node_id)]
    for rid, weight in zip(domain, weights):
        vector += [("entry_id", rid), ("weight", weight)]
    vector += [("order", rid) for rid in order]
    vector += [("shard", rid) for rid in order[:SHARD_REPLICAS]]
    vector += [("lookup", rid) for rid in order[:LOOKUP_MAX]]
    return vector


def publish_vector(name, signer, record, nonce, authority, dns):
    message = proof_message(nonce, authority, record, dns)
    proof = ed25519.sign(signer.seed, message)
    assert check_publish(record, dns, proof, nonce, authority, common.NOW) is None
    return [
        ("name", name),
        ("seed", signer.seed),
        ("identity", signer.identity),
        ("node_id", derive.node_id(signer.identity)),
        ("record", record),
        ("now", common.NOW),
        ("nonce", nonce),
        ("authority", authority),
        ("dns", common.text_bool(dns)),
        ("record_sha256", hashlib.sha256(record).digest()),
        ("message", message),
        ("proof", proof),
        ("request", common.request("publish", publish_value(record, dns, proof))),
    ], proof


def publish_negative(name, record, dns, proof, nonce, authority, now, reason):
    actual = check_publish(record, dns, proof, nonce, authority, now)
    if actual != reason:
        raise AssertionError(f"negative publish {name}: expected {reason}, checker says {actual}")
    return [
        ("name", name),
        ("record", record),
        ("dns", common.text_bool(dns)),
        ("proof", proof),
        ("nonce", nonce),
        ("authority", authority),
        ("now", now),
        ("expect", "reject"),
        ("reason", reason),
    ]


def vectors():
    domain = registry_domain()
    assert len(RELAYS) >= 8 and len(domain) < len(RELAYS)
    out = [
        [("name", "directory"), ("directory", common.response("directory", directory_value()))]
        + [("domain_id", rid) for rid in domain]
    ]
    for i in range(1, 7):
        out.append(shard_vector(f"shard-node-{i}", f"ns-registry-node-{i}", domain))

    signer = node_records.Signer("ns-registry-publisher-v2", "ns-registry-publisher-wg-v2")
    other = node_records.Signer("ns-registry-other-v2", "ns-registry-other-wg-v2")
    record = common.record(signer)
    proofs = {}
    for authority, nonce, tag in ((common.AUTHORITY, common.NONCE, "a"), (common.OTHER_AUTHORITY, common.OTHER_NONCE, "b")):
        for dns in (True, False):
            vector, proof = publish_vector(f"publish-{tag}-dns-{common.text_bool(dns)}", signer, record, nonce, authority, dns)
            proofs[authority, dns] = proof
            out.append(vector)

    proof = proofs[common.AUTHORITY, True]
    args = (common.NONCE, common.AUTHORITY, common.NOW)
    tampered = bytearray(proof)
    tampered[10] ^= 0x01
    out.append(publish_negative("tampered-proof", record, True, bytes(tampered), *args, "bad_proof"))
    out.append(publish_negative("dns-flipped", record, False, proof, *args, "bad_proof"))
    out.append(
        publish_negative("wrong-authority", record, True, proof, common.NONCE, common.OTHER_AUTHORITY, common.NOW, "bad_proof")
    )
    out.append(publish_negative("wrong-nonce", record, True, proof, common.OTHER_NONCE, common.AUTHORITY, common.NOW, "bad_proof"))
    other_proof = ed25519.sign(other.seed, proof_message(common.NONCE, common.AUTHORITY, record, True))
    out.append(publish_negative("proof-by-other-identity", record, True, other_proof, *args, "bad_proof"))
    out.append(
        publish_negative("record-expired", record, True, proof, common.NONCE, common.AUTHORITY, common.WEEK, "record_expired")
    )
    bad_record = bytearray(record)
    bad_record[-5] ^= 0x01
    out.append(publish_negative("record-bad-signature", bytes(bad_record), True, proof, *args, "record_bad_signature"))
    return out
