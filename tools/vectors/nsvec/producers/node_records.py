"""NodeRecord canonical encoding, signature and rejection cases (quick-v2 §3.1, §3.2, §12.1-§12.3)."""

from .. import cbor, derive, ed25519, x25519

CRATE = "ns-wire"
GROUP = "node_records"
TITLE = "NS v2 NodeRecord encodings and signatures, valid and rejected"
SECTIONS = "ns/quick-v2.md §3.1, §3.2, §12.1, §12.2, §12.3"

VERSION = 2
CONTEXT = b"ns/node-record/v2"
MAX_BYTES = 600
MAX_RELAYS = 4
MAX_SERVICE_SECONDS = 604800
U64_MAX = cbor.U64_MAX

ISSUED_AT = 1790000000
HOME_RELAY = "hkg-a1.relay.ns.io:51822"


def relay_of_length(length, tag):
    """A lowercase DNS-name relay identifier `host:51822` of exactly `length` bytes, labels <= 63."""
    suffix = f".{tag}.relay.ns.io:51822"
    remaining = length - len(suffix)
    assert remaining >= 1
    labels = []
    while remaining > 64:
        labels.append("a" * 63)
        remaining -= 64
    if remaining == 64:
        labels += ["a" * 62, "a"]
    else:
        labels.append("a" * remaining)
    relay = ".".join(labels) + suffix
    assert len(relay) == length
    return relay


class Signer:
    def __init__(self, seed_label, wg_label):
        self.seed_label = seed_label
        self.seed = derive.seed(seed_label)
        self.identity = derive.identity(self.seed)
        self.wg_key = x25519.public_key(derive.seed(wg_label))


def body(identity, wg_key, gen, issued_at, expires, relays, version=VERSION):
    """The first seven fields, in order (quick-v2 §3.1)."""
    return [version, identity, wg_key, gen, issued_at, expires, list(relays)]


def signing_message(fields):
    """`"ns/node-record/v2" ‖ CBOR(first seven fields)` with no separator (quick-v2 §3.1, §12.2)."""
    return CONTEXT + cbor.encode(fields)


def sign(signer, gen, issued_at, expires, relays, version=VERSION):
    fields = body(signer.identity, signer.wg_key, gen, issued_at, expires, relays, version)
    message = signing_message(fields)
    signature = ed25519.sign(signer.seed, message)
    return fields, message, signature, cbor.encode(fields + [signature])


def validate(encoded):
    """Returns None for a valid record or the first violated rule (quick-v2 §3.1-§3.2, §12.1).

    A service period `expires - issued_at` above 604800 s makes the record invalid
    (quick-v2 §3.2, bound from §3.1 and §12.3); it is checked before the signature.
    """
    if len(encoded) > MAX_BYTES:
        return "too_large"
    try:
        record = cbor.decode(encoded)
    except cbor.CborError as err:
        return "trailing_bytes" if str(err) == "trailing bytes" else "non_canonical"
    if not isinstance(record, list) or len(record) != 8:
        return "array_arity"
    ver, ident, wg_key, gen, issued_at, expires, relays, sig = record
    if ver != VERSION:
        return "version"
    shapes = [(ident, bytes, 32), (wg_key, bytes, 32), (sig, bytes, 64)]
    if any(not isinstance(v, t) or len(v) != n for v, t, n in shapes):
        return "field_type"
    if any(not isinstance(v, int) for v in (gen, issued_at, expires)) or not isinstance(relays, list):
        return "field_type"
    if len(relays) > MAX_RELAYS:
        return "too_many_relays"
    if any(not isinstance(r, str) for r in relays):
        return "field_type"
    if gen == 0:
        return "zero_generation"
    if expires <= issued_at:
        return "expires_not_after_issued"
    if expires - issued_at > MAX_SERVICE_SECONDS:
        return "service_period"
    point = ed25519.decode_point(ident)
    if point is not None and ed25519.is_small_order(point):
        return "weak_identity"
    if not ed25519.verify(ident, signing_message(record[:7]), sig):
        return "bad_signature"
    return None


def positive(name, signer, gen, issued_at, expires, relays):
    fields, message, signature, encoded = sign(signer, gen, issued_at, expires, relays)
    reason = validate(encoded)
    if reason is not None:
        raise AssertionError(f"valid record {name} rejected: {reason}")
    vector = [
        ("name", name),
        ("seed_label", signer.seed_label),
        ("seed", signer.seed),
        ("identity", signer.identity),
        ("wg_key", signer.wg_key),
        ("gen", gen),
        ("issued_at", issued_at),
        ("expires", expires),
        ("relay_count", len(relays)),
    ]
    vector += [("relay", relay) for relay in relays]
    vector += [
        ("message", message),
        ("signature", signature),
        ("encoded_len", len(encoded)),
        ("encoded", encoded),
    ]
    return vector, encoded, fields, signature


def negative(name, encoded, reason):
    actual = validate(encoded)
    if actual != reason:
        raise AssertionError(f"negative record {name}: expected {reason}, validator says {actual}")
    return [("name", name), ("encoded", encoded), ("expect", "reject"), ("reason", reason)]


def flip(data, index, mask=0x01):
    out = bytearray(data)
    out[index] ^= mask
    return bytes(out)


def vectors():
    demo = Signer("ns-demo-node-v2", "ns-demo-wg-v2")
    other = Signer("ns-vector-identity-1", "ns-vector-wg-1")
    week = ISSUED_AT + MAX_SERVICE_SECONDS
    four = [HOME_RELAY, "fra-b2.relay.ns.io:51822", "sjc-c3.relay.ns.io:443", "nrt-d4.relay.ns.io:51822"]

    out = []
    minimal, minimal_enc, minimal_fields, minimal_sig = positive("minimal", demo, 1, ISSUED_AT, week, [])
    out.append(minimal)
    out.append(positive("home-relay", demo, 1, ISSUED_AT, week, [HOME_RELAY])[0])
    max_relays, max_enc, _, _ = positive("max-relays", demo, 3, ISSUED_AT, week, four)
    out.append(max_relays)
    out.append(positive("other-identity", other, 7, ISSUED_AT + 3600, ISSUED_AT + 7200, [HOME_RELAY])[0])

    # Fill four relays so the record is exactly MAX_BYTES; one more byte is too large.
    _, _, _, probe = sign(demo, 1, ISSUED_AT, week, [relay_of_length(100, f"e{i}") for i in range(4)])
    spare = MAX_BYTES - len(probe)
    assert spare >= 0 and spare % 4 == 0
    edge = [relay_of_length(100 + spare // 4, f"e{i}") for i in range(4)]
    size_max, size_max_enc, _, _ = positive("size-600", demo, 1, ISSUED_AT, week, edge)
    assert len(size_max_enc) == MAX_BYTES
    out.append(size_max)
    out.append(positive("relay-255-bytes", demo, 1, ISSUED_AT, week, [relay_of_length(255, "long")])[0])
    out.append(positive("longest-service-period", demo, 2, ISSUED_AT + 1, week + 1, [])[0])
    out.append(positive("shortest-service-period", demo, 1, ISSUED_AT, ISSUED_AT + 1, [])[0])
    out.append(positive("int-boundary-1-2-bytes", demo, 23, 255, 256, [])[0])
    out.append(positive("int-boundary-2-4-bytes", demo, 65535, 65536, 65536 + MAX_SERVICE_SECONDS, [])[0])
    out.append(positive("int-boundary-4-8-bytes", demo, 2**32 - 1, 2**32, 2**32 + 1, [])[0])
    out.append(positive("int-max-u64", demo, U64_MAX, U64_MAX - 1, U64_MAX, [HOME_RELAY])[0])

    # Negative vectors: each breaks exactly one rule.
    out.append(negative("tampered-signature", flip(minimal_enc, len(minimal_enc) - 24), "bad_signature"))
    k_offset = minimal_enc.index(demo.wg_key)
    out.append(negative("tampered-wg-key", flip(minimal_enc, k_offset), "bad_signature"))
    relay_offset = max_enc.index(HOME_RELAY.encode())
    out.append(negative("tampered-relay", flip(max_enc, relay_offset, 0x02), "bad_signature"))
    s_plus_l = int.from_bytes(minimal_sig[32:], "little") + ed25519.L
    out.append(
        negative(
            "non-canonical-s",
            cbor.encode(minimal_fields + [minimal_sig[:32] + s_plus_l.to_bytes(32, "little")]),
            "bad_signature",
        )
    )

    def reencode(gen_head=None, ident_head=None, outer_head=None, relays_raw=None):
        ver, ident, wg_key, gen, issued_at, expires, relays = minimal_fields
        parts = [
            outer_head or cbor.head(cbor.ARRAY, 8),
            cbor.encode(ver),
            (ident_head or cbor.head(cbor.BYTES, 32)) + ident,
            cbor.encode(wg_key),
            gen_head or cbor.encode(gen),
            cbor.encode(issued_at),
            cbor.encode(expires),
            relays_raw or cbor.encode(relays),
            cbor.encode(minimal_sig),
        ]
        return b"".join(parts)

    assert reencode() == minimal_enc
    out.append(negative("non-canonical-gen", reencode(gen_head=cbor.head(cbor.UINT, 1, 1)), "non_canonical"))
    out.append(
        negative("non-canonical-bytes-length", reencode(ident_head=cbor.head(cbor.BYTES, 32, 2)), "non_canonical")
    )
    out.append(
        negative("non-canonical-array-length", reencode(outer_head=cbor.head(cbor.ARRAY, 8, 1)), "non_canonical")
    )
    out.append(negative("indefinite-relays", reencode(relays_raw=bytes([0x9F, 0xFF])), "non_canonical"))
    out.append(negative("trailing-bytes", minimal_enc + b"\x00", "trailing_bytes"))
    out.append(negative("array-arity-7", cbor.encode(minimal_fields), "array_arity"))
    for version in (1, 3):
        encoded = sign(demo, 1, ISSUED_AT, week, [], version=version)[3]
        out.append(negative(f"version-{version}", encoded, "version"))
    long_period = sign(demo, 1, ISSUED_AT, week + 1, [])[3]
    out.append(negative("service-period-too-long", long_period, "service_period"))
    out.append(negative("expires-equal-issued", sign(demo, 1, ISSUED_AT, ISSUED_AT, [])[3], "expires_not_after_issued"))
    out.append(negative("expires-before-issued", sign(demo, 1, ISSUED_AT, ISSUED_AT - 1, [])[3], "expires_not_after_issued"))
    out.append(negative("zero-generation", sign(demo, 0, ISSUED_AT, week, [])[3], "zero_generation"))
    five = four + ["ams-e5.relay.ns.io:51822"]
    out.append(negative("too-many-relays", sign(demo, 1, ISSUED_AT, week, five)[3], "too_many_relays"))
    edge_large = edge[:3] + [relay_of_length(len(edge[3]) + 1, "e3")]
    too_large = sign(demo, 1, ISSUED_AT, week, edge_large)[3]
    assert len(too_large) == MAX_BYTES + 1
    out.append(negative("too-large", too_large, "too_large"))

    # Identity point of order 1 with R = [7]B, S = 7: the cofactorless equation holds for
    # every message, so only the small-order check rejects it (quick-v2 §12.2).
    weak = ed25519.encode_point(ed25519.IDENTITY)
    weak_fields = body(weak, demo.wg_key, 1, ISSUED_AT, week, [])
    forged = ed25519.encode_point(ed25519._mul(7, ed25519.BASE)) + (7).to_bytes(32, "little")
    assert ed25519.verify(weak, signing_message(weak_fields), forged, strict=False)
    out.append(negative("small-order-identity", cbor.encode(weak_fields + [forged]), "weak_identity"))
    return out
