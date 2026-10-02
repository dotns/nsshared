"""Known-answer self-test of the embedded primitives; generation aborts on any mismatch."""

import hashlib

from . import cbor, ed25519, kdf, x25519

# RFC 8032 §7.1: (secret key, public key, message, signature).
ED25519_VECTORS = {
    "TEST 1": (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    "TEST 2": (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    "TEST 3": (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    "TEST SHA(abc)": (
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
        "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
}

# RFC 7748 §5.2: (scalar, u-coordinate, output).
X25519_VECTORS = [
    (
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    ),
    (
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    ),
]
# RFC 7748 §5.2 iterated function: iterations -> k.
X25519_ITERATIONS = {
    1: "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
    1000: "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
}
# RFC 7748 §6.1.
X25519_DH = {
    "a": "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    "ka": "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    "b": "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    "kb": "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    "k": "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
}

# RFC 8949 Appendix A examples that fall inside the quick-v2 §12.1 subset.
CBOR_EXAMPLES = [
    (0, "00"),
    (1, "01"),
    (10, "0a"),
    (23, "17"),
    (24, "1818"),
    (25, "1819"),
    (100, "1864"),
    (1000, "1903e8"),
    (1000000, "1a000f4240"),
    (1000000000000, "1b000000e8d4a51000"),
    (18446744073709551615, "1bffffffffffffffff"),
    (None, "f6"),
    (b"", "40"),
    (bytes.fromhex("01020304"), "4401020304"),
    ("", "60"),
    ("a", "6161"),
    ("IETF", "6449455446"),
    ('"\\', "62225c"),
    ("ü", "62c3bc"),
    ("水", "63e6b0b4"),
    ("\U00010151", "64f0908591"),
    ([], "80"),
    ([1, 2, 3], "83010203"),
    ([1, [2, 3], [4, 5]], "8301820203820405"),
    (list(range(1, 26)), "98190102030405060708090a0b0c0d0e0f101112131415161718181819"),
]
# RFC 8949 Appendix A encodings outside the subset; the strict decoder must reject them.
CBOR_REJECTED = [
    "c249010000000000000000",  # tag
    "20",  # negative integer
    "f90000",  # float
    "f4",  # false
    "a0",  # map
    "5f42010243030405ff",  # indefinite byte string
    "9fff",  # indefinite array
    "83018202039f0405ff",  # nested indefinite array
]


class SelfTestError(AssertionError):
    """A primitive disagrees with its published known-answer vector."""


def _check(condition, what):
    if not condition:
        raise SelfTestError(what)


def run():
    """Runs every known-answer test, raising SelfTestError on the first mismatch."""
    for name, (sk, pk, msg, sig) in ED25519_VECTORS.items():
        sk, pk, msg, sig = (bytes.fromhex(x) for x in (sk, pk, msg, sig))
        _check(ed25519.public_key(sk) == pk, f"RFC 8032 {name} public key")
        _check(ed25519.sign(sk, msg) == sig, f"RFC 8032 {name} signature")
        _check(ed25519.verify(pk, msg, sig), f"RFC 8032 {name} verify")
        _check(not ed25519.verify(pk, msg + b"\x00", sig), f"RFC 8032 {name} wrong message")
    _check(
        bytes.fromhex(ED25519_VECTORS["TEST SHA(abc)"][2]) == hashlib.sha512(b"abc").digest(),
        "RFC 8032 TEST SHA(abc) message is SHA-512(abc)",
    )

    # Non-canonical S: S + L verifies only when S is reduced modulo L.
    _, pk, msg, sig = (bytes.fromhex(x) for x in ED25519_VECTORS["TEST 1"])
    s = int.from_bytes(sig[32:], "little") + ed25519.L
    bad_s = sig[:32] + s.to_bytes(32, "little")
    _check(ed25519.verify(pk, msg, bad_s, strict=False), "lax verify accepts S + L")
    _check(not ed25519.verify(pk, msg, bad_s), "strict verify rejects S + L")

    # Small-order A: with A the identity, R = [s]B, S = s satisfies the cofactorless
    # equation for every message, so only the small-order check rejects it.
    small_a = ed25519.encode_point(ed25519.IDENTITY)
    s = 7
    forged = ed25519.encode_point(ed25519._mul(s, ed25519.BASE)) + s.to_bytes(32, "little")
    _check(ed25519.verify(small_a, b"any", forged, strict=False), "lax verify accepts small-order A")
    _check(not ed25519.verify(small_a, b"any", forged), "strict verify rejects small-order A")

    for k, u, out in X25519_VECTORS:
        _check(x25519.x25519(bytes.fromhex(k), bytes.fromhex(u)).hex() == out, "RFC 7748 §5.2 X25519")
    k = u = x25519.BASE_U
    for i in range(1, max(X25519_ITERATIONS) + 1):
        k, u = x25519.x25519(k, u), k
        if i in X25519_ITERATIONS:
            _check(k.hex() == X25519_ITERATIONS[i], f"RFC 7748 §5.2 X25519 after {i} iterations")
    dh = {name: bytes.fromhex(value) for name, value in X25519_DH.items()}
    _check(x25519.public_key(dh["a"]) == dh["ka"], "RFC 7748 §6.1 Alice public key")
    _check(x25519.public_key(dh["b"]) == dh["kb"], "RFC 7748 §6.1 Bob public key")
    _check(x25519.x25519(dh["a"], dh["kb"]) == dh["k"], "RFC 7748 §6.1 Alice shared secret")
    _check(x25519.x25519(dh["b"], dh["ka"]) == dh["k"], "RFC 7748 §6.1 Bob shared secret")

    ikm = bytes([0x0B]) * 22
    prk = kdf.hkdf_extract(b"", ikm)
    _check(prk.hex() == "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", "RFC 5869 A.3 PRK")
    _check(
        kdf.hkdf(ikm, b"", 42).hex()
        == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        "RFC 5869 A.3 OKM",
    )

    for item, encoded in CBOR_EXAMPLES:
        _check(cbor.encode(item).hex() == encoded, f"RFC 8949 Appendix A encode {encoded}")
        _check(cbor.decode(bytes.fromhex(encoded)) == item, f"RFC 8949 Appendix A decode {encoded}")
    for encoded in CBOR_REJECTED:
        try:
            cbor.decode(bytes.fromhex(encoded))
        except cbor.CborError:
            continue
        raise SelfTestError(f"RFC 8949 Appendix A {encoded} outside the subset was accepted")
    for item in (-1, 1.5, True, {}):
        try:
            cbor.encode(item)
        except TypeError:
            continue
        raise SelfTestError(f"CBOR encoder accepted {item!r} outside the subset")
