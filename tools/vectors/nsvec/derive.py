"""Identity derivations straight from the specification text (quick-v2 §2.2)."""

import base64
import hashlib
import ipaddress

from . import ed25519
from .kdf import keyed_blake2s

NODE_ID_LABEL = b"ns-node-id-v2"
NODE_ADDR_LABEL = b"ns-node-addr-v2"

ADDRESS_PREFIX = 0xFD


def seed(label):
    """A deterministic 32-byte seed: SHA-256 of an ASCII label (as in quick-v2 §2.3)."""
    return hashlib.sha256(label.encode("ascii")).digest()


def identity(seed_bytes):
    """The Ed25519 identity key `I` of a seed (quick-v2 §2.1)."""
    return ed25519.public_key(seed_bytes)


def node_id(ident):
    """BLAKE2s(out = 12, key = "ns-node-id-v2")(I) (quick-v2 §2.2)."""
    return keyed_blake2s(NODE_ID_LABEL, ident, 12)


def node_id_text(raw):
    """Lowercase unpadded RFC 4648 base32 of the 12-byte node ID, 20 characters (quick-v2 §2.2)."""
    text = base64.b32encode(raw).decode("ascii").rstrip("=").lower()
    assert len(text) == 20
    return text


def group_g(ident):
    """The 119-bit `g = BLAKE2s(out = 15, key = "ns-node-addr-v2")(I) >> 1` (quick-v2 §2.2)."""
    return int.from_bytes(keyed_blake2s(NODE_ADDR_LABEL, ident, 15), "big") >> 1


def node_addr(ident, m):
    """`addr(I, m) = fd ‖ g ‖ m`; N6 is m = 0 and N4 is m = 1 (quick-v2 §2.2)."""
    assert m in (0, 1)
    return ((ADDRESS_PREFIX << 120) | (group_g(ident) << 1) | m).to_bytes(16, "big")


def ipv6_text(raw):
    """RFC 5952 text form of a 16-byte address."""
    return str(ipaddress.IPv6Address(raw))
