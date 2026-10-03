"""Identity derivations straight from the specification text (quick-v2 §2.2, §6.2; next §4.1)."""

import base64
import hashlib
import ipaddress

from . import ed25519
from .kdf import keyed_blake2s

NODE_ID_LABEL = b"ns-node-id-v2"
NODE_ADDR_LABEL = b"ns-node-addr-v2"
ALIAS4_LABEL = b"ns-alias4-v2"
LAN_ADDR_LABEL = b"ns-lan-addr-v2"

ADDRESS_PREFIX = 0xFD
ALIAS_KINDS = (4, 6)
ALIAS_CANDIDATES = 16
DEFAULT_POOL = ipaddress.IPv4Network("100.64.0.0/10")


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


def lan6_prefix(ident, subnet_id):
    """`fd ‖ BLAKE2s(out = 9, key = "ns-lan-addr-v2")(I ‖ subnet_id_be16) ‖ 0x0000`, the /96
    prefix with the low 32 IPv4 bits zero (next §4.1)."""
    digest = keyed_blake2s(LAN_ADDR_LABEL, ident + subnet_id.to_bytes(2, "big"), 9)
    return bytes([ADDRESS_PREFIX]) + digest + bytes(6)


def lan6_embed(prefix, ipv4):
    """The prefix with an IPv4 address in its low 32 bits (next §4.1)."""
    return prefix[:12] + ipaddress.IPv4Address(ipv4).packed


def alias_h22(ident, kind, index):
    """`H22(I, kind, i)`: the high 22 bits of BLAKE2s(out = 3, key = "ns-alias4-v2")(I ‖ kind_u8 ‖ i_u8)
    (quick-v2 §2.2, §6.2)."""
    assert kind in ALIAS_KINDS and 0 <= index < ALIAS_CANDIDATES
    return int.from_bytes(keyed_blake2s(ALIAS4_LABEL, ident + bytes([kind, index]), 3), "big") >> 2


def alias_candidate(ident, kind, index, pool=DEFAULT_POOL):
    """Candidate `i = pool.base + (H22(I, kind, i) mod pool.size)` (quick-v2 §6.2)."""
    return pool.network_address + alias_h22(ident, kind, index) % pool.num_addresses


def ipv6_text(raw):
    """RFC 5952 text form of a 16-byte address."""
    return str(ipaddress.IPv6Address(raw))
