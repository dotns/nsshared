"""Inputs and JSON helpers shared by the nsshared-rendezvous producers (rendezvous §3, §4, §5.2,
§5.4; quick-v2 §7.2). Not a producer itself."""

import base64
import hashlib
import json

from .. import derive
from . import node_records

CRATE = "nsshared-proto"

# Fixed time: one hour into the records' service period.
NOW = node_records.ISSUED_AT + 3600
WEEK = node_records.ISSUED_AT + node_records.MAX_SERVICE_SECONDS

AUTHORITY = "hkg-a1.relay.ns.io:443"
OTHER_AUTHORITY = "fra.relay.ns.io:443"

MAX_MESSAGE_BYTES = 16 * 1024


def fixed(label, length=32):
    """`length` deterministic bytes: the leading bytes of SHA-256 of an ASCII label."""
    return hashlib.sha256(label.encode("ascii")).digest()[:length]


NONCE = fixed("ns-rendezvous-challenge-nonce-1")
OTHER_NONCE = fixed("ns-rendezvous-challenge-nonce-2")


class Key:
    """An Ed25519 key from a fixed seed label (quick-v2 §2.1, §2.3)."""

    def __init__(self, label):
        self.label = label
        self.seed = derive.seed(label)
        self.public = derive.identity(self.seed)


def record(signer, gen=1, issued_at=node_records.ISSUED_AT, expires=WEEK, relays=(node_records.HOME_RELAY,)):
    """A valid signed NodeRecord (quick-v2 §3.1)."""
    encoded = node_records.sign(signer, gen, issued_at, expires, list(relays))[3]
    assert node_records.validate(encoded) is None
    return encoded


def b64u(data):
    """Unpadded base64url (rendezvous §3)."""
    return base64.urlsafe_b64encode(bytes(data)).decode("ascii").rstrip("=")


def compact(obj):
    """Compact JSON text, keys in insertion (spec field) order, ASCII only."""
    text = json.dumps(obj, separators=(",", ":"), ensure_ascii=True)
    assert text.isascii()
    return text


def request(operation, value):
    """`{"operation": <name>, "value": <payload>}` (rendezvous §3)."""
    return compact({"operation": operation, "value": value})


def response(result, value):
    """`{"result": <name>, "value": <payload>}` (rendezvous §3)."""
    return compact({"result": result, "value": value})


def text_bool(value):
    return "true" if value else "false"
