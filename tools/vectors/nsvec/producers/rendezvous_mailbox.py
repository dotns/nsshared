"""`/quick/v2` JSON messages: one per request and result kind, valid and rejected
(rendezvous §3, §3.1, §4, §5.2, §5.4; quick-v2 §7.2)."""

import base64
import json
import re

from .. import derive
from . import control_messages, node_records, rendezvous_registry
from . import rendezvous_common as common
from .rendezvous_common import b64u

CRATE = common.CRATE
GROUP = "mailbox_json"
TITLE = "NS rendezvous v2 /quick/v2 JSON messages, valid and rejected"
SECTIONS = "ns/rendezvous.md §3, §3.1, §4, §5.2, §5.4; ns/quick-v2.md §7.2"

MAX_INTRO = 4096
MAX_DATA = 8192
MAX_TTL = 900
MAX_WAIT_MS = 20000
MAX_CANDIDATES = 4
ERROR_CODES = (
    "invalid_message",
    "invalid_actor",
    "invalid_code",
    "unknown_relay",
    "invalid_directory",
    "unknown_mailbox",
    "not_permitted",
    "wrong_stage",
    "capacity",
    "queue_full",
    "rate_limited",
    "conflict",
    "randomness",
    "storage",
    "unavailable",
)

# --- Independent check (rendezvous §3, §5.2) ----------------------------------------


class Reject(Exception):
    pass


def _b64(value, exact=None, maximum=None):
    """Unpadded base64url in its canonical form (rendezvous §3)."""
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]*", value) or len(value) % 4 == 1:
        raise Reject("base64")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64u(raw) != value:
        raise Reject("base64")
    if (exact is not None and len(raw) != exact) or (maximum is not None and len(raw) > maximum):
        raise Reject("base64")
    return raw


def _uint(value, lo=0, hi=2**64 - 1):
    if type(value) is not int:
        raise Reject("type")
    if not lo <= value <= hi:
        raise Reject("range")
    return value


def _enum(value, names):
    if value not in names:
        raise Reject("range")
    return value


def _kind(value):
    if type(value) is not str or not re.fullmatch(r"[a-z0-9-]{1,32}", value):
        raise Reject("range")


def _digits(value):
    if type(value) is not str or not re.fullmatch(r"[0-9]{8}", value):
        raise Reject("range")


def _object(value, fields):
    if type(value) is not dict:
        raise Reject("type")
    if set(value) - set(fields):
        raise Reject("unknown_field")
    if set(fields) - set(value):
        raise Reject("missing_field")
    for key, check in fields.items():
        check(value[key])
    return value


def _null(value):
    if value is not None:
        raise Reject("type")


def _list(value, maximum, item):
    if type(value) is not list:
        raise Reject("type")
    if len(value) > maximum:
        raise Reject("range")
    for entry in value:
        item(entry)


def _optional(check):
    return lambda value: None if value is None else check(value)


def _nonzero_nonce(value):
    if _b64(value, 32) == bytes(32):
        raise Reject("range")


def _capabilities(value):
    _list(value, 16, lambda token: None if type(token) is str and re.fullmatch(r"[a-z0-9.-]{1,32}", token) else _raise("range"))


def _relay_id(value):
    if type(value) is not str or not control_messages.dns_relay_ok(value):
        raise Reject("range")


def _raise(reason):
    raise Reject(reason)


def _open(value):
    _object(
        value,
        {
            "kind": _kind,
            "ttl": lambda v: _uint(v, 1, MAX_TTL),
            "admission": lambda v: _enum(v, ("first", "owner")),
            "candidates": lambda v: _uint(v, 1, MAX_CANDIDATES),
            "intro": lambda v: _b64(v, maximum=MAX_INTRO),
        },
    )
    if value["admission"] == "first" and value["candidates"] != 1:
        raise Reject("range")


def _directory(value):
    _object(value, {"version": lambda v: _uint(v, 1), "relays": lambda v: _list(v, 576, lambda e: None)})


ID = lambda v: _b64(v, 16)  # noqa: E731
ACTOR = lambda v: _b64(v, 32)  # noqa: E731
SEQ = lambda v: _uint(v, 1)  # noqa: E731

REQUESTS = {
    "directory": _null,
    "publish": lambda v: _object(
        v, {"record": lambda r: _b64(r, maximum=node_records.MAX_BYTES), "dns": lambda d: None if type(d) is bool else _raise("type"), "proof": lambda p: _b64(p, 64)}
    ),
    "lookup_node": lambda v: _object(v, {"node_id": lambda n: _b64(n, 12)}),
    "hello": lambda v: _object(v, {"actor": ACTOR, "signature": lambda s: _b64(s, 64)}),
    "open": _open,
    "lookup": _digits,
    "join": lambda v: _object(v, {"id": ID, "intro": lambda i: _b64(i, maximum=MAX_INTRO)}),
    "admit": lambda v: _object(v, {"id": ID, "actor": ACTOR}),
    "reject": lambda v: _object(v, {"id": ID, "actor": ACTOR}),
    "send": lambda v: _object(v, {"id": ID, "data": lambda d: _b64(d, maximum=MAX_DATA)}),
    "recv": lambda v: _object(v, {"id": ID, "after": _uint, "wait_ms": lambda w: _uint(w, 0, MAX_WAIT_MS)}),
    "close": lambda v: _object(v, {"id": ID}),
}

RESPONSES = {
    "challenge": lambda v: _object(v, {"nonce": _nonzero_nonce, "authority": _relay_id, "capabilities": _capabilities}),
    "directory": _directory,
    "published": lambda v: _object(v, {"expires": _uint}),
    "record": lambda v: _object(v, {"record": _optional(lambda r: _b64(r, maximum=node_records.MAX_BYTES))}),
    "ok": _null,
    "opened": lambda v: _object(v, {"id": ID, "digits": _digits, "expires": _uint}),
    "found": lambda v: _object(v, {"id": ID, "kind": _kind, "expires": _uint, "intro": lambda i: _b64(i, maximum=MAX_INTRO)}),
    "sent": lambda v: _object(v, {"seq": SEQ}),
    "mailbox": lambda v: _object(
        v,
        {
            "stage": lambda s: _enum(s, ("open", "admitted", "closing")),
            "waiting": lambda w: _list(w, MAX_CANDIDATES, lambda e: _object(e, {"actor": ACTOR, "intro": lambda i: _b64(i, maximum=MAX_INTRO)})),
            "peer": _optional(ACTOR),
            "messages": lambda m: _list(m, 16, lambda e: _object(e, {"seq": SEQ, "data": lambda d: _b64(d, maximum=MAX_DATA)})),
        },
    ),
    "error": lambda v: _enum(v, ERROR_CODES),
}


def check(text, kind):
    """Returns None for a valid message or the first violated rule (rendezvous §3, §5.2)."""
    if len(text.encode("utf-8")) > common.MAX_MESSAGE_BYTES:
        return "oversize"
    try:
        message = json.loads(text)
    except ValueError:
        return "json"
    key, table = ("operation", REQUESTS) if kind == "request" else ("result", RESPONSES)
    try:
        if type(message) is not dict:
            raise Reject("type")
        if set(message) - {key, "value"}:
            raise Reject("unknown_field")
        if set(message) != {key, "value"}:
            raise Reject("missing_field")
        if message[key] not in table:
            raise Reject("unknown_name")
        table[message[key]](message["value"])
    except Reject as err:
        return str(err)
    return None


# --- Vectors ------------------------------------------------------------------------


def positive(name, kind, label, value, fields=()):
    text = common.request(label, value) if kind == "request" else common.response(label, value)
    reason = check(text, kind)
    if reason is not None:
        raise AssertionError(f"valid message {name} rejected: {reason}")
    key = "operation" if kind == "request" else "result"
    return [("name", name), ("kind", kind), (key, label)] + list(fields) + [("json", text)]


def negative(name, kind, text, reason):
    actual = check(text, kind)
    if actual != reason:
        raise AssertionError(f"negative message {name}: expected {reason}, checker says {actual}")
    return [("name", name), ("kind", kind), ("json", text), ("expect", "reject"), ("reason", reason)]


def vectors():
    mailbox_id = common.fixed("ns-rendezvous-mailbox-id-1", 16)
    owner = common.Key("ns-rendezvous-actor-1")
    peer = common.Key("ns-rendezvous-actor-2")
    candidate = common.Key("ns-rendezvous-actor-3")
    hello_sig = common.fixed("ns-rendezvous-hello-signature", 32) * 2
    intro = b"ns transfer intro \x00\xff\xfe"
    data = bytes(range(0xF0, 0x100)) + b"payload"
    digits = "04718263"
    publisher = node_records.Signer("ns-registry-publisher-v2", "ns-registry-publisher-wg-v2")
    record = common.record(publisher)
    proof = common.fixed("ns-rendezvous-publish-proof", 32) * 2
    node_id = derive.node_id(publisher.identity)
    expires = common.NOW + 300
    hid = ("id", mailbox_id)

    out = [
        positive("request-directory", "request", "directory", None),
        positive(
            "request-publish",
            "request",
            "publish",
            rendezvous_registry.publish_value(record, True, proof),
            [("record", record), ("dns", "true"), ("proof", proof)],
        ),
        positive("request-lookup-node", "request", "lookup_node", {"node_id": b64u(node_id)}, [("node_id", node_id)]),
        positive(
            "request-hello",
            "request",
            "hello",
            {"actor": b64u(owner.public), "signature": b64u(hello_sig)},
            [("actor", owner.public), ("signature", hello_sig)],
        ),
        positive(
            "request-open",
            "request",
            "open",
            {"kind": "transfer", "ttl": 300, "admission": "first", "candidates": 1, "intro": b64u(intro)},
            [("mailbox_kind", "transfer"), ("ttl", 300), ("admission", "first"), ("candidates", 1), ("intro", intro)],
        ),
        positive(
            "request-open-empty-intro",
            "request",
            "open",
            {"kind": "chat-v1", "ttl": 900, "admission": "owner", "candidates": 4, "intro": ""},
            [("mailbox_kind", "chat-v1"), ("ttl", 900), ("admission", "owner"), ("candidates", 4)],
        ),
        positive("request-lookup", "request", "lookup", digits, [("digits", digits)]),
        positive("request-join", "request", "join", {"id": b64u(mailbox_id), "intro": b64u(intro)}, [hid, ("intro", intro)]),
        positive(
            "request-admit", "request", "admit", {"id": b64u(mailbox_id), "actor": b64u(peer.public)}, [hid, ("actor", peer.public)]
        ),
        positive(
            "request-reject",
            "request",
            "reject",
            {"id": b64u(mailbox_id), "actor": b64u(candidate.public)},
            [hid, ("actor", candidate.public)],
        ),
        positive("request-send", "request", "send", {"id": b64u(mailbox_id), "data": b64u(data)}, [hid, ("data", data)]),
        positive(
            "request-recv",
            "request",
            "recv",
            {"id": b64u(mailbox_id), "after": 3, "wait_ms": MAX_WAIT_MS},
            [hid, ("after", 3), ("wait_ms", MAX_WAIT_MS)],
        ),
        positive("request-close", "request", "close", {"id": b64u(mailbox_id)}, [hid]),
        positive(
            "response-challenge",
            "response",
            "challenge",
            {"nonce": b64u(common.NONCE), "authority": common.AUTHORITY, "capabilities": ["udp", "wss", "mailbox", "registry"]},
            [("nonce", common.NONCE), ("authority", common.AUTHORITY)]
            + [("capability", c) for c in ("udp", "wss", "mailbox", "registry")],
        ),
        positive(
            "response-directory",
            "response",
            "directory",
            rendezvous_registry.directory_value(),
            [("version", rendezvous_registry.DIRECTORY_VERSION), ("relay_count", len(rendezvous_registry.RELAYS))],
        ),
        positive("response-published", "response", "published", {"expires": common.WEEK}, [("expires", common.WEEK)]),
        positive("response-record", "response", "record", {"record": b64u(record)}, [("record", record)]),
        positive("response-record-null", "response", "record", {"record": None}),
        positive("response-ok", "response", "ok", None),
        positive(
            "response-opened",
            "response",
            "opened",
            {"id": b64u(mailbox_id), "digits": digits, "expires": expires},
            [hid, ("digits", digits), ("expires", expires)],
        ),
        positive(
            "response-found",
            "response",
            "found",
            {"id": b64u(mailbox_id), "kind": "transfer", "expires": expires, "intro": b64u(intro)},
            [hid, ("mailbox_kind", "transfer"), ("expires", expires), ("intro", intro)],
        ),
        positive("response-sent", "response", "sent", {"seq": 1}, [("seq", 1)]),
        positive(
            "response-mailbox-owner-open",
            "response",
            "mailbox",
            {
                "stage": "open",
                "waiting": [{"actor": b64u(peer.public), "intro": b64u(intro)}, {"actor": b64u(candidate.public), "intro": b64u(b"\x01")}],
                "peer": None,
                "messages": [],
            },
            [("stage", "open"), ("waiting_actor", peer.public), ("waiting_intro", intro), ("waiting_actor", candidate.public), ("waiting_intro", b"\x01")],
        ),
        positive(
            "response-mailbox-admitted",
            "response",
            "mailbox",
            {
                "stage": "admitted",
                "waiting": [],
                "peer": b64u(peer.public),
                "messages": [{"seq": 4, "data": b64u(data)}, {"seq": 5, "data": b64u(b"\x00")}],
            },
            [("stage", "admitted"), ("peer", peer.public), ("message_seq", 4), ("message_data", data), ("message_seq", 5), ("message_data", b"\x00")],
        ),
        positive("response-error", "response", "error", "capacity", [("error", "capacity")]),
        positive("response-error-unavailable", "response", "error", "unavailable", [("error", "unavailable")]),
    ]

    id_text = b64u(mailbox_id)
    close = '{"operation":"close","value":{"id":"%s"}}'
    rows = [
        ("request-unknown-envelope-field", "request", '{"operation":"close","value":{"id":"%s"},"extra":1}' % id_text, "unknown_field"),
        ("request-unknown-value-field", "request", '{"operation":"close","value":{"id":"%s","extra":1}}' % id_text, "unknown_field"),
        ("response-unknown-value-field", "response", '{"result":"sent","value":{"seq":1,"extra":true}}', "unknown_field"),
        ("request-missing-value-field", "request", '{"operation":"recv","value":{"id":"%s","after":0}}' % id_text, "missing_field"),
        ("request-missing-value", "request", '{"operation":"directory"}', "missing_field"),
        ("request-base64-padding", "request", close % (id_text + "=="), "base64"),
        ("request-base64-padding-intro", "request", '{"operation":"join","value":{"id":"%s","intro":"AA=="}}' % id_text, "base64"),
        ("request-base64-standard-alphabet", "request", close % ("++++" + id_text[4:]), "base64"),
        ("request-base64-non-canonical-bits", "request", close % (id_text[:-1] + chr(ord(id_text[-1]) + 1)), "base64"),
        ("request-id-15-bytes", "request", close % b64u(mailbox_id[:15]), "base64"),
        ("request-node-id-11-bytes", "request", '{"operation":"lookup_node","value":{"node_id":"%s"}}' % b64u(node_id[:11]), "base64"),
        ("request-unknown-operation", "request", '{"operation":"resume","value":null}', "unknown_name"),
        ("response-unknown-result", "response", '{"result":"closed","value":null}', "unknown_name"),
        ("request-lookup-7-digits", "request", '{"operation":"lookup","value":"0471826"}', "range"),
        ("request-lookup-letter", "request", '{"operation":"lookup","value":"0471826a"}', "range"),
        ("request-lookup-number", "request", '{"operation":"lookup","value":4718263}', "range"),
        ("request-directory-object", "request", '{"operation":"directory","value":{}}', "type"),
        ("response-ok-object", "response", '{"result":"ok","value":{}}', "type"),
        ("request-open-array", "request", '{"operation":"open","value":["transfer",300,"first",1,""]}', "type"),
        ("request-open-ttl-0", "request", '{"operation":"open","value":{"kind":"transfer","ttl":0,"admission":"first","candidates":1,"intro":""}}', "range"),
        ("request-open-ttl-901", "request", '{"operation":"open","value":{"kind":"transfer","ttl":901,"admission":"first","candidates":1,"intro":""}}', "range"),
        ("request-open-candidates-5", "request", '{"operation":"open","value":{"kind":"pairing","ttl":600,"admission":"owner","candidates":5,"intro":""}}', "range"),
        ("request-open-first-candidates-2", "request", '{"operation":"open","value":{"kind":"transfer","ttl":600,"admission":"first","candidates":2,"intro":""}}', "range"),
        ("request-open-admission-any", "request", '{"operation":"open","value":{"kind":"transfer","ttl":600,"admission":"any","candidates":1,"intro":""}}', "range"),
        ("request-open-kind-uppercase", "request", '{"operation":"open","value":{"kind":"Pairing","ttl":600,"admission":"owner","candidates":4,"intro":""}}', "range"),
        ("request-recv-wait-20001", "request", '{"operation":"recv","value":{"id":"%s","after":0,"wait_ms":20001}}' % id_text, "range"),
        ("request-recv-after-negative", "request", '{"operation":"recv","value":{"id":"%s","after":-1,"wait_ms":0}}' % id_text, "range"),
        ("request-recv-after-float", "request", '{"operation":"recv","value":{"id":"%s","after":1.0,"wait_ms":0}}' % id_text, "type"),
        ("response-sent-seq-0", "response", '{"result":"sent","value":{"seq":0}}', "range"),
        ("response-error-unknown-code", "response", '{"result":"error","value":"teapot"}', "range"),
        ("response-challenge-zero-nonce", "response", '{"result":"challenge","value":{"nonce":"%s","authority":"%s","capabilities":[]}}' % (b64u(bytes(32)), common.AUTHORITY), "range"),
        ("request-join-intro-4097", "request", '{"operation":"join","value":{"id":"%s","intro":"%s"}}' % (id_text, b64u(bytes(MAX_INTRO + 1))), "base64"),
        ("request-send-data-8193", "request", '{"operation":"send","value":{"id":"%s","data":"%s"}}' % (id_text, b64u(bytes(MAX_DATA + 1))), "base64"),
        ("request-not-object", "request", '["close",{"id":"%s"}]' % id_text, "type"),
    ]
    out += [negative(*row) for row in rows]

    # 16384 bytes is the largest message; whitespace pads a valid request past it.
    def padded(total):
        head, tail = '{"operation":"directory",', '"value":null}'
        return head + " " * (total - len(head) - len(tail)) + tail

    assert check(padded(common.MAX_MESSAGE_BYTES), "request") is None
    out.append(negative("request-oversize-16385", "request", padded(common.MAX_MESSAGE_BYTES + 1), "oversize"))
    out.append(
        [("name", "request-size-16384"), ("kind", "request"), ("operation", "directory"), ("decode_only", "true"), ("json", padded(common.MAX_MESSAGE_BYTES))]
    )
    return out
