"""Pairing mailbox payloads: Invite, Join, ACCEPT, COMPLETE, their signatures and hashes, and
the pairing PSK (quick-v2 §10.2, §12.1-§12.3)."""

import hashlib

from .. import cbor, derive, ed25519, x25519
from ..kdf import hkdf
from . import node_records
from . import rendezvous_common as common

CRATE = common.CRATE
GROUP = "pairing"
TITLE = "NS rendezvous v2 pairing payloads, signatures and PSK, valid and rejected"
SECTIONS = "ns/quick-v2.md §10.2, §12.1, §12.2, §12.3"

VERSION = 2
ACCEPT, COMPLETE = 1, 2
INVITE_CONTEXT = b"ns/pairing-invite/v2"
JOIN_CONTEXT = b"ns/pairing-join/v2"
ACCEPT_CONTEXT = b"ns/pairing-accept/v2"
PSK_CONTEXT = b"ns/pairing-psk/v2"
DEFAULT_TTL = 600
PSK_BYTES = 32


def invite_fields(record, e_a, authority, expires, name, version=VERSION):
    """The first six Invite fields; `record_a` is the nested NodeRecord array (quick-v2 §10.2)."""
    return [version, cbor.decode(record), e_a, authority, expires, name]


def join_fields(record, e_b, mailbox_id, invite_hash, name, version=VERSION):
    """The first six Join fields (quick-v2 §10.2)."""
    return [version, cbor.decode(record), e_b, mailbox_id, invite_hash, name]


def signed(seed, context, fields):
    """`fields ‖ [Ed25519(context ‖ CBOR(fields))]`, encoded (quick-v2 §10.2, §12.2)."""
    message = context + cbor.encode(fields)
    signature = ed25519.sign(seed, message)
    return message, signature, cbor.encode(fields + [signature])


def accept_message(invite_hash, join_hash):
    return ACCEPT_CONTEXT + invite_hash + join_hash


def accept(seed, invite_hash, join_hash):
    """`[2, 1, [join_hash, sig]]` (quick-v2 §10.2)."""
    message = accept_message(invite_hash, join_hash)
    signature = ed25519.sign(seed, message)
    return message, signature, cbor.encode([VERSION, ACCEPT, [join_hash, signature]])


def psk(own_secret, peer_public, i_a, i_b, invite_hash, join_hash):
    """`HKDF-SHA256(ikm = X25519(e_a, e_b), info = "ns/pairing-psk/v2" ‖ I_a ‖ I_b ‖ invite_hash ‖
    join_hash)` with an empty salt; an all-zero DH result is rejected (quick-v2 §10.2)."""
    shared = x25519.x25519(own_secret, peer_public)
    if shared == bytes(32):
        return shared, None
    return shared, hkdf(shared, PSK_CONTEXT + i_a + i_b + invite_hash + join_hash, PSK_BYTES)


# --- Independent checks (quick-v2 §10.2, §12.1) ----------------------------------------


def _decode(encoded, arity):
    try:
        item = cbor.decode(encoded)
    except cbor.CborError as err:
        return None, "trailing_bytes" if str(err) == "trailing bytes" else "non_canonical"
    if type(item) is not list or len(item) != arity:
        return None, "schema"
    if item[0] != VERSION:
        return None, "version"
    return item, None


def _signed_payload(encoded, context, now):
    item, reason = _decode(encoded, 7)
    if reason:
        return None, reason
    record = cbor.encode(item[1])
    if node_records.validate(record) is not None:
        return None, "record"
    if now >= item[1][5]:
        return None, "record_expired"
    if not ed25519.verify(item[1][1], context + cbor.encode(item[:6]), item[6]):
        return None, "signature"
    return item, None


def check_invite(encoded, dialed, now):
    item, reason = _signed_payload(encoded, INVITE_CONTEXT, now)
    if reason:
        return reason
    if item[3] != dialed:
        return "authority"
    return "expired" if now >= item[4] else None


def check_join(encoded, mailbox_id, invite_hash, now):
    item, reason = _signed_payload(encoded, JOIN_CONTEXT, now)
    if reason:
        return reason
    if item[3] != mailbox_id:
        return "mailbox_id"
    return "invite_hash" if item[4] != invite_hash else None


def check_message(encoded):
    item, reason = _decode(encoded, 3)
    if reason:
        return reason
    if item[1] not in (ACCEPT, COMPLETE):
        return "message_type"
    return None


def check_accept(encoded, invite, join):
    reason = check_message(encoded)
    if reason:
        return reason
    _, mtype, body = cbor.decode(encoded)
    if mtype != ACCEPT:
        return "not_accept"
    join_hash, signature = body
    if join_hash != hashlib.sha256(join).digest():
        return "join_hash"
    i_a = cbor.decode(invite)[1][1]
    if not ed25519.verify(i_a, accept_message(hashlib.sha256(invite).digest(), join_hash), signature):
        return "signature"
    return None


# --- Vectors ------------------------------------------------------------------------


class Party:
    def __init__(self, tag):
        self.signer = node_records.Signer(f"ns-pairing-{tag}-v2", f"ns-pairing-{tag}-wg-v2")
        self.record = common.record(self.signer)
        self.ephemeral_label = f"ns-pairing-{tag}-ephemeral-v2"
        self.ephemeral_secret = derive.seed(self.ephemeral_label)
        self.ephemeral = x25519.public_key(self.ephemeral_secret)


def session(name, a, b, mailbox_id, name_a, name_b):
    expires = common.NOW + DEFAULT_TTL
    i_msg, i_sig, invite = signed(a.signer.seed, INVITE_CONTEXT, invite_fields(a.record, a.ephemeral, common.AUTHORITY, expires, name_a))
    invite_hash = hashlib.sha256(invite).digest()
    j_msg, j_sig, join = signed(b.signer.seed, JOIN_CONTEXT, join_fields(b.record, b.ephemeral, mailbox_id, invite_hash, name_b))
    join_hash = hashlib.sha256(join).digest()
    a_msg, a_sig, accepted = accept(a.signer.seed, invite_hash, join_hash)
    complete = cbor.encode([VERSION, COMPLETE, []])
    i_a, i_b = a.signer.identity, b.signer.identity
    shared, key = psk(a.ephemeral_secret, b.ephemeral, i_a, i_b, invite_hash, join_hash)
    assert psk(b.ephemeral_secret, a.ephemeral, i_a, i_b, invite_hash, join_hash) == (shared, key)
    assert check_invite(invite, common.AUTHORITY, common.NOW) is None
    assert check_join(join, mailbox_id, invite_hash, common.NOW) is None
    assert check_accept(accepted, invite, join) is None and check_message(complete) is None

    vector = [
        ("name", name),
        ("now", common.NOW),
        ("authority", common.AUTHORITY),
        ("ttl", DEFAULT_TTL),
        ("seed_a", a.signer.seed),
        ("identity_a", i_a),
        ("record_a", a.record),
        ("e_a_seed_label", a.ephemeral_label),
        ("e_a_secret", a.ephemeral_secret),
        ("e_a", a.ephemeral),
        ("expires", expires),
    ]
    vector += [("name_a", name_a)] if name_a is not None else []
    vector += [
        ("invite_message", i_msg),
        ("invite_signature", i_sig),
        ("invite", invite),
        ("invite_hash", invite_hash),
        ("open_request", common.request("open", open_value(invite))),
        ("seed_b", b.signer.seed),
        ("identity_b", i_b),
        ("record_b", b.record),
        ("e_b_seed_label", b.ephemeral_label),
        ("e_b_secret", b.ephemeral_secret),
        ("e_b", b.ephemeral),
        ("mailbox_id", mailbox_id),
    ]
    vector += [("name_b", name_b)] if name_b is not None else []
    vector += [
        ("join_message", j_msg),
        ("join_signature", j_sig),
        ("join", join),
        ("join_hash", join_hash),
        ("accept_message", a_msg),
        ("accept_signature", a_sig),
        ("accept", accepted),
        ("complete", complete),
        ("shared_secret", shared),
        ("psk_info", PSK_CONTEXT + i_a + i_b + invite_hash + join_hash),
        ("psk", key),
    ]
    return vector, invite, join, accepted, complete, invite_hash


def open_value(invite):
    """`open {kind: "pairing", admission: owner, candidates: 4, ttl, intro: Invite}`
    (quick-v2 §10.2 step 1, rendezvous §5.2 field order)."""
    return {"kind": "pairing", "ttl": DEFAULT_TTL, "admission": "owner", "candidates": 4, "intro": common.b64u(invite)}


def negative(name, kind, encoded, reason, context):
    checks = {
        "invite": lambda: check_invite(encoded, context["authority"], context["now"]),
        "join": lambda: check_join(encoded, context["mailbox_id"], context["invite_hash"], context["now"]),
        "accept": lambda: check_accept(encoded, context["invite"], context["join"]),
        "message": lambda: check_message(encoded),
    }
    actual = checks[kind]()
    if actual != reason:
        raise AssertionError(f"negative pairing {name}: expected {reason}, checker says {actual}")
    vector = [("name", name), ("kind", kind), ("encoded", encoded)]
    keys = {
        "invite": ("authority", "now"),
        "join": ("mailbox_id", "invite_hash", "now"),
        "accept": ("invite", "join"),
        "message": (),
    }[kind]
    vector += [(key, context[key]) for key in keys]
    return vector + [("expect", "reject"), ("reason", reason)]


def flip(data, index, mask=0x01):
    out = bytearray(data)
    out[index] ^= mask
    return bytes(out)


def vectors():
    a, b, c = Party("inviter"), Party("joiner"), Party("third")
    mailbox_id = common.fixed("ns-pairing-mailbox-id-1", 16)
    out = []
    vector, invite, join, accepted, complete, invite_hash = session("pairing-named", a, b, mailbox_id, "laptop", "phone")
    out.append(vector)
    out.append(session("pairing-unnamed", a, c, common.fixed("ns-pairing-mailbox-id-2", 16), None, None)[0])

    ctx = {
        "authority": common.AUTHORITY,
        "now": common.NOW,
        "mailbox_id": mailbox_id,
        "invite_hash": invite_hash,
        "invite": invite,
        "join": join,
    }
    out.append(negative("invite-tampered-signature", "invite", flip(invite, len(invite) - 3), "signature", ctx))
    out.append(negative("invite-tampered-ephemeral", "invite", flip(invite, invite.index(a.ephemeral)), "signature", ctx))
    out.append(negative("invite-wrong-authority", "invite", invite, "authority", dict(ctx, authority=common.OTHER_AUTHORITY)))
    out.append(negative("invite-expired", "invite", invite, "expired", dict(ctx, now=common.NOW + DEFAULT_TTL)))
    out.append(negative("invite-trailing-bytes", "invite", invite + b"\x00", "trailing_bytes", ctx))
    v3 = signed(a.signer.seed, INVITE_CONTEXT, invite_fields(a.record, a.ephemeral, common.AUTHORITY, common.NOW + 600, None, 3))[2]
    out.append(negative("invite-version-3", "invite", v3, "version", ctx))

    out.append(negative("join-tampered-signature", "join", flip(join, len(join) - 3), "signature", ctx))
    wrong_hash = hashlib.sha256(b"not the invite").digest()
    wrong = signed(b.signer.seed, JOIN_CONTEXT, join_fields(b.record, b.ephemeral, mailbox_id, wrong_hash, "phone"))[2]
    out.append(negative("join-wrong-invite-hash", "join", wrong, "invite_hash", ctx))
    other_box = common.fixed("ns-pairing-mailbox-id-2", 16)
    wrong_box = signed(b.signer.seed, JOIN_CONTEXT, join_fields(b.record, b.ephemeral, other_box, invite_hash, "phone"))[2]
    out.append(negative("join-wrong-mailbox-id", "join", wrong_box, "mailbox_id", ctx))
    out.append(negative("join-trailing-bytes", "join", join + b"\x00", "trailing_bytes", ctx))

    out.append(negative("accept-tampered-signature", "accept", flip(accepted, len(accepted) - 3), "signature", ctx))
    other_join_hash = hashlib.sha256(wrong).digest()
    out.append(negative("accept-wrong-join-hash", "accept", accept(a.signer.seed, invite_hash, other_join_hash)[2], "join_hash", ctx))
    by_joiner = accept(b.signer.seed, invite_hash, hashlib.sha256(join).digest())[2]
    out.append(negative("accept-signed-by-joiner", "accept", by_joiner, "signature", ctx))
    out.append(negative("accept-is-complete", "accept", complete, "not_accept", ctx))
    out.append(negative("accept-trailing-bytes", "message", accepted + b"\x00", "trailing_bytes", ctx))
    out.append(negative("complete-trailing-bytes", "message", complete + b"\x00", "trailing_bytes", ctx))
    out.append(negative("message-unknown-type", "message", cbor.encode([VERSION, 3, []]), "message_type", ctx))
    out.append(negative("message-version-3", "message", cbor.encode([3, COMPLETE, []]), "version", ctx))

    # A peer ephemeral of u = 0 (a small-order point) makes the DH result all zero.
    join_hash = hashlib.sha256(join).digest()
    shared, key = psk(a.ephemeral_secret, bytes(32), a.signer.identity, b.signer.identity, invite_hash, join_hash)
    assert shared == bytes(32) and key is None
    out.append(
        [
            ("name", "psk-all-zero-dh"),
            ("kind", "psk"),
            ("own_secret", a.ephemeral_secret),
            ("peer_public", bytes(32)),
            ("identity_a", a.signer.identity),
            ("identity_b", b.signer.identity),
            ("invite_hash", invite_hash),
            ("join_hash", join_hash),
            ("expect", "reject"),
            ("reason", "all_zero_shared_secret"),
        ]
    )
    return out
