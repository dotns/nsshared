"""Actor `hello` signatures over the connection challenge (rendezvous §3, §4; quick-v2 §12.2)."""

from .. import ed25519
from . import rendezvous_common as common

CRATE = common.CRATE
GROUP = "hello"
TITLE = "NS rendezvous actor hello signatures, valid and rejected"
SECTIONS = "ns/rendezvous.md §3, §4; ns/quick-v2.md §12.2"

ACTOR_CONTEXT = b"ns-rendezvous-actor-v1\x00"


def signed_message(nonce, authority):
    """`"ns-rendezvous-actor-v1\\0" ‖ nonce ‖ authority`, no length prefixes (rendezvous §4)."""
    return ACTOR_CONTEXT + nonce + authority.encode("ascii")


def positive(name, actor, nonce, authority):
    message = signed_message(nonce, authority)
    signature = ed25519.sign(actor.seed, message)
    assert ed25519.verify(actor.public, message, signature)
    value = {"actor": common.b64u(actor.public), "signature": common.b64u(signature)}
    return [
        ("name", name),
        ("actor_seed_label", actor.label),
        ("actor_seed", actor.seed),
        ("actor", actor.public),
        ("nonce", nonce),
        ("authority", authority),
        ("message", message),
        ("signature", signature),
        ("request", common.request("hello", value)),
    ], signature


def negative(name, actor, signature, nonce, authority, reason="invalid_signature"):
    if ed25519.verify(actor, signed_message(nonce, authority), signature):
        raise AssertionError(f"negative hello {name} verifies")
    return [
        ("name", name),
        ("actor", actor),
        ("signature", signature),
        ("nonce", nonce),
        ("authority", authority),
        ("expect", "reject"),
        ("reason", reason),
    ]


def vectors():
    actor = common.Key("ns-rendezvous-actor-1")
    other = common.Key("ns-rendezvous-actor-2")
    out = []
    vector, signature = positive("hello", actor, common.NONCE, common.AUTHORITY)
    out.append(vector)
    out.append(positive("hello-other-actor", other, common.OTHER_NONCE, common.OTHER_AUTHORITY)[0])

    tampered = bytearray(signature)
    tampered[5] ^= 0x01
    out.append(negative("tampered-signature", actor.public, bytes(tampered), common.NONCE, common.AUTHORITY))
    out.append(negative("wrong-authority", actor.public, signature, common.NONCE, common.OTHER_AUTHORITY))
    out.append(negative("wrong-nonce", actor.public, signature, common.OTHER_NONCE, common.AUTHORITY))
    out.append(negative("wrong-actor", other.public, signature, common.NONCE, common.AUTHORITY))
    s_plus_l = int.from_bytes(signature[32:], "little") + ed25519.L
    non_canonical = signature[:32] + s_plus_l.to_bytes(32, "little")
    out.append(negative("non-canonical-s", actor.public, non_canonical, common.NONCE, common.AUTHORITY))

    # Identity point actor with R = [7]B, S = 7: the cofactorless equation holds for every
    # message, so only the small-order check of strict verification rejects it (quick-v2 §12.2).
    weak = ed25519.encode_point(ed25519.IDENTITY)
    forged = ed25519.encode_point(ed25519._mul(7, ed25519.BASE)) + (7).to_bytes(32, "little")
    assert ed25519.verify(weak, signed_message(common.NONCE, common.AUTHORITY), forged, strict=False)
    out.append(negative("small-order-actor", weak, forged, common.NONCE, common.AUTHORITY))
    return out
