"""Independent complete membership and diagnostic observation candidates."""

import copy

from .. import cbor
from .account import key, sign
from .node_records import Signer, sign as record_sign
from .publication import DOMAIN

CRATE = "nsshared-proto"
GROUP = "realm-publication"
TITLE = "Complete realm membership and policy observation candidate fixture authority"
SECTIONS = "docs/realm-publication-candidate.md"


def vectors():
    issuer = key(bytes([1]) * 32)[0]
    recipient = key(bytes([2]) * 32)[0]
    members = []
    for index in (1, 2):
        signer = Signer(f"membership-node-{index}", f"membership-wg-{index}")
        record = record_sign(signer, index, 100, 200, [])[3]
        members.append([[1, signer.identity, signer.wg_key, index], record])
    complete = [1, 2, [["030C1G60R30C1G60R30C1G60R3", [members[0]]], ["09144GJ289144GJ289144GJ289", [members[1]]]]]
    out = []

    def emit(name, kind, value, decision="accept", raw=None):
        out.append([("name", name), ("kind", kind),
                    ("bytes", cbor.encode(value) if raw is None else raw),
                    ("decision", decision)])

    emit("two-realms", "membership", complete)
    emit("omitted-realm", "membership", [1, 2, complete[2][:1]])
    emit("empty", "membership", [1, 2, []])
    emit("served-empty-realm", "membership", [1, 2, [["030C1G60R30C1G60R30C1G60R3", []]]])
    same_realm = [1, 2, [["030C1G60R30C1G60R30C1G60R3", sorted(members, key=lambda v: v[0][1])]]]
    emit("sorted-members", "membership", same_realm)
    emit("duplicate-identity", "membership", [1, 2, [["030C1G60R30C1G60R30C1G60R3", [members[0]]],
                                                       ["09144GJ289144GJ289144GJ289", [members[0]]]]], "refuse")
    changed = copy.deepcopy(complete)
    # Re-sign the second record with the first key so each binding remains valid.
    signer = Signer("membership-node-2", "membership-wg-1")
    changed[2][1][1][0] = [[1, signer.identity, signer.wg_key, 2],
                          record_sign(signer, 2, 100, 200, [])[3]]
    emit("duplicate-key", "membership", changed, "refuse")
    for label, position, replacement in [("wrong-binding", 2, bytes([42]) * 32),
                                          ("wrong-identity", 1, issuer),
                                          ("wrong-generation", 3, 3),
                                          ("zero-version", 0, 0),
                                          ("zero-key", 2, bytes(32))]:
        changed = copy.deepcopy(complete)
        changed[2][0][1][0][0][position] = replacement
        emit(label, "membership", changed, "refuse")
    changed = copy.deepcopy(complete)
    changed[2][0][1][0][1] = members[0][1][:-1] + bytes([members[0][1][-1] ^ 1])
    emit("record-signature", "membership", changed, "refuse")
    emit("realm-order", "membership", [1, 2, complete[2][::-1]], "refuse")
    emit("member-order", "membership", [1, 2, [["030C1G60R30C1G60R30C1G60R3", same_realm[2][0][1][::-1]]]], "refuse")
    emit("duplicate-realm", "membership", [1, 2, [complete[2][0]] * 2], "refuse")
    emit("empty-realm-name", "membership", [1, 2, [["", []]]], "refuse")
    emit("long-realm-name", "membership", [1, 2, [["a" * 257, []]]], "refuse")
    emit("oversized-realms", "membership", None, "refuse", raw=b"\x83\x01\x02\x99\x01\x01")
    emit("oversized-members", "membership", None, "refuse",
         raw=b"\x83\x01\x02\x81\x82" + cbor.encode("030C1G60R30C1G60R30C1G60R3") + b"\x99\x20\x01")
    for counter in (0, 1, 2**64 - 1):
        emit(f"counter-{counter}", "policy", [1, 11, counter])
    emit("policy-negative", "policy", None, "refuse", raw=b"\x83\x01\x0b\x20")
    for name, value in [
                         ("policy-wrong-family", [1, 2, 1]),
                         ("policy-wrong-schema", [2, 11, 1]),
                         ("policy-text", [1, 11, "1"])]:
        emit(name, "policy", value, "refuse")
    for kind, value in [("membership", complete), ("policy", [1, 11, 1])]:
        raw = cbor.encode(value)
        for name, data in [("trailing", raw + b"\0"), ("truncated", raw[:-1]),
                            ("nonminimal", raw[:1] + b"\x18\x01" + raw[2:])]:
            emit(kind + "-" + name, kind, None, "refuse", raw=data)

    def event(name, payload, version, family=2, kind="realm-peers", channel=1,
              scope="collection", recipient_key=recipient, decision="accept", expires=200):
        content = [1, issuer, recipient_key, "030C1G60R30C1G60R30C1G60R3", scope, family, kind, channel,
                   True, version, 100, expires, 0, payload]
        raw = cbor.encode(content)
        emit(name, "event", None, decision,
             raw=cbor.encode([raw, sign(bytes([1]) * 32, DOMAIN + raw)]))

    event("install", cbor.encode(complete), 1)
    malformed = copy.deepcopy(complete)
    malformed[2][1][1][0][0][2] = bytes([42]) * 32
    event("malformed-no-renewal", cbor.encode(malformed), 2, decision="refuse", expires=300)
    event("remove-omitted", cbor.encode([1, 2, complete[2][:1]]), 2)
    event("withdraw", cbor.encode([1, 2, []]), 3)
    event("older-after-restart", cbor.encode(complete), 2, decision="refuse")
    event("empty-carrier", b"", 4)
    event("wrong-scope", cbor.encode(complete), 5, scope="other", decision="refuse")
    event("wrong-recipient", cbor.encode(complete), 5, recipient_key=issuer, decision="refuse")
    event("wrong-channel", cbor.encode(complete), 5, channel=0, decision="refuse")
    event("policy-observation", cbor.encode([1, 11, 42]), 1, 11, "policy-version", 0)
    event("policy-lower-observation", cbor.encode([1, 11, 1]), 2, 11, "policy-version", 0)
    event("policy-replay", cbor.encode([1, 11, 100]), 1, 11, "policy-version", 0, decision="refuse")
    event("policy-wrong-scope", cbor.encode([1, 11, 1]), 3, 11, "policy-version", 0,
          scope="other", decision="refuse")
    event("policy-malformed", cbor.encode([1, 11, "1"]), 3, 11, "policy-version", 0, decision="refuse")
    return out
