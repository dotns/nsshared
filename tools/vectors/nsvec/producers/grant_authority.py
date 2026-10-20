"""Independent service grant, payer, retirement and Node authority candidates."""

import copy
import json

from .. import cbor
from .account import key
from .subnet import mapped, prefix, route_json, selected

CRATE = "nsshared-proto"
GROUP = "grant-authority"
TITLE = "Service grant and Node L3 authority candidate"
SECTIONS = "docs/grant-authority-candidate.md; docs/l8-account-payload-profile.md"


def vectors():
    a, b = [key(bytes([i]) * 32)[0] for i in (1, 2)]
    nsd, realm, subject = [bytes([i]) * 16 for i in (21, 22, 23)]
    resource = cbor.encode([nsd, realm, bytes([24]) * 16])
    second = cbor.encode([nsd, realm, bytes([25]) * 16])
    token, fresh = bytes([31]) * 16, bytes([32]) * 16
    payer = [realm, subject]
    egress = [resource, b, a, [payer], token, 10000, [0, "backend", "service.example", 6, 443, [7]]]
    real = prefix("10.0.0.0/8")
    route = [resource, real, mapped(real), a, b, [prefix("10.1.0.0/16")],
             [prefix("10.2.0.0/16")], [1, [real]]]
    subnet = [1, 4, nsd, realm, b, 1, [route]]
    exit_grant = egress[:6] + [[1, cbor.encode(subnet)]]
    binding = [resource, b, token, [payer]]
    claim, other = [resource, b, token], [second, b, token]
    policy = [1, a, b, 1, [[realm, sorted([a, b])]], [[realm, a, b, 6, 443, 443]]]
    keys = sorted([[a, bytes([41]) * 32], [b, bytes([42]) * 32]])
    out = []

    def emit(name, kind, value, decision="accept", raw=None, **extra):
        fields = [("name", name), ("kind", kind), ("bytes", cbor.encode(value) if raw is None else raw), ("decision", decision)]
        fields.extend(extra.items())
        out.append(fields)

    def grants(entry, family=3, revision=1):
        return [1, family, a, a, revision, [entry]]

    def authority(active, retired=(), revision=1):
        return [1, 6, a, a, revision, active, list(retired)]

    expected = json.dumps(dict(resource=[x.hex() for x in cbor.decode(resource)],
                               client=b.hex(), provider=a.hex(), payer_realm=realm.hex(),
                               payer_subject=subject.hex(), incarnation=token.hex(),
                               expiry=10000), separators=(",", ":"))
    emit("egress", "grants", grants(egress), context=expected,
         details=json.dumps(egress[6][1:], separators=(",", ":")))
    emit("exit", "grants", grants(exit_grant, 4), context=expected,
         route=json.dumps(route_json(route), separators=(",", ":")),
         output=json.dumps(selected(route), separators=(",", ":")))
    emit("egress-empty", "grants", [1, 3, a, a, 2, []])
    emit("exit-empty", "grants", [1, 4, a, a, 2, []])
    emit("payer", "payer", [1, 5, a, a, 1, [binding]])
    emit("payer-empty", "payer", [1, 5, a, a, 2, []])
    for name, family, entry in [("egress", 3, egress), ("exit", 4, exit_grant)]:
        renewed = copy.deepcopy(entry)
        renewed[4] = fresh
        emit(name + "-fresh-regrant", "grants", grants(renewed, family, 3))
    for name, payers, decision in [("missing-payer", [], "missing-payer"),
                                   ("ambiguous-payer", [payer, payer], "ambiguous-payer"),
                                   ("cross-realm-payer", [payer, [nsd, subject]], "ambiguous-payer"),
                                   ("text-subject", [[realm, "01ABC"]], "encoding"),
                                   ("identity-subject", [[realm, a]], "encoding"),
                                   ("short-subject", [[realm, subject[:-1]]], "encoding")]:
        for family, original in [(3, egress), (4, exit_grant)]:
            changed = copy.deepcopy(original)
            changed[3] = payers
            emit(f"{family}-{name}", "grants", grants(changed, family), decision)
        changed = copy.deepcopy(binding)
        changed[3] = payers
        emit("payer-" + name, "payer", [1, 5, a, a, 1, [changed]], decision)
    for name, index, value, decision in [("zero-expiry", 5, 0, "field"),
                                         ("wrong-provider", 2, b, "scope"),
                                         ("wrong-family", 6, [0, "backend", "service.example", 17, 53, None], "encoding")]:
        changed = copy.deepcopy(exit_grant)
        changed[index] = value
        emit(name, "grants", grants(changed, 4), decision)
    changed = copy.deepcopy(egress)
    changed[6][3] = 1
    emit("unknown-protocol", "grants", grants(changed), "field")
    changed = copy.deepcopy(egress)
    changed[6][4] = 0
    emit("zero-port", "grants", grants(changed), "field")
    emit("duplicate-grant", "grants", [1, 3, a, a, 1, [egress, egress]], "ordering")
    emit("initial-authority", "withdrawal", authority([claim, other]))
    emit("selective-withdrawal", "withdrawal", authority([other], [[resource, token]], 2))
    emit("fresh-regrant", "withdrawal", authority([[resource, b, fresh], other], [[resource, token]], 3))
    emit("retired-regrant", "withdrawal", authority([claim, other], [[resource, token]], 3), "retired-incarnation")
    emit("authority-empty", "withdrawal", authority([], [[resource, token], [second, token]], 4))
    emit("node-authority", "l3-authority", [1, keys, cbor.encode(policy)])
    changed = copy.deepcopy(policy)
    changed[5] = []
    emit("missing-policy-denies", "l3-authority", [1, keys, cbor.encode(changed)])
    changed = copy.deepcopy(policy)
    changed[4] = []
    emit("missing-membership", "l3-authority", [1, keys, cbor.encode(changed)], "policy")
    emit("missing-binding", "l3-authority", [1, keys[:1], cbor.encode(policy)], "binding")
    emit("missing-policy-field", "l3-authority", [1, keys, cbor.encode(policy[:-1])], "policy")
    changed = copy.deepcopy(keys)
    changed[1][1] = changed[0][1]
    emit("duplicate-key", "l3-authority", [1, changed, cbor.encode(policy)], "binding")
    changed = copy.deepcopy(keys)
    changed[0][1] = bytes(32)
    emit("zero-key", "l3-authority", [1, changed, cbor.encode(policy)], "binding")
    changed = copy.deepcopy(policy)
    namespace = bytes([26]) * 16
    changed[4].append([namespace, sorted([a, b])])
    changed[5].append([namespace, a, b, 17, 53, 53])
    emit("two-namespaces", "l3-authority", [1, keys, cbor.encode(changed)])
    changed[3] = 2
    changed[4] = changed[4][1:]
    changed[5] = changed[5][1:]
    emit("selective-namespace-withdrawal", "l3-authority", [1, keys, cbor.encode(changed)])
    for name, kind, value in [("egress", "grants", grants(egress)),
                               ("exit", "grants", grants(exit_grant, 4)),
                               ("payer", "payer", [1, 5, a, a, 1, [binding]]),
                               ("withdrawal", "withdrawal", authority([claim, other])),
                               ("l3", "l3-authority", [1, keys, cbor.encode(policy)])]:
        raw = cbor.encode(value)
        emit(name + "-trailing", kind, value, "encoding", raw=raw + b"\0")
        emit(name + "-truncated", kind, value, "encoding", raw=raw[:-1])
        emit(name + "-nonminimal-schema", kind, value, "encoding", raw=raw[:1] + b"\x18\x01" + raw[2:])
        emit(name + "-missing", kind, value, "encoding", raw=b"\x80")
        if kind in ("grants", "payer"):
            subject_bytes = b"\x50" + subject
            emit(name + "-tagged-subject", kind, value, "encoding", raw=raw.replace(subject_bytes, b"\xc2" + subject_bytes))
            emit(name + "-nonminimal-subject", kind, value, "encoding", raw=raw.replace(subject_bytes, b"\x58\x10" + subject))
    return out
