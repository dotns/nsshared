"""Independent exact floor data text and capability-token boundary vectors."""
import copy
import hashlib
from .. import cbor
from . import public_edge

CRATE = "nsshared-proto"
GROUP = "floor-text"
TITLE = "Exact service and Exit floor data text"
SECTIONS = "repository docs/control-report-candidate.md"


def vectors():
    base = next(dict(v)["bytes"] for v in public_edge.vectors() if dict(v)["name"] == "request-1")
    base = cbor.decode(base)
    out = []

    def digest(request):
        request[-1] = hashlib.sha256(b"ns.account.service-floor.v1\0" + cbor.encode(request[7:10])).digest()
        return request

    def request(service="web api", exit_ref="exit west", label="team name"):
        declaration = {"declaration_key": service, "display_name": "Presentation only",
                       "description": None, "enabled": True, "protocols": ["tcp"],
                       "backend_host": ["dns", "backend.example"], "backend_port": 80,
                       "port_mode": "fixed", "requested_port": 8080}
        report = {"scope": base[2:5], "strict_mode": True, "declarations": [declaration]}
        value = copy.deepcopy(base)
        value[7] = public_edge.m6(report)
        value[8] = [[service, ["service.tcp"], [[label, "Platform Engineering"]]]]
        value[9] = [[exit_ref, [0], True, ["exit.tcp"], [[label, "Platform Engineering"]]]]
        return digest(value)

    def response(pending, outcomes=None):
        if outcomes is None:
            outcomes = [[pending[8][0][0]], [pending[9][0][0]], []]
        return pending[:7] + [pending[-1], outcomes]

    def emit(name, kind, value, accept=True, **extra):
        out.append([("name", name), ("kind", kind), ("bytes", cbor.encode(value)),
                    ("expect", "accept" if accept else "refuse"), *extra.items()])

    cases = [("spaces", "web api", "exit west", "team name"),
             ("padded", " web api ", " exit west ", " team name "),
             ("one-space", " ", " ", " "),
             ("unicode-nfc", "api \u00e9", "exit\u00a0west", "team\u00a0name"),
             ("unicode-nfd", "api e\u0301", "exit\u2003west", "team\u2003name"),
             ("byte-limit", "s" * 255, "e" * 256, "k" * 256),
             ("utf8-byte-limit", "\u00e9" * 127, "\u00e9" * 128, "\u00e9" * 128)]
    for name, service, exit_ref, label in cases:
        value = request(service, exit_ref, label)
        emit(name + "-request", "request", value, service=service.encode(), exit=exit_ref.encode(), label=label.encode())
        for suffix, outcomes in [("accepted", [[service], [exit_ref], []]),
                                 ("service-rejected", [[], [exit_ref], [[0, service, "policy refused"]]]),
                                 ("exit-rejected", [[service], [], [[1, exit_ref, "scope refused"]]])]:
            answer = response(value, outcomes)
            emit(name + "-" + suffix, "match", answer, pending=cbor.encode(value), accepted="yes" if suffix == "accepted" else "no")
    good = request()
    for name, value in [("empty", ""), ("nul", "bad\0key"), ("tab", "bad\tkey"),
                        ("newline", "bad\nkey"), ("del", "bad\x7fkey"), ("unicode-control", "bad\u0085key"),
                        ("too-long", "x" * 257), ("utf8-too-long", "\u00e9" * 129)]:
        for site in ["metadata-reference", "exit-reference", "service-label-key", "exit-label-key"]:
            changed = copy.deepcopy(good)
            if site == "metadata-reference":
                changed = request(service=value)
            elif site == "exit-reference":
                changed[9][0][0] = value
            elif site == "service-label-key":
                changed[8][0][2][0][0] = value
            else:
                changed[9][0][4][0][0] = value
            emit(site + "-" + name, "request", digest(changed), False)
        emit("rejection-reason-" + name, "response", response(good, [[], ["exit west"], [[0, "web api", value]]]), False)
        if name != "empty":
            for site in ["service", "exit"]:
                changed = copy.deepcopy(good)
                if site == "service":
                    changed[8][0][2][0][1] = value
                else:
                    changed[9][0][4][0][1] = value
                emit(site + "-label-value-" + name, "request", digest(changed), False)
        for site, outcomes in [
                ("accepted-service", [[value], ["exit west"], []]),
                ("accepted-exit", [["web api"], [value], []]),
                ("rejected-service", [[], ["exit west"], [[0, value, "reason"]]]),
                ("rejected-exit", [["web api"], [], [[1, value, "reason"]]])]:
            emit(site + "-" + name, "response", response(good, outcomes), False)
    for kind in ["service", "exit"]:
        for name, values in [("space", ["bad token"]), ("control", ["bad\ttoken"]),
                             ("empty", [""]), ("length", ["x" * 65]), ("count", ["a"] * 65),
                             ("duplicate", ["a", "a"]), ("unsorted", ["b", "a"])]:
            changed = copy.deepcopy(good)
            changed[8][0][1] = values if kind == "service" else changed[8][0][1]
            changed[9][0][3] = values if kind == "exit" else changed[9][0][3]
            emit(kind + "-capability-" + name, "request", digest(changed), False)
    for site in ["service-label", "exit-label", "exit-reference"]:
        for mode in ["duplicate", "unsorted", "count"]:
            changed = copy.deepcopy(good)
            if site == "exit-reference":
                item = copy.deepcopy(changed[9][0])
                values = [copy.deepcopy(item) for _ in range(257 if mode == "count" else 2)]
                if mode == "unsorted":
                    values[0][0], values[1][0] = "z exit", "a exit"
                changed[9] = values
            else:
                values = [["team name", "one"] for _ in range(257 if mode == "count" else 2)]
                if mode == "unsorted":
                    values[0][0], values[1][0] = "z key", "a key"
                if site == "service-label":
                    changed[8][0][2] = values
                else:
                    changed[9][0][4] = values
            emit(site + "-" + mode, "request", digest(changed), False)
    for site in ["accepted-service", "accepted-exit", "rejected-service", "rejected-exit"]:
        for mode in ["duplicate", "unsorted", "count"]:
            count = 257 if mode == "count" else 2
            refs = ["web api" if site.endswith("service") else "exit west"] * count
            if mode == "unsorted":
                refs = ["z ref", "a ref"]
            outcomes = [[], [], []]
            if site.startswith("accepted"):
                outcomes[0 if site.endswith("service") else 1] = refs
            else:
                outcomes[2] = [[0 if site.endswith("service") else 1, ref, "reason"] for ref in refs]
            emit(site + "-" + mode, "response", response(good, outcomes), False)
    padded = request(" web api ", " exit west ", " team name ")
    for name, outcomes, pending in [
            ("trimmed-service", [["web api"], [" exit west "], []], padded),
            ("trimmed-exit", [[" web api "], ["exit west"], []], padded),
            ("folded-service", [["WEB API"], ["exit west"], []], good),
            ("collapsed-service", [["web api"], ["exit west"], []], request("web  api")),
            ("normalized-service", [["api \u00e9"], ["exit west"], []], request("api e\u0301")),
            ("trimmed-rejected-service", [[], [" exit west "], [[0, "web api", "reason"]]], padded),
            ("trimmed-rejected-exit", [[" web api "], [], [[1, "exit west", "reason"]]], padded)]:
        emit(name, "match", response(pending, outcomes), False, pending=cbor.encode(pending))
    for name, value in [("empty", ""), ("padded", " value  "), ("byte-limit", "é" * 128)]:
        changed = copy.deepcopy(good)
        changed[8][0][2][0][1] = value
        changed[9][0][4][0][1] = value
        emit("label-values-" + name, "request", digest(changed), service=b"web api", exit=b"exit west", label=b"team name")
        emit("label-values-" + name + "-accepted", "match", response(changed), pending=cbor.encode(changed), accepted="yes")
    two = copy.deepcopy(good)
    declarations = [{"declaration_key": key, "display_name": None, "description": None,
                     "enabled": True, "protocols": ["tcp"],
                     "backend_host": ["dns", "backend.example"], "backend_port": 80,
                     "port_mode": "fixed", "requested_port": 8080} for key in ["a api", "z api"]]
    two[7] = public_edge.m6({"scope": base[2:5], "strict_mode": True, "declarations": declarations})
    two[8] = [[key, ["service.tcp"], [["a key", "one"], ["z key", "two"]]] for key in ["a api", "z api"]]
    two[9] = [[key, [0], True, ["exit.tcp"], [["a key", "one"], ["z key", "two"]]] for key in ["a exit", "z exit"]]
    digest(two)
    emit("ordered-data-request", "request", two, service=b"a api", exit=b"a exit", label=b"a key")
    emit("ordered-data-accepted", "match", response(two, [["a api", "z api"], ["a exit", "z exit"], []]), pending=cbor.encode(two), accepted="yes")
    emit("ordered-data-rejected", "match", response(two, [[], [], [[0, "a api", "reason"], [0, "z api", "reason"], [1, "a exit", "reason"], [1, "z exit", "reason"]]]), pending=cbor.encode(two), accepted="no")
    for name, refs in [("duplicate", ["a api", "a api"]), ("unsorted", ["z api", "a api"]), ("count", ["a api"] * 257)]:
        changed = copy.deepcopy(two)
        changed[8] = [[ref, ["service.tcp"], []] for ref in refs]
        emit("metadata-" + name, "request", digest(changed), False)
    return out
