"""Independent anonymous selector bytes and documented consumer matching outcomes."""

from .. import cbor
from .account import key

CRATE = "nsshared-proto"
GROUP = "anonymous-public-edge"
TITLE = "Anonymous public-edge selectors and verified-only policy matching"
SECTIONS = "docs/l8-account-payload-profile.md and docs/l8-public-edge-candidate.md"


def vectors():
    realm = bytes([1]) * 16
    node = key(bytes([1]) * 32)[0]
    anonymous = bytes.fromhex("820103")
    user = cbor.encode([1, 1, realm, bytes([3]) * 16])
    node_subject = cbor.encode([1, 2, node])
    group = cbor.encode([1, 0, realm, "group:eng"])
    outsider = cbor.encode([1, 0, realm, "external:other"])
    groups = [[group, sorted([user, node_subject])]]
    out = []

    def policy(selectors, protocol=None, destinations=None):
        return [1, realm, [[selectors, destinations or ["backend.example:8080"], protocol]], groups]

    def emit(name, kind, value, accept=True, extra=()):
        out.append([("name", name), ("kind", kind), ("bytes", cbor.encode(value)),
                    ("expect", "accept" if accept else "reject"), *extra])

    policies = [("any-verified", [None]), ("anonymous", [anonymous]),
                ("user", [user]), ("node", [node_subject]), ("group", [group]),
                ("anonymous-subjects", sorted([anonymous, user, node_subject, group]))]
    # Expected outcomes follow the contract table, independent of consumer code.
    expected = {
        "any-verified": {"verified-user", "verified-node", "verified-other"},
        "anonymous": {"anonymous"}, "user": {"verified-user"},
        "node": {"verified-node"},
        "group": {"verified-user", "verified-node"},
        "anonymous-subjects": {"anonymous", "verified-user", "verified-node"},
    }
    principals = [("anonymous", None), ("verified-user", user),
                  ("verified-node", node_subject), ("group-label", group),
                  ("verified-other", outsider), ("missing", None), ("untrusted", user)]
    for name, selectors in policies:
        emit(name, "policy", policy(selectors))
        for principal, subject in principals:
            extra = [("principal", principal),
                     ("matches", "true" if principal in expected[name] else "false")]
            if subject is not None:
                extra.append(("subject", subject))
            emit(name + "-" + principal, "matching", policy(selectors), extra=extra)
    for name, selectors in [
        ("null-anonymous", [None, anonymous]), ("null-subject", [None, user]),
        ("anonymous-null", [anonymous, None]),
        ("unknown-selector", [cbor.encode([1, 4])]),
        ("nonminimal-version", [bytes.fromhex("82180103")]),
        ("nonminimal-tag", [bytes.fromhex("82011803")]),
        ("nonminimal-array", [bytes.fromhex("98020103")]),
        ("trailing-selector", [anonymous + b"\0"]),
        ("wrong-version", [cbor.encode([2, 3])]),
        ("wrong-arity", [cbor.encode([1, 3, 0])]),
        ("bare-array", [[1, 3]]), ("empty-subjects", []),
        ("duplicate-anonymous", [anonymous, anonymous]),
        ("unordered", [user, anonymous]),
        ("unordered-qualified", [anonymous, user, node_subject]),
    ]:
        emit(name, "policy", policy(selectors), False)
    emit("bad-protocol", "policy", policy([anonymous], 1), False)
    emit("duplicate-destination", "policy", policy([anonymous], destinations=["a:1", "a:1"]), False)
    emit("empty-destinations", "policy", [1, realm, [[[anonymous], [], None]], []], False)
    emit("anonymous-not-identity", "subject", [1, 3], False)
    emit("anonymous-not-group-member", "policy",
         [1, realm, [[[group], ["a:1"], None]], [[group, [anonymous]]]], False)
    emit("anonymous-not-binding", "binding", [1, realm, 1, "credential", anonymous, True, 200], False)
    emit("anonymous-not-admin", "admin", [1, anonymous, 0, realm, 200], False)
    for name, protocol, public_port in [("http", 0, 80), ("tcp", 6, 9000), ("udp", 17, 9000)]:
        cases = [("without-auth", [anonymous], True, False),
                 ("any-verified", [None], True, False),
                 ("user", [user], True, False),
                 ("anonymous-subjects", sorted([anonymous, user, node_subject, group]), True, False),
                 ("anonymous-auth", [anonymous], True, True),
                 ("invalid-selector", [cbor.encode([1, 4])], False, False)]
        for suffix, selectors, accepted, requires_auth in cases:
            rule = policy(selectors, 17 if protocol == 17 else 6)
            reference = cbor.encode([bytes([4]) * 16, bytes([5]) * 16, bytes([6]) * 16])
            headers = cbor.encode([1, False, None, None, None, None, False])
            options = [0, None, None, [None] * 11, None, None, None, []]
            dependencies = [[0, "auth", 1]] if requires_auth else []
            route = ["route", "public.example" if protocol == 0 else None, [], [], reference, node, protocol,
                     public_port, 8080, cbor.encode(rule), headers, dependencies, options]
            auth = cbor.encode([1, realm, dependencies, [], [], []])
            emit(name + "-" + suffix, "edge",
                 [1, 7, "01040G2081040G2081040G2081", "edge", [[realm, auth, [route]]]],
                 accepted, extra=[("protocol", protocol), ("requires_auth", "true" if requires_auth else "false")])
    return out
