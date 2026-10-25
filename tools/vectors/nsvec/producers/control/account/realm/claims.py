"""Spec-derived policy and claim inputs, without calling the Rust consumer."""

import hashlib
import json
import urllib.parse

from nsvec import cbor, ed25519
from nsvec.producers.control.account.control import envelope as bootstrap_envelope

CRATE = "nsshared-control"
GROUP = "account/realm/claims"
TITLE = "Policy, subject, admin scope and signed request canonical values"
SPEC = "docs/spec/account/realm.md"
EXTERNAL = None


def vectors():
    realm = bytes([1]) * 16
    other = bytes([2]) * 16
    node = ed25519.public_key(bytes([1]) * 32)
    user = cbor.encode([1, 1, realm, bytes([3]) * 16])
    external = cbor.encode([1, 0, realm, "external:app"])
    group = cbor.encode([1, 0, realm, "group:eng"])
    binding = [1, realm, 1, "credential-a", external, True, 200]
    out = []

    def emit(name, kind, value, accepted=True, raw=None, extra=()):
        if kind == "jwt" and accepted:
            extra = [*extra, ("claim_name_json", json.dumps(value[3])),
                     ("claim_value_json", json.dumps(value[4]))]
        out.append([("name", name), ("kind", kind),
                    ("bytes", cbor.encode(value) if raw is None else raw),
                    ("expect", "accept" if accepted else "reject"), *extra])

    for name, value in [("external", [1, 0, realm, "external:app"]),
                        ("user", [1, 1, realm, bytes([3]) * 16]),
                        ("node", [1, 2, node])]:
        emit("subject-" + name, "subject", value)
    for name, value in [("missing", [1, 0, realm]),
                        ("empty", [1, 0, realm, ""]),
                        ("no-suffix", [1, 0, realm, "user:"]),
                        ("unknown-prefix", [1, 0, realm, "visitor:a"]),
                        ("whitespace", [1, 0, realm, "user:a b"]),
                        ("wrong-realm-width", [1, 0, other[:-1], "user:a"]),
                        ("wrong-user-width", [1, 1, realm, bytes(32)]),
                        ("invalid-node", [1, 2, (2).to_bytes(32, "little")]),
                        ("unknown-tag", [1, 9, node]),
                        ("long-name", [1, 0, realm, "external:" + "a" * 256])]:
        emit("subject-" + name, "subject", value, False)
    emit("binding-credential", "binding", binding)
    emit("binding-node", "binding", [1, realm, 0, node, user, False, None])
    for name, index, value in [("realm", 1, other), ("group", 4, group),
                               ("anchor", 2, 9), ("empty-anchor", 3, "")]:
        bad = binding.copy()
        bad[index] = value
        emit("binding-wrong-" + name, "binding", bad, False)
    policy = [1, realm, [[[group], ["db:5432"], 6]], [[group, [external, user]]]]
    policy[3][0][1].sort()
    emit("policy-groups", "policy", policy)
    emit("policy-empty", "policy", [1, realm, [], []])
    emit("policy-wildcard", "policy", [1, realm, [[[None], ["*:*"], None]], []])
    for name, value in [("unknown-group", [1, realm, policy[2], []]),
                        ("empty-subjects", [1, realm, [[[], ["db:5432"], 6]], []]),
                        ("mixed-wildcard", [1, realm, [[[None, user], ["*:*"], None]], []]),
                        ("duplicate-subject", [1, realm, [[[user, user], ["*:*"], None]], []]),
                        ("duplicate-destination", [1, realm, [[[user], ["a:1", "a:1"], 6]], []]),
                        ("protocol", [1, realm, [[[user], ["a:1"], 2]], []]),
                        ("cross-realm", [1, other, policy[2], policy[3]]),
                        ("group-member", [1, realm, policy[2], [[group, [group]]]])]:
        emit("policy-" + name, "policy", value, False)
    for scope in range(3):
        emit("admin-scope-" + str(scope), "admin", [1, user, scope, realm, 200])
    emit("admin-unbound", "admin", [1, user, 0, None, 200])
    for name, value in [("unknown-scope", [1, user, 3, realm, 200]),
                        ("missing-scope", [1, user, realm, 200]),
                        ("missing-subject", [1, None, 1, realm, 200]),
                        ("group", [1, group, 1, realm, 200]),
                        ("cross-realm", [1, user, 1, other, 200])]:
        emit("admin-" + name, "admin", value, False)
    jwt = [1, cbor.encode(binding), "issuer-a", "sub", "client-a", ["read", "write"]]
    emit("jwt-binding", "jwt", jwt)
    emit("jwt-department-spaces", "jwt", jwt[:3] + ["department", "Platform Engineering"] + jwt[5:])
    emit("jwt-unsorted-scopes", "jwt", jwt[:-1] + [["write", "read"]], False)
    emit("jwt-empty-claim", "jwt", jwt[:4] + [""] + jwt[5:])
    emit("jwt-node-anchor", "jwt", [1, cbor.encode([1, realm, 0, node, user, True, None]), *jwt[2:]], False)
    for field, index in [("name", 3), ("value", 4)]:
        for case, exact in [
            ("internal-space", "Platform Engineering"),
            ("padded", "  Platform Engineering\t"),
            ("unicode", "\u00e9"), ("decomposed", "e\u0301"),
            ("control", "\0\r\n\t"), ("empty", ""),
            ("whitespace-only", " \u00a0 "),
            ("ascii-boundary", "a" * 256),
            ("utf8-boundary", "\u00e9" * 128),
        ]:
            exact_binding = jwt.copy()
            exact_binding[index] = exact
            emit(f"jwt-{field}-{case}", "jwt", exact_binding)
        for case, invalid in [
            ("too-long", "a" * 257), ("utf8-too-long", "\u00e9" * 129),
            ("null", None), ("bytes", b"department"), ("integer", 1),
        ]:
            invalid_binding = jwt.copy()
            invalid_binding[index] = invalid
            emit(f"jwt-{field}-{case}", "jwt", invalid_binding, False)
        emit(f"jwt-{field}-missing", "jwt", jwt[:index] + jwt[index + 1:], False)
        prefix = cbor.head(cbor.ARRAY, len(jwt)) + b"".join(cbor.encode(v) for v in jwt[:index])
        suffix = b"".join(cbor.encode(v) for v in jwt[index + 1:])
        for case, invalid_text in [("invalid-utf8", b"\x61\xff"),
                                   ("nonminimal-text", b"\x78\x00")]:
            emit(f"jwt-{field}-{case}", "jwt", None, False, prefix + invalid_text + suffix)
    emit("jwt-authority-whitespace", "jwt", jwt[:2] + ["issuer a"] + jwt[3:], False)
    emit("jwt-scope-whitespace", "jwt", jwt[:-1] + [["read write"]], False)
    credential_space = binding.copy()
    credential_space[3] = "credential a"
    emit("binding-reference-whitespace", "binding", credential_space, False)
    emit("policy-destination-whitespace", "policy", [1, realm, [[[user], ["db: 5432"], 6]], []], False)
    header = [1, True, "x-subject", "x-signature", "header-key", 60, True]
    emit("signed-header", "header", header)
    emit("disabled-header", "header", [1, False, None, None, None, None, False])
    for name, index, value in [("missing-key", 4, None), ("zero-validity", 5, 0),
                               ("inbound", 6, False), ("uppercase", 2, "X-Subject"),
                               ("same-header", 3, "x-subject"), ("bad-header", 2, "x:subject"),
                               ("whitespace-header", 2, "x subject"),
                               ("whitespace-key", 4, "header key")]:
        bad = header.copy()
        bad[index] = value
        emit("header-" + name, "header", bad, False)
    emit("subject-name-boundary", "subject", [1, 0, realm, "external:" + "a" * 247])
    emit("policy-rule-boundary", "policy", [1, realm, [[[user], ["a:1"], 17]] * 256, []])
    emit("policy-too-many-rules", "policy", [1, realm, [[[user], ["a:1"], 17]] * 257, []], False)
    emit("policy-destination-boundary", "policy", [1, realm, [[[user], [f"host{i:03d}:1" for i in range(256)], None]], []])
    emit("policy-too-many-destinations", "policy", [1, realm, [[[user], [f"host{i:03d}:1" for i in range(257)], None]], []], False)
    # Same shortest-form and trailing-input refusals for every new decoder.
    samples = [("subject", [1, 0, realm, "user:a"]), ("binding", binding),
               ("policy", policy), ("admin", [1, user, 1, realm, 200]),
               ("jwt", jwt), ("header", header)]
    for kind, value in samples:
        valid = cbor.encode(value)
        emit(kind + "-nonminimal", kind, value, False, valid[:1] + b"\x18\x01" + valid[2:])
        emit(kind + "-trailing", kind, value, False, valid + b"\0")
        emit(kind + "-version", kind, [2, *value[1:]], False)
    # Existing request envelope, signed independently in both domains.
    payload = cbor.encode([1, user, 1, realm, 200])
    content = cbor.encode([1, 0, node, node, "admin.inspect", 100, bytes([4]) * 16, payload])
    for name, domain, accepted in [("request", bootstrap_envelope.REQUEST, True),
                                    ("wrong-domain", bootstrap_envelope.RESPONSE, False)]:
        carrier = [content, ed25519.sign(bytes([1]) * 32, domain + content)]
        emit(name, "request", carrier, accepted, extra=[("signer", node), ("pin", bootstrap_envelope.pin(node)),
             ("signing_input", bootstrap_envelope.REQUEST + content)])
    valid_request = cbor.encode([content, ed25519.sign(bytes([1]) * 32, bootstrap_envelope.REQUEST + content)])
    emit("request-trailing", "request", None, False, valid_request + b"\0")
    emit("request-nonminimal", "request", None, False, b"\x98\x02" + valid_request[1:])
    response = cbor.encode([1, 1, node, node, "admin.inspect", 100, bytes([4]) * 16, payload])
    emit("response-as-request", "request", [response, ed25519.sign(bytes([1]) * 32,
         bootstrap_envelope.RESPONSE + response)], False, extra=[("signer", node)])
    for name, method, scheme, host, path, query in [
        ("signed-url", "GET", "https", " Example.COM:443 ", "/a/../b%2Fc", "z=2&a=hello+world&a=%2f&X-Nsgw-Signature=ignored"),
        ("signed-url-head", "HEAD", "http", "EXAMPLE.com:8080", "/", "x=&x&%58-Nsgw-Signature=ignored"),
    ]:
        pairs = [tuple(urllib.parse.unquote_to_bytes(p) for p in (part.split("=", 1) if "=" in part else [part, ""]))
                 for part in query.split("&") if part]
        pairs = sorted((urllib.parse.quote_from_bytes(k, safe="-_.~"), urllib.parse.quote_from_bytes(v, safe="-_.~"))
                       for k, v in pairs if k != b"X-Nsgw-Signature")
        canonical_query = "&".join(k + "=" + v for k, v in pairs)
        canonical_host = host.strip().lower()
        default = ":443" if scheme == "https" else ":80"
        if canonical_host.endswith(default):
            canonical_host = canonical_host[:-len(default)]
        request = f"{method}\n{path}\n{canonical_query}\nhost:{canonical_host}\n\nhost\nUNSIGNED-PAYLOAD"
        text = "NSGW-HMAC-SHA256\n200\nrealm-a/route-a/nsgw_signed_url\n" + hashlib.sha256(request.encode()).hexdigest()
        emit(name, "url", [method, scheme, host, path, query], extra=[("request", request.encode()), ("signing_input", text.encode())])
    return out
