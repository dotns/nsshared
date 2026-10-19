"""Independent discovery and authenticated opaque carrier decisions."""

import base64
import copy
import hashlib

from .. import cbor

REQUEST = b"ns.account.call.request.v1\0"
RESPONSE = b"ns.account.call.response.v1\0"


def pin(key):
    x = base64.urlsafe_b64encode(key).rstrip(b"=")
    jwk = b'{"crv":"Ed25519","kty":"OKP","x":"' + x + b'"}'
    return base64.urlsafe_b64encode(hashlib.sha256(jwk).digest()).rstrip(b"=").decode()


def vectors(a, b, sign):
    out = []
    pa, pb = pin(a), pin(b)
    spki = base64.urlsafe_b64encode(bytes([7]) * 32).rstrip(b"=").decode()
    origin = "https://control.example/"
    endpoints = [[1, "noise://control.example:8443/"],
                 [2, "quic://control.example:8444/"], [0, origin]]
    discovery = [1, 1, origin, [1], endpoints, bytes([3]) * 32, [spki], [pb, pa]]

    def emit(name, kind, raw, decision, extra=()):
        fields = [("name", "bootstrap-" + name), ("kind", kind),
                  ("bytes", raw), ("decision", decision),
                  ("expect", "accept" if decision == "accepted" else "reject")]
        fields.extend(extra)
        out.append(fields)

    def discover(name, value=discovery, decision="accepted", raw=None, local=(), supported=(0, 2, 1)):
        extra = [("local_pins", cbor.encode(list(local)))]
        if decision == "accepted":
            effective = [p for p in value[7] if not local or p in local]
            extra += [("canonical", cbor.encode(value)), ("origin", value[2]),
                      ("endpoints", cbor.encode(value[4])), ("noise", cbor.encode(value[5])),
                      ("quic_pins", cbor.encode(value[6])),
                      ("effective_pins", cbor.encode(effective)),
                      ("supported", cbor.encode(list(supported))),
                      ("selected", cbor.encode(next((e for e in value[4] if e[0] in supported), None)))]
        emit(name, "bootstrap-discovery", cbor.encode(value) if raw is None else raw, decision, extra)

    discover("discovery")
    discover("select-quic", supported=[2, 0])
    discover("select-https", supported=[0])
    discover("select-none", supported=[])
    https_only = copy.deepcopy(discovery)
    https_only[4], https_only[5], https_only[6] = [[0, origin]], None, []
    discover("https-only", https_only)
    discover("intersection", local=[pa])
    discover("intersection-preserves-discovery-order", local=[pa, pb])
    discover("empty-intersection", local=[spki], decision="empty-intersection")
    discover("local-duplicate", local=[pa, pa], decision="pins")
    discover("local-noncanonical", local=[pa + "="], decision="pins")
    for name, index, value, decision in [
        ("trust-version", 1, 2, "version"), ("missing-envelope-version", 3, [], "version"),
        ("unsupported-envelope-version", 3, [2], "version"),
        ("plaintext-discovery", 2, "http://control.example/", "origin"),
        ("empty-endpoints", 4, [], "endpoints"),
        ("duplicate-endpoints", 4, endpoints * 2, "endpoints"),
        ("plaintext-kind", 4, [[3, "http://control.example/"]], "endpoint-kind"),
        ("unknown-kind", 4, [[99, origin]], "endpoint-kind"),
        ("noise-without-key", 5, None, "noise-key"),
        ("quic-without-pins", 6, [], "quic-pins"),
        ("empty-envelope-pins", 7, [], "empty-pins"),
        ("duplicate-envelope-pins", 7, [pa, pa], "pins"),
        ("duplicate-quic-pins", 6, [spki, spki], "pins"),
        ("noncanonical-envelope-pin", 7, [pa + "="], "pins"),
        ("noncanonical-quic-pin", 6, [spki[:-1] + "d"], "pins"),
    ]:
        value_doc = copy.deepcopy(discovery)
        value_doc[index] = value
        discover(name, value_doc, decision)
    for name, bad in [
        ("endpoint-scheme", "http://control.example/"),
        ("endpoint-path", "https://control.example/a"),
        ("endpoint-credentials", "https://u@control.example/"),
        ("endpoint-query", "https://control.example/?a"),
        ("endpoint-fragment", "https://control.example/#a"),
        ("endpoint-uppercase", "https://CONTROL.example/"),
        ("endpoint-default-port", "https://control.example:443/"),
        ("endpoint-noncanonical-ip", "https://127.0.0.01/"),
        ("endpoint-escaped-host", "https://%61.example/"),
        ("endpoint-hex-ip", "https://0x7f000001/"),
        ("endpoint-short-ip", "https://127.1/"),
        ("endpoint-numeric-tld", "https://example.1/"),
        ("endpoint-dotted-mapped-ipv6", "https://[::ffff:192.0.2.1]/"),
        ("endpoint-long-ipv6", "https://[2001:0db8::1]/"),
    ]:
        value_doc = copy.deepcopy(discovery)
        value_doc[4] = [[0, bad]]
        discover(name, value_doc, "origin")
    for name, endpoint in [
        ("noise-missing-port", [1, "noise://control.example/"]),
        ("quic-zero-port", [2, "quic://control.example:0/"]),
        ("noise-leading-zero-port", [1, "noise://control.example:08443/"]),
    ]:
        value_doc = copy.deepcopy(discovery)
        value_doc[4] = [endpoint]
        discover(name, value_doc, "origin")
    for name, url in [("ipv4", "https://192.0.2.1/"), ("ipv6", "https://[2001:db8::1]/"), ("mapped-ipv6", "https://[::ffff:c000:201]/")]:
        value_doc = copy.deepcopy(discovery)
        value_doc[4] = [[0, url]]
        discover(name, value_doc)
    discover("legacy-field", raw=cbor.encode(discovery + [bytes([4]) * 32]), decision="bounds")
    raw = cbor.encode(discovery)
    discover("discovery-trailing", raw=raw + b"\0", decision="trailing")
    discover("discovery-nonminimal", raw=b"\x98\x08" + raw[1:], decision="nonminimal")
    discover("discovery-missing-schema", raw=raw[:1] + b"\xf6" + raw[2:], decision="version")
    discover("discovery-oversize", raw=raw + bytes(262145 - len(raw)), decision="bounds")

    payload = b"\x82\x01\x40"  # Opaque example bytes; no service message clone.
    content = [1, 1, a, b, "example.reply", 1000, bytes([9]) * 16, payload]

    def envelope(name, value=content, decision="accepted", domain=None, direction=1,
                 recipient=b, kind="example.reply", now=1000, seen=None,
                 pins=(pb, pa), local=(), signature=None, raw=None):
        encoded = cbor.encode(value)
        signature = sign(bytes([1]) * 32, (domain or (REQUEST if value[1] == 0 else RESPONSE)) + encoded) if signature is None else signature
        carrier = cbor.encode([encoded, signature])
        extra = [("discovered_pins", cbor.encode(list(pins))),
                 ("local_pins", cbor.encode(list(local))), ("direction", direction),
                 ("recipient", recipient), ("expected_kind", kind), ("now", now),
                 ("seen", cbor.encode(seen))]
        if decision == "accepted":
            extra += [("canonical", carrier), ("issuer", value[2]),
                      ("named_recipient", cbor.encode(value[3])), ("payload", value[7]),
                      ("nonce", value[6]), ("timestamp", value[5])]
        emit(name, "bootstrap-envelope", carrier if raw is None else raw, decision, extra)
        return carrier

    valid = envelope("response")
    request = content.copy(); request[1] = 0
    envelope("request", request, direction=0)
    anonymous = content.copy(); anonymous[3] = None
    envelope("response-without-recipient", anonymous)
    envelope("response-local-intersection", local=[pa])
    envelope("unpinned-signer", pins=[pb], decision="signer")
    envelope("signer-excluded-by-intersection", local=[pb], decision="signer")
    envelope("envelope-empty-discovered", pins=[], decision="empty-pins")
    envelope("envelope-empty-intersection", local=[spki], decision="empty-intersection")
    envelope("wrong-recipient", recipient=a, decision="recipient")
    envelope("wrong-kind", kind="example.other", decision="kind")
    envelope("wrong-domain", domain=REQUEST, decision="signature")
    envelope("wrong-direction", direction=0, decision="direction")
    envelope("invalid-signature", signature=bytes(64), decision="signature")
    for name, index, field in [("tampered-issuer", 2, b), ("tampered-payload", 7, b"changed"),
                               ("tampered-nonce", 6, bytes([8]) * 16),
                               ("tampered-timestamp", 5, 1001)]:
        changed = content.copy(); changed[index] = field
        original_signature = sign(bytes([1]) * 32, RESPONSE + cbor.encode(content))
        envelope(name, changed, decision="signature", signature=original_signature)
    changed = content.copy(); changed[1] = 9
    envelope("unknown-direction", changed, decision="direction")
    for name, kind in [("empty-kind", ""), ("oversize-kind", "x" * 257)]:
        changed = content.copy(); changed[4] = kind
        envelope(name, changed, decision="kind" if not kind else "bounds")
    for name, now, decision in [("stale", 1061, "clock"), ("future", 939, "clock"),
                                ("skew-past-boundary", 1060, "accepted"),
                                ("skew-future-boundary", 940, "accepted")]:
        envelope(name, now=now, decision=decision)
    for name, timestamp, now, decision in [
        ("clock-zero", 0, 0, "accepted"),
        ("clock-max", 2**64 - 1, 2**64 - 1, "accepted"),
        ("clock-max-stale", 0, 2**64 - 1, "clock"),
    ]:
        changed = content.copy(); changed[5] = timestamp
        envelope(name, changed, now=now, decision=decision)
    envelope("replay", seen=999, decision="replay")
    envelope("replay-boundary", seen=880, decision="replay")
    envelope("replay-expired", seen=879)
    envelope("replay-future", seen=1001, decision="replay")
    for name, version in [("envelope-unsupported-version", 2), ("envelope-missing-version", None)]:
        changed = content.copy(); changed[0] = version
        envelope(name, changed, decision="version")
    envelope("envelope-trailing", raw=valid + b"\0", decision="trailing")
    envelope("envelope-nonminimal", raw=b"\x98\x02" + valid[1:], decision="nonminimal")
    inner_nonminimal = b"\x98\x08" + cbor.encode(content)[1:]
    envelope("content-nonminimal", raw=cbor.encode([inner_nonminimal, sign(bytes([1]) * 32, RESPONSE + inner_nonminimal)]), decision="nonminimal")
    envelope("content-trailing", raw=cbor.encode([cbor.encode(content) + b"\0", bytes(64)]), decision="trailing")
    envelope("declared-carrier-oversize", raw=b"\x82" + cbor.head(cbor.BYTES, 8388609), decision="bounds")
    # Boundary inputs are raw bytes, independent of their transport implementation.
    for boundary, maximum in [(0, 262144), (1, 8388608), (2, 16384),
                               (3, 16384), (4, 65519), (5, 65535)]:
        for delta in (0, 1):
            emit(f"boundary-{boundary}-{delta}", "bootstrap-boundary", b"x" * (maximum + delta),
                 "accepted" if delta == 0 else "bounds", [("boundary", boundary)])
    return out
