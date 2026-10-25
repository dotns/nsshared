"""Independent signed per-kind publication and atomic snapshot fixtures."""

import copy
import unicodedata

from .. import cbor

DOMAIN = b"ns.account.publication.v1\0"
LIMIT = 1_048_576


def vectors(a, b, sign):
    out = []
    # These are labelled fixture authorities, not NSD producer output.
    content = [1, a, b, "030C1G60R30C1G60R30C1G60R3", "scope-a", 11, "node-l3", 1,
               True, 8, 100, 200, 0, b"fixture-node-l3"]
    prior = [[a, b, "030C1G60R30C1G60R30C1G60R3", "scope-a", 11, "node-l3", 7]]
    scopes = [["030C1G60R30C1G60R30C1G60R3", "scope-a"], ["030C1G60R30C1G60R30C1G60R3", "scope-b"], ["09144GJ289144GJ289144GJ289", "scope-b"]]

    def signed(value, domain=DOMAIN, corrupt=False):
        raw = cbor.encode(value)
        signature = sign(bytes([1]) * 32, domain + raw)
        if corrupt:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        return cbor.encode([raw, signature])

    def emit(name, raw, decision, *, mode="event", channel=1, states=prior,
             now=150, reason="none", decisions="none", canonical=True, present=1):
        fields = [("name", "publication-" + name), ("kind", "publication-" + mode),
                  ("bytes", raw), ("decision", decision), ("reason", reason),
                  ("issuer", a), ("recipient", b), ("scopes", cbor.encode(scopes)),
                  ("states", cbor.encode(states)), ("now", now), ("channel", channel),
                  ("present", present), ("encoded_length", len(raw)),
                  ("decisions", decisions)]
        next_states = copy.deepcopy(states)

        def replace_state(event_bytes, action):
            if action not in ("replace", "withdraw", "fetch-failed"):
                return
            value = cbor.decode(cbor.decode(event_bytes)[0])
            key = value[1:7]
            next_states[:] = [state for state in next_states if state[:6] != key]
            next_states.append(key + [value[9]])

        if mode == "event":
            replace_state(raw, decision)
        elif decision == "accepted":
            for event_bytes, action in zip(cbor.decode(raw)[1], decisions.split(",")):
                replace_state(event_bytes, action)
        fields.append(("next_states", cbor.encode(sorted(next_states))))
        if canonical:
            fields.append(("canonical", raw))
        if mode == "event" and canonical:
            value = cbor.decode(cbor.decode(raw)[0])
            # Only representable Rust content enters the producer API.
            if value[0] == 1 and value[3] and value[7] in (0, 1) and value[12] in (0, 1):
                owners = {(1, "own-node"): 0, (2, "realm-peers"): 1,
                          (3, "egress-grants"): 1, (4, "exit-grants"): 1,
                          (4, "subnet-routes"): 1,
                          (5, "payer-bindings"): 1, (6, "resource-authority"): 0,
                          (7, "public-edge"): 0, (8, "directory"): 1,
                          (8, "identity-classes"): 0, (9, "usage-profile"): 0,
                          (10, "node-control-profile"): 0, (11, "node-l3"): 1,
                          (11, "policy-version"): 0}
                valid = (0 < len(value[4].encode()) <= 256
                         and not any(ch.isspace() or unicodedata.category(ch) == "Cc" for ch in value[4])
                         and 0 < len(value[6].encode()) <= 256
                         and owners.get((value[5], value[6])) == value[7]
                         and value[9] > 0 and value[10] < value[11]
                         and (value[12] == 0 or
                              (value[5:7] == [11, "node-l3"] and value[13])))
                result = "fields" if not valid else "bounds" if len(raw) > LIMIT else "accept"
                fields.extend([("producer_content", cbor.decode(raw)[0]),
                               ("producer_result", result),
                               ("signing_input", DOMAIN + cbor.decode(raw)[0])])
        out.append(fields)

    def event(name, decision="replace", *, changes=None, raw=None, **kwargs):
        value = copy.deepcopy(content)
        for index, item in (changes or {}).items():
            value[index] = item
        encoded = signed(value) if raw is None else raw
        emit(name, encoded, decision, **kwargs)
        return encoded

    valid = event("complete")
    event("empty", "withdraw", changes={13: b""})
    event("absent", "absent", raw=b"\xf6", present=0, canonical=False)
    event("absent-without-state", "absent", raw=b"\xf6", present=0, states=[], canonical=False)
    event("fetch-failed", "fetch-failed", changes={12: 1, 13: b"fixture-fetch-failed"})
    event("unknown-kind", "unknown-kind", changes={6: "future-kind"})
    event("unknown-family", "unknown-kind", changes={5: 99})
    event("signed-channel-mismatch", "channel-mismatch", changes={7: 0})
    event("received-channel-mismatch", "channel-mismatch", channel=0)
    event("different-scope", changes={3: "09144GJ289144GJ289144GJ289", 4: "scope-b", 9: 1})
    event("scope-only", changes={4: "scope-b", 9: 1})
    event("issuer-version-isolated", states=[[b, b, "030C1G60R30C1G60R30C1G60R3", "scope-a", 11, "node-l3", 99]])
    event("recipient-version-isolated", states=[[a, a, "030C1G60R30C1G60R30C1G60R3", "scope-a", 11, "node-l3", 99]])
    event("withdrawal-tombstone", "refused", states=[prior[0][:-1] + [8]], reason="stale")
    event("failure-tombstone", "refused", states=[prior[0][:-1] + [8]],
          changes={12: 1, 13: b"fixture-fetch-failed"}, reason="stale")
    # Independent ownership checklist, including both kinds of the relay family.
    for family, kind, channel in [
        (1, "own-node", 0), (2, "realm-peers", 1), (3, "egress-grants", 1),
        (4, "exit-grants", 1), (4, "subnet-routes", 1), (5, "payer-bindings", 1),
        (6, "resource-authority", 0), (7, "public-edge", 0),
        (8, "directory", 1), (8, "identity-classes", 0),
        (9, "usage-profile", 0), (10, "node-control-profile", 0),
        (11, "node-l3", 1), (11, "policy-version", 0),
    ]:
        payload = content[13]
        if family in (3, 4) and kind != "subnet-routes":
            payload = cbor.encode([1, family, a, b, 8, []])
        elif kind == "subnet-routes":
            payload = cbor.encode([1, 4, bytes([21])*16, bytes([3])*16, b, 8, []])
        elif family == 9:
            payload = cbor.encode([1, b, ["l8-completed-io-v1", "l8-relay-data-v1"]])
        elif family == 10:
            payload = cbor.encode([1, [bytes([3])*16, bytes([3])*16], 2, [0, 1, 2, 3, 4]])
        event("owner-" + kind, changes={5: family, 6: kind, 7: channel, 13: payload}, channel=channel)
        event("misplaced-" + kind, "channel-mismatch",
              changes={5: family, 6: kind, 7: channel}, channel=1-channel)
    event("different-kind", changes={5: 2, 6: "realm-peers", 9: 1})
    event("first", states=[], changes={9: 1})
    event("at-issue", now=100)
    event("before-expiry", now=199)
    for name, changes, reason in [
        ("stale", {9: 6}, "stale"), ("replayed", {9: 7}, "stale"),
        ("zero-version", {9: 0}, "fields"),
        ("partial", {8: False}, "incomplete"),
        ("wrong-issuer", {1: b}, "issuer"),
        ("wrong-recipient", {2: a}, "recipient"),
        ("wrong-realm", {3: "0A1850M2GA1850M2GA1850M2GA"}, "scope"),
        ("wrong-scope", {4: "scope-other"}, "scope"),
        ("future", {10: 151}, "validity"),
        ("empty-validity", {11: 100}, "fields"),
        ("empty-realm", {3: ""}, "fields"),
        ("empty-scope", {4: ""}, "fields"),
        ("empty-kind", {6: ""}, "fields"),
        ("long-kind", {6: "k" * 257}, "encoding"),
        ("long-scope", {4: "s" * 257}, "encoding"),
        ("reversed-validity", {10: 201}, "fields"),
        ("wrong-failure-family", {5: 2, 12: 1}, "fields"),
        ("invalid-channel", {7: 2}, "fields"),
        ("invalid-outcome", {12: 2}, "fields"),
        ("wrong-failure-kind", {5: 2, 6: "realm-peers", 12: 1}, "fields"),
        ("empty-failure", {12: 1, 13: b""}, "fields"),
        ("schema", {0: 2}, "fields"),
        ("unknown-expired", {6: "future-kind", 11: 149}, "validity"),
        ("control-scope", {4: "scope\n"}, "fields"),
        ("whitespace-scope", {4: "scope a"}, "fields"),
    ]:
        event(name, "refused", changes=changes, reason=reason)
    event("at-expiry", "refused", now=200, reason="validity")
    event("bad-signature", "refused", raw=signed(content, corrupt=True), reason="signature")
    event("wrong-domain", "refused", raw=signed(content, b"ns.account.call.response.v1\0"), reason="signature")
    event("trailing", "refused", raw=valid + b"\x00", reason="encoding", canonical=False)
    event("nonminimal", "refused", raw=b"\x98\x02" + valid[1:], reason="encoding", canonical=False)
    for name, raw in [
        ("truncated-length", b"\x82\x5a\x00\x01"),
        ("declared-beyond-input", b"\x82\x5a\x00\x01\x00\x00"),
        ("declared-u64-max", b"\x82\x5b" + b"\xff" * 8),
        ("nested-truncated-length", cbor.encode([cbor.encode(content)[:-len(content[13])-1] + b"\x5a\x00", bytes(64)])),
        ("nested-declared-beyond-input", cbor.encode([cbor.encode(content)[:-len(content[13])-1] + b"\x5a\x00\x01\x00\x00", bytes(64)])),
    ]:
        event(name, "refused", raw=raw, reason="encoding", canonical=False)

    # Calibrate encoded lengths independently, including CBOR overhead.
    large = copy.deepcopy(content)
    large[5:8] = [7, "public-edge", 0]
    large[13] = b"x" * LIMIT
    excess = len(signed(large)) - LIMIT
    large[13] = large[13][excess:]
    exact = signed(large)
    assert len(exact) == LIMIT
    emit("exact-limit", exact, "replace", channel=0)
    large[13] += b"x"
    over = signed(large)
    assert len(over) == LIMIT + 1
    emit("over-limit", over, "terminate-stream", channel=0)
    # Size takes precedence over invalid framing and causes no replacement.
    emit("over-limit-malformed", b"\xff" * (LIMIT + 1), "terminate-stream",
         channel=0, canonical=False)
    emit("polled-over-limit", over, "refused", reason="bounds")

    def snapshot(name, events, decision="accepted", reason="none", decisions="none", raw=None):
        emit(name, cbor.encode([1, events]) if raw is None else raw,
             decision, mode="snapshot", reason=reason, decisions=decisions,
             canonical=raw is None)

    snapshot("snapshot", [valid], decisions="replace")
    snapshot("snapshot-empty", [])
    other = copy.deepcopy(content)
    other[3:5], other[9] = ["09144GJ289144GJ289144GJ289", "scope-b"], 1
    snapshot("snapshot-scopes", [valid, signed(other)], decisions="replace,replace")
    empty = copy.deepcopy(content)
    empty[13] = b""
    snapshot("snapshot-withdraw", [signed(empty)], decisions="withdraw")
    failure = copy.deepcopy(content)
    failure[12:14] = [1, b"fixture-fetch-failed"]
    snapshot("snapshot-fetch-failed", [signed(failure)], decisions="fetch-failed")
    unknown = copy.deepcopy(content)
    unknown[6] = "future-kind"
    snapshot("snapshot-unknown", [signed(unknown)], decisions="unknown-kind")
    stream = copy.deepcopy(content)
    stream[5:8] = [7, "public-edge", 0]
    snapshot("snapshot-channel", [signed(stream)], decisions="channel-mismatch")
    snapshot("snapshot-atomic-invalid", [valid, signed(other, corrupt=True)],
             "rejected", "signature")
    snapshot("snapshot-failure-before-invalid", [signed(failure), signed(other, corrupt=True)],
             "rejected", "signature")
    snapshot("snapshot-duplicate", [valid, valid], "rejected", "order")
    snapshot("snapshot-unsorted", [signed(other), valid], "rejected", "order")
    stale = copy.deepcopy(content)
    stale[9] = 7
    snapshot("snapshot-stale", [signed(stale)], "rejected", "stale")
    snapshot("snapshot-over-limit", [over], "rejected", "bounds")
    snapshot("snapshot-truncated-length", [], "rejected", "encoding", raw=b"\x82\x01\x81\x5a\x00")
    snapshot("snapshot-declared-length", [], "rejected", "encoding", raw=b"\x82\x01\x81\x5a\x00\x01\x00\x00")
    snapshot("snapshot-declared-count", [], "rejected", "encoding", raw=b"\x82\x01\x9b" + b"\xff" * 8)
    return out
