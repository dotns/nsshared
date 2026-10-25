"""Spec-derived source fences and immutable route receipt fixtures; no Rust input."""
import copy
from nsvec import cbor, derive, ed25519
from nsvec.producers.control.account.control import envelope as bootstrap_envelope
from nsvec.signing import carrier as signed_carrier

CRATE = "nsshared-control"
GROUP = "account/publication/source-selection"
TITLE = "Source authority and immutable Node route receipts (fixture authority)"
SPEC = "docs/spec/account/publication.md"
EXTERNAL = None
BINDING = b"ns.account.source-binding.v1\0"
PUBLICATION = b"ns.account.source-publication.v1\0"


def vectors():
    seed = bytes([2]) * 32
    nsd = ed25519.public_key(seed)
    node = ed25519.public_key(bytes([1]) * 32)
    provider = ed25519.public_key(bytes([3]) * 32)
    realm = "030C1G60R30C1G60R30C1G60R3"
    a = [1, nsd, node, realm, "nodes", "explicit-gateway-profile", node,
         bytes([10]) * 16, 1, 1]
    b = copy.deepcopy(a)
    b[7], b[9] = bytes([11]) * 16, 2
    stream = [0, bytes([4]) * 16, 1]
    poll = [1, bytes([4]) * 16, 1, bytes([5]) * 16]
    out = []

    def signed(value, domain, corrupt=False):
        return signed_carrier(seed, value, domain, corrupt)

    sa, sb = signed(a, BINDING), signed(b, BINDING)
    c = copy.deepcopy(b)
    c[3], c[7] = "09144GJ289144GJ289144GJ289", bytes([12])*16
    sc = signed(c, BINDING)

    def emit(name, mode, raw, accepted=True, **fields):
        out.append([("name", name), ("mode", mode), ("bytes", raw),
                    ("decision", "accepted" if accepted else "refused"),
                    *fields.items()])

    for name, value in [("source-a", a), ("source-b", b)]:
        emit(name, "binding", signed(value, BINDING), signing_input=BINDING + cbor.encode(value), wg_key=bytes([42])*32, n4=derive.node_addr(node, 1), n6=derive.node_addr(node, 0))
    emit("source-c", "binding", sc, signing_input=BINDING + cbor.encode(c))
    for name, index, value in [
        ("old-profile-binding", 5, "gateway-v1"), ("zero-contribution", 7, bytes(16)),
        ("zero-epoch", 8, 0), ("zero-generation", 9, 0),
        ("noncanonical-realm", 3, realm.lower()), ("empty-scope", 4, ""),
        ("control-scope", 4, "nodes\n"), ("whitespace-scope", 4, "nodes a"),
    ]:
        changed = copy.deepcopy(a)
        changed[index] = value
        emit(name, "binding", signed(changed, BINDING), False)
    emit("binding-credential", "binding", signed(a + ["carrier_credential"], BINDING), False)
    emit("binding-signature", "binding", signed(a, BINDING, True), False)
    emit("binding-wrong-domain", "binding", signed(a, PUBLICATION), False)

    def carrier(payload, request, operation, direction=1, recipient=node, signer_seed=seed):
        signer = ed25519.public_key(signer_seed)
        raw = cbor.encode([1, direction, signer, recipient, operation, 100, request, payload])
        domain = bootstrap_envelope.RESPONSE if direction else bootstrap_envelope.REQUEST
        return cbor.encode([raw, ed25519.sign(signer_seed, domain + raw)])

    request_id = bytes([6]) * 16
    enrollment = cbor.encode([1, [1, node, bytes([42])*32, 1], ["node.control"]])
    membership = [bytes([3])*16, bytes([3])*16]
    staged = cbor.encode([1, membership, enrollment, "explicit-gateway-profile",
                          b"provisioned", None])
    mismatches = []
    for field, index, value in [
        ("nsd", 1, provider), ("recipient", 2, provider),
        ("realm", 3, c[3]), ("scope", 4, "other"),
        ("profile", 5, "gateway-v1"), ("source-node", 6, provider),
    ]:
        changed = copy.deepcopy(a)
        changed[index] = value
        mismatches.append((field, signed(changed, BINDING)))
    for label, normal, op in [
        ("register", [1, membership, enrollment, "explicit-gateway-profile", 0], "machine.register"),
        ("auth", [1, "a.b.c"], "machine.auth"),
    ]:
        for suffix, source, nonce, recipient, operation, malformed in [
            ("a", sa, request_id, node, op, False),
            ("missing-binding", None, request_id, node, op, False),
            ("mismatched-binding", sc, request_id, node, op, False),
            ("wrong-request", sa, bytes([7])*16, node, op, False),
            ("wrong-recipient", sa, request_id, None, op, False),
            ("wrong-operation", sa, request_id, node, "info.get", False),
            ("bad-binding-signature", signed(a, BINDING, True), request_id, node, op, False),
            ("standalone-binding", sa, request_id, node, op, True),
        ]:
            payload = cbor.encode([1, sa, request_id] if malformed else
                                  normal + ([] if source is None else [source]))
            emit(label + "-" + suffix, "acceptance", carrier(payload, nonce, operation,
                 recipient=recipient), suffix == "a", operation=op, request=staged)
        for field, changed in mismatches:
            emit(label + "-mismatched-" + field, "acceptance",
                 carrier(cbor.encode(normal + [changed]), request_id, op), False,
                 operation=op, request=staged)


    egress = copy.deepcopy(a)
    egress[4], egress[7] = "egress", bytes([13])*16
    se = signed(egress, BINDING)
    emit("source-egress", "binding", se, signing_input=BINDING + cbor.encode(egress))
    for label, source, expected_scope, expected_realm in [
        ("egress", se, "egress", realm), ("other-network", sc, "nodes", c[3])]:
        emit("register-" + label, "acceptance",
             carrier(cbor.encode([1, membership, enrollment, "explicit-gateway-profile", 0, source]),
                     request_id, "machine.register"), False, operation="machine.register",
             request=staged, expected_scope=expected_scope, expected_realm=expected_realm)
    equal = [1, membership, enrollment, "explicit-gateway-profile", 1, sa]
    emit("register-equal", "acceptance", carrier(cbor.encode(equal), request_id, "machine.register"),
         operation="machine.register", request=staged, committed=enrollment)
    for label, scope, source in [("nodes", "nodes", sa), ("egress", "egress", se)]:
        auth_request = cbor.encode([1, membership, [1, node, bytes([42])*32, 1],
                                    "control", [realm, scope]])
        nonce = bytes([6 if scope == "nodes" else 8])*16
        other_realm = copy.deepcopy(a if scope == "nodes" else egress)
        other_realm[3] = c[3]
        emit("auth-request-" + label, "authentication-request", auth_request)
        for suffix, returned, accepted in [("accepted", source, True),
                                           ("swapped-scope", se if scope == "nodes" else sa, False),
                                           ("swapped-realm", signed(other_realm, BINDING), False)]:
            emit("auth-" + label + "-" + suffix, "selected-authentication",
                 carrier(cbor.encode([1, "a.b.c", returned]), nonce, "machine.auth"),
                 accepted, request=auth_request, scope=scope, pending_nonce=nonce)

    for name, value in [("stream-context", stream), ("snapshot-context", poll)]:
        emit(name, "context", cbor.encode(value))
    for name, value in [
        ("zero-context-boot", [0, bytes(16), 1]),
        ("zero-context-attempt", [0, stream[1], 0]),
        ("overflow-context-attempt", [0, stream[1], 2**32]),
        ("zero-context-poll", [1, poll[1], 1, bytes(16)]),
        ("wrong-context-tag", [2, stream[1], 1]),
        ("context-extra-fields", stream + [0]),
    ]:
        emit(name, "context", cbor.encode(value), False)

    def publication(binding, version, *, context=poll, channel=1, family=11,
                    kind="node-l3", payload=b"fixture-l3", outcome=0, changes=None,
                    corrupt=False, outer_changes=None):
        event = [1, nsd, node, realm, "nodes", family, kind, channel, True,
                 version, 100, 200, outcome, payload]
        for index, value in (changes or {}).items():
            event[index] = value
        inner = signed(event, b"ns.account.publication.v1\0")
        content = [1, binding, cbor.encode(context), inner]
        for index, value in (outer_changes or {}).items():
            content[index] = value
        return signed(content, PUBLICATION, corrupt)

    for name, binding, version, kwargs, accepted in [
        ("delayed-a-higher-version", sa, 99, {}, False),
        ("current-b", sb, 9, {}, True),
        ("complete-empty-b", sb, 10, {"payload": b""}, True),
        ("failure-b", sb, 11, {"outcome": 1, "payload": b"fixture-failure"}, True),
        ("wrong-boot", sb, 12, {"context": [1, bytes([9])*16, 1, poll[3]]}, False),
        ("wrong-attempt", sb, 12, {"context": [1, poll[1], 2, poll[3]]}, False),
        ("wrong-poll", sb, 12, {"context": [1, poll[1], 1, bytes([9])*16]}, False),
        ("wrong-profile-publication", signed(a[:5] + ["gateway-v1"] + a[6:], BINDING), 99, {}, False),
        ("missing-binding", b"", 12, {}, False),
        ("bad-outer-signature", sb, 12, {"corrupt": True}, False),
        ("wrong-inner-scope", sb, 12, {"changes": {4: "other"}}, False),
        ("partial-b", sb, 12, {"changes": {8: False}}, False),
        ("stale-b", sb, 7, {}, False),
        ("publication-credential", sb, 12, {"outer_changes": {2: cbor.encode(poll + ["carrier_credential"])}}, False),
    ]:
        wire = publication(binding, version, **kwargs)
        content = cbor.decode(wire)[0]
        emit(name, "publication", wire, accepted, signing_input=PUBLICATION + content)
    # The same exact wrapper covers every dependent input's existing channel.
    for family, kind, channel in [(2, "realm-peers", 1), (3, "egress-grants", 1),
                                   (4, "exit-grants", 1), (7, "public-edge", 0)]:
        source = se if family == 3 else sb
        scope = "egress" if family == 3 else "nodes"
        payload = cbor.encode([1, family, nsd, node, 12, []]) if family in (3, 4) else b"fixture-l3"
        emit("source-" + kind, "publication", publication(source, 12, family=family,
             kind=kind, channel=channel, context=stream if channel == 0 else poll,
             payload=payload, changes={4: scope}), channel=channel,
             current_source="source-egress" if family == 3 else "source-b")
    resource = cbor.encode([bytes([21])*16, bytes([22])*16, bytes([23])*16])
    payer = [bytes([22])*16, bytes([24])*16]
    bindings = [[resource, node, bytes([token])*16, [payer], [0, protocol]]
                for token, protocol in [(31, 6), (32, 17)]]
    claims = [[entry[0], entry[1], entry[2], entry[4]] for entry in bindings]
    for name, family, kind, channel, payload in [
        ("source-protocol-payers", 5, "payer-bindings", 1, [1, 5, nsd, node, 1, bindings]),
        ("source-protocol-active", 6, "resource-authority", 0, [1, 6, nsd, node, 1, claims, []]),
    ]:
        emit(name, "publication", publication(sb, 12, family=family, kind=kind,
             channel=channel, context=stream if channel == 0 else poll,
             payload=cbor.encode(payload)), channel=channel)
    for name, changes in [("expired-b", {11: 150}), ("future-b", {10:151}),
                          ("wrong-inner-recipient", {2:provider}), ("wrong-inner-issuer", {1:node}),
                          ("wrong-inner-realm", {3:"09144GJ289144GJ289144GJ289"})]:
        emit(name, "publication", publication(sb, 12, changes=changes), False)
    for name, ctx, channel in [("context-channel-mismatch", stream, 1), ("received-channel-mismatch", poll, 0)]:
        emit(name, "publication", publication(sb, 12, context=ctx), False, channel=channel)
    old = signed([1, nsd, node, realm, "nodes", 11, "node-l3", 1, True, 99, 100, 200, 0, b"old"],
                 b"ns.account.publication.v1\0")
    emit("no-old-form-fallback", "publication", old, False)
    valid = publication(sb, 9)
    emit("trailing-publication", "publication", valid + b"\0", False)
    emit("nonminimal-publication", "publication", b"\x98\x02" + valid[1:], False)
    emit("snapshot-b", "snapshot", cbor.encode([1, [valid]]))
    emit("snapshot-empty", "snapshot", cbor.encode([1, []]))
    emit("snapshot-atomic-old-source", "snapshot", cbor.encode([1, [valid, publication(sa, 99)]]), False)
    emit("snapshot-duplicate", "snapshot", cbor.encode([1, [valid, valid]]), False)

    other = publication(sc, 9, changes={3:c[3]})
    emit("snapshot-multiple-scopes", "scoped-snapshot", cbor.encode([1, [valid, other]]))
    emit("snapshot-multiple-scopes-old-source", "scoped-snapshot", cbor.encode([1, [publication(sa, 99), other]]), False)

    # Fully signed mixed batches: key order is specified independently so a
    # wrong-channel refusal cannot be explained by duplicate or unsorted keys.
    low = publication(sb, 12, family=2, kind="realm-peers")
    high = publication(sb, 12)
    def mixed(name, entries, actions, accepted, scope_count=1, failure="channel"):
        emit(name, "snapshot-channel", cbor.encode([1, entries]), accepted,
             scope_count=scope_count, event_actions=",".join(actions), failure=failure)

    mixed("channel-known-only", [low, high], ["replace", "replace"], True)
    extension = publication(sb, 12, family=9, kind="future-kind")
    unknown_first = publication(sb, 12, family=0, kind="future-kind")
    unknown_last = publication(sb, 12, family=99, kind="future-kind")
    mixed("channel-unknown-kind-between", [low, extension, high],
          ["replace", "unknown-kind", "replace"], True)
    mixed("channel-unknown-family-before", [unknown_first, low, high],
          ["unknown-kind", "replace", "replace"], True)
    mixed("channel-unknown-family-after", [low, high, unknown_last],
          ["replace", "replace", "unknown-kind"], True)
    mixed("channel-multiple-scopes-unknown-kind", [low, extension, other],
          ["replace", "unknown-kind", "replace"], True, 2)
    mixed("channel-multiple-scopes-unknown-family", [low, unknown_last, other],
          ["replace", "unknown-kind", "replace"], True, 2)

    for name, family, kind, channel, action in [
        ("known-stream-declared-stream", 7, "public-edge", 0, "channel-mismatch"),
        ("known-stream-declared-snapshot", 7, "public-edge", 1, "channel-mismatch"),
        ("known-snapshot-declared-stream", 5, "payer-bindings", 0, "channel-mismatch"),
        ("unknown-kind-declared-stream", 9, "future-kind", 0, "unknown-kind"),
        ("unknown-family-before-declared-stream", 0, "future-kind", 0, "unknown-kind"),
        ("unknown-family-after-declared-stream", 99, "future-kind", 0, "unknown-kind"),
    ]:
        wrong = publication(sb, 12, family=family, kind=kind, channel=channel)
        for scopes in (1, 2):
            if family == 0:
                entries, actions = [wrong, low, high if scopes == 1 else other], [action, "replace", "replace"]
            elif family == 99 and scopes == 1:
                entries, actions = [low, high, wrong], ["replace", "replace", action]
            else:
                entries, actions = [low, wrong, high if scopes == 1 else other], ["replace", action, "replace"]
            mixed("channel-" + name + "-scopes-" + str(scopes), entries, actions, False, scopes)

    nested = cbor.decode(extension)[0]
    nested = cbor.decode(nested)
    inner = cbor.decode(nested[3])
    inner[1] = bytes([inner[1][0] ^ 1]) + inner[1][1:]
    nested[3] = cbor.encode(inner)
    bad_inner_signature = signed(nested, PUBLICATION)
    for name, wrong in [
        ("bad-outer-signature", publication(sb, 12, family=9, kind="future-kind", corrupt=True)),
        ("bad-inner-signature", bad_inner_signature),
        ("wrong-context", publication(sb, 12, family=9, kind="future-kind", context=[1, poll[1], 2, poll[3]])),
        ("old-source", publication(sa, 12, family=9, kind="future-kind")),
        ("wrong-scope", publication(sb, 12, family=9, kind="future-kind", changes={4:"zz-other"})),
    ]:
        for scopes in (1, 2):
            if name == "wrong-scope" and scopes == 1:
                entries, actions = [low, high, wrong], ["replace", "replace", "refused"]
            else:
                entries, actions = [low, wrong, high if scopes == 1 else other], ["replace", "refused", "replace"]
            mixed("channel-" + name + "-scopes-" + str(scopes), entries, actions, False, scopes, "authentication")

    route = cbor.encode([bytes([21])*16, bytes([22])*16, bytes([23])*16])
    select_a = [1, sa, bytes([30])*16, bytes([31])*16, [0, provider, route, [0, []]]]
    clear_a = [1, sa, bytes([32])*16, bytes([31])*16, [1, 10]]
    select_b = [1, sb, bytes([33])*16, bytes([34])*16, [0, provider, route, [0, []]]]
    for name, value in [("select-a", select_a), ("clear-a", clear_a), ("select-b", select_b)]:
        operation = "node.route.clear" if value[4][0] else "node.route.select"
        raw = cbor.encode(value)
        emit(name, "command", raw)
        emit("signed-" + name, "command-carrier", carrier(raw, value[2], operation,
             direction=0, recipient=nsd, signer_seed=bytes([1])*32))
    raw = cbor.encode(select_b)
    for name, nonce, recipient, op, signer in [
        ("request-zero-nonce", bytes(16), nsd, "node.route.select", bytes([1])*32),
        ("request-missing-recipient", select_b[2], None, "node.route.select", bytes([1])*32),
        ("request-retired-operation", select_b[2], nsd, "client.exit_node_selection.v1", bytes([1])*32),
        ("request-wrong-signer", select_b[2], nsd, "node.route.select", bytes([3])*32),
    ]:
        emit(name, "command-carrier", carrier(raw, nonce, op, direction=0, recipient=recipient, signer_seed=signer), False)
    emit("request-fresh-attempt", "command-carrier", carrier(cbor.encode(select_b), bytes([99])*16,
         "node.route.select", direction=0, recipient=nsd, signer_seed=bytes([1])*32))
    explicit = copy.deepcopy(select_b)
    explicit[4][3] = [1, [[4, bytes([10, 0, 0, 0]), 8]]]
    emit("select-explicit", "command", cbor.encode(explicit))
    variants = [
        ("retired-gateway-id", 4, [0, "gateway-id", route, [0, []]]),
        ("old-profile-command", 1, signed(b[:5] + ["gateway-v1"] + b[6:], BINDING)),
        ("missing-command-binding", 1, b""),
        ("zero-request", 2, bytes(16)), ("zero-selection", 3, bytes(16)),
        ("zero-clear-generation", 4, [1, 0]),
        ("mixed-selection", 4, [0, provider, route, [0, [[4, bytes(4), 0]]]]),
        ("misaligned-selection", 4, [0, provider, route, [1, [[4, bytes([10, 0, 0, 1]), 8]]]]),
    ]
    for name, index, item in variants:
        value = copy.deepcopy(select_b)
        value[index] = item
        emit(name, "command", cbor.encode(value), False)
    emit("carrier-credential-command", "command", cbor.encode(select_b + ["carrier_credential"]), False)
    emit("retired-gateway-field", "command", cbor.encode(select_b + ["selected_gateway_id"]), False)
    emit("command-trailing", "command", cbor.encode(select_b) + b"\0", False)

    for name, command, generation, outcome in [("receipt-select-a", select_a, 10, 0),
                                               ("receipt-clear-a", clear_a, 10, 1),
                                               ("receipt-select-b", select_b, 11, 0),
                                               ("receipt-clear-absent", clear_a, 10, 2)]:
        receipt = cbor.encode([1, cbor.encode(command), generation, outcome])
        emit(name, "receipt", receipt)
        for replay in (False, True):
            response = cbor.encode([1, receipt, replay])
            operation = "node.route.clear" if command[4][0] else "node.route.select"
            wire = carrier(response, command[2], operation)
            emit(name + ("-replay" if replay else "-response"), "response", wire)
    receipt_a = cbor.encode([1, cbor.encode(clear_a), 10, 1])
    response_a = cbor.encode([1, receipt_a, True])
    emit("response-wrong-request", "response", carrier(response_a, bytes([99])*16, "node.route.clear"), False)
    emit("response-missing-recipient", "response", carrier(response_a, clear_a[2], "node.route.clear", recipient=None), False)
    emit("response-wrong-operation", "response", carrier(response_a, clear_a[2], "node.route.select"), False)
    retry_nonce = bytes([98])*16
    emit("receipt-clear-a-fresh-replay", "response", carrier(response_a, retry_nonce, "node.route.clear"), pending_nonce=retry_nonce)
    old_command = copy.deepcopy(clear_a)
    old_command[1] = signed(a[:5] + ["gateway-v1"] + a[6:], BINDING)
    old_receipt = cbor.encode([1, cbor.encode(old_command), 10, 1])
    emit("old-profile-receipt", "receipt", old_receipt, False)
    emit("receipt-wrong-generation", "receipt", cbor.encode([1, cbor.encode(clear_a), 11, 1]), False)
    emit("receipt-wrong-outcome", "receipt", cbor.encode([1, cbor.encode(clear_a), 10, 0]), False)
    return out
