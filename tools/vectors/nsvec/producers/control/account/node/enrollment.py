"""Enrollment publications and decisions, independent of the Rust consumer."""

from nsvec import cbor, derive
from nsvec.producers.control.account import profile

CRATE = "nsshared-control"
GROUP = "account/node/enrollment"
TITLE = "Enrollment decisions"
SPEC = "docs/spec/account/node.md"
EXTERNAL = None


def vectors():
    return _vectors(*profile.keys())


def _vectors(a, b):
    before = [1, a, bytes([3]) * 32, 4]
    replacement = [2, b, bytes([4]) * 32, 1]
    rotation = [1, a, bytes([4]) * 32, 5]
    capabilities = ["example.alpha.v1", "example_beta-2"]
    out = []

    def derived(prefix, binding):
        ident = binding[1]
        return [(prefix + "identity", ident),
                (prefix + "node_id", derive.node_id_text(derive.node_id(ident))),
                (prefix + "n6", derive.node_addr(ident, 0)),
                (prefix + "n4", derive.node_addr(ident, 1))]

    def emit(name, binding, decision, accepted=before, transition=None,
             authorized=False, caps=capabilities, raw=None, canonical=True):
        publication = cbor.encode([1, binding, caps])
        fields = [("name", "enrollment-" + name), ("kind", "enrollment"),
                  ("bytes", publication if raw is None else raw),
                  ("decision", decision), ("rebind", "authorized" if authorized else "denied")]
        accepted_decision = decision in {"initial", "equal", "identity-replacement", "record-rotation"}
        fields.append(("expect", "accept" if accepted_decision else "reject"))
        if not accepted_decision:
            fields.append(("reason", decision))
        if canonical:
            fields.append(("canonical", publication))
        fields.extend(derived("presented_", binding))
        if accepted is not None:
            fields.append(("accepted", cbor.encode([1, accepted, capabilities])))
            fields.extend(derived("accepted_", accepted))
        if transition is not None:
            fields.append(("lifecycle", cbor.encode(transition)))
            fields.extend(derived("lifecycle_before_", transition[2]))
            fields.extend(derived("lifecycle_after_", transition[3]))
        out.append(fields)

    def lifecycle(tag, old, new):
        return [1, tag, old, new, bytes([5]) * 16, bytes([6]) * 16]

    emit("accepted", before, "initial", accepted=None)
    emit("equal-binding", before, "equal")
    emit("empty-capabilities", before, "equal", caps=[])
    emit("capability-boundary", before, "equal", caps=[f"example.{i:02d}." + "a" * 53 for i in range(64)])
    emit("identity-replacement", replacement, "identity-replacement", transition=lifecycle(0, before, replacement))
    emit("stable-i-rotation", rotation, "record-rotation", transition=lifecycle(1, before, rotation), authorized=True)
    emit("rejected-staged-version-restart", replacement, "lifecycle-required")
    emit("rotation-without-lifecycle", rotation, "lifecycle-required", authorized=True)
    emit("lower-version", before, "lower-version", accepted=replacement)
    emit("unauthorized-rebind", rotation, "rebind-unauthorized", transition=lifecycle(1, before, rotation))
    emit("wrong-lifecycle-before", replacement, "lifecycle-mismatch", transition=lifecycle(0, before[:3] + [3], replacement))
    emit("wrong-lifecycle-after", rotation, "lifecycle-mismatch", transition=lifecycle(0, before, replacement), authorized=True)
    # Ordinary registration needs neither grants nor a usage reporter.
    # Retain the nonzero examples above as structural receiver coverage only.
    for name, binding, decision, tag, old, new, authorized in [
        ("identity-replacement", replacement, "identity-replacement", 0, before, replacement, False),
        ("stable-i-rotation", rotation, "record-rotation", 1, before, rotation, True),
        ("wrong-lifecycle-before", replacement, "lifecycle-mismatch", 0, before[:3] + [3], replacement, False),
        ("wrong-lifecycle-after", rotation, "lifecycle-mismatch", 0, before, replacement, True),
        ("unauthorized-rebind", rotation, "rebind-unauthorized", 1, before, rotation, False),
    ]:
        emit(name + "-zero-placeholders", binding, decision,
             transition=[1, tag, old, new, bytes(16), bytes(16)],
             authorized=authorized, caps=[])
    emit("invalid-lifecycle", rotation, "invalid-field", transition=lifecycle(0, before, rotation), authorized=True)
    emit("initial-with-lifecycle", replacement, "lifecycle-mismatch", accepted=None, transition=lifecycle(0, before, replacement))
    emit("same-key-record-refresh", before[:3] + [5], "lifecycle-required")
    for name, caps, decision in [
        ("unsorted-capabilities", list(reversed(capabilities)), "invalid-capabilities"),
        ("duplicate-capabilities", [capabilities[0]] * 2, "invalid-capabilities"),
        ("invalid-capability-characters", ["example/alpha"], "invalid-capabilities"),
        ("uppercase-capability", ["EXAMPLE"], "invalid-capabilities"),
        ("non-ascii-capability", ["exämple"], "invalid-capabilities"),
        ("empty-capability", [""], "invalid-capabilities"),
        ("long-capability", ["a" * 65], "capability-bounds"),
        ("too-many-capabilities", [f"example.{i:02d}" for i in range(65)], "capability-bounds"),
    ]:
        emit(name, before, decision, caps=caps, canonical=False)
    valid = cbor.encode([1, before, capabilities])
    emit("trailing", before, "trailing-bytes", raw=valid + b"\0", canonical=False)
    emit("nonminimal-array", before, "non-shortest", raw=b"\x98\x03" + valid[1:], canonical=False)
    emit("nonminimal-schema", before, "non-shortest", raw=valid[:1] + b"\x18\x01" + valid[2:], canonical=False)
    emit("zero-version", [0] + before[1:], "invalid-field", canonical=False)
    emit("zero-generation", before[:3] + [0], "invalid-field", canonical=False)
    emit("zero-k", before[:2] + [bytes(32), before[3]], "invalid-field", canonical=False)
    return out
