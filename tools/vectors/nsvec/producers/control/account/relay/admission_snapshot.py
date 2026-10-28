"""Independent controlled snapshot admission history cases."""

import base64
import copy
import json

from nsvec.producers.control.account import profile

CRATE = "nsshared-control"
GROUP = "account/relay/admission-snapshot"
TITLE = "Controlled snapshot admission history"
SPEC = "docs/spec/account/relay.md"
EXTERNAL = None


def vectors():
    a, b = profile.keys()
    entries = [
        {"identity": base64.urlsafe_b64encode(key).rstrip(b"=").decode(),
         "class": cls, "admission_since": since}
        for key, cls, since in [(a, "ordinary_node", 3), (b, "gateway_node", 7)]
    ]
    snapshot = {"schema_version": 3, "issued_at_unix_ms": 1000,
                "roster_version": 7, "identities": entries}
    out = []

    def emit(name, obj, decision):
        fields = [("name", name), ("bytes", json.dumps(obj, separators=(",", ":")).encode()),
                  ("decision", decision)]
        if decision == "accepted":
            mapping = ",".join(
                f'{entry["identity"]}:{entry["class"]}:{entry["admission_since"]}'
                for entry in obj["identities"]
            )
            fields.extend([("mapping", mapping or "empty"),
                           ("roster_version", obj["roster_version"])])
        out.append(fields)

    emit("continuous-and-readmitted", snapshot, "accepted")
    emit("complete-empty", {**snapshot, "identities": []}, "accepted")
    emit("schema-two", {**snapshot, "schema_version": 2}, "field")
    emit("schema-two-empty", {**snapshot, "schema_version": 2, "identities": []}, "field")
    changed = copy.deepcopy(snapshot)
    del changed["identities"][1]["admission_since"]
    emit("missing-admission-start", changed, "json")
    legacy = copy.deepcopy(snapshot)
    legacy["schema_version"] = 2
    for entry in legacy["identities"]:
        del entry["admission_since"]
    emit("legacy-history-free", legacy, "json")
    for name, value, decision in [
        ("zero", 0, "field"), ("above-version", 8, "field"),
        ("null", None, "json"), ("negative", -1, "json"),
        ("string", "3", "json"), ("fraction", 1.5, "json"),
    ]:
        changed = copy.deepcopy(snapshot)
        changed["identities"][1]["admission_since"] = value
        emit(name, changed, decision)
    for name, version, since in [("first-version", 1, 1),
                                 ("maximum-version", 2**64 - 1, 2**64 - 1)]:
        changed = copy.deepcopy(snapshot)
        changed["roster_version"] = version
        for entry in changed["identities"]:
            entry["admission_since"] = since
        emit(name, changed, "accepted")
    return out
