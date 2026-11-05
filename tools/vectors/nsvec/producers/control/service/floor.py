"""Independent versioned M6 floor content and report.replace fixtures."""

import copy
import hashlib

from nsvec import cbor, ed25519
from nsvec.producers.control.account.control import envelope as carrier
from nsvec.producers.control.service import canonical

CRATE = "nsshared-control"
GROUP = "service/floor"
FORMAT = "json"


def digest(content):
    return hashlib.sha256(b"ns.service.floor.v1\x00" + content).digest()


def document():
    floor = {
        "floor_version": 1,
        "report": bytes.fromhex(canonical.document()["report_cbor"]),
        "metadata": [["alpha", ["tcp", "udp"], [["role", "web"]]]],
        "exit_profiles": [["office", [1, ["10.0.0.0/8", "2001:db8::/32"]], True,
                           ["tcp", "udp"], [["site", "office"]]]],
    }
    encoded = cbor.encode_value(floor)
    message = {
        "schema": 1, "kind": "report.replace", "nsd_id": bytes(range(16)),
        "network_id": bytes(range(16, 32)), "subject_identity": bytes(range(32)),
        "runtime_generation": 1, "runtime_id": bytes([7]) * 16,
        "authority_epoch": 2, "request_id": bytes([8]) * 16, "session_seq": None,
        "body": {"report_revision": 3, "report_digest": digest(encoded), "report_content": encoded},
    }
    invalid = {}

    def case(name, change):
        changed = copy.deepcopy(floor)
        change(changed)
        invalid[name] = cbor.encode_value(changed).hex()

    def prefixes(values):
        return lambda value: value["exit_profiles"][0].__setitem__(1, [1, values])

    case("invalid_cidr", prefixes(["10.0.0.1/8"]))
    case("invalid_prefix_length", prefixes(["10.0.0.0/33"]))
    case("noncanonical_ipv6", prefixes(["2001:0db8::/32"]))
    case("empty_cidrs", prefixes([]))
    case("duplicate_cidrs", prefixes(["10.0.0.0/8", "10.0.0.0/8"]))
    case("overlapping_cidrs", prefixes(["10.0.0.0/8", "10.1.0.0/16"]))
    case("unordered_cidrs", prefixes(["2001:db8::/32", "10.0.0.0/8"]))
    case("oversize_cidrs", prefixes([f"10.{i // 256}.{i % 256}.0/24" for i in range(257)]))
    for name, selection in [
        ("empty_selection", []), ("unknown_selection", [2]),
        ("unknown_selection_payload", [2, []]), ("default_payload", [0, []]),
        ("default_cidrs", [0, ["0.0.0.0/0"]]), ("default_extra", [0, [], False]),
        ("explicit_missing_cidrs", [1]), ("selection_boolean", [True]),
        ("selection_text", ["0"]), ("selection_not_array", 0),
    ]:
        case(name, lambda v, selection=selection: v["exit_profiles"][0].__setitem__(1, selection))
    case("duplicate_profiles", lambda v: v["exit_profiles"].append(copy.deepcopy(v["exit_profiles"][0])))
    case("unordered_profiles", lambda v: v["exit_profiles"].append(["aaa", [1, ["192.0.2.0/24"]], True, [], []]))
    case("duplicate_metadata", lambda v: v["metadata"].append(copy.deepcopy(v["metadata"][0])))
    case("dangling_metadata", lambda v: v["metadata"][0].__setitem__(0, "absent"))
    case("unordered_capabilities", lambda v: v["metadata"][0].__setitem__(1, ["udp", "tcp"]))
    case("duplicate_labels", lambda v: v["metadata"][0].__setitem__(2, [["role", "a"], ["role", "b"]]))
    case("oversize_text", lambda v: v["metadata"][0].__setitem__(1, ["x" * 256]))
    case("unknown_version", lambda v: v.__setitem__("floor_version", 2))
    case("unknown_field", lambda v: v.__setitem__("extra", 1))
    default = copy.deepcopy(floor)
    default["exit_profiles"][0][1] = [0]
    default_encoded = cbor.encode_value(default)
    default_message = copy.deepcopy(message)
    default_message["body"] = dict(report_revision=3, report_digest=digest(default_encoded),
                                   report_content=default_encoded)
    return {"floor_cbor": encoded.hex(), "floor_sha256": digest(encoded).hex(),
            "message_cbor": cbor.encode_value(message).hex(), "invalid": invalid,
            "signed": signed_vectors(floor, message),
            "default_floor_cbor": default_encoded.hex(),
            "default_floor_sha256": digest(default_encoded).hex(),
            "default_message_cbor": cbor.encode_value(default_message).hex(),
            "signed_default": signed_vectors(default, default_message)}


def signed_vectors(floor, message):
    node = ed25519.public_key(bytes([1]) * 32)
    authority = ed25519.public_key(bytes([2]) * 32)
    floor = copy.deepcopy(floor)
    # The independent legacy fixture has exactly one publisher byte sequence.
    assert floor["report"].count(bytes(range(32))) == 1
    floor["report"] = floor["report"].replace(bytes(range(32)), node)
    content = cbor.encode_value(floor)
    request = copy.deepcopy(message)
    request["subject_identity"] = node
    request["body"] = dict(report_revision=3, report_digest=digest(content), report_content=content)
    response = copy.deepcopy(request)
    response["kind"] = "report.accepted"
    response["body"] = dict(accepted_revision=3, report_digest=digest(content), bindings=[])

    def signed(payload, response=False, nonce=9):
        content = cbor.encode([1, int(response), authority if response else node,
                               node if response else authority, "service.control.v1", 100,
                               bytes([nonce]) * 16, cbor.encode_value(payload)])
        signature = ed25519.sign(bytes([2 if response else 1]) * 32,
                                 (carrier.RESPONSE if response else carrier.REQUEST) + content)
        return cbor.encode([content, signature]).hex()

    wrong_digest = copy.deepcopy(response)
    wrong_digest["body"]["report_digest"] = hashlib.sha256(b"ns.service.report.v1\x00" + floor["report"]).digest()
    stale = copy.deepcopy(response)
    stale["runtime_generation"] = 2
    revision = copy.deepcopy(response)
    revision["body"]["accepted_revision"] = 4
    return dict(node_pin=carrier.pin(node), authority_pin=carrier.pin(authority),
                request=signed(request), accepted=signed(response, True),
                legacy_digest=signed(wrong_digest, True), stale_runtime=signed(stale, True),
                wrong_revision=signed(revision, True), wrong_nonce=signed(response, True, 10))
