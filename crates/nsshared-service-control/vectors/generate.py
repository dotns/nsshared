"""Independent M6 deterministic CBOR vector generator; Python stdlib only."""

import argparse
import hashlib
import json
from pathlib import Path


def head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    for limit, marker, width in ((256, 24, 1), (65536, 25, 2), (2**32, 26, 4), (2**64, 27, 8)):
        if value < limit:
            return bytes([(major << 5) | marker]) + value.to_bytes(width, "big")
    raise ValueError("out of range")


def encode(value):
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int) and 0 <= value < 2**64:
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return head(3, len(data)) + data
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(map(encode, value))
    if isinstance(value, dict):
        items = [(encode(key), encode(item)) for key, item in value.items()]
        items.sort(key=lambda entry: (len(entry[0]), entry[0]))
        return head(5, len(items)) + b"".join(key + item for key, item in items)
    raise TypeError(type(value))


def digest(domain, value):
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + encode(value)).hexdigest()


def main(check=False):
    nsd = bytes(range(16))
    network = bytes(range(16, 32))
    service = bytes(range(32, 48))
    publisher = bytes(range(32))
    policy = bytes([0x5A]) * 32
    backend = ["ipv4", bytes([127, 0, 0, 1])]
    declaration = {
        "declaration_key": "alpha",
        "display_name": "Alpha",
        "description": None,
        "enabled": True,
        "protocols": ["tcp", "udp"],
        "backend_host": backend,
        "backend_port": 8080,
        "port_mode": "auto",
        "requested_port": None,
    }
    report = {
        "scope": [publisher, nsd, network],
        "strict_mode": True,
        "declarations": [declaration],
    }
    listener = {
        "service_ref": [nsd, network, service],
        "publisher_identity": publisher,
        "listener_revision": 1,
        "port": 8080,
        "protocols": ["tcp", "udp"],
        "backend_host": backend,
        "backend_port": 8080,
        "enforcement_policy_version": 1,
        "enforcement_policy_digest": policy,
    }
    changed_name = {**declaration, "display_name": "Renamed"}
    changed_backend = {**listener, "backend_port": 8081}
    live_nsd = bytes([1]) * 16
    live_network = bytes([2]) * 16
    live_service = bytes([1]) * 16
    live_ref = [live_nsd, live_network, live_service]
    live_publisher = bytes([3]) * 32
    live_intent = {
        "service_ref": live_ref,
        "publisher_identity": live_publisher,
        "listener_revision": 1,
        "port": 8080,
        "protocols": ["tcp", "udp"],
        "backend_host": backend,
        "backend_port": 8080,
        "enforcement_policy_version": 1,
        "enforcement_policy_digest": bytes([4]) * 32,
    }
    live_digest = bytes.fromhex(digest("ns.service.listener.v1", live_intent))
    live_proposal = {
        "service_ref": live_ref,
        "listener_revision": 1,
        "intent_digest": live_digest,
        "allocation_round": 1,
        "proposal_seq": 1,
        "proposal_id": bytes([5]) * 16,
        "port": 8080,
    }
    live_snapshot = {
        "scope": [live_publisher, live_nsd, live_network],
        "snapshot_revision": 1,
        "resources": [{
            "service_ref": live_ref,
            "service_label": "web",
            "publisher_identity": live_publisher,
            "listener_revision": 1,
            "intent_digest": live_digest,
            "port": 8080,
            "protocols": ["tcp", "udp"],
            "node6": bytes([6]) * 16,
            "vip": bytes([10, 0, 0, 8]),
        }],
        "routes": [{
            "service_ref": live_ref,
            "destination_identity": live_publisher,
            "destination_node6": bytes([6]) * 16,
            "port": 8080,
        }],
        "grants": [{
            "service_ref": live_ref,
            "consumer_identity": bytes([7]) * 32,
            "allowed_protocols": ["tcp", "udp"],
            "policy_version": 1,
            "policy_digest": bytes([4]) * 32,
        }],
        "listeners": [{"intent": encode(live_intent), "proposal": live_proposal}],
        "withdrawals": [{"service_ref": [live_nsd, live_network, bytes([2]) * 16], "listener_revision": 1}],
    }
    output = {
        "report_cbor": encode(report).hex(),
        "report_sha256": digest("ns.service.report.v1", report),
        "report_renamed_sha256": digest("ns.service.report.v1", {**report, "declarations": [changed_name]}),
        "listener_cbor": encode(listener).hex(),
        "listener_sha256": digest("ns.service.listener.v1", listener),
        "listener_backend_changed_sha256": digest("ns.service.listener.v1", changed_backend),
        "snapshot_empty_cbor": encode({"scope": [publisher, nsd, network], "snapshot_revision": 1, "resources": [], "routes": [], "listeners": [], "grants": [], "withdrawals": []}).hex(),
        "snapshot_empty_sha256": digest("ns.service.snapshot.v1", {"scope": [publisher, nsd, network], "snapshot_revision": 1, "resources": [], "routes": [], "listeners": [], "grants": [], "withdrawals": []}),
        "snapshot_nonempty_cbor": encode(live_snapshot).hex(),
        "snapshot_nonempty_sha256": digest("ns.service.snapshot.v1", live_snapshot),
    }
    destination = Path(__file__).with_name("service-control-v1.json")
    rendered = json.dumps(output, indent=2) + "\n"
    if check:
        if not destination.exists() or destination.read_text() != rendered:
            raise SystemExit("service-control-v1.json differs from its independent generator")
    else:
        destination.write_text(rendered)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    main(parser.parse_args().check)
