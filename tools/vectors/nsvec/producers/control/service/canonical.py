"""Independent M6 canonical maps, digests and refusals of the service contract."""

import hashlib

from nsvec import cbor

CRATE = "nsshared-control"
GROUP = "service/canonical"
FORMAT = "json"


def service_digest(domain, value):
    """SHA-256 of `domain`, a zero separator and the canonical value."""
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + cbor.encode_value(value)).hexdigest()


def document():
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
    live_digest = bytes.fromhex(service_digest("ns.service.listener.v1", live_intent))
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
        "listeners": [{"intent": cbor.encode_value(live_intent), "proposal": live_proposal}],
        "withdrawals": [{"service_ref": [live_nsd, live_network, bytes([2]) * 16], "listener_revision": 1}],
    }
    return {
        "report_cbor": cbor.encode_value(report).hex(),
        "report_sha256": service_digest("ns.service.report.v1", report),
        "report_renamed_sha256": service_digest("ns.service.report.v1", {**report, "declarations": [changed_name]}),
        "listener_cbor": cbor.encode_value(listener).hex(),
        "listener_sha256": service_digest("ns.service.listener.v1", listener),
        "listener_backend_changed_sha256": service_digest("ns.service.listener.v1", changed_backend),
        "snapshot_empty_cbor": cbor.encode_value({"scope": [publisher, nsd, network], "snapshot_revision": 1, "resources": [], "routes": [], "listeners": [], "grants": [], "withdrawals": []}).hex(),
        "snapshot_empty_sha256": service_digest("ns.service.snapshot.v1", {"scope": [publisher, nsd, network], "snapshot_revision": 1, "resources": [], "routes": [], "listeners": [], "grants": [], "withdrawals": []}),
        "snapshot_nonempty_cbor": cbor.encode_value(live_snapshot).hex(),
        "snapshot_nonempty_sha256": service_digest("ns.service.snapshot.v1", live_snapshot),
        # 32 nested arrays that each declare 16 384 members and carry none.
        "declared_length_cbor": (cbor.head(4, 16_384) * 32).hex(),
        "declared_length_error": "truncated",
    }
