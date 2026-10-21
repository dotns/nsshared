"""Independent participant credentials and directory binding bytes, fixture authority."""
import json

from .. import cbor
from . import account

CRATE = "nsshared-proto"
GROUP = "participant-authority"
TITLE = "Participant authority and directory bindings (fixture authority)"
SECTIONS = "repository docs/participant-authority-candidate.md"
DOMAIN = b"ns.account.directory-binding.v1\0"
PROOF = b"nsgw-participant-candidate-v1\0"
DIRECTORY = json.dumps({"version": 1, "relays": [{"id": 17, "code": "HK",
    "host": "relay.example.test", "ips": ["203.0.113.17"], "port": 443,
    "capabilities": ["udp", "wss"]}]}, separators=(",", ":"))


def vectors():
    issuer = account.key(bytes([1])*32)[0]
    participant = account.key(bytes([2])*32)[0]
    stranger = account.key(bytes([3])*32)[0]
    context = issuer + participant
    exporter = bytes([4])*32
    next_exporter = bytes([5])*32
    proof = account.sign(bytes([2])*32, PROOF + exporter)
    next_proof = account.sign(bytes([2])*32, PROOF + next_exporter)
    correlation = bytes([6])*16
    credential = bytes([7])*32
    pair_request = context + correlation
    deadline = b"\1" + (2000).to_bytes(8, "big")
    out = []

    def emit(name, mode, raw, accepted=True, **fields):
        out.append([("name", name), ("mode", mode), ("bytes", raw),
                    ("decision", "accepted" if accepted else "refused"),
                    ("sequence", "participant_auth_transport"), *fields.items()])

    def frame(kind, body):
        return (len(body)+1).to_bytes(4, "big") + bytes([kind]) + body

    def transport(name, kind, body, accepted=True, **fields):
        emit(name, "transport", frame(kind, body), accepted, **fields)

    transport("enroll-authorized", 7, pair_request + credential + proof,
              exporter=exporter, action="enroll")
    stranger_proof = account.sign(bytes([3])*32, PROOF + exporter)
    transport("enroll-unprovisioned-key", 7, issuer + stranger + correlation + credential + stranger_proof,
              False, exporter=exporter, action="enroll")
    transport("enroll-wrong-credential", 7, pair_request + bytes([8])*32 + proof,
              False, exporter=exporter, action="enroll")
    transport("enrolled", 8, pair_request + deadline, action="response")
    transport("authenticate", 1, context + proof, exporter=exporter, action="authenticate")
    transport("old-connection-proof", 1, context + proof, False,
              exporter=next_exporter, action="authenticate")
    transport("authenticate-fresh", 1, context + next_proof,
              exporter=next_exporter, action="authenticate")
    transport("renew", 9, pair_request, action="renew")
    transport("renewed", 10, pair_request + deadline, action="response")
    transport("response-wrong-correlation", 10, context + bytes([8])*16 + deadline,
              False, action="response")
    transport("response-wrong-pair", 8, issuer + stranger + correlation + deadline,
              False, action="response")
    transport("response-expired", 10, pair_request + b"\1" + bytes(8), False, action="response")
    transport("revoked-authenticate", 1, context + next_proof, False,
              exporter=next_exporter, action="authenticate", enabled=0)
    transport("revoked-renew", 9, pair_request, False, action="renew", enabled=0)
    transport("revoked-report", 5, b"immutable-report", False, action="report", enabled=0)
    for name, kind, body in [("absent-deadline", 2, b"\0"),
                              ("finite-deadline", 2, deadline), ("refused", 3, b""),
                              ("roster-content", 4, b"unchanged-roster"),
                              ("report-content", 5, b"unchanged-report"),
                              ("answer-content", 6, b"unchanged-answer")]:
        emit(name, "frame", frame(kind, body))
    for name, kind, body in [("invalid-identity", 1, b"\2"+bytes(31)+participant+proof), ("unknown-kind", 11, b""), ("empty-roster", 4, b""),
                              ("bad-deadline-tag", 2, b"\2"),
                              ("truncated-deadline", 2, b"\1\0"),
                              ("extra-deadline", 2, deadline+b"\0"),
                              ("zero-correlation", 9, context+bytes(16)),
                              ("truncated-proof", 1, context+proof[:-1])]:
        emit(name, "frame", frame(kind, body), False)
    emit("frame-trailing", "frame", frame(3, b"")+b"\0", False)
    emit("frame-zero-length", "frame", bytes(4), False)
    emit("frame-over-bound", "frame", (1048578).to_bytes(4, "big")+b"\4", False)

    realms = ["030C1G60R30C1G60R30C1G60R3", "09144GJ289144GJ289144GJ289"]
    base = [1, issuer, 17, participant, realms, 1, 1000, 2000]

    def signed(content, domain=DOMAIN, corrupt=False):
        raw = cbor.encode(content)
        sig = account.sign(bytes([1])*32, domain + raw)
        if corrupt:
            sig = bytes([sig[0]^1]) + sig[1:]
        return cbor.encode([raw, sig])

    def binding(name, value, accepted=True, floor=0, previous=None, now=1000, **options):
        raw = signed(value, **options)
        fields = dict(floor=floor, now_ms=now, directory=DIRECTORY)
        if previous is not None:
            fields["previous"] = signed(previous)
        if accepted:
            fields["signing_input"] = DOMAIN+cbor.encode(value)
        emit(name, "binding", raw, accepted, **fields)

    replacement = base[:4] + [[realms[1]], 2] + base[6:]
    empty = base[:4] + [[], 3] + base[6:]
    binding("binding-ab", base)
    binding("binding-remove-a", replacement, floor=1, previous=base)
    binding("binding-empty", empty, floor=2, previous=replacement)
    binding("binding-idempotent", empty, floor=3, previous=empty)
    binding("binding-restart-replay", base, False, floor=3)
    binding("binding-equal-after-restart", empty, False, floor=3)
    binding("binding-changed-equal", replacement[:5]+[3]+replacement[6:], False,
            floor=3, previous=empty)
    binding("binding-new-owner", base[:3]+[stranger]+base[4:5]+[4]+base[6:], floor=3)
    for name, index, value in [("wrong-issuer", 1, stranger), ("wrong-id", 2, 18),
                               ("zero-id", 2, 0), ("overflow-id", 2, 65536),
                               ("zero-version", 5, 0), ("reversed-time", 7, 999),
                               ("duplicate-realms", 4, [realms[0]]*2),
                               ("unordered-realms", 4, list(reversed(realms))),
                               ("noncanonical-realm", 4, [realms[0].lower()])]:
        changed = list(base)
        changed[index] = value
        binding("binding-"+name, changed, False)
    binding("binding-future", base, False, now=999)
    binding("binding-expired", base, False, now=2000)
    binding("binding-before-expiry", base, now=1999)
    binding("binding-wrong-domain", base, False, domain=PROOF)
    binding("binding-bad-signature", base, False, corrupt=True)
    binding("binding-extra-field", base+[0], False)
    emit("binding-nonminimal", "binding", b"\x98\x02"+signed(base)[1:], False, floor=0, now_ms=1000)
    emit("binding-trailing", "binding", signed(base)+b"\0", False, floor=0, now_ms=1000)
    roster = cbor.encode([1, issuer, participant, 2, 1000, 86401000, []])
    emit("revocation-empty-roster", "roster", cbor.encode([roster, account.sign(bytes([1])*32,
         b"ns.account.roster.v1\0"+roster)]))
    return out
