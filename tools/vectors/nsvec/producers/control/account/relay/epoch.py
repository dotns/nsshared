"""Independent fixed-layout recovery command vectors; no runtime authority."""
from nsvec import ed25519

CRATE = "nsshared-control"
GROUP = "account/relay/epoch"
TITLE = "Version-1 participant epoch requests and results"
SPEC = "docs/spec/account/relay.md"
EXTERNAL = None


def vectors():
    issuer = ed25519.public_key(bytes([1]) * 32)
    recipient = ed25519.public_key(bytes([2]) * 32)
    correlation = bytes([6]) * 16
    maximum = 2**64 - 1
    out = []

    def u64(value):
        return value.to_bytes(8, "big")

    def prefix(generation=17, epoch=23):
        return issuer + recipient + correlation + b"\1" + u64(generation) + u64(epoch)

    def frame(kind, body):
        return (len(body) + 1).to_bytes(4, "big") + bytes([kind]) + body

    def emit(name, kind, body, accepted=True, **fields):
        out.append([("name", name), ("bytes", frame(kind, body)),
                    ("decision", "accepted" if accepted else "refused"), *fields.items()])

    def result(outcome, epoch=0, publication=0, retry=0, head=None):
        return (prefix() if head is None else head) + bytes([outcome]) + u64(epoch) + u64(publication) + u64(retry)

    emit("request", 11, prefix())
    emit("request-one", 11, prefix(1, 1))
    emit("request-maximum", 11, prefix(maximum, maximum))
    for outcome, name in enumerate(["allocated", "already-fresh", "rate-limited",
                                     "stale-custody", "invalid-epoch", "unavailable"]):
        body = result(outcome, 24 if outcome < 2 else 0, 1 if outcome < 2 else 0,
                      2000 if outcome == 2 else 0)
        emit(name, 12, body, outcome=outcome)
    emit("result-maximum", 12, result(0, maximum, maximum, head=prefix(maximum, maximum-1)), outcome=0)
    emit("retry-maximum", 12, result(2, retry=maximum), outcome=2)
    emit("independent-counters", 12, result(1, 24, maximum), outcome=1)
    for kind, body in [(11, prefix()), (12, result(0, 24, 1))]:
        for name, start, end, replacement in [
            ("version-zero", 80, 81, b"\0"), ("version-unknown", 80, 81, b"\2"),
            ("generation-zero", 81, 89, bytes(8)), ("epoch-zero", 89, 97, bytes(8)),
            ("correlation-zero", 64, 80, bytes(16)),
            ("issuer-invalid", 0, 32, b"\2" + bytes(31)),
            ("recipient-invalid", 32, 64, b"\2" + bytes(31))]:
            emit(f"{kind}-{name}", kind, body[:start] + replacement + body[end:], False)
        emit(f"{kind}-short", kind, body[:-1], False)
        emit(f"{kind}-extra", kind, body+b"\0", False)
    for outcome in (0, 1):
        for name, epoch, publication, retry in [("epoch-less", 22, 1, 0),
                ("epoch-equal", 23, 1, 0), ("epoch-zero", 0, 1, 0),
                ("publication-zero", 24, 0, 0), ("retry", 24, 1, 1)]:
            emit(f"success-{outcome}-{name}", 12, result(outcome, epoch, publication, retry), False)
    for name, epoch, publication, retry in [("missing-retry", 0, 0, 0),
                ("epoch", 24, 0, 2000), ("publication", 0, 1, 2000)]:
        emit(f"rate-limited-{name}", 12, result(2, epoch, publication, retry), False)
    for outcome in (3, 4, 5):
        for index, name in enumerate(["epoch", "publication", "retry"]):
            values = [0, 0, 0]
            values[index] = 1
            emit(f"refusal-{outcome}-{name}", 12, result(outcome, *values), False)
    for outcome in (6, 255):
        emit(f"outcome-{outcome}", 12, result(outcome), False)
    return out
