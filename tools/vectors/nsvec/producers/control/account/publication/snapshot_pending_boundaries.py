"""Independent pending-request total encoding bounds with authenticated empty polls."""
from nsvec import cbor, ed25519
from nsvec.producers.control.account.control import envelope as bootstrap_envelope

CRATE = "nsshared-control"
GROUP = "account/publication/snapshot-pending-boundaries"
TITLE = "Pending snapshot request byte boundaries (fixture authority)"
SPEC = "docs/spec/account/publication.md"
EXTERNAL = None


def vectors():
    subscriber = ed25519.public_key(bytes([1])*32)
    seed = bytes([2])*32
    issuer = ed25519.public_key(seed)
    realm = "030C1G60R30C1G60R30C1G60R3"
    correlation = bytes([5])*16
    snapshot = cbor.encode([1, []])
    content = cbor.encode([1, 1, issuer, subscriber, "config.snapshot", 100,
                           correlation, snapshot])
    envelope = cbor.encode([content, ed25519.sign(seed, bootstrap_envelope.RESPONSE + content)])
    out = []
    for target in (8192, 8193):
        texts = [f"{i:02}" + "x"*148 for i in range(32)]

        def request():
            scopes = [[issuer, subscriber, realm, text] for text in texts]
            return cbor.encode([1, subscriber, scopes, bytes([3])*16, 1, correlation])

        # Keep all string lengths within one CBOR head width and semantic bounds.
        for i in range(32):
            difference = target - len(request())
            amount = max(24-len(texts[i]), min(255-len(texts[i]), difference))
            texts[i] = texts[i] + "x"*amount if amount >= 0 else texts[i][:amount]
            if len(request()) == target:
                break
        raw = request()
        assert len(raw) == target
        assert texts == sorted(set(texts)) and all(24 <= len(t) <= 255 for t in texts)
        out.append([("name", "pending-at-ceiling" if target == 8192 else "pending-over-ceiling"),
                    ("pending", raw), ("scope_texts", cbor.encode(texts)),
                    ("encoded_length", len(raw)), ("bytes", envelope),
                    ("pin", bootstrap_envelope.pin(issuer)),
                    ("decision", "accepted" if target == 8192 else "refused")])
    return out
