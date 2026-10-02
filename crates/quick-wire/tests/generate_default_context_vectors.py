"""Independent default-context derivations using only Python's standard library.

Run with --check to compare the committed vectors, or without arguments to print
them. This generator does not call the Rust implementation or use signing keys.
"""

import argparse
import base64
import hashlib
from pathlib import Path


def generate():
    context = hashlib.sha256(b"keynet-default-context-v1").digest()
    lines = ["# identity|n6|n4|slot|identity_label"]
    for identity in (bytes(range(32)), bytes(32), bytes(reversed(range(32)))):
        address = bytearray(b"\xfd" + hashlib.blake2s(
            b"\x01" + context + identity, key=b"keynet-addr-v1", digest_size=15
        ).digest())
        address[-1] &= 0xFE
        n6 = address.hex()
        address[-1] |= 1
        slot = hashlib.blake2s(
            context + identity, key=b"keynet-relay-slot-v1", digest_size=16
        ).hexdigest()
        label = base64.b32encode(hashlib.blake2s(
            identity, key=b"keynet-id-v1", digest_size=12
        ).digest()).decode("ascii").rstrip("=").lower()
        lines.append("|".join((identity.hex(), n6, address.hex(), slot, label)))
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = generate()
    if args.check:
        fixture = Path(__file__).parent / "fixtures/default-context-v1/derivations.vec"
        if fixture.read_text(encoding="ascii") != expected:
            raise SystemExit("default-context derivation vectors differ")
    else:
        print(expected, end="")
