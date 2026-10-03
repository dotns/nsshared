"""Pure-Python X25519 (RFC 7748 §5). Not constant time; for test vector generation only."""

P = 2**255 - 19
A24 = 121665


def _decode_scalar(k):
    if len(k) != 32:
        raise ValueError("X25519 scalar must be 32 bytes")
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def _decode_u(u):
    if len(u) != 32:
        raise ValueError("X25519 u-coordinate must be 32 bytes")
    return int.from_bytes(u, "little") & ((1 << 255) - 1)


def x25519(k, u):
    """X25519(k, u) with the Montgomery ladder of RFC 7748 §5."""
    scalar = _decode_scalar(k)
    x1 = _decode_u(u)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in reversed(range(255)):
        bit = (scalar >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return int.to_bytes(x2 * pow(z2, P - 2, P) % P, 32, "little")


BASE_U = bytes([9]) + bytes(31)


def public_key(private):
    """X25519(k, 9): the public key of a 32-byte private key (RFC 7748 §6.1)."""
    return x25519(private, BASE_U)
