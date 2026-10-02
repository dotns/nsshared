"""Pure-Python Ed25519 (RFC 8032 §5.1): seed key generation, signing and strict verification.

Strict verification follows quick-v2 §12.2: a non-canonical `S` (S >= L) and small-order
public keys or `R` points are rejected, and the cofactorless equation [S]B = R + [k]A is
checked. Not constant time; for test vector generation only.
"""

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

# Extended homogeneous coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, xy = T/Z (§5.1.4).
IDENTITY = (0, 1, 1, 0)


def _add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(scalar, point):
    result = IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p1, p2):
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _recover_x(y, sign):
    """Recovers x from y and the sign bit (§5.1.3), or None when no point exists."""
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
BASE = (_GX, _GY, 1, _GX * _GY % P)


def encode_point(point):
    """Encodes a point as 32 bytes: little-endian y with the sign of x in the top bit (§5.1.2)."""
    x, y, z, _ = point
    zinv = pow(z, P - 2, P)
    x, y = x * zinv % P, y * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def decode_point(data):
    """Decodes a 32-byte point (§5.1.3); returns None for non-canonical or invalid input."""
    if len(data) != 32:
        return None
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def is_small_order(point):
    """True when [8]P is the identity, i.e. the point lies in the torsion subgroup."""
    return _equal(_mul(8, point), IDENTITY)


def _sha512_int(*parts):
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def _expand(seed):
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key(seed):
    """Returns the 32-byte public key of a 32-byte seed (§5.1.5)."""
    scalar, _ = _expand(seed)
    return encode_point(_mul(scalar, BASE))


def sign(seed, message):
    """Returns the 64-byte pure Ed25519 signature of `message` under `seed` (§5.1.6)."""
    scalar, prefix = _expand(seed)
    public = encode_point(_mul(scalar, BASE))
    r = _sha512_int(prefix, message) % L
    r_enc = encode_point(_mul(r, BASE))
    k = _sha512_int(r_enc, public, message) % L
    s = (r + k * scalar) % L
    return r_enc + int.to_bytes(s, 32, "little")


def verify(public, message, signature, strict=True):
    """Verifies a signature (§5.1.7).

    With `strict` (the quick-v2 §12.2 rule) `S >= L`, a small-order `A` and a small-order `R`
    are rejected; without it `S` is reduced modulo L and small-order points pass, which the
    self-test uses to show that the strict checks matter.
    """
    if len(public) != 32 or len(signature) != 64:
        return False
    a = decode_point(public)
    r = decode_point(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if strict:
        if s >= L or is_small_order(a) or is_small_order(r):
            return False
    k = _sha512_int(signature[:32], public, message) % L
    return _equal(_mul(s % L if not strict else s, BASE), _add(r, _mul(k, a)))
