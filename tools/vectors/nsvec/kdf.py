"""Hash-based derivations: keyed BLAKE2s labels (quick-v2 §2.2) and HKDF-SHA256 (RFC 5869)."""

import hashlib
import hmac


def keyed_blake2s(label, data, out):
    """BLAKE2s(out = `out`, key = `label`)(data), the quick-v2 §2.2 derivation form."""
    return hashlib.blake2s(data, digest_size=out, key=label).digest()


def hkdf_extract(salt, ikm):
    """HKDF-Extract with SHA-256; an empty salt is HashLen zero bytes (RFC 5869 §2.2)."""
    if not salt:
        salt = bytes(hashlib.sha256().digest_size)
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    """HKDF-Expand with SHA-256 (RFC 5869 §2.3)."""
    if length > 255 * 32:
        raise ValueError("HKDF output too long")
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def hkdf(ikm, info, length, salt=b""):
    """HKDF-SHA256 (RFC 5869), zero-length salt by default as the quick-v2 derivations use."""
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)
