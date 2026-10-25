"""Domain-separated Ed25519 signed carriers `[content, signature]` of the account
contracts: the signature covers the domain followed by the content bytes."""

from . import cbor, ed25519


def signature(seed, domain, content, corrupt=False):
    """Signs `domain || content`; `corrupt` flips one bit of the result."""
    value = ed25519.sign(seed, domain + content)
    return bytes([value[0] ^ 1]) + value[1:] if corrupt else value


def carrier(seed, value, domain, corrupt=False):
    """Encodes `value` and returns the canonical `[content, signature]` carrier."""
    content = cbor.encode(value)
    return cbor.encode([content, signature(seed, domain, content, corrupt)])
