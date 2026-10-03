"""Deterministic CBOR for the quick-v2 §12.1 subset (RFC 8949 §4.2.1).

Supported items: unsigned integers (shortest form), byte strings, UTF-8 text strings,
definite-length arrays, booleans
and null. No floats, tags, maps, negative integers or indefinite lengths. The decoder accepts only the canonical encoding of this subset.
"""

UINT, BYTES, TEXT, ARRAY = 0, 2, 3, 4
FALSE, TRUE, NULL = 0xF4, 0xF5, 0xF6
U64_MAX = 2**64 - 1


def head(major, value, width=None):
    """Encodes an item head; `width` (0, 1, 2, 4 or 8 argument bytes) forces a
    possibly non-shortest form, which negative vectors use."""
    if not 0 <= value <= U64_MAX:
        raise ValueError("CBOR argument out of range")
    if width is None:
        width = 0 if value < 24 else 1 if value < 2**8 else 2 if value < 2**16 else 4 if value < 2**32 else 8
    if width == 0:
        if value >= 24:
            raise ValueError("value does not fit the initial byte")
        return bytes([major << 5 | value])
    info = {1: 24, 2: 25, 4: 26, 8: 27}[width]
    return bytes([major << 5 | info]) + value.to_bytes(width, "big")


def encode(item):
    """Encodes `item` (int >= 0, bytes, str, list, bool or None) canonically."""
    if item is None:
        return bytes([NULL])
    if isinstance(item, bool):
        return bytes([TRUE if item else FALSE])
    if isinstance(item, int):
        if item < 0:
            raise TypeError("negative integers are outside the quick-v2 §12.1 subset")
        return head(UINT, item)
    if isinstance(item, (bytes, bytearray)):
        return head(BYTES, len(item)) + bytes(item)
    if isinstance(item, str):
        data = item.encode("utf-8")
        return head(TEXT, len(data)) + data
    if isinstance(item, list):
        return head(ARRAY, len(item)) + b"".join(encode(x) for x in item)
    raise TypeError(f"{type(item).__name__} is outside the quick-v2 §12.1 subset")


class CborError(ValueError):
    """Input that is not the canonical encoding of a §12.1 subset item."""


def decode(data):
    """Decodes exactly one canonical item; raises CborError otherwise (also on trailing bytes)."""
    item, offset = _decode_at(bytes(data), 0)
    if offset != len(data):
        raise CborError("trailing bytes")
    return item


def _decode_at(data, offset):
    if offset >= len(data):
        raise CborError("truncated")
    initial = data[offset]
    major, info = initial >> 5, initial & 0x1F
    offset += 1
    if initial == NULL:
        return None, offset
    if initial in (FALSE, TRUE):
        return initial == TRUE, offset
    if major not in (UINT, BYTES, TEXT, ARRAY):
        raise CborError(f"major type {major} outside the subset")
    if info < 24:
        value = info
    elif info in (24, 25, 26, 27):
        width = 1 << (info - 24)
        if offset + width > len(data):
            raise CborError("truncated")
        value = int.from_bytes(data[offset : offset + width], "big")
        offset += width
        if head(major, value) != head(major, value, width):
            raise CborError("non-shortest integer or length")
    else:
        raise CborError("indefinite length or reserved additional information")
    if major == UINT:
        return value, offset
    if major == ARRAY:
        items = []
        for _ in range(value):
            item, offset = _decode_at(data, offset)
            items.append(item)
        return items, offset
    if offset + value > len(data):
        raise CborError("truncated")
    chunk = data[offset : offset + value]
    offset += value
    if major == BYTES:
        return chunk, offset
    try:
        return chunk.decode("utf-8"), offset
    except UnicodeDecodeError as err:
        raise CborError("invalid UTF-8 text") from err
