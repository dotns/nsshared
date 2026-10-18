//! Bounded deterministic CBOR subset used by service control.

use std::collections::HashSet;

use thiserror::Error;

/// Maximum accepted wire item length.
pub const MAX_WIRE_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_ITEMS: usize = 16_384;

/// Values allowed on the service-control wire. Maps use ASCII text keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    /// Unsigned integer.
    UInt(u64),
    /// Boolean.
    Bool(bool),
    /// Byte string.
    Bytes(Vec<u8>),
    /// UTF-8 text.
    Text(String),
    /// Null.
    Null,
    /// Fixed-length array.
    Array(Vec<Self>),
    /// Fixed-length map.
    Map(Vec<(String, Self)>),
}

/// Invalid or noncanonical CBOR input.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CborError {
    /// Item is truncated.
    #[error("truncated CBOR")]
    Truncated,
    /// Item is larger than the wire limit.
    #[error("CBOR size limit exceeded")]
    TooLarge,
    /// Container is too deep or has too many members.
    #[error("CBOR container limit exceeded")]
    ContainerLimit,
    /// The value is outside the permitted deterministic subset.
    #[error("unsupported CBOR value")]
    Unsupported,
    /// UTF-8 or map key is invalid.
    #[error("invalid CBOR text or map key")]
    InvalidText,
    /// Duplicate map key.
    #[error("duplicate CBOR map key")]
    DuplicateKey,
    /// Input is not the unique deterministic representation.
    #[error("noncanonical CBOR")]
    Noncanonical,
}

/// Encodes a value, sorting map keys by encoded key length and then bytes.
///
/// # Errors
/// Returns an error for duplicate or non-ASCII map keys, excessive size or depth.
pub fn encode_canonical(value: &Value) -> Result<Vec<u8>, CborError> {
    let mut output = Vec::new();
    encode_item(value, &mut output, 0)?;
    if output.len() > MAX_WIRE_BYTES {
        return Err(CborError::TooLarge);
    }
    Ok(output)
}

/// Decodes one canonical value and verifies that its original bytes are the unique encoding.
///
/// # Errors
/// Returns an error for malformed, noncanonical or unsupported input.
pub fn decode_canonical(input: &[u8]) -> Result<Value, CborError> {
    if input.len() > MAX_WIRE_BYTES {
        return Err(CborError::TooLarge);
    }
    let mut cursor = Cursor { input, offset: 0 };
    let value = cursor.item(0)?;
    if cursor.offset != input.len() || encode_canonical(&value)?.as_slice() != input {
        return Err(CborError::Noncanonical);
    }
    Ok(value)
}

fn encode_head(major: u8, value: u64, output: &mut Vec<u8>) {
    if value < 24 {
        output.push((major << 5) | u8::try_from(value).unwrap_or_default());
    } else if let Ok(value) = u8::try_from(value) {
        output.extend_from_slice(&[(major << 5) | 24, value]);
    } else if let Ok(value) = u16::try_from(value) {
        output.push((major << 5) | 25);
        output.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        output.push((major << 5) | 26);
        output.extend_from_slice(&value.to_be_bytes());
    } else {
        output.push((major << 5) | 27);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_item(value: &Value, output: &mut Vec<u8>, depth: usize) -> Result<(), CborError> {
    if depth > MAX_DEPTH {
        return Err(CborError::ContainerLimit);
    }
    match value {
        Value::UInt(value) => encode_head(0, *value, output),
        Value::Bool(value) => output.push(if *value { 0xf5 } else { 0xf4 }),
        Value::Bytes(value) => {
            encode_head(2, value.len() as u64, output);
            output.extend_from_slice(value);
        }
        Value::Text(value) => {
            encode_head(3, value.len() as u64, output);
            output.extend_from_slice(value.as_bytes());
        }
        Value::Null => output.push(0xf6),
        Value::Array(items) => {
            if items.len() > MAX_ITEMS {
                return Err(CborError::ContainerLimit);
            }
            encode_head(4, items.len() as u64, output);
            for item in items {
                encode_item(item, output, depth + 1)?;
            }
        }
        Value::Map(entries) => {
            if entries.len() > MAX_ITEMS {
                return Err(CborError::ContainerLimit);
            }
            let mut ordered = Vec::with_capacity(entries.len());
            let mut seen = HashSet::with_capacity(entries.len());
            for (key, value) in entries {
                if !key.is_ascii() {
                    return Err(CborError::InvalidText);
                }
                if !seen.insert(key) {
                    return Err(CborError::DuplicateKey);
                }
                let mut encoded_key = Vec::new();
                encode_head(3, key.len() as u64, &mut encoded_key);
                encoded_key.extend_from_slice(key.as_bytes());
                ordered.push((encoded_key, value));
            }
            ordered.sort_unstable_by(|(left, _), (right, _)| {
                left.len().cmp(&right.len()).then_with(|| left.cmp(right))
            });
            encode_head(5, ordered.len() as u64, output);
            for (key, value) in ordered {
                output.extend_from_slice(&key);
                encode_item(value, output, depth + 1)?;
            }
        }
    }
    if output.len() > MAX_WIRE_BYTES {
        return Err(CborError::TooLarge);
    }
    Ok(())
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], CborError> {
        let end = self.offset.checked_add(count).ok_or(CborError::TooLarge)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(CborError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    fn argument(&mut self, additional: u8) -> Result<u64, CborError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => Ok(u64::from(self.take(1)?[0])),
            25 => {
                let mut bytes = [0; 2];
                bytes.copy_from_slice(self.take(2)?);
                Ok(u64::from(u16::from_be_bytes(bytes)))
            }
            26 => {
                let mut bytes = [0; 4];
                bytes.copy_from_slice(self.take(4)?);
                Ok(u64::from(u32::from_be_bytes(bytes)))
            }
            27 => {
                let mut bytes = [0; 8];
                bytes.copy_from_slice(self.take(8)?);
                Ok(u64::from_be_bytes(bytes))
            }
            _ => Err(CborError::Unsupported),
        }
    }

    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::ContainerLimit);
        }
        let first = self.take(1)?[0];
        let major = first >> 5;
        let additional = first & 31;
        if major == 7 {
            return match first {
                0xf4 => Ok(Value::Bool(false)),
                0xf5 => Ok(Value::Bool(true)),
                0xf6 => Ok(Value::Null),
                _ => Err(CborError::Unsupported),
            };
        }
        if !matches!(major, 0 | 2..=5) {
            return Err(CborError::Unsupported);
        }
        let argument = self.argument(additional)?;
        if major == 0 {
            return Ok(Value::UInt(argument));
        }
        let length = usize::try_from(argument).map_err(|_| CborError::TooLarge)?;
        match major {
            2 => {
                if length > MAX_WIRE_BYTES {
                    return Err(CborError::TooLarge);
                }
                Ok(Value::Bytes(self.take(length)?.to_vec()))
            }
            3 => {
                if length > MAX_WIRE_BYTES {
                    return Err(CborError::TooLarge);
                }
                let text =
                    std::str::from_utf8(self.take(length)?).map_err(|_| CborError::InvalidText)?;
                Ok(Value::Text(text.to_owned()))
            }
            4 => {
                if length > MAX_ITEMS {
                    return Err(CborError::ContainerLimit);
                }
                let mut items = Vec::with_capacity(length);
                for _ in 0..length {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                if length > MAX_ITEMS {
                    return Err(CborError::ContainerLimit);
                }
                let mut entries = Vec::with_capacity(length);
                let mut seen = HashSet::with_capacity(length);
                for _ in 0..length {
                    let Value::Text(key) = self.item(depth + 1)? else {
                        return Err(CborError::InvalidText);
                    };
                    if !key.is_ascii() {
                        return Err(CborError::InvalidText);
                    }
                    if !seen.insert(key.clone()) {
                        return Err(CborError::DuplicateKey);
                    }
                    let value = self.item(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            _ => Err(CborError::Unsupported),
        }
    }
}
