//! Reader, writer and validation helpers shared by the account contracts.

use nsshared_codec::cbor::{CborReader, CborWriter};
use nsshared_identity::{keys::IdentityKey, realm::RealmId};

use std::net::Ipv6Addr;

use crate::{
    account::AccountError, account::MAX_BYTES, account::SCHEMA,
    account::limits::MAX_HOSTNAME_BYTES, account::limits::MAX_ITEMS,
    account::limits::MAX_TEXT_BYTES, account::limits::REALM_TEXT_BYTES, service::ServiceRef,
};

/// Returns `error` unless `condition` holds.
pub(in crate::account) fn ensure<E>(condition: bool, error: E) -> Result<(), E> {
    if condition { Ok(()) } else { Err(error) }
}

/// Refuses with [`AccountError::Field`] unless `condition` holds.
pub(in crate::account) fn require(condition: bool) -> Result<(), AccountError> {
    ensure(condition, AccountError::Field)
}

/// True when `values` is strictly ascending, so also free of duplicates.
pub(in crate::account) fn ascending<T: PartialOrd>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

/// True when the keys of `values` are strictly ascending.
pub(in crate::account) fn ascending_by<T, K: PartialOrd + ?Sized>(
    values: &[T],
    key: impl Fn(&T) -> &K,
) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

/// Starts reading a schema 1 contract array of exactly `arity` items.
pub(in crate::account) fn reader(input: &[u8], arity: u64) -> Result<CborReader<'_>, AccountError> {
    let mut reader = CborReader::new(input, MAX_BYTES)?;
    reader.array(arity)?;
    require(reader.uint()? == SCHEMA)?;
    Ok(reader)
}

/// Refuses encoded contracts above [`MAX_BYTES`].
pub(in crate::account) fn bounded(bytes: Vec<u8>) -> Result<Vec<u8>, AccountError> {
    ensure(bytes.len() <= MAX_BYTES, AccountError::Bounds)?;
    Ok(bytes)
}

/// Reads a validated 32-byte Ed25519 identity key.
pub(in crate::account) fn identity(
    reader: &mut CborReader<'_>,
) -> Result<IdentityKey, AccountError> {
    IdentityKey::from_bytes(&reader.fixed_bytes()?).map_err(|_| AccountError::Field)
}

/// Reads canonical RealmId text.
pub(in crate::account) fn realm(reader: &mut CborReader<'_>) -> Result<RealmId, AccountError> {
    Ok(reader.text_up_to(REALM_TEXT_BYTES)?.parse()?)
}

/// True for token text: 1 to 256 UTF-8 bytes without whitespace or control characters.
/// Scope text and policy labels follow this rule.
pub(in crate::account) fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && !value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
}

/// Refuses text that is not [token text](is_token).
pub(in crate::account) fn token(value: &str) -> Result<(), AccountError> {
    require(is_token(value))
}

/// Refuses data text outside 1 to 256 UTF-8 bytes or with control characters.
pub(in crate::account) fn data_text(value: &str) -> Result<(), AccountError> {
    require(
        !value.is_empty() && value.len() <= MAX_TEXT_BYTES && !value.chars().any(char::is_control),
    )
}

/// Refuses more than 256 texts, texts out of strict ascending order and any text that
/// is not [token text](is_token).
pub(in crate::account) fn ordered_tokens(values: &[String]) -> Result<(), AccountError> {
    require(values.len() <= MAX_ITEMS && ascending(values))?;
    values.iter().try_for_each(|value| token(value))
}

/// Writes at most 256 texts in their given order, each accepted by `check`.
pub(in crate::account) fn write_text_sequence(
    out: &mut CborWriter,
    values: &[String],
    check: impl Fn(&str) -> Result<(), AccountError>,
) -> Result<(), AccountError> {
    require(values.len() <= MAX_ITEMS)?;
    out.array(values.len());
    for value in values {
        check(value)?;
        out.text(value);
    }
    Ok(())
}

/// Writes at most 256 strictly ascending texts, each accepted by `check`.
pub(in crate::account) fn write_texts(
    out: &mut CborWriter,
    values: &[String],
    check: impl Fn(&str) -> Result<(), AccountError>,
) -> Result<(), AccountError> {
    require(values.len() <= MAX_ITEMS && ascending(values))?;
    out.array(values.len());
    for value in values {
        check(value)?;
        out.text(value);
    }
    Ok(())
}

/// Reads at most 256 texts of at most `maximum` bytes each.
pub(in crate::account) fn read_texts(
    input: &mut CborReader<'_>,
    maximum: usize,
) -> Result<Vec<String>, AccountError> {
    let count = input.array_up_to(MAX_ITEMS)?;
    (0..count)
        .map(|_| Ok(input.text_up_to(maximum)?.to_owned()))
        .collect()
}

/// Writes an optional text accepted by `check`, or `null`.
pub(in crate::account) fn write_optional_text(
    out: &mut CborWriter,
    value: Option<&str>,
    check: impl Fn(&str) -> Result<(), AccountError>,
) -> Result<(), AccountError> {
    match value {
        Some(value) => {
            check(value)?;
            out.text(value);
        }
        None => {
            out.null();
        }
    }
    Ok(())
}

/// Reads an optional text of at most `maximum` bytes.
pub(in crate::account) fn read_optional_text(
    input: &mut CborReader<'_>,
    maximum: usize,
) -> Result<Option<String>, AccountError> {
    if input.take_null() {
        Ok(None)
    } else {
        Ok(Some(input.text_up_to(maximum)?.to_owned()))
    }
}

/// Writes an optional unsigned integer, or `null`.
pub(in crate::account) fn write_optional_uint(out: &mut CborWriter, value: Option<u64>) {
    match value {
        Some(value) => out.uint(value),
        None => out.null(),
    };
}

/// Reads an optional unsigned integer.
pub(in crate::account) fn read_optional_uint(
    input: &mut CborReader<'_>,
) -> Result<Option<u64>, AccountError> {
    if input.take_null() {
        Ok(None)
    } else {
        Ok(Some(input.uint()?))
    }
}

/// Writes an M6 service reference as its unchanged canonical M6 bytes.
pub(in crate::account) fn write_reference(
    out: &mut CborWriter,
    value: &ServiceRef,
) -> Result<(), AccountError> {
    out.bytes(&value.canonical().map_err(|_| AccountError::Field)?);
    Ok(())
}

/// Reads an M6 service reference embedded as canonical M6 bytes.
pub(in crate::account) fn read_reference(
    input: &mut CborReader<'_>,
) -> Result<ServiceRef, AccountError> {
    ServiceRef::decode(input.bytes_up_to(MAX_BYTES)?).map_err(|_| AccountError::Field)
}

/// Refuses text that is not a lowercase DNS hostname of at most 253 bytes.
pub(in crate::account) fn hostname(value: &str) -> Result<(), AccountError> {
    require(!value.is_empty() && value.len() <= MAX_HOSTNAME_BYTES && value.is_ascii())?;
    require(value.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    }))
}

/// Refuses text that is not an `https` URL with a canonical host and optional port and
/// without user information, query, fragment or backslash.
pub(in crate::account) fn issuer_url(value: &str) -> Result<(), AccountError> {
    require(!value.contains(['@', '?', '#', '\\']))?;
    let rest = value.strip_prefix("https://").ok_or(AccountError::Field)?;
    let authority = rest.split('/').next().ok_or(AccountError::Field)?;
    let port = if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']').ok_or(AccountError::Field)?;
        let address: Ipv6Addr = host.parse().map_err(|_| AccountError::Field)?;
        require(address.to_string() == host)?;
        if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or(AccountError::Field)?)
        }
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        hostname(host)?;
        port
    };
    if let Some(port) = port {
        let number: u16 = port.parse().map_err(|_| AccountError::Field)?;
        require(number > 0 && number.to_string() == port)?;
    }
    Ok(())
}
