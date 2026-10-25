//! Lowercase hexadecimal text.

/// Encodes bytes as lowercase hex.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Strictly decodes lowercase hex; `None` for odd lengths or other characters.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

/// Decodes lowercase hex, panicking on malformed fixture text.
#[must_use]
pub fn unhex(text: &str) -> Vec<u8> {
    decode(text).unwrap_or_else(|| panic!("not lowercase hex: {text}"))
}
