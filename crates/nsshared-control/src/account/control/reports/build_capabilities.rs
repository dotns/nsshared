//! Compile-time build capability observations, never negotiation or authority.
use crate::account::{AccountError, codec::ascending, codec::require};
use nsshared_codec::cbor::{CborReader, CborWriter};

/// Maximum feature tokens in one build observation.
pub const MAX_BUILD_FEATURES: usize = 32;
/// Maximum encoded bytes of one feature token.
pub const MAX_FEATURE_TOKEN_BYTES: usize = 64;

/// A binary's capability version and the feature tokens it was built with.
///
/// Observation only: a receiver records and displays the values and never changes
/// behaviour based on them. Machine capabilities stay the only behaviour-gating tokens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildCapabilities {
    /// Positive capability version of the reporting binary.
    pub capability_version: u32,
    /// Strictly ascending `<area>.<name>.v<N>` feature tokens.
    pub features: Vec<String>,
}
impl BuildCapabilities {
    /// Checks the version, token grammar, ordering and bounds.
    /// # Errors
    /// Refuses version 0, more than [`MAX_BUILD_FEATURES`] tokens, a token longer than
    /// [`MAX_FEATURE_TOKEN_BYTES`] or outside the grammar, and unsorted or repeated tokens.
    pub fn validate(&self) -> Result<(), AccountError> {
        require(
            self.capability_version > 0
                && self.features.len() <= MAX_BUILD_FEATURES
                && ascending(&self.features)
                && self.features.iter().all(|token| is_feature_token(token)),
        )
    }
    pub(super) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        self.validate()?;
        out.array(2)
            .uint(u64::from(self.capability_version))
            .array(self.features.len());
        for token in &self.features {
            out.text(token);
        }
        Ok(())
    }
    pub(super) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(2)?;
        let capability_version = u32::try_from(input.uint()?).map_err(|_| AccountError::Field)?;
        let count = input.array_up_to(MAX_BUILD_FEATURES)?;
        let features = (0..count)
            .map(|_| Ok(input.text_up_to(MAX_FEATURE_TOKEN_BYTES)?.to_owned()))
            .collect::<Result<_, AccountError>>()?;
        Ok(Self {
            capability_version,
            features,
        })
    }
}

/// Whether `token` is a bounded `<area>.<name>.v<N>` feature token.
///
/// `area` and `name` are lowercase ASCII letters, digits and underscores starting with a
/// letter; `N` is a positive decimal without a leading zero.
#[must_use]
pub fn is_feature_token(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(area), Some(name), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let word = |part: &str| {
        part.bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
            && part
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
    };
    let number = version.strip_prefix('v').is_some_and(|digits| {
        digits
            .bytes()
            .next()
            .is_some_and(|byte| matches!(byte, b'1'..=b'9'))
            && digits.bytes().all(|byte| byte.is_ascii_digit())
    });
    token.len() <= MAX_FEATURE_TOKEN_BYTES && word(area) && word(name) && number
}
