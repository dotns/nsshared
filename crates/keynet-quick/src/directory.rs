use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

use crate::Error;

/// Immutable identifiers, not positions in a sorted list. Never reuse an ID/code.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayEntry {
    pub id: u16,
    pub code: String,
    pub authority: String,
}

/// Versioned public locator metadata. It contains no invitations or node registry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub version: u64,
    pub relays: Vec<RelayEntry>,
}

pub const LETTERS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";

impl Directory {
    pub fn builtin() -> Self {
        Self {
            version: 1,
            relays: [
                (1, "KT", "hkg-a1.43.159.53.106.sslip.io:51822"),
                (2, "KM", "hkg-a2.124.156.159.181.sslip.io:51822"),
                (3, "SG", "sin-a1.43.133.56.69.sslip.io:51822"),
            ]
            .into_iter()
            .map(|(id, code, authority)| RelayEntry {
                id,
                code: code.into(),
                authority: authority.into(),
            })
            .collect(),
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        let mut ids = BTreeSet::new();
        let mut codes = BTreeSet::new();
        let mut authorities = BTreeSet::new();
        if self.version == 0 || self.relays.is_empty() || self.relays.len() > LETTERS.len().pow(2) {
            return Err(Error::InvalidDirectory);
        }
        for relay in &self.relays {
            if relay.id == 0
                || !valid_prefix(&relay.code)
                || !ids.insert(relay.id)
                || !codes.insert(&relay.code)
                || !authorities.insert(&relay.authority)
                || validate_authority(&relay.authority).is_err()
            {
                return Err(Error::InvalidDirectory);
            }
        }
        Ok(())
    }

    /// A trusted update may add entries/change addresses, never reassign an ID.
    pub fn validate_update(&self, previous: &Self) -> Result<(), Error> {
        self.validate()?;
        if self.version < previous.version {
            return Err(Error::InvalidDirectory);
        }
        if self.version == previous.version {
            let unchanged = self.relays.len() == previous.relays.len()
                && self
                    .relays
                    .iter()
                    .all(|entry| previous.relays.contains(entry));
            if !unchanged {
                return Err(Error::InvalidDirectory);
            }
        }
        for old in &previous.relays {
            let Some(new) = self.relays.iter().find(|entry| entry.id == old.id) else {
                return Err(Error::InvalidDirectory);
            };
            if new.code != old.code {
                return Err(Error::InvalidDirectory);
            }
        }
        Ok(())
    }

    pub fn resolve(&self, prefix: &str) -> Result<&RelayEntry, Error> {
        self.relays
            .iter()
            .find(|relay| relay.code == prefix)
            .ok_or(Error::UnknownRelay)
    }
}

pub fn valid_prefix(value: &str) -> bool {
    value.len() == 2 && value.bytes().all(|byte| LETTERS.contains(&byte))
}

pub fn validate_authority(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !b".-:[]".contains(&byte))
    {
        return Err(Error::InvalidDirectory);
    }
    let url = url::Url::parse(&format!("https://{value}")).map_err(|_| Error::InvalidDirectory)?;
    if url.host_str().is_none() || url.port() == Some(0) {
        return Err(Error::InvalidDirectory);
    }
    Ok(())
}

/// Redacted short invitation or self-locating custom-relay handoff.
#[derive(Clone)]
pub struct Locator {
    pub prefix: Option<String>,
    pub authority: Option<String>,
    digits: Zeroizing<String>,
}

impl std::fmt::Debug for Locator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Locator([REDACTED])")
    }
}

impl Locator {
    pub fn parse(value: &str) -> Result<Self, Error> {
        let value = value.trim();
        if value.len() > 300 {
            return Err(Error::InvalidCode);
        }
        if let Some(rest) = value.strip_prefix("nsq://") {
            let (authority, digits) = rest.split_once('/').ok_or(Error::InvalidCode)?;
            validate_authority(authority).map_err(|_| Error::InvalidCode)?;
            check_digits(digits)?;
            return Ok(Self {
                prefix: None,
                authority: Some(authority.to_owned()),
                digits: Zeroizing::new(digits.into()),
            });
        }
        if !value.is_ascii() || value.len() != 10 {
            return Err(Error::InvalidCode);
        }
        let prefix = value[..2].to_ascii_uppercase();
        if !valid_prefix(&prefix) {
            return Err(Error::InvalidCode);
        }
        check_digits(&value[2..])?;
        Ok(Self {
            prefix: Some(prefix),
            authority: None,
            digits: Zeroizing::new(value[2..].into()),
        })
    }

    pub fn digits(&self) -> &str {
        &self.digits
    }

    pub fn display_for(
        authority: &str,
        digits: &str,
        directory: &Directory,
    ) -> Result<Zeroizing<String>, Error> {
        validate_authority(authority)?;
        check_digits(digits)?;
        Ok(Zeroizing::new(
            match directory
                .relays
                .iter()
                .find(|entry| entry.authority == authority)
            {
                Some(entry) => format!("{}{digits}", entry.code),
                None => format!("nsq://{authority}/{digits}"),
            },
        ))
    }
}

pub fn check_digits(value: &str) -> Result<(), Error> {
    if value.len() == 8 && value.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(())
    } else {
        Err(Error::InvalidCode)
    }
}

/// Rejection sampling avoids modulo bias. Collision retry is the broker's job.
pub fn random_digits() -> Result<String, Error> {
    const SPACE: u32 = 100_000_000;
    const LIMIT: u32 = u32::MAX - (u32::MAX % SPACE);
    for _ in 0..128 {
        let candidate = u32::from_be_bytes(crate::random()?);
        if candidate < LIMIT {
            return Ok(format!("{:08}", candidate % SPACE));
        }
    }
    Err(Error::Randomness)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_codes_are_unique_stable_and_not_array_positions() {
        let original = Directory::builtin();
        original.validate().unwrap();
        let mut reordered = original.clone();
        reordered.relays.reverse();
        reordered.validate_update(&original).unwrap();
        assert_eq!(reordered.resolve("KT").unwrap().id, 1);
        reordered.relays[0].code = "KT".into();
        assert_eq!(reordered.validate(), Err(Error::InvalidDirectory));
        let mut rebound = original.clone();
        rebound.relays[0].code = "AA".into();
        assert_eq!(
            rebound.validate_update(&original),
            Err(Error::InvalidDirectory)
        );
    }
    #[test]
    fn accepts_lowercase_and_leading_zeroes_without_guessing_or_leaking() {
        let code = Locator::parse(" kt00307264\n").unwrap();
        assert_eq!(code.prefix.as_deref(), Some("KT"));
        assert_eq!(code.digits(), "00307264");
        assert!(!format!("{code:?}").contains("307264"));
        for invalid in [
            "KT5830726",
            "KT583072640",
            "IT58307264",
            "KT58-307264",
            "éT58307264",
            "KT５８３０７２６４",
            "nsq://user@host/12345678",
            "nsq://host/12345678?x=1",
        ] {
            assert!(Locator::parse(invalid).is_err());
        }
        let custom = Locator::parse("nsq://relay.example.com:51822/12345678").unwrap();
        assert_eq!(custom.authority.as_deref(), Some("relay.example.com:51822"));
    }
}
