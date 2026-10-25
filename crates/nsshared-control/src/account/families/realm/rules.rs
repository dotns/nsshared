//! Ordered accept rules; matching and evaluation stay in gateway consumers.

use nsshared_identity::realm::RealmId;

use crate::{
    account::AccountError, account::MAX_BYTES, account::SCHEMA, account::bounded,
    account::node::TransportProtocol, account::reader, account::realm::PolicySubject,
    account::require,
};
use crate::{account::realm::subject::MAX_POLICY_ITEMS, account::realm::subject::ordered_text};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};

use std::collections::BTreeSet;

const ANONYMOUS_SELECTOR: &[u8] = &[0x82, 0x01, 0x03];

/// A rule selector, distinct from a credential or signed identity subject.
///
/// Consumers match Anonymous only against an explicitly classified unauthenticated
/// visitor, without a subject payload. Verified principals never match Anonymous;
/// AnyVerified and Subject (including expanded groups) match verified input only.
/// Missing or untrusted input matches none. Destination, port, protocol and required
/// authentication dependencies must still pass; selector matching grants no bypass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubjectSelector {
    /// Any verified principal; encoded as the sole null in a rule's subject set.
    AnyVerified,
    /// One unchanged qualified subject or explicitly defined group.
    Subject(PolicySubject),
    /// Explicit anonymous visitor; byte string containing canonical CBOR [1, 3].
    Anonymous,
}

/// One accept rule; there is no implicit permission or deny-rule translation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectRule {
    /// Strict selector payload-byte order; AnyVerified is exclusive.
    pub subjects: Vec<SubjectSelector>,
    /// Ordered unique destination matcher strings interpreted by the evaluator.
    pub destinations: Vec<String>,
    /// None matches both TCP and UDP.
    pub protocol: Option<TransportProtocol>,
}

/// Explicit expanded group membership, qualified by the enclosing policy realm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectGroup {
    /// Realm-local group subject.
    pub group: PolicySubject,
    /// Ordered unique non-group subjects.
    pub members: Vec<PolicySubject>,
}

/// Pure policy value with no publication or runtime semantics of its own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectPolicy {
    /// Realm in which local policy labels and bindings are meaningful.
    pub realm: RealmId,
    /// Rules retain supplied evaluator order.
    pub rules: Vec<SubjectRule>,
    /// Groups in strict canonical subject-byte order.
    pub groups: Vec<SubjectGroup>,
}

fn subject_set(values: &[PolicySubject], realm: RealmId) -> Result<Vec<Vec<u8>>, AccountError> {
    require(values.len() <= MAX_POLICY_ITEMS)?;
    let bytes = values
        .iter()
        .map(|subject| {
            subject.in_realm(realm)?;
            require(!subject.is_group())?;
            subject.canonical()
        })
        .collect::<Result<Vec<_>, _>>()?;
    require(bytes.windows(2).all(|p| p[0] < p[1]))?;
    Ok(bytes)
}

impl SubjectPolicy {
    /// Encodes bounded policy input; this performs no rule matching.
    ///
    /// # Errors
    /// Rejects cross-realm, missing groups, duplicate or unordered sets and bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        require(self.rules.len() <= MAX_POLICY_ITEMS && self.groups.len() <= MAX_POLICY_ITEMS)?;
        let mut group_keys = BTreeSet::new();
        let mut previous = None;
        for group in &self.groups {
            group.group.in_realm(self.realm)?;
            require(group.group.is_group())?;
            let key = group.group.canonical()?;
            require(previous.as_ref().is_none_or(|last| last < &key))?;
            previous = Some(key.clone());
            group_keys.insert(key);
            subject_set(&group.members, self.realm)?;
        }
        let mut out = CborWriter::default();
        out.array(4)
            .uint(SCHEMA)
            .bytes(self.realm.as_bytes())
            .array(self.rules.len());
        for rule in &self.rules {
            require(!rule.subjects.is_empty() && rule.subjects.len() <= MAX_POLICY_ITEMS)?;
            require(!rule.destinations.is_empty())?;
            ordered_text(&rule.destinations)?;
            out.array(3).array(rule.subjects.len());
            let mut previous = None;
            for subject in &rule.subjects {
                let bytes = match subject {
                    SubjectSelector::AnyVerified => {
                        require(rule.subjects.len() == 1)?;
                        out.null();
                        continue;
                    }
                    SubjectSelector::Subject(subject) => {
                        subject.in_realm(self.realm)?;
                        let bytes = subject.canonical()?;
                        require(!subject.is_group() || group_keys.contains(&bytes))?;
                        bytes
                    }
                    SubjectSelector::Anonymous => ANONYMOUS_SELECTOR.to_vec(),
                };
                require(previous.as_ref().is_none_or(|last| last < &bytes))?;
                previous = Some(bytes.clone());
                out.bytes(&bytes);
            }
            out.array(rule.destinations.len());
            for destination in &rule.destinations {
                out.text(destination);
            }
            if let Some(protocol) = rule.protocol {
                out.uint(protocol as u64);
            } else {
                out.null();
            }
        }
        out.array(self.groups.len());
        for group in &self.groups {
            out.array(2)
                .bytes(&group.group.canonical()?)
                .array(group.members.len());
            for member in &group.members {
                out.bytes(&member.canonical()?);
            }
        }
        bounded(out.into_bytes())
    }

    /// Decodes canonical policy values without installing or evaluating them.
    ///
    /// # Errors
    /// Rejects unknown protocols, malformed subjects, scope/order violations or bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 4)?;
        let realm = RealmId::from_bytes(input.fixed_bytes()?);
        let count = input.array_up_to(MAX_POLICY_ITEMS)?;
        let mut rules = Vec::with_capacity(count);
        for _ in 0..count {
            input.array(3)?;
            let count = input.array_up_to(MAX_POLICY_ITEMS)?;
            let mut subjects = Vec::with_capacity(count);
            for _ in 0..count {
                subjects.push(if input.take_null() {
                    SubjectSelector::AnyVerified
                } else {
                    let bytes = input.bytes_up_to(MAX_BYTES)?;
                    if bytes == ANONYMOUS_SELECTOR {
                        SubjectSelector::Anonymous
                    } else {
                        SubjectSelector::Subject(PolicySubject::decode(bytes)?)
                    }
                });
            }
            let destinations = read_texts(&mut input)?;
            let protocol = if input.take_null() {
                None
            } else {
                Some(match input.uint()? {
                    6 => TransportProtocol::Tcp,
                    17 => TransportProtocol::Udp,
                    _ => return Err(AccountError::InvalidField),
                })
            };
            rules.push(SubjectRule {
                subjects,
                destinations,
                protocol,
            });
        }
        let count = input.array_up_to(MAX_POLICY_ITEMS)?;
        let mut groups = Vec::with_capacity(count);
        for _ in 0..count {
            input.array(2)?;
            let group = PolicySubject::decode(input.bytes_up_to(MAX_BYTES)?)?;
            let count = input.array_up_to(MAX_POLICY_ITEMS)?;
            let mut members = Vec::with_capacity(count);
            for _ in 0..count {
                members.push(PolicySubject::decode(input.bytes_up_to(MAX_BYTES)?)?);
            }
            groups.push(SubjectGroup { group, members });
        }
        input.finish()?;
        let value = Self {
            realm,
            rules,
            groups,
        };
        value.canonical()?;
        Ok(value)
    }
}

pub(in crate::account) fn read_texts(
    input: &mut CborReader<'_>,
) -> Result<Vec<String>, AccountError> {
    let count = input.array_up_to(MAX_POLICY_ITEMS)?;
    (0..count)
        .map(|_| {
            Ok(input
                .text_up_to(crate::account::realm::subject::MAX_POLICY_TEXT)?
                .to_owned())
        })
        .collect()
}
