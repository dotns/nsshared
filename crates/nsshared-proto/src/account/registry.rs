use super::{AccountError, SCHEMA, reader, require};
use crate::encoding::CborWriter;

/// Stable candidate family identifiers, matching the request's eleven families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum FamilyId {
    /// Enrollment and own Node binding.
    Enrollment = 1,
    /// Complete served realms and peer contributions.
    RealmsPeers,
    /// Ordinary Egress grants.
    Egress,
    /// Exit Subnet grants and selection.
    ExitSubnet,
    /// Explicit payer assignments.
    Payer,
    /// Withdrawal and fresh-incarnation regrant.
    Withdrawal,
    /// Public edge names, backends, authentication and material.
    PublicEdge,
    /// Relay directory and independent participant admission.
    Relay,
    /// Usage reports and versioned units.
    Usage,
    /// Ordinary Node-control vocabulary.
    NodeControl,
    /// Mapping or retirement of the old surface.
    V1Replacement,
}

/// Existing M6 contract groups; these are references, never replacement types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum M6Reuse {
    /// Id, Identity, Digest and ServiceRef.
    Identities,
    /// Declaration, ReportContent and their exact canonical bytes.
    Declarations,
    /// ListenerIntent and its digest.
    Listeners,
    /// Snapshot, its component types, validated service labels and digest.
    Snapshots,
    /// All MessageBody variants, codec, constants, errors and revisions.
    Messages,
    /// Existing service-control-v1.json bytes and vector tests.
    Vectors,
}

impl M6Reuse {
    const fn name(self) -> &'static str {
        match self {
            Self::Identities => "identities",
            Self::Declarations => "declarations",
            Self::Listeners => "listeners",
            Self::Snapshots => "snapshots",
            Self::Messages => "messages",
            Self::Vectors => "vectors",
        }
    }
}

/// Only a validated complete publication clears these kinds in its named scope.
/// A complete empty set withdraws that scope; missing or malformed content fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplacementRule {
    /// Complete publication identifier.
    pub publication: &'static str,
    /// Replaced kinds, comma-separated; `|` distinguishes separately named scopes.
    pub clears: &'static str,
}

/// One immutable candidate family registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FamilyRegistration {
    /// Stable identifier.
    pub id: FamilyId,
    /// Family wire version.
    pub version: u64,
    /// Stable family name.
    pub name: &'static str,
    /// Complete replacement semantics.
    pub replacement: ReplacementRule,
    /// Owning candidate work record, linked in the specification.
    pub owner: &'static str,
    /// Existing M6 groups reused whenever this family carries service work.
    pub m6: &'static [M6Reuse],
}

use M6Reuse::{Declarations, Identities, Listeners, Messages, Snapshots, Vectors};

macro_rules! family {
    ($id:ident, $name:literal, $publication:literal, $clears:literal, [$($extra:ident),*]) => {
        FamilyRegistration {
            id: FamilyId::$id,
            version: 1,
            name: $name,
            replacement: ReplacementRule { publication: $publication, clears: $clears },
            owner: "account-payload-profile",
            m6: &[Identities, $($extra,)* Messages, Vectors],
        }
    };
}

/// Complete family registry in stable identifier order.
pub const FAMILIES: [FamilyRegistration; 11] = [
    family!(
        Enrollment,
        "enrollment",
        "own-node",
        "binding,capabilities,endpoints",
        [Declarations]
    ),
    family!(
        RealmsPeers,
        "realms-peers",
        "realm-peers",
        "realms,peer-contributions",
        [Snapshots]
    ),
    family!(
        Egress,
        "egress",
        "egress-grants",
        "resources,grants,payers",
        [Declarations, Listeners, Snapshots]
    ),
    family!(
        ExitSubnet,
        "exit-subnet",
        "exit-grants",
        "routes,grants,exclusions,bypasses,selection",
        [Listeners, Snapshots]
    ),
    family!(Payer, "payer", "payer-bindings", "payers", [Snapshots]),
    family!(
        Withdrawal,
        "withdrawal",
        "resource-authority",
        "authority,incarnations",
        [Snapshots]
    ),
    family!(
        PublicEdge,
        "public-edge",
        "public-edge",
        "backends,names,aliases,ports,domains,subjects,auth,materials",
        [Declarations, Snapshots]
    ),
    family!(
        Relay,
        "relay",
        "relay-directory-roster",
        "directory|identity-classes",
        [Snapshots]
    ),
    family!(
        Usage,
        "usage",
        "usage-profile",
        "units,reporters,parameters",
        []
    ),
    family!(
        NodeControl,
        "node-control",
        "node-control-profile",
        "vocabulary,capabilities",
        []
    ),
    family!(
        V1Replacement,
        "v1-replacement",
        "surface-map",
        "mappings,retirements",
        [Declarations, Listeners, Snapshots]
    ),
];

/// The exact immutable candidate registry, including replacement and reuse rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FamilyRegistry;

impl FamilyRegistry {
    /// Encodes every registered family with canonical CBOR.
    #[must_use]
    pub fn canonical(self) -> Vec<u8> {
        let mut out = CborWriter::default();
        out.array(2).uint(SCHEMA).array(FAMILIES.len());
        for family in FAMILIES {
            out.array(7)
                .uint(family.id as u64)
                .uint(family.version)
                .text(family.name)
                .text(family.replacement.publication)
                .text(family.replacement.clears)
                .text(family.owner)
                .array(family.m6.len());
            for item in family.m6 {
                out.text(item.name());
            }
        }
        out.into_bytes()
    }

    /// Decodes the exact supported registry, refusing altered or missing entries.
    ///
    /// # Errors
    /// Rejects malformed CBOR or any unrecognized registry semantics.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 2)?;
        input.array(FAMILIES.len() as u64)?;
        for family in FAMILIES {
            input.array(7)?;
            require(input.uint()? == family.id as u64)?;
            require(input.uint()? == family.version)?;
            require(input.text_up_to(128)? == family.name)?;
            require(input.text_up_to(128)? == family.replacement.publication)?;
            require(input.text_up_to(256)? == family.replacement.clears)?;
            require(input.text_up_to(128)? == family.owner)?;
            input.array(family.m6.len() as u64)?;
            for item in family.m6 {
                require(input.text_up_to(32)? == item.name())?;
            }
        }
        input.finish()?;
        Ok(Self)
    }
}
