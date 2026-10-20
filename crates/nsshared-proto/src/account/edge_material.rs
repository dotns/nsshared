//! Generation-qualified references and public authentication bindings.

use super::policy_subject::{ordered_text, text};
use super::{AccountError, JwtSubjectBinding, MAX_BYTES, SubjectBinding, bounded, reader, require};
use crate::encoding::{CborReader, CborWriter};

/// Maximum entries in each public-edge collection.
pub const MAX_EDGE_ITEMS: usize = 256;

/// Material category, independent of confidential material bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u64)]
pub enum EdgeMaterialKind {
    /// Authentication verifier or signing material.
    Auth = 0,
    /// Server certificate material.
    Certificate = 1,
    /// Client certificate trust bundle.
    ClientCa = 2,
}

/// A realm-local material identity and its exact required generation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EdgeMaterialRef {
    /// Material category.
    pub kind: EdgeMaterialKind,
    /// Opaque reference, never secret bytes or a filesystem path.
    pub reference: String,
    /// Positive generation in this reference's domain.
    pub generation: u64,
}

impl EdgeMaterialRef {
    pub(super) fn validate(&self) -> Result<(), AccountError> {
        text(&self.reference)?;
        require(self.generation > 0)
    }

    pub(super) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        self.validate()?;
        out.array(3)
            .uint(self.kind as u64)
            .text(&self.reference)
            .uint(self.generation);
        Ok(())
    }

    pub(super) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(3)?;
        let kind = match input.uint()? {
            0 => EdgeMaterialKind::Auth,
            1 => EdgeMaterialKind::Certificate,
            2 => EdgeMaterialKind::ClientCa,
            _ => return Err(AccountError::InvalidField),
        };
        let value = Self {
            kind,
            reference: input.text_up_to(256)?.to_owned(),
            generation: input.uint()?,
        };
        value.validate()?;
        Ok(value)
    }
}

pub(super) fn materials_valid(values: &[EdgeMaterialRef]) -> Result<(), AccountError> {
    require(values.len() <= MAX_EDGE_ITEMS)?;
    require(
        values
            .windows(2)
            .all(|p| (p[0].kind, &p[0].reference) < (p[1].kind, &p[1].reference)),
    )?;
    for value in values {
        value.validate()?;
    }
    Ok(())
}

pub(super) fn read_materials(
    input: &mut CborReader<'_>,
) -> Result<Vec<EdgeMaterialRef>, AccountError> {
    let count = input.array_up_to(MAX_EDGE_ITEMS)?;
    (0..count).map(|_| EdgeMaterialRef::read(input)).collect()
}

/// Explicit public JWT trust metadata; key verification/acquisition is external.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeJwtAuthority {
    /// Realm-local authority identity used by JwtSubjectBinding.
    pub reference: String,
    /// Explicit HTTPS issuer URL.
    pub issuer: String,
    /// Strictly ordered acceptable audiences.
    pub audiences: Vec<String>,
    /// Exact auth material generation supplying qualified verifier keys.
    pub key_material: EdgeMaterialRef,
}

/// Complete realm-local material and subject-binding contribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeAuth {
    /// Binary policy realm.
    pub realm: [u8; 16],
    /// Complete references in kind/reference order.
    pub materials: Vec<EdgeMaterialRef>,
    /// Exact existing bindings in canonical-byte order.
    pub bindings: Vec<SubjectBinding>,
    /// Exact existing JWT joins in canonical-byte order.
    pub jwt_bindings: Vec<JwtSubjectBinding>,
    /// Public JWT authorities in reference order.
    pub authorities: Vec<EdgeJwtAuthority>,
}

fn write_blobs(values: &[Vec<u8>], out: &mut CborWriter) -> Result<(), AccountError> {
    require(values.len() <= MAX_EDGE_ITEMS && values.windows(2).all(|p| p[0] < p[1]))?;
    out.array(values.len());
    for value in values {
        out.bytes(value);
    }
    Ok(())
}

pub(super) fn issuer_url(value: &str) -> Result<(), AccountError> {
    use std::net::Ipv6Addr;
    require(!value.contains(['@', '?', '#', '\\']))?;
    let rest = value
        .strip_prefix("https://")
        .ok_or(AccountError::InvalidField)?;
    let authority = rest.split('/').next().ok_or(AccountError::InvalidField)?;
    let port = if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']').ok_or(AccountError::InvalidField)?;
        let address: Ipv6Addr = host.parse().map_err(|_| AccountError::InvalidField)?;
        require(address.to_string() == host)?;
        if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or(AccountError::InvalidField)?)
        }
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        super::public_edge::hostname(host)?;
        port
    };
    if let Some(port) = port {
        let number: u16 = port.parse().map_err(|_| AccountError::InvalidField)?;
        require(number > 0 && number.to_string() == port)?;
    }
    Ok(())
}

impl EdgeAuth {
    /// Encodes only references and existing public binding objects.
    ///
    /// # Errors
    /// Rejects invalid scopes, authority joins, ordering, generations or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        materials_valid(&self.materials)?;
        require(self.authorities.len() <= MAX_EDGE_ITEMS)?;
        require(
            self.authorities
                .windows(2)
                .all(|p| p[0].reference < p[1].reference),
        )?;
        let mut out = CborWriter::default();
        out.array(6)
            .uint(1)
            .bytes(&self.realm)
            .array(self.materials.len());
        for value in &self.materials {
            value.write(&mut out)?;
        }
        let bindings = self
            .bindings
            .iter()
            .map(|v| {
                v.subject.in_realm(self.realm)?;
                require(v.realm == self.realm)?;
                v.canonical()
            })
            .collect::<Result<Vec<_>, AccountError>>()?;
        write_blobs(&bindings, &mut out)?;
        let bindings = self
            .jwt_bindings
            .iter()
            .map(|v| {
                require(v.binding.realm == self.realm)?;
                require(
                    self.authorities
                        .iter()
                        .any(|a| a.reference == v.authority_ref),
                )?;
                v.canonical()
            })
            .collect::<Result<Vec<_>, AccountError>>()?;
        write_blobs(&bindings, &mut out)?;
        out.array(self.authorities.len());
        for authority in &self.authorities {
            text(&authority.reference)?;
            text(&authority.issuer)?;
            issuer_url(&authority.issuer)?;
            ordered_text(&authority.audiences)?;
            require(!authority.audiences.is_empty())?;
            require(
                authority.key_material.kind == EdgeMaterialKind::Auth
                    && self.materials.contains(&authority.key_material),
            )?;
            out.array(4)
                .text(&authority.reference)
                .text(&authority.issuer)
                .array(authority.audiences.len());
            for audience in &authority.audiences {
                out.text(audience);
            }
            authority.key_material.write(&mut out)?;
        }
        bounded(out.into_bytes())
    }

    /// Decodes a complete bounded authentication contribution.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical input and invalid nested public metadata.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 6)?;
        let realm = input.fixed_bytes()?;
        let materials = read_materials(&mut input)?;
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let bindings = (0..count)
            .map(|_| SubjectBinding::decode(input.bytes_up_to(MAX_BYTES)?))
            .collect::<Result<_, _>>()?;
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let jwt_bindings = (0..count)
            .map(|_| JwtSubjectBinding::decode(input.bytes_up_to(MAX_BYTES)?))
            .collect::<Result<_, _>>()?;
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let mut authorities = Vec::with_capacity(count);
        for _ in 0..count {
            input.array(4)?;
            let reference = input.text_up_to(256)?.to_owned();
            let issuer = input.text_up_to(256)?.to_owned();
            let count = input.array_up_to(MAX_EDGE_ITEMS)?;
            let audiences = (0..count)
                .map(|_| Ok(input.text_up_to(256)?.to_owned()))
                .collect::<Result<_, AccountError>>()?;
            authorities.push(EdgeJwtAuthority {
                reference,
                issuer,
                audiences,
                key_material: EdgeMaterialRef::read(&mut input)?,
            });
        }
        input.finish()?;
        let value = Self {
            realm,
            materials,
            bindings,
            jwt_bindings,
            authorities,
        };
        value.canonical()?;
        Ok(value)
    }
}

/// Material installation acknowledgement, never route readiness by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeMaterialAck {
    /// Exact pending confidential operation id.
    pub request_id: [u8; 16],
    /// Signed served realm.
    pub served_realm: String,
    /// Signed authority scope.
    pub scope: String,
    /// Realm owning this reference.
    pub realm: [u8; 16],
    /// Exact material generation.
    pub material: EdgeMaterialRef,
    /// True means installed; false is an explicit rejection.
    pub installed: bool,
}

impl EdgeMaterialAck {
    /// Encodes a correlated installation result.
    ///
    /// # Errors
    /// Rejects invalid scopes, material references and bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        text(&self.served_realm)?;
        text(&self.scope)?;
        let mut out = CborWriter::default();
        out.array(7)
            .uint(1)
            .bytes(&self.request_id)
            .text(&self.served_realm)
            .text(&self.scope)
            .bytes(&self.realm);
        self.material.write(&mut out)?;
        out.uint(u64::from(!self.installed));
        bounded(out.into_bytes())
    }

    /// Decodes a bounded exact material acknowledgement.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical fields and unknown status values.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 7)?;
        let request_id = input.fixed_bytes()?;
        let served_realm = input.text_up_to(256)?.to_owned();
        let scope = input.text_up_to(256)?.to_owned();
        let realm = input.fixed_bytes()?;
        let material = EdgeMaterialRef::read(&mut input)?;
        let installed = match input.uint()? {
            0 => true,
            1 => false,
            _ => return Err(AccountError::InvalidField),
        };
        input.finish()?;
        let value = Self {
            request_id,
            served_realm,
            scope,
            realm,
            material,
            installed,
        };
        value.canonical()?;
        Ok(value)
    }

    /// Compares an authenticated result against an externally retained request.
    ///
    /// # Errors
    /// Rejects any correlation mismatch or a rejected installation.
    pub fn validate_installation(
        &self,
        request_id: [u8; 16],
        served_realm: &str,
        scope: &str,
        realm: [u8; 16],
        material: &EdgeMaterialRef,
    ) -> Result<(), AccountError> {
        self.canonical()?;
        require(
            self.installed
                && self.request_id == request_id
                && self.served_realm == served_realm
                && self.scope == scope
                && self.realm == realm
                && &self.material == material,
        )
    }
}
