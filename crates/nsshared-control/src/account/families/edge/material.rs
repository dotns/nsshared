//! Generation-qualified references and public authentication bindings.

use crate::{
    account::AccountError, account::codec::bounded, account::codec::reader, account::codec::realm,
    account::codec::require, account::codec::token, account::limits::MAX_ITEMS,
    account::limits::MAX_TEXT_BYTES,
};
use nsshared_identity::realm::RealmId;

use nsshared_codec::{cbor::CborReader, cbor::CborWriter};

/// Maximum entries in each public-edge collection.
pub const MAX_EDGE_ITEMS: usize = MAX_ITEMS;

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
    pub(in crate::account) fn validate(&self) -> Result<(), AccountError> {
        token(&self.reference)?;
        require(self.generation > 0)
    }

    pub(in crate::account) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        self.validate()?;
        out.array(3)
            .uint(self.kind as u64)
            .text(&self.reference)
            .uint(self.generation);
        Ok(())
    }

    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(3)?;
        let kind = match input.uint()? {
            0 => EdgeMaterialKind::Auth,
            1 => EdgeMaterialKind::Certificate,
            2 => EdgeMaterialKind::ClientCa,
            _ => return Err(AccountError::Field),
        };
        let value = Self {
            kind,
            reference: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
            generation: input.uint()?,
        };
        value.validate()?;
        Ok(value)
    }
}

pub(in crate::account) fn materials_valid(values: &[EdgeMaterialRef]) -> Result<(), AccountError> {
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

pub(in crate::account) fn read_materials(
    input: &mut CborReader<'_>,
) -> Result<Vec<EdgeMaterialRef>, AccountError> {
    let count = input.array_up_to(MAX_EDGE_ITEMS)?;
    (0..count).map(|_| EdgeMaterialRef::read(input)).collect()
}

/// Material installation acknowledgement, never route readiness by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeMaterialAck {
    /// Exact pending confidential auth request id for auth configuration;
    /// separately gateway-minted status id for certificate/client-CA material,
    /// never the acquisition request id.
    /// Always correlated with the full material reference, realm and generation.
    pub request_id: [u8; 16],
    /// Signed served realm.
    pub served_realm: RealmId,
    /// Signed authority scope.
    pub scope: String,
    /// Realm owning this reference.
    pub realm: RealmId,
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
        token(&self.scope)?;
        let mut out = CborWriter::default();
        out.array(7)
            .uint(1)
            .bytes(&self.request_id)
            .text(&self.served_realm.to_string())
            .text(&self.scope)
            .bytes(self.realm.as_bytes());
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
        let served_realm = realm(&mut input)?;
        let scope = input.text_up_to(MAX_TEXT_BYTES)?.to_owned();
        let realm = RealmId::from_bytes(input.fixed_bytes()?);
        let material = EdgeMaterialRef::read(&mut input)?;
        let installed = match input.uint()? {
            0 => true,
            1 => false,
            _ => return Err(AccountError::Field),
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
        served_realm: RealmId,
        scope: &str,
        realm: RealmId,
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
