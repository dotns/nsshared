use crate::envelope::ControlEnvelope;

use super::codec::{Field, payload};
use super::{Error, validate_lifetime, validate_live_credential};

payload!(OverlayAddresses, "", {
    1_u64 => v4: [u8; 4], 2_u64 => v4_salt: u64, 3_u64 => v6: [u8; 16],
});
payload!(ObservedEndpoint, "", { 1_u64 => ip: Vec<u8>, 2_u64 => port: u64 });
payload!(PinRequest, "", { 1_u64 => ttl_secs: u64 });
payload!(PinInfo, "", { 1_u64 => value: String, 2_u64 => expires_in_secs: u64 });
payload!(AnchorChallenge, "", {
    1_u64 => anchor_seq: u64, 2_u64 => state_digest: [u8; 32], 3_u64 => format_version: u64,
});
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Register {
    pub network_pub: [u8; 32],
    pub wg_pub: [u8; 32],
    pub member_incarnation: u64,
    pub allocate_pin: Option<PinRequest>,
    pub network_proof: Option<[u8; 64]>,
    pub vouch: Option<Vec<u8>>,
    pub recovery_intent: Option<bool>,
}
payload!(Registered, "mesh.registered", {
    1_u64 => nonce: [u8; 16], 2_u64 => status: u64, 3_u64 => network_pub: [u8; 32],
    4_u64 => pin: Option<PinInfo>, 5_u64 => admins: Vec<u8>, 6_u64 => admins_revision: u64,
    7_u64 => latest_seq: u64, 8_u64 => observed_addr: ObservedEndpoint,
    9_u64 => relay_key: [u8; 32], 10_u64 => ttl_secs: u64,
    11_u64 => slot_status: u64, 12_u64 => anchor: Option<AnchorChallenge>,
    13_u64 => creation_receipt: Option<Vec<u8>>,
});
payload!(Cookie, "mesh.cookie", { 1_u64 => nonce: [u8; 16], 2_u64 => cookie: [u8; 16] });
payload!(Join, "mesh.join", {
    1_u64 => pin: String, 2_u64 => joiner_wg: [u8; 32], 3_u64 => capabilities: u64,
    4_u64 => expires_at: u64, 5_u64 => cookie: Option<[u8; 16]>, 6_u64 => request_id: [u8; 16],
});
payload!(Accept, "mesh.accept", {
    1_u64 => network_pub: [u8; 32], 2_u64 => network_name: String,
    3_u64 => relay_origin: String, 4_u64 => approver_wg: [u8; 32],
    5_u64 => joiner_id: [u8; 20], 6_u64 => joiner_wg: [u8; 32],
    7_u64 => request_id: [u8; 16], 8_u64 => member_incarnation: u64,
    9_u64 => capabilities: u64, 10_u64 => joiner_addrs: OverlayAddresses,
    11_u64 => approver_addrs: OverlayAddresses, 12_u64 => added_at: u64,
    13_u64 => expires_at: u64, 14_u64 => network_sig: [u8; 64],
    15_u64 => joiner_pub: [u8; 32],
});
payload!(Resolved, "mesh.resolved", {
    1_u64 => network_pub: [u8; 32], 2_u64 => request_id: [u8; 16],
    3_u64 => joiner_id: [u8; 20], 4_u64 => approver_id: [u8; 20], 5_u64 => seq: u64,
});
payload!(Deny, "mesh.deny", {
    1_u64 => request_id: [u8; 16], 2_u64 => joiner_id: [u8; 20], 3_u64 => reason: String,
});
payload!(Vouch, "mesh.vouch", {
    1_u64 => network_pub: [u8; 32], 2_u64 => member_id: [u8; 20],
    3_u64 => member_wg: [u8; 32], 4_u64 => incarnation: u64,
    5_u64 => register_nonce: [u8; 16], 6_u64 => issued_at: u64, 7_u64 => expires_at: u64,
    8_u64 => signature: [u8; 64],
});
payload!(Unbind, "mesh.unbind", { 1_u64 => network_pub: [u8; 32] });
payload!(Sequenced, "mesh.sequenced", {
    1_u64 => network_pub: [u8; 32], 2_u64 => seq: u64, 3_u64 => record: Vec<u8>,
});
payload!(Eviction, "mesh.evict", {
    1_u64 => member_id: [u8; 20], 2_u64 => incarnation: u64,
    3_u64 => reason: String, 4_u64 => member_pub: [u8; 32],
});
payload!(Admins, "mesh.admins", { 1_u64 => admins: Vec<u8>, 2_u64 => admins_revision: u64 });
payload!(SignedManagementRecord, "", {
    1_u64 => kind: u64, 2_u64 => network_pub: [u8; 32], 3_u64 => op_id: [u8; 16],
    4_u64 => author_pub: [u8; 32], 5_u64 => issued_at: u64, 6_u64 => expires_at: u64,
    7_u64 => body: Vec<u8>, 8_u64 => signature: [u8; 64],
});

pub const CAPABILITY_EXIT: u64 = 1;

fn ensure(condition: bool, message: &'static str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::Payload(message))
    }
}

fn validate_pin(pin: &str) -> Result<(), Error> {
    let bytes = pin.as_bytes();
    ensure(
        bytes.len() == 11
            && bytes[..2]
                .iter()
                .all(|c| c.is_ascii_uppercase() && *c != b'I' && *c != b'O')
            && bytes[2] == b'-'
            && bytes[3..].iter().all(u8::is_ascii_digit),
        "PIN",
    )
}

fn validate_admins(admins: &[u8]) -> Result<(), Error> {
    ensure(
        admins.len() <= 640 && admins.len().is_multiple_of(20),
        "admin width or count",
    )?;
    let mut previous = None;
    for member in admins.chunks_exact(20) {
        if previous.is_some_and(|previous| previous >= member) {
            return Err(Error::Payload("admin ordering"));
        }
        previous = Some(member);
    }
    Ok(())
}

impl OverlayAddresses {
    fn validate(&self) -> Result<(), Error> {
        ensure(u32::try_from(self.v4_salt).is_ok(), "IPv4 salt width")
    }
}
impl Cookie {
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}
impl Unbind {
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}
impl ObservedEndpoint {
    fn validate(&self) -> Result<(), Error> {
        ensure(
            matches!(self.ip.len(), 4 | 16) && (1..=65535).contains(&self.port),
            "endpoint",
        )
    }
}
impl PinRequest {
    fn validate(&self) -> Result<(), Error> {
        ensure(self.ttl_secs > 0, "PIN TTL")
    }
}
impl PinInfo {
    fn validate(&self) -> Result<(), Error> {
        validate_pin(&self.value)?;
        ensure((1..=3600).contains(&self.expires_in_secs), "PIN TTL")
    }
}
impl AnchorChallenge {
    fn validate(&self) -> Result<(), Error> {
        ensure(self.format_version == 1, "anchor version")
    }
}
impl Register {
    pub const API: &'static str = "mesh.register";

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        super::codec::encode(&self.to_value())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_value(super::codec::decode(bytes)?)
    }

    fn validate(&self) -> Result<(), Error> {
        ensure(self.member_incarnation > 0, "incarnation")?;
        if let Some(pin) = &self.allocate_pin {
            pin.validate()?;
        }
        if let Some(credential) = &self.vouch {
            ensure(!credential.is_empty(), "empty vouch")?;
        }
        ensure(self.recovery_intent != Some(false), "recovery intent")?;
        Ok(())
    }

    pub fn network_proof_input(
        &self,
        nonce: &[u8; 16],
        signer: &[u8; 32],
    ) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = b"nsmesh-network-proof-v1\0".to_vec();
        self.network_pub.sign_into(&mut out);
        nonce.sign_into(&mut out);
        self.wg_pub.sign_into(&mut out);
        self.member_incarnation.sign_into(&mut out);
        signer.sign_into(&mut out);
        // Keep the v1 proof input byte-for-byte stable for ordinary registration.
        // The validated only non-default value carries an explicit presence/value marker.
        if self.recovery_intent.is_some() {
            out.extend_from_slice(&[1, 1]);
        }
        Ok(out)
    }

    pub fn verify_network_proof(&self, nonce: &[u8; 16], signer: &[u8; 32]) -> Result<(), Error> {
        let proof = self
            .network_proof
            .ok_or(Error::Payload("network proof missing"))?;
        super::recovery::verify(
            &self.network_pub,
            &self.network_proof_input(nonce, signer)?,
            &proof,
        )
    }
}

impl Field for Register {
    fn to_value(&self) -> ciborium::value::Value {
        let mut fields = vec![
            (0_u64.to_value(), 1_u64.to_value()),
            (1_u64.to_value(), self.network_pub.to_value()),
            (2_u64.to_value(), self.wg_pub.to_value()),
            (3_u64.to_value(), self.member_incarnation.to_value()),
            (4_u64.to_value(), self.allocate_pin.to_value()),
            (5_u64.to_value(), self.network_proof.to_value()),
            (6_u64.to_value(), self.vouch.to_value()),
        ];
        if let Some(intent) = self.recovery_intent {
            fields.push((7_u64.to_value(), intent.to_value()));
        }
        ciborium::value::Value::Map(fields)
    }

    fn from_value(value: ciborium::value::Value) -> Result<Self, Error> {
        let mut fields = super::codec::fields(value)?;
        let result = Self {
            network_pub: super::codec::take(&mut fields, 1)?,
            wg_pub: super::codec::take(&mut fields, 2)?,
            member_incarnation: super::codec::take(&mut fields, 3)?,
            allocate_pin: super::codec::take(&mut fields, 4)?,
            network_proof: super::codec::take(&mut fields, 5)?,
            vouch: super::codec::take(&mut fields, 6)?,
            recovery_intent: fields
                .remove(&7)
                .map_or_else(|| Ok(None), Option::<bool>::from_value)?,
        };
        result.validate()?;
        Ok(result)
    }

    fn sign_into(&self, out: &mut Vec<u8>) {
        self.network_pub.sign_into(out);
        self.wg_pub.sign_into(out);
        self.member_incarnation.sign_into(out);
        self.allocate_pin.sign_into(out);
        self.network_proof.sign_into(out);
        self.vouch.sign_into(out);
        self.recovery_intent.sign_into(out);
    }
}
impl Registered {
    pub const REGISTERED: u64 = 0;
    pub const NOT_A_MEMBER: u64 = 1;
    pub const NOT_ENTITLED: u64 = 2;
    pub const RECOVERING: u64 = 3;
    pub const CAPACITY: u64 = 4;
    pub const SLOT_BOUND: u64 = 0;
    pub const SLOT_CONFLICT: u64 = 1;
    pub const SLOT_CAPACITY: u64 = 2;

    fn validate(&self) -> Result<(), Error> {
        ensure(
            self.status <= Self::CAPACITY && self.slot_status <= Self::SLOT_CAPACITY,
            "registration status",
        )?;
        validate_admins(&self.admins)?;
        self.observed_addr.validate()?;
        if let Some(pin) = &self.pin {
            pin.validate()?;
        }
        if let Some(anchor) = &self.anchor {
            anchor.validate()?;
            ensure(self.status == Self::RECOVERING, "anchor outside recovery")?;
        }
        if self.creation_receipt.is_some() {
            ensure(
                self.status == Self::REGISTERED && self.latest_seq == 0 && self.admins.is_empty(),
                "genesis receipt state",
            )?;
        }
        Ok(())
    }
}
impl Join {
    fn validate(&self) -> Result<(), Error> {
        validate_pin(&self.pin)?;
        ensure(self.capabilities & !CAPABILITY_EXIT == 0, "capabilities")
    }
}
impl Accept {
    fn validate(&self) -> Result<(), Error> {
        ensure(
            super::member_id(&self.joiner_pub) == self.joiner_id,
            "joiner identity binding",
        )?;
        ensure(
            !self.network_name.is_empty() && self.network_name.len() <= 64,
            "network name",
        )?;
        ensure(
            !self.relay_origin.is_empty() && self.relay_origin.len() <= 255,
            "relay origin size",
        )?;
        validate_relay_origin(&self.relay_origin)?;
        self.joiner_addrs.validate()?;
        self.approver_addrs.validate()?;
        ensure(
            self.member_incarnation > 0 && self.capabilities & !CAPABILITY_EXIT == 0,
            "incarnation or capabilities",
        )?;
        validate_lifetime(self.added_at, self.expires_at)
    }

    pub fn network_signing_input(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = b"nsmesh-accept-v1\0".to_vec();
        self.network_pub.sign_into(&mut out);
        self.network_name.sign_into(&mut out);
        self.relay_origin.sign_into(&mut out);
        self.approver_wg.sign_into(&mut out);
        self.joiner_id.sign_into(&mut out);
        self.joiner_wg.sign_into(&mut out);
        self.request_id.sign_into(&mut out);
        self.member_incarnation.sign_into(&mut out);
        self.capabilities.sign_into(&mut out);
        self.joiner_addrs.sign_into(&mut out);
        self.approver_addrs.sign_into(&mut out);
        self.added_at.sign_into(&mut out);
        self.expires_at.sign_into(&mut out);
        self.joiner_pub.sign_into(&mut out);
        Ok(out)
    }

    pub fn verify_network_signature(&self) -> Result<(), Error> {
        super::recovery::verify(
            &self.network_pub,
            &self.network_signing_input()?,
            &self.network_sig,
        )
    }

    /// Authenticate the original add without renewing its signed timestamps.
    pub fn verify_historical(envelope: &ControlEnvelope) -> Result<Self, Error> {
        ensure(envelope.api == Self::API, "accept API")?;
        super::verify_historical_request(envelope)?;
        let value = Self::decode(envelope.payload.as_ref())?;
        ensure(value.added_at == envelope.ts, "accept timestamp binding")?;
        value.verify_network_signature()?;
        Ok(value)
    }

    pub fn verify_join(&self, expected: &JoinBinding, now: u64) -> Result<(), Error> {
        self.verify_network_signature()?;
        ensure(
            self.network_pub == expected.network_pub
                && self.joiner_id == expected.joiner_id
                && self.joiner_pub == expected.joiner_pub
                && self.joiner_wg == expected.joiner_wg
                && self.request_id == expected.request_id,
            "join request binding",
        )?;
        validate_live_credential(self.added_at, self.expires_at, now, expected.deadline)
    }
}

pub struct JoinBinding {
    pub network_pub: [u8; 32],
    pub joiner_id: [u8; 20],
    pub joiner_pub: [u8; 32],
    pub joiner_wg: [u8; 32],
    pub request_id: [u8; 16],
    pub deadline: u64,
}

impl Resolved {
    fn validate(&self) -> Result<(), Error> {
        ensure(self.seq > 0, "sequence")
    }
}
impl Deny {
    fn validate(&self) -> Result<(), Error> {
        ensure(self.reason.len() <= 128, "reason")
    }
}
impl Vouch {
    fn validate(&self) -> Result<(), Error> {
        ensure(self.incarnation > 0, "incarnation")?;
        validate_lifetime(self.issued_at, self.expires_at)
    }
    pub fn signing_input(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = b"nsmesh-vouch-v1\0".to_vec();
        self.network_pub.sign_into(&mut out);
        self.member_id.sign_into(&mut out);
        self.member_wg.sign_into(&mut out);
        self.incarnation.sign_into(&mut out);
        self.register_nonce.sign_into(&mut out);
        self.issued_at.sign_into(&mut out);
        self.expires_at.sign_into(&mut out);
        Ok(out)
    }
    pub fn verify_historical(envelope: &ControlEnvelope) -> Result<Self, Error> {
        ensure(envelope.api == Self::API, "vouch API")?;
        super::verify_historical_request(envelope)?;
        let value = Self::decode(envelope.payload.as_ref())?;
        ensure(value.issued_at == envelope.ts, "vouch timestamp binding")?;
        super::recovery::verify(
            &envelope.machine_key_pub,
            &value.signing_input()?,
            &value.signature,
        )?;
        Ok(value)
    }
}

pub fn validate_relay_origin(origin: &str) -> Result<(), Error> {
    ensure(origin.len() <= 255, "relay origin size")?;
    let url = reqwest::Url::parse(origin).map_err(|_| Error::Payload("relay origin"))?;
    ensure(
        matches!(url.scheme(), "udp" | "wss" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && matches!(url.path(), "" | "/"),
        "relay origin components",
    )?;
    let host = url
        .host()
        .ok_or(Error::Payload("relay host"))?
        .to_string()
        .to_ascii_lowercase();
    let port = url
        .port_or_known_default()
        .ok_or(Error::Payload("relay port"))?;
    ensure(
        port != 0 && origin == format!("{}://{}:{port}", url.scheme(), host),
        "canonical relay origin",
    )
}
impl Sequenced {
    fn validate(&self) -> Result<(), Error> {
        ensure(self.seq > 0 && !self.record.is_empty(), "sequenced record")
    }
}
impl Eviction {
    fn validate(&self) -> Result<(), Error> {
        ensure(self.incarnation > 0 && self.reason.len() <= 128, "eviction")
    }
}
impl Admins {
    fn validate(&self) -> Result<(), Error> {
        validate_admins(&self.admins)?;
        ensure(self.admins_revision > 0, "admin revision")
    }
}
impl SignedManagementRecord {
    pub const EVICT: u64 = 0;
    pub const ADMINS: u64 = 1;

    fn validate(&self) -> Result<(), Error> {
        validate_lifetime(self.issued_at, self.expires_at)?;
        match self.kind {
            Self::EVICT => {
                Eviction::decode(&self.body)?;
            }
            Self::ADMINS => {
                Admins::decode(&self.body)?;
            }
            _ => return Err(Error::Payload("management kind")),
        }
        Ok(())
    }
    pub fn signing_input(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = b"nsmesh-record-v1\0".to_vec();
        self.kind.sign_into(&mut out);
        self.network_pub.sign_into(&mut out);
        self.op_id.sign_into(&mut out);
        self.author_pub.sign_into(&mut out);
        self.issued_at.sign_into(&mut out);
        self.expires_at.sign_into(&mut out);
        self.body.sign_into(&mut out);
        Ok(out)
    }
    pub fn verify(&self) -> Result<(), Error> {
        super::recovery::verify(&self.author_pub, &self.signing_input()?, &self.signature)
    }
}
