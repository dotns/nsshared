//! Conversion between typed message bodies and their exact CBOR maps.

use crate::cbor::Value;
use crate::contract::{
    ContractError, Envelope as RawEnvelope, bytes, exact_map, field, fixed, map, option_bytes,
    option_text, option_uint, optional_fixed, optional_text, optional_uint, port, text, unsigned,
};
use crate::message::{
    LeaseAcquire, LeaseResult, Message, MessageBody, MessageKind, PortResult, ReadyProof,
    ReportAccepted, ReportBinding, ReportReplace, RuntimeBind, RuntimeFloorResult, ServiceLeaseRef,
    SnapshotAck, SnapshotPush,
};
use crate::snapshot::{Snapshot, proposal_from_value, proposal_value};

impl Message {
    /// Encodes an exact schema-1 message. The body variant fixes the wire kind.
    ///
    /// # Errors
    /// Returns an error for invalid binding, content or canonical CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, ContractError> {
        RawEnvelope {
            kind: self.body.kind().as_str().to_owned(),
            nsd_id: self.nsd_id,
            network_id: self.network_id,
            subject_identity: self.subject_identity,
            runtime_generation: self.runtime_generation,
            runtime_id: self.runtime_id,
            authority_epoch: self.authority_epoch,
            request_id: self.request_id,
            session_seq: self.session_seq,
            body: self.body.value()?,
        }
        .encode()
    }

    /// Decodes canonical CBOR to an exhaustive typed body.
    ///
    /// # Errors
    /// Returns an error for an unsupported kind or any unknown/invalid body field.
    pub fn decode(input: &[u8]) -> Result<Self, ContractError> {
        let raw = RawEnvelope::decode(input)?;
        let kind = MessageKind::try_from(raw.kind.as_str())?;
        let body = MessageBody::from_value(kind, &raw.body)?;
        Ok(Self {
            nsd_id: raw.nsd_id,
            network_id: raw.network_id,
            subject_identity: raw.subject_identity,
            runtime_generation: raw.runtime_generation,
            runtime_id: raw.runtime_id,
            authority_epoch: raw.authority_epoch,
            request_id: raw.request_id,
            session_seq: raw.session_seq,
            body,
        })
    }
}

impl MessageBody {
    fn value(&self) -> Result<Value, ContractError> {
        Ok(match self {
            Self::RuntimeFloor | Self::SessionOpen | Self::ReportHead => map(vec![]),
            Self::RuntimeFloorResult(body) => map(vec![
                ("current_generation", option_uint(body.current_generation)),
                ("current_runtime_id", option_bytes(body.current_runtime_id)),
                ("active", Value::Bool(body.active)),
                ("authority_epoch", Value::UInt(body.authority_epoch)),
            ]),
            Self::RuntimeBind(body) => map(vec![
                ("recovery", Value::Bool(body.recovery)),
                ("observed_generation", option_uint(body.observed_generation)),
                (
                    "observed_runtime_id",
                    option_bytes(body.observed_runtime_id),
                ),
                ("owner_recovery", Value::Bool(body.owner_recovery)),
            ]),
            Self::RuntimeBindResult(epoch) => map(vec![("authority_epoch", Value::UInt(*epoch))]),
            Self::SessionOpenResult(seq) => map(vec![("session_seq", Value::UInt(*seq))]),
            Self::ReportReplace(body) => {
                let (content, digest) = body.report.canonical()?;
                map(vec![
                    ("report_revision", Value::UInt(body.report_revision)),
                    ("report_digest", bytes(digest)),
                    ("report_content", Value::Bytes(content)),
                ])
            }
            Self::ReportHeadResult(body) | Self::ReportAccepted(body) => {
                report_accepted_value(body)
            }
            Self::SnapshotPush(body) => {
                let (content, digest) = body.snapshot.canonical()?;
                map(vec![
                    (
                        "snapshot_revision",
                        Value::UInt(body.snapshot.snapshot_revision),
                    ),
                    ("snapshot_digest", bytes(digest)),
                    ("content", Value::Bytes(content)),
                ])
            }
            Self::SnapshotAck(body) => map(vec![
                ("snapshot_revision", Value::UInt(body.snapshot_revision)),
                ("snapshot_digest", bytes(body.snapshot_digest)),
                ("accepted", Value::Bool(body.accepted)),
                ("enforcement_applied", Value::Bool(body.enforcement_applied)),
                ("dns_applied", Value::Bool(body.dns_applied)),
                ("error", option_text(&body.error)),
            ]),
            Self::ListenerReady(body) | Self::LeaseRefresh(body) => ready_value(body),
            Self::LeaseAcquire(body) => map(vec![
                ("consumer_seq", Value::UInt(body.consumer_seq)),
                ("snapshot_revision", Value::UInt(body.snapshot_revision)),
                ("snapshot_digest", bytes(body.snapshot_digest)),
                (
                    "services",
                    Value::Array(body.services.iter().map(service_value).collect()),
                ),
            ]),
            Self::LeaseResult(body) => lease_result_value(body),
            Self::PortResult(body) | Self::PortQueryResult(body) => {
                let mut fields = fields(proposal_value(&body.proposal));
                fields.push(("result".into(), Value::Text(body.result.clone())));
                fields.push(("terminal_floor".into(), option_uint(body.terminal_floor)));
                Value::Map(fields)
            }
            Self::PortCancel(body) | Self::PortQuery(body) => proposal_value(body),
            Self::ServiceRetryPort(reference) => map(vec![("service_ref", reference.value())]),
            Self::Error(code) => map(vec![("code", Value::Text(code.clone()))]),
        })
    }

    fn from_value(kind: MessageKind, value: &Value) -> Result<Self, ContractError> {
        let Value::Map(fields) = value else {
            return Err(ContractError::InvalidField);
        };
        Ok(match kind {
            MessageKind::RuntimeFloor => Self::RuntimeFloor,
            MessageKind::RuntimeFloorResult => Self::RuntimeFloorResult(RuntimeFloorResult {
                current_generation: optional_uint(field(fields, "current_generation")?)?,
                current_runtime_id: optional_fixed(field(fields, "current_runtime_id")?)?,
                active: boolean(field(fields, "active")?)?,
                authority_epoch: unsigned(field(fields, "authority_epoch")?)?,
            }),
            MessageKind::RuntimeBind => Self::RuntimeBind(RuntimeBind {
                recovery: boolean(field(fields, "recovery")?)?,
                observed_generation: optional_uint(field(fields, "observed_generation")?)?,
                observed_runtime_id: optional_fixed(field(fields, "observed_runtime_id")?)?,
                owner_recovery: boolean(field(fields, "owner_recovery")?)?,
            }),
            MessageKind::RuntimeBindResult => {
                Self::RuntimeBindResult(unsigned(field(fields, "authority_epoch")?)?)
            }
            MessageKind::SessionOpen => Self::SessionOpen,
            MessageKind::SessionOpenResult => {
                Self::SessionOpenResult(unsigned(field(fields, "session_seq")?)?)
            }
            MessageKind::ReportHead => Self::ReportHead,
            MessageKind::ReportHeadResult => Self::ReportHeadResult(report_accepted(fields)?),
            MessageKind::ReportReplace => {
                let Value::Bytes(content) = field(fields, "report_content")? else {
                    return Err(ContractError::InvalidField);
                };
                Self::ReportReplace(ReportReplace {
                    report_revision: unsigned(field(fields, "report_revision")?)?,
                    report: crate::contract::ReportContent::decode(content)?,
                })
            }
            MessageKind::ReportAccepted => Self::ReportAccepted(report_accepted(fields)?),
            MessageKind::SnapshotPush => {
                let Value::Bytes(content) = field(fields, "content")? else {
                    return Err(ContractError::InvalidField);
                };
                Self::SnapshotPush(SnapshotPush {
                    snapshot: Snapshot::decode(content)?,
                })
            }
            MessageKind::SnapshotAck => Self::SnapshotAck(SnapshotAck {
                snapshot_revision: unsigned(field(fields, "snapshot_revision")?)?,
                snapshot_digest: fixed(field(fields, "snapshot_digest")?)?,
                accepted: boolean(field(fields, "accepted")?)?,
                enforcement_applied: boolean(field(fields, "enforcement_applied")?)?,
                dns_applied: boolean(field(fields, "dns_applied")?)?,
                error: optional_text(field(fields, "error")?)?,
            }),
            MessageKind::ListenerReady => Self::ListenerReady(ready_from_value(value)?),
            MessageKind::LeaseRefresh => Self::LeaseRefresh(ready_from_value(value)?),
            MessageKind::LeaseAcquire => {
                let Value::Array(services) = field(fields, "services")? else {
                    return Err(ContractError::InvalidField);
                };
                Self::LeaseAcquire(LeaseAcquire {
                    consumer_seq: unsigned(field(fields, "consumer_seq")?)?,
                    snapshot_revision: unsigned(field(fields, "snapshot_revision")?)?,
                    snapshot_digest: fixed(field(fields, "snapshot_digest")?)?,
                    services: services
                        .iter()
                        .map(service_from_value)
                        .collect::<Result<_, _>>()?,
                })
            }
            MessageKind::LeaseResult => Self::LeaseResult(lease_result_from_value(fields)?),
            MessageKind::PortResult => Self::PortResult(port_result_from_value(value)?),
            MessageKind::PortCancel => Self::PortCancel(proposal_from_value(value)?),
            MessageKind::PortQuery => Self::PortQuery(proposal_from_value(value)?),
            MessageKind::PortQueryResult => Self::PortQueryResult(port_result_from_value(value)?),
            MessageKind::ServiceRetryPort => Self::ServiceRetryPort(
                crate::contract::ServiceRef::from_value(field(fields, "service_ref")?)?,
            ),
            MessageKind::Error => Self::Error(text(field(fields, "code")?)?.to_owned()),
        })
    }
}

fn fields(value: Value) -> Vec<(String, Value)> {
    if let Value::Map(fields) = value {
        fields
    } else {
        Vec::new()
    }
}

fn boolean(value: &Value) -> Result<bool, ContractError> {
    crate::contract::boolean(value)
}

fn service_value(service: &ServiceLeaseRef) -> Value {
    map(vec![
        ("service_ref", service.service_ref.value()),
        ("listener_revision", Value::UInt(service.listener_revision)),
        ("intent_digest", bytes(service.intent_digest)),
    ])
}

fn service_from_value(value: &Value) -> Result<ServiceLeaseRef, ContractError> {
    let fields = exact_map(
        value,
        &["service_ref", "listener_revision", "intent_digest"],
    )?;
    Ok(ServiceLeaseRef {
        service_ref: crate::contract::ServiceRef::from_value(field(fields, "service_ref")?)?,
        listener_revision: unsigned(field(fields, "listener_revision")?)?,
        intent_digest: fixed(field(fields, "intent_digest")?)?,
    })
}

fn report_accepted_value(body: &ReportAccepted) -> Value {
    map(vec![
        ("accepted_revision", Value::UInt(body.accepted_revision)),
        ("report_digest", option_bytes(body.report_digest)),
        (
            "bindings",
            Value::Array(
                body.bindings
                    .iter()
                    .map(|binding| {
                        map(vec![
                            (
                                "declaration_key",
                                Value::Text(binding.declaration_key.clone()),
                            ),
                            ("service_ref", binding.service_ref.value()),
                            (
                                "port",
                                binding
                                    .port
                                    .map_or(Value::Null, |port| Value::UInt(u64::from(port))),
                            ),
                            (
                                "proposal_state",
                                Value::Text(binding.proposal_state.clone()),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn report_accepted(fields: &[(String, Value)]) -> Result<ReportAccepted, ContractError> {
    let Value::Array(bindings) = field(fields, "bindings")? else {
        return Err(ContractError::InvalidField);
    };
    Ok(ReportAccepted {
        accepted_revision: unsigned(field(fields, "accepted_revision")?)?,
        report_digest: optional_fixed(field(fields, "report_digest")?)?,
        bindings: bindings
            .iter()
            .map(|item| {
                let fields = exact_map(
                    item,
                    &["declaration_key", "service_ref", "port", "proposal_state"],
                )?;
                let port = if *field(fields, "port")? == Value::Null {
                    None
                } else {
                    Some(port(field(fields, "port")?)?)
                };
                Ok(ReportBinding {
                    declaration_key: text(field(fields, "declaration_key")?)?.to_owned(),
                    service_ref: crate::contract::ServiceRef::from_value(field(
                        fields,
                        "service_ref",
                    )?)?,
                    port,
                    proposal_state: text(field(fields, "proposal_state")?)?.to_owned(),
                })
            })
            .collect::<Result<_, ContractError>>()?,
    })
}

fn ready_value(body: &ReadyProof) -> Value {
    let mut fields = fields(proposal_value(&body.proposal));
    fields.push(("refresh_seq".into(), Value::UInt(body.refresh_seq)));
    fields.push((
        "snapshot_revision".into(),
        Value::UInt(body.snapshot_revision),
    ));
    fields.push(("snapshot_digest".into(), bytes(body.snapshot_digest)));
    fields.push((
        "enforcement_policy_digest".into(),
        bytes(body.enforcement_policy_digest),
    ));
    Value::Map(fields)
}

fn ready_from_value(value: &Value) -> Result<ReadyProof, ContractError> {
    let Value::Map(fields) = value else {
        return Err(ContractError::InvalidField);
    };
    let proposal = proposal_from_value(&Value::Map(
        fields
            .iter()
            .filter(|(name, _)| {
                !matches!(
                    name.as_str(),
                    "refresh_seq"
                        | "snapshot_revision"
                        | "snapshot_digest"
                        | "enforcement_policy_digest"
                )
            })
            .cloned()
            .collect(),
    ))?;
    Ok(ReadyProof {
        proposal,
        refresh_seq: unsigned(field(fields, "refresh_seq")?)?,
        snapshot_revision: unsigned(field(fields, "snapshot_revision")?)?,
        snapshot_digest: fixed(field(fields, "snapshot_digest")?)?,
        enforcement_policy_digest: fixed(field(fields, "enforcement_policy_digest")?)?,
    })
}

fn lease_result_value(body: &LeaseResult) -> Value {
    let mut fields = fields(service_value(&body.service));
    fields.extend([
        ("grant_id".into(), option_bytes(body.grant_id)),
        ("refresh_seq".into(), option_uint(body.refresh_seq)),
        ("consumer_seq".into(), option_uint(body.consumer_seq)),
        ("remaining_ms".into(), Value::UInt(body.remaining_ms)),
        ("result".into(), Value::Text(body.result.clone())),
        (
            "snapshot_revision".into(),
            option_uint(body.snapshot_revision),
        ),
        ("snapshot_digest".into(), option_bytes(body.snapshot_digest)),
    ]);
    Value::Map(fields)
}

fn lease_result_from_value(fields: &[(String, Value)]) -> Result<LeaseResult, ContractError> {
    let service = service_from_value(&Value::Map(
        fields
            .iter()
            .filter(|(name, _)| {
                matches!(
                    name.as_str(),
                    "service_ref" | "listener_revision" | "intent_digest"
                )
            })
            .cloned()
            .collect(),
    ))?;
    Ok(LeaseResult {
        service,
        grant_id: optional_fixed(field(fields, "grant_id")?)?,
        refresh_seq: optional_uint(field(fields, "refresh_seq")?)?,
        consumer_seq: optional_uint(field(fields, "consumer_seq")?)?,
        remaining_ms: unsigned(field(fields, "remaining_ms")?)?,
        result: text(field(fields, "result")?)?.to_owned(),
        snapshot_revision: optional_uint(field(fields, "snapshot_revision")?)?,
        snapshot_digest: optional_fixed(field(fields, "snapshot_digest")?)?,
    })
}

fn port_result_from_value(value: &Value) -> Result<PortResult, ContractError> {
    let Value::Map(fields) = value else {
        return Err(ContractError::InvalidField);
    };
    let proposal = proposal_from_value(&Value::Map(
        fields
            .iter()
            .filter(|(name, _)| !matches!(name.as_str(), "result" | "terminal_floor"))
            .cloned()
            .collect(),
    ))?;
    Ok(PortResult {
        proposal,
        result: text(field(fields, "result")?)?.to_owned(),
        terminal_floor: optional_uint(field(fields, "terminal_floor")?)?,
    })
}
