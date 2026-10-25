//! Exact body schemas for every service-control message kind.

use super::*;

type Fields<'a> = &'a [(String, Value)];

pub(super) fn validate(envelope: &Envelope) -> Result<(), ContractError> {
    let session_required = matches!(
        envelope.kind.as_str(),
        "session.open"
            | "session.open.result"
            | "snapshot.push"
            | "snapshot.ack"
            | "listener.ready"
            | "lease.refresh"
            | "lease.acquire"
            | "lease.result"
            | "port.result"
            | "port.cancel"
            | "port.query"
            | "port.query.result"
    );
    if session_required != envelope.session_seq.is_some() {
        return Err(ContractError::InvalidField);
    }
    let body = match envelope.kind.as_str() {
        "runtime.floor" | "session.open" | "report.head" => exact_map(&envelope.body, &[])?,
        "runtime.bind" => {
            let fields = exact_map(
                &envelope.body,
                &[
                    "recovery",
                    "observed_generation",
                    "observed_runtime_id",
                    "owner_recovery",
                ],
            )?;
            let recovery = boolean(field(fields, "recovery")?)?;
            let owner_recovery = boolean(field(fields, "owner_recovery")?)?;
            let observed = optional_uint(field(fields, "observed_generation")?)?;
            let observed_id: Option<Id> = optional_fixed(field(fields, "observed_runtime_id")?)?;
            if observed.is_some() != observed_id.is_some()
                || observed == Some(0)
                || observed_id == Some([0; 16])
                || (recovery && observed.is_none())
                || (!recovery && (owner_recovery || observed.is_some() || observed_id.is_some()))
            {
                return Err(ContractError::InvalidField);
            }
            fields
        }
        "runtime.floor.result" => {
            let fields = exact_map(
                &envelope.body,
                &[
                    "current_generation",
                    "current_runtime_id",
                    "active",
                    "authority_epoch",
                ],
            )?;
            let generation = optional_uint(field(fields, "current_generation")?)?;
            let runtime_id: Option<Id> = optional_fixed(field(fields, "current_runtime_id")?)?;
            let active = boolean(field(fields, "active")?)?;
            if generation.is_some() != runtime_id.is_some()
                || generation == Some(0)
                || runtime_id == Some([0; 16])
                || (active && generation.is_none())
            {
                return Err(ContractError::InvalidField);
            }
            if Some(nonzero(field(fields, "authority_epoch")?)?) != envelope.authority_epoch {
                return Err(ContractError::DigestConflict);
            }
            fields
        }
        "runtime.bind.result" => {
            let fields = exact_map(&envelope.body, &["authority_epoch"])?;
            if Some(nonzero(field(fields, "authority_epoch")?)?) != envelope.authority_epoch {
                return Err(ContractError::DigestConflict);
            }
            fields
        }
        "session.open.result" => {
            let fields = exact_map(&envelope.body, &["session_seq"])?;
            if Some(nonzero(field(fields, "session_seq")?)?) != envelope.session_seq {
                return Err(ContractError::DigestConflict);
            }
            fields
        }
        "report.replace" => {
            let fields = exact_map(
                &envelope.body,
                &["report_revision", "report_digest", "report_content"],
            )?;
            nonzero(field(fields, "report_revision")?)?;
            let digest: Digest = fixed(field(fields, "report_digest")?)?;
            let content = byte_string(field(fields, "report_content")?)?;
            let report = ReportContent::decode(content)?;
            if report.publisher_identity != envelope.subject_identity
                || report.nsd_id != envelope.nsd_id
                || report.network_id != envelope.network_id
                || report.canonical()?.1 != digest
            {
                return Err(ContractError::DigestConflict);
            }
            fields
        }
        "report.head.result" | "report.accepted" => {
            let fields = exact_map(
                &envelope.body,
                &["accepted_revision", "report_digest", "bindings"],
            )?;
            let revision = unsigned(field(fields, "accepted_revision")?)?;
            let digest: Option<Digest> = optional_fixed(field(fields, "report_digest")?)?;
            if (revision == 0) != digest.is_none() {
                return Err(ContractError::InvalidField);
            }
            validate_bindings(field(fields, "bindings")?, envelope)?;
            if revision == 0 && field(fields, "bindings")? != &Value::Array(vec![]) {
                return Err(ContractError::InvalidField);
            }
            fields
        }
        "snapshot.push" => {
            let fields = exact_map(
                &envelope.body,
                &["snapshot_revision", "snapshot_digest", "content"],
            )?;
            let revision = nonzero(field(fields, "snapshot_revision")?)?;
            let digest: Digest = fixed(field(fields, "snapshot_digest")?)?;
            let content = decode_canonical(byte_string(field(fields, "content")?)?)?;
            let snapshot_fields = snapshot_fields(&content, envelope)?;
            if unsigned(field(snapshot_fields, "snapshot_revision")?)? != revision
                || snapshot_digest(&content)? != digest
            {
                return Err(ContractError::DigestConflict);
            }
            fields
        }
        "snapshot.ack" => {
            let fields = exact_map(
                &envelope.body,
                &[
                    "snapshot_revision",
                    "snapshot_digest",
                    "accepted",
                    "enforcement_applied",
                    "dns_applied",
                    "error",
                ],
            )?;
            nonzero(field(fields, "snapshot_revision")?)?;
            let _: Digest = fixed(field(fields, "snapshot_digest")?)?;
            let accepted = boolean(field(fields, "accepted")?)?;
            let enforcement = boolean(field(fields, "enforcement_applied")?)?;
            let dns = boolean(field(fields, "dns_applied")?)?;
            let error = optional_text(field(fields, "error")?)?;
            if error
                .as_deref()
                .is_some_and(|code| !ERROR_CODES.contains(&code))
            {
                return Err(ContractError::UnsupportedField);
            }
            if (enforcement || dns) && !accepted {
                return Err(ContractError::InvalidField);
            }
            fields
        }
        "listener.ready" | "lease.refresh" => {
            let fields = exact_map(
                &envelope.body,
                &[
                    "service_ref",
                    "listener_revision",
                    "intent_digest",
                    "allocation_round",
                    "proposal_seq",
                    "proposal_id",
                    "port",
                    "refresh_seq",
                    "snapshot_revision",
                    "snapshot_digest",
                    "enforcement_policy_digest",
                ],
            )?;
            proposal_binding(fields, envelope)?;
            nonzero(field(fields, "refresh_seq")?)?;
            nonzero(field(fields, "snapshot_revision")?)?;
            let _: Digest = fixed(field(fields, "snapshot_digest")?)?;
            let _: Digest = fixed(field(fields, "enforcement_policy_digest")?)?;
            fields
        }
        "lease.acquire" => {
            let fields = exact_map(
                &envelope.body,
                &[
                    "consumer_seq",
                    "snapshot_revision",
                    "snapshot_digest",
                    "services",
                ],
            )?;
            nonzero(field(fields, "consumer_seq")?)?;
            nonzero(field(fields, "snapshot_revision")?)?;
            let _: Digest = fixed(field(fields, "snapshot_digest")?)?;
            validate_service_set(field(fields, "services")?, envelope)?;
            fields
        }
        "lease.result" => {
            let fields = exact_map(
                &envelope.body,
                &[
                    "service_ref",
                    "listener_revision",
                    "intent_digest",
                    "grant_id",
                    "refresh_seq",
                    "consumer_seq",
                    "remaining_ms",
                    "result",
                    "snapshot_revision",
                    "snapshot_digest",
                ],
            )?;
            service_ref(field(fields, "service_ref")?, envelope)?;
            nonzero(field(fields, "listener_revision")?)?;
            let _: Digest = fixed(field(fields, "intent_digest")?)?;
            let grant: Option<Id> = optional_fixed(field(fields, "grant_id")?)?;
            if grant == Some([0; 16]) {
                return Err(ContractError::InvalidField);
            }
            let refresh = optional_uint(field(fields, "refresh_seq")?)?;
            let consumer = optional_uint(field(fields, "consumer_seq")?)?;
            if refresh.is_some() == consumer.is_some() || refresh == Some(0) || consumer == Some(0)
            {
                return Err(ContractError::InvalidField);
            }
            let remaining = unsigned(field(fields, "remaining_ms")?)?;
            if remaining > MAX_LEASE_MS {
                return Err(ContractError::InvalidField);
            }
            let result = text(field(fields, "result")?)?;
            if result != "ok" && !ERROR_CODES.contains(&result) {
                return Err(ContractError::UnsupportedField);
            }
            let snapshot_revision = optional_uint(field(fields, "snapshot_revision")?)?;
            let snapshot: Option<Digest> = optional_fixed(field(fields, "snapshot_digest")?)?;
            if consumer.is_some() != snapshot_revision.is_some()
                || consumer.is_some() != snapshot.is_some()
                || snapshot_revision == Some(0)
            {
                return Err(ContractError::InvalidField);
            }
            if (result == "ok" && (grant.is_none() || remaining == 0))
                || (result != "ok" && (grant.is_some() || remaining != 0))
            {
                return Err(ContractError::InvalidField);
            }
            fields
        }
        "port.result" | "port.query.result" => {
            let fields = exact_map(
                &envelope.body,
                &[
                    "service_ref",
                    "listener_revision",
                    "intent_digest",
                    "allocation_round",
                    "proposal_seq",
                    "proposal_id",
                    "port",
                    "result",
                    "terminal_floor",
                ],
            )?;
            proposal_binding(fields, envelope)?;
            let result = text(field(fields, "result")?)?;
            let floor = optional_uint(field(fields, "terminal_floor")?)?;
            if !matches!(
                result,
                "proposed"
                    | "claimed"
                    | "installed"
                    | "terminated-pure"
                    | "apply-failed"
                    | "conflict"
                    | "unknown"
                    | "tombstoned"
            ) || (result == "terminated-pure") != floor.is_some()
                || floor == Some(0)
            {
                return Err(ContractError::InvalidField);
            }
            fields
        }
        "port.cancel" | "port.query" => {
            let fields = exact_map(
                &envelope.body,
                &[
                    "service_ref",
                    "listener_revision",
                    "intent_digest",
                    "allocation_round",
                    "proposal_seq",
                    "proposal_id",
                    "port",
                ],
            )?;
            proposal_binding(fields, envelope)?;
            fields
        }
        "service.retry-port" => {
            let fields = exact_map(&envelope.body, &["service_ref"])?;
            service_ref(field(fields, "service_ref")?, envelope)?;
            fields
        }
        "error" => {
            let fields = exact_map(&envelope.body, &["code"])?;
            if !ERROR_CODES.contains(&text(field(fields, "code")?)?) {
                return Err(ContractError::UnsupportedField);
            }
            fields
        }
        _ => return Err(ContractError::UnsupportedField),
    };
    let _ = body;
    Ok(())
}

const ERROR_CODES: &[&str] = &[
    "unsupported-version",
    "unsupported-field",
    "invalid-encoding",
    "unauthorized",
    "stale-runtime",
    "stale-epoch",
    "stale-session",
    "stale-report",
    "stale-snapshot",
    "stale-listener",
    "stale-proposal",
    "stale-refresh",
    "enforcement-not-applied",
    "runtime-recovery-required",
    "digest-conflict",
    "state-inconsistent",
    "port-unavailable",
    "port-pool-exhausted",
    "allocation-exhausted",
    "recovery-required",
    "apply-failed",
    "lease-expired",
    "storage-unavailable",
    "counter-exhausted",
];

fn nonzero(value: &Value) -> Result<u64, ContractError> {
    let value = unsigned(value)?;
    if value == 0 {
        Err(ContractError::InvalidField)
    } else {
        Ok(value)
    }
}

fn byte_string(value: &Value) -> Result<&[u8], ContractError> {
    if let Value::Bytes(bytes) = value {
        Ok(bytes)
    } else {
        Err(ContractError::InvalidField)
    }
}

fn service_ref(value: &Value, envelope: &Envelope) -> Result<ServiceRef, ContractError> {
    let reference = ServiceRef::from_value(value)?;
    if reference.nsd_id != envelope.nsd_id || reference.network_id != envelope.network_id {
        return Err(ContractError::DigestConflict);
    }
    Ok(reference)
}

fn proposal_binding(fields: Fields<'_>, envelope: &Envelope) -> Result<(), ContractError> {
    service_ref(field(fields, "service_ref")?, envelope)?;
    for name in ["listener_revision", "allocation_round", "proposal_seq"] {
        nonzero(field(fields, name)?)?;
    }
    let _: Digest = fixed(field(fields, "intent_digest")?)?;
    let proposal_id: Id = fixed(field(fields, "proposal_id")?)?;
    if proposal_id == [0; 16] {
        return Err(ContractError::InvalidField);
    }
    port(field(fields, "port")?)?;
    Ok(())
}

fn validate_service_set(value: &Value, envelope: &Envelope) -> Result<(), ContractError> {
    let Value::Array(items) = value else {
        return Err(ContractError::InvalidField);
    };
    let mut previous: Option<Vec<u8>> = None;
    for item in items {
        let fields = exact_map(item, &["service_ref", "listener_revision", "intent_digest"])?;
        service_ref(field(fields, "service_ref")?, envelope)?;
        nonzero(field(fields, "listener_revision")?)?;
        let _: Digest = fixed(field(fields, "intent_digest")?)?;
        let encoded = encode_canonical(item)?;
        if previous.as_ref().is_some_and(|earlier| earlier >= &encoded) {
            return Err(ContractError::InvalidField);
        }
        previous = Some(encoded);
    }
    Ok(())
}

fn validate_bindings(value: &Value, envelope: &Envelope) -> Result<(), ContractError> {
    let Value::Array(items) = value else {
        return Err(ContractError::InvalidField);
    };
    let mut previous: Option<Vec<u8>> = None;
    for item in items {
        let fields = exact_map(
            item,
            &["declaration_key", "service_ref", "port", "proposal_state"],
        )?;
        let key = text(field(fields, "declaration_key")?)?.as_bytes().to_vec();
        if previous.as_ref().is_some_and(|earlier| earlier >= &key) {
            return Err(ContractError::InvalidField);
        }
        previous = Some(key);
        service_ref(field(fields, "service_ref")?, envelope)?;
        if *field(fields, "port")? != Value::Null {
            port(field(fields, "port")?)?;
        }
        if !matches!(
            text(field(fields, "proposal_state")?)?,
            "pending" | "offered" | "claimed" | "ready" | "recovery-required" | "exhausted"
        ) {
            return Err(ContractError::UnsupportedField);
        }
    }
    Ok(())
}

fn snapshot_fields<'a>(value: &'a Value, envelope: &Envelope) -> Result<Fields<'a>, ContractError> {
    let fields = exact_map(
        value,
        &[
            "scope",
            "snapshot_revision",
            "resources",
            "routes",
            "listeners",
            "grants",
            "withdrawals",
        ],
    )?;
    let Value::Array(scope) = field(fields, "scope")? else {
        return Err(ContractError::InvalidField);
    };
    if scope.len() != 3
        || fixed::<32>(&scope[0])? != envelope.subject_identity
        || fixed::<16>(&scope[1])? != envelope.nsd_id
        || fixed::<16>(&scope[2])? != envelope.network_id
    {
        return Err(ContractError::DigestConflict);
    }
    snapshot_digest(value)?;
    Ok(fields)
}
