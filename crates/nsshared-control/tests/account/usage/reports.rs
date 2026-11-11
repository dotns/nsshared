#![allow(clippy::unwrap_used, clippy::panic)]

use nsshared_control::{
    account::AccountError, account::MAX_BYTES, account::MAX_IDENTITIES,
    account::grants::GrantPublication, account::node::ReporterIncarnation,
    account::relay::IdentityClass, account::relay::ParticipantRosterGeneration,
    account::relay::ParticipantRosterScope, account::relay::RosterEntry,
    account::relay::RosterVersion, account::usage::BatchLossWindow, account::usage::RelayBilling,
    account::usage::RelayDirection, account::usage::RelayUsage, account::usage::ServiceBoundary,
    account::usage::ServiceDirection, account::usage::ServiceOperation,
    account::usage::ServiceUsage, account::usage::UsageAnswer, account::usage::UsageError,
    account::usage::UsageOutcome, account::usage::UsageProfile, account::usage::UsageReport,
    account::usage::UsageRows, account::usage::UsageWatermark,
};
use nsshared_identity::keys::IdentitySecret;
use nsshared_testkit::hex::unhex;
use std::collections::BTreeMap;

type Vector = BTreeMap<&'static str, &'static str>;

fn vectors() -> Vec<Vector> {
    nsshared_testkit::vector_fields!("account/usage/reports")
        .into_iter()
        .filter(|fields| fields.contains_key("bytes"))
        .collect()
}

fn sample(name: &str) -> Vec<u8> {
    unhex(vectors().iter().find(|v| v["name"] == name).unwrap()["bytes"])
}

fn report(name: &str) -> UsageReport {
    UsageReport::decode(&sample(name)).unwrap()
}

fn history(version: u64, destination_class: IdentityClass) -> ParticipantRosterGeneration {
    let a = IdentitySecret::from_seed([1; 32]).public();
    let b = IdentitySecret::from_seed([2; 32]).public();
    ParticipantRosterGeneration {
        scope: ParticipantRosterScope {
            issuer: a,
            recipient: b,
        },
        version: RosterVersion(version),
        attribution_epoch: RosterVersion(version),
        identities: vec![
            RosterEntry {
                identity: a,
                class: IdentityClass::OrdinaryNode,
                network: None,
            },
            RosterEntry {
                identity: b,
                class: destination_class,
                network: None,
            },
        ],
        // Historical ownership remains valid for comparison after roster expiry.
        issued_at_unix_ms: 0,
        valid_until_unix_ms: 1,
    }
}

#[test]
fn service_usage_vectors() {
    let grant = GrantPublication::decode(&sample("historical-grant")).unwrap();
    let grant = &grant.grants[0];
    let payer = grant.payer().unwrap();
    let mut accepted = 0;
    let mut refused = 0;
    for vector in vectors().iter().filter(|v| v["kind"] == "service") {
        let bytes = unhex(vector["bytes"]);
        let decoded = ServiceUsage::decode(&bytes);
        if vector["decision"] == "reject" {
            assert!(decoded.is_err(), "{}", vector["name"]);
            refused += 1;
            continue;
        }
        let decoded = decoded.unwrap();
        assert_eq!(decoded.canonical(), bytes, "{}", vector["name"]);
        assert_eq!(decoded.payer_subject, payer.subject);
        assert_eq!(decoded.grant, grant.incarnation);
        assert_eq!(decoded.reporter, ReporterIncarnation([6; 16]));
        assert_eq!(
            decoded.completed_bytes,
            vector["quantity"].parse::<u64>().unwrap()
        );
        assert_eq!(
            decoded.direction as u64,
            vector["direction"].parse::<u64>().unwrap()
        );
        assert_eq!(
            decoded.payer_realm,
            if vector["name"] == "same-user-other-realm" {
                [26; 16].into()
            } else {
                payer.realm
            }
        );
        assert_eq!(
            decoded.boundary,
            if vector["name"] == "public-ingress" {
                ServiceBoundary::PublicIngress
            } else {
                ServiceBoundary::CompletedHostWritesAndSends
            }
        );
        accepted += 1;
    }
    assert_eq!(accepted, 7);
    assert!(refused >= 12);
    assert_eq!(
        ServiceUsage::decode(&sample("tcp-partial"))
            .unwrap()
            .batch_loss_window,
        BatchLossWindow::Unset
    );
    assert_eq!(
        ServiceUsage::decode(&sample("udp-send"))
            .unwrap()
            .batch_loss_window,
        BatchLossWindow::Measured { duration_ms: 0 }
    );
    assert_eq!(
        ServiceUsage::decode(&sample("echo-reply"))
            .unwrap()
            .batch_loss_window,
        BatchLossWindow::Measured { duration_ms: 12 }
    );
    // A failed synthetic reply leaves the independently completed probe intact.
    assert_eq!(
        ServiceUsage::decode(&sample("echo-probe-reply-failed"))
            .unwrap()
            .completed_bytes,
        8
    );
    assert_eq!(
        ServiceUsage::decode(&sample("failed-send"))
            .unwrap()
            .completed_bytes,
        0
    );

    let original = report("service-report");
    let alternate = report("other-realm-report");
    let (UsageRows::Service(original), UsageRows::Service(alternate)) =
        (&original.rows, &alternate.rows)
    else {
        panic!()
    };
    original[0].validate_grant(grant).unwrap();
    assert_eq!(
        original[0].unit.payer_subject,
        alternate[0].unit.payer_subject
    );
    assert_ne!(original[0].unit.payer_realm, alternate[0].unit.payer_realm);
    assert!(matches!(
        alternate[0].validate_grant(grant),
        Err(UsageError::HistoricalGrant)
    ));
    let mut other_grant = grant.clone();
    other_grant.payers[0].realm = alternate[0].unit.payer_realm;
    alternate[0].validate_grant(&other_grant).unwrap();
    assert!(matches!(
        original[0].validate_grant(&other_grant),
        Err(UsageError::HistoricalGrant)
    ));
    for changed in 0..4 {
        let mut row = original[0].clone();
        match changed {
            0 => row.resource.nsd_id[0] ^= 1,
            1 => row.client = row.provider,
            2 => row.provider = row.client,
            _ => row.unit.grant.0[0] ^= 1,
        }
        assert!(matches!(
            row.validate_grant(grant),
            Err(UsageError::HistoricalGrant)
        ));
    }
}

#[test]
fn relay_usage_vectors() {
    for vector in vectors().iter().filter(|v| v["kind"] == "relay") {
        let bytes = unhex(vector["bytes"]);
        let decoded = RelayUsage::decode(&bytes);
        if vector["decision"] == "reject" {
            assert!(decoded.is_err(), "{}", vector["name"]);
            continue;
        }
        let decoded = decoded.unwrap();
        assert_eq!(decoded.canonical().unwrap(), bytes);
        assert_eq!(
            decoded.source,
            IdentitySecret::from_seed([1; 32]).public().node_id()
        );
        assert_eq!(
            decoded.destination,
            IdentitySecret::from_seed([2; 32]).public().node_id()
        );
        assert_eq!(decoded.encoded_bytes, 1248);
        assert_eq!(decoded.reporter, ReporterIncarnation([6; 16]));
        assert_eq!(
            decoded.direction,
            if matches!(vector["name"], "gateway-return" | "gateway-source-return") {
                RelayDirection::DestinationToSource
            } else {
                RelayDirection::SourceToDestination
            }
        );
        let ordinary = vector["name"] == "ordinary";
        let mut historical = history(
            if ordinary { 8 } else { 7 },
            if ordinary {
                IdentityClass::OrdinaryNode
            } else {
                IdentityClass::GatewayNode
            },
        );
        if vector["name"].starts_with("gateway-source-") {
            historical.identities[0].class = IdentityClass::GatewayNode;
            historical.identities[1].class = IdentityClass::OrdinaryNode;
        }
        assert_eq!(decoded.source_class, historical.identities[0].class);
        assert_eq!(decoded.destination_class, historical.identities[1].class);
        assert_eq!(
            decoded.validate_history(Some(&historical)).unwrap(),
            if ordinary {
                RelayBilling::Billable
            } else {
                RelayBilling::GatewayExcluded
            }
        );
        assert!(matches!(
            decoded.validate_history(None),
            Err(UsageError::UnknownMapping)
        ));
    }
    let original = RelayUsage::decode(&sample("historical-epoch")).unwrap();
    let historical = history(7, IdentityClass::GatewayNode);
    let replacement = history(8, IdentityClass::OrdinaryNode);
    assert!(matches!(
        original.validate_history(Some(&replacement)),
        Err(UsageError::UnknownMapping)
    ));
    assert_eq!(
        original.validate_history(Some(&historical)).unwrap(),
        RelayBilling::GatewayExcluded
    );
    let captured = original.canonical().unwrap();
    let mut renewed = historical.clone();
    for publication_version in [8, 9, 100] {
        renewed.version = RosterVersion(publication_version);
        assert_eq!(
            original.validate_history(Some(&renewed)).unwrap(),
            RelayBilling::GatewayExcluded
        );
        assert_eq!(original.canonical().unwrap(), captured);
    }
    // Matching publication version alone cannot authenticate a different billing epoch.
    renewed.version = original.epoch;
    renewed.attribution_epoch = RosterVersion(original.epoch.0 + 1);
    assert!(matches!(
        original.validate_history(Some(&renewed)),
        Err(UsageError::UnknownMapping)
    ));
    let mut missing = historical.clone();
    missing.identities.pop();
    assert!(matches!(
        original.validate_history(Some(&missing)),
        Err(UsageError::UnknownMapping)
    ));
    let mut ambiguous = historical.clone();
    ambiguous.identities.push(ambiguous.identities[0].clone());
    assert!(matches!(
        original.validate_history(Some(&ambiguous)),
        Err(UsageError::UnknownMapping)
    ));
    let wrong_class = history(7, IdentityClass::OrdinaryNode);
    assert!(matches!(
        original.validate_history(Some(&wrong_class)),
        Err(UsageError::UnknownMapping)
    ));
    let mut wrong_scope = historical;
    wrong_scope.scope.issuer = wrong_scope.scope.recipient;
    assert!(matches!(
        original.validate_history(Some(&wrong_scope)),
        Err(UsageError::UnknownMapping)
    ));
}

#[test]
fn usage_report_vectors() {
    for vector in vectors().iter().filter(|v| v["kind"] == "report") {
        let bytes = unhex(vector["bytes"]);
        let decoded = UsageReport::decode(&bytes);
        if vector["decision"] == "reject" {
            assert!(decoded.is_err(), "{}", vector["name"]);
            continue;
        }
        let decoded = decoded.unwrap();
        assert_eq!(decoded.canonical().unwrap(), bytes);
        assert_eq!(
            decoded.sequence,
            if vector["name"] == "multipart-second" {
                2
            } else {
                1
            }
        );
        assert_eq!(
            (
                decoded.start_unix,
                decoded.end_unix,
                decoded.part_index,
                decoded.part_count
            ),
            match vector["name"] {
                "multipart-first" => (100, 200, 0, 2),
                "multipart-second" => (100, 200, 1, 2),
                _ => (100, 200, 0, 1),
            }
        );
        assert_eq!(decoded.computed_digest().unwrap(), decoded.part_digest);
        if let UsageRows::Service(rows) = &decoded.rows
            && vector["name"].starts_with("service-operation-")
        {
            assert_eq!(
                rows[0].operation as u64,
                vector["name"]
                    .rsplit('-')
                    .next()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
            );
            if rows[0].operation != ServiceOperation::UdpSend {
                assert_eq!(rows[0].unit.completed_bytes, 8);
            }
        }
    }
    let original = report("service-report");
    original
        .validate_duplicate(&report("service-report"))
        .unwrap();
    let mut changed = original.clone();
    let UsageRows::Service(rows) = &mut changed.rows else {
        panic!()
    };
    rows[0].unit.completed_bytes += 1;
    assert!(matches!(changed.canonical(), Err(UsageError::Digest)));
    changed.part_digest = changed.computed_digest().unwrap();
    assert!(matches!(
        changed.validate_duplicate(&original),
        Err(UsageError::Conflict)
    ));
    // All envelope metadata participates in the digest; valid changes need a new commitment.
    for index in 0..5 {
        let mut changed = original.clone();
        match index {
            0 => changed.sequence += 1,
            1 => changed.start_unix -= 1,
            2 => changed.end_unix += 1,
            3 => changed.part_count += 1,
            _ => {
                changed.part_count = 2;
                changed.part_index = 1;
            }
        }
        assert!(matches!(changed.canonical(), Err(UsageError::Digest)));
        assert_ne!(changed.computed_digest().unwrap(), original.part_digest);
    }
}

#[test]
fn usage_answer_vectors() {
    for vector in vectors().iter().filter(|v| v["kind"] == "answer") {
        let bytes = unhex(vector["bytes"]);
        let decoded = UsageAnswer::decode(&bytes);
        if vector["decision"] == "reject" {
            assert!(decoded.is_err(), "{}", vector["name"]);
            continue;
        }
        let decoded = decoded.unwrap();
        assert_eq!(decoded.canonical().unwrap(), bytes);
        let pending = report(match vector["name"] {
            "relay-ack" | "unknown-mapping" => "relay-report",
            "multipart-ack" => "multipart-second",
            _ => "service-report",
        });
        assert_eq!(decoded.validate_for(&pending).unwrap(), &decoded.outcome);
    }
    assert_eq!(sample("ack"), sample("duplicate-ack"));
    let ack = UsageAnswer::decode(&sample("ack")).unwrap();
    assert_eq!(
        ack.outcome,
        UsageOutcome::Accepted {
            accepted_through: 1
        }
    );
    let pending = report("service-report");
    for index in 0..6 {
        let mut changed = ack.clone();
        match index {
            0 => changed.reporter = IdentitySecret::from_seed([3; 32]).public(),
            1 => changed.incarnation.0[0] ^= 1,
            2 => changed.profile = UsageProfile::Relay,
            3 => {
                changed.sequence = 2;
                changed.outcome = UsageOutcome::Accepted {
                    accepted_through: 2,
                };
            }
            4 => changed.part_index += 1,
            _ => changed.part_digest[0] ^= 1,
        }
        assert!(matches!(
            changed.validate_for(&pending),
            Err(UsageError::Scope)
        ));
    }
    for (name, expected) in [
        ("conflict-absent", UsageWatermark::Absent),
        ("conflict-malformed", UsageWatermark::Malformed),
        ("conflict-zero", UsageWatermark::Present(0)),
        ("conflict-present", UsageWatermark::Present(3)),
    ] {
        assert_eq!(
            UsageAnswer::decode(&sample(name)).unwrap().outcome,
            UsageOutcome::Conflict(expected)
        );
    }
    let repair = UsageAnswer::decode(&sample("unknown-mapping")).unwrap();
    assert!(matches!(
        repair.validate_for(&report("relay-report")).unwrap(),
        UsageOutcome::UnknownMapping {
            epoch: RosterVersion(7),
            ..
        }
    ));
    for index in 0..3 {
        let mut changed = repair.clone();
        let UsageOutcome::UnknownMapping { scope, epoch, node } = &mut changed.outcome else {
            panic!()
        };
        match index {
            0 => epoch.0 += 1,
            1 => scope.issuer = scope.recipient,
            _ => *node = IdentitySecret::from_seed([3; 32]).public().node_id(),
        }
        assert!(matches!(
            changed.validate_for(&report("relay-report")),
            Err(UsageError::Scope)
        ));
    }
    assert!(matches!(
        ack.validate_for(&report("other-realm-report")),
        Err(UsageError::Scope)
    ));
}

#[test]
fn usage_constructed_bounds_and_scope() {
    let mut value = report("service-report");
    let UsageRows::Service(rows) = &mut value.rows else {
        panic!()
    };
    rows[0].unit.reporter.0[0] ^= 1;
    assert!(matches!(value.computed_digest(), Err(UsageError::Scope)));
    let mut value = report("relay-report");
    let UsageRows::Relay(rows) = &mut value.rows else {
        panic!()
    };
    rows[0].scope.recipient = rows[0].scope.issuer;
    assert!(matches!(value.computed_digest(), Err(UsageError::Scope)));
    let mut value = report("service-report");
    let UsageRows::Service(rows) = &mut value.rows else {
        panic!()
    };
    rows[0].unit.boundary = ServiceBoundary::PublicIngress;
    assert!(matches!(value.computed_digest(), Err(UsageError::Field)));
    let UsageRows::Service(rows) = &mut value.rows else {
        panic!()
    };
    rows[0].operation = ServiceOperation::PublicIngress;
    value.part_digest = value.computed_digest().unwrap();
    assert_eq!(
        UsageReport::decode(&value.canonical().unwrap()).unwrap(),
        value
    );
    let UsageRows::Service(rows) = &mut value.rows else {
        panic!()
    };
    rows[0].unit.boundary = ServiceBoundary::CompletedHostWritesAndSends;
    rows[0].operation = ServiceOperation::EchoReplySend;
    assert_eq!(rows[0].unit.direction, ServiceDirection::ClientToProvider);
    assert!(matches!(value.computed_digest(), Err(UsageError::Field)));

    let mut value = report("service-report");
    let UsageRows::Service(rows) = &mut value.rows else {
        panic!()
    };
    *rows = vec![rows[0].clone(); MAX_IDENTITIES + 1];
    assert!(matches!(
        value.computed_digest(),
        Err(UsageError::Contract(AccountError::Bounds))
    ));
    for parts in [0, MAX_IDENTITIES as u64 + 1] {
        let mut value = report("service-report");
        value.part_count = parts;
        assert!(matches!(value.computed_digest(), Err(UsageError::Field)));
    }
    let oversized = vec![0; MAX_BYTES + 1];
    assert!(UsageReport::decode(&oversized).is_err());
    assert!(UsageAnswer::decode(&oversized).is_err());
    assert!(RelayUsage::decode(&oversized).is_err());
    assert!(ServiceUsage::decode(&oversized).is_err());
}
