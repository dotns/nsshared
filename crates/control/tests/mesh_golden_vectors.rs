use std::collections::BTreeSet;

use control::envelope::ControlEnvelope;
use control::mesh::*;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct Suite {
    version: u64,
    vectors: Vec<Vector>,
}
#[derive(Deserialize)]
struct Vector {
    name: String,
    api: String,
    kind: String,
    payload_hex: String,
    envelope_hex: String,
    signing_input_hex: String,
}
fn suite() -> Suite {
    serde_json::from_str(include_str!("fixtures/mesh-v1/vectors.json")).unwrap()
}
fn public(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

#[test]
fn mesh_fixed_vectors_cover_every_api_and_preserve_original_envelopes() {
    let suite = suite();
    assert_eq!(suite.version, 1);
    assert_eq!(suite.vectors.len(), 27);
    let mut apis = BTreeSet::new();
    for vector in &suite.vectors {
        let payload = hex::decode(&vector.payload_hex).unwrap();
        apis.insert(vector.api.as_str());
        if matches!(vector.kind.as_str(), "hello" | "unsigned") {
            assert!(vector.envelope_hex.is_empty());
            continue;
        }
        let bytes = hex::decode(&vector.envelope_hex).unwrap();
        let envelope = ControlEnvelope::from_cbor(&bytes).unwrap();
        assert_eq!(envelope.to_cbor().unwrap(), bytes, "{}", vector.name);
        assert_eq!(envelope.payload.as_ref(), payload);
        assert_eq!(envelope.api, vector.api);
        assert_eq!(envelope.ts, 1000);
        assert_eq!(envelope.nonce, [2; 16]);
        assert_eq!(envelope.machine_id, None);
        let input = hex::decode(&vector.signing_input_hex).unwrap();
        VerifyingKey::from_bytes(&envelope.machine_key_pub)
            .unwrap()
            .verify_strict(&input, &Signature::from_bytes(&envelope.signature))
            .unwrap();
        if vector.kind == "response" {
            verify_response(&envelope, 1000, &public(13)).unwrap();
            assert!(verify_request(&envelope, 1000).is_err());
        } else if vector.kind == "managed" {
            envelope.verify_request(1000).unwrap();
            assert!(verify_request(&envelope, 1000).is_err());
        } else {
            verify_request(&envelope, 1000).unwrap();
            assert!(verify_response(&envelope, 1000, &public(11)).is_err());
        }
        for field in 0..6 {
            let mut invalid = envelope.clone();
            match field {
                0 => invalid.api.push('x'),
                1 => invalid.ts += 1,
                2 => invalid.nonce[0] ^= 1,
                3 => invalid.machine_key_pub[0] ^= 1,
                4 => invalid.payload[0] ^= 1,
                _ => invalid.machine_id = Some("managed-identity".into()),
            }
            if vector.kind == "response" {
                assert!(invalid.verify_response(1000, &public(13)).is_err());
            } else {
                assert!(invalid.verify_request(1000).is_err());
            }
        }
        if vector.kind != "managed" {
            assert!(encode_udp(&bytes).unwrap().len() <= 1200);
            assert!(encode_wss(WssFrame::Control(&bytes), 1500).unwrap().len() <= 1200);
        }
    }
    assert_eq!(
        apis,
        BTreeSet::from([
            "",
            "info.get",
            "mesh.register",
            "mesh.registered",
            "mesh.cookie",
            "mesh.join",
            "mesh.accept",
            "mesh.resolved",
            "mesh.deny",
            "mesh.evict",
            "mesh.admins",
            "mesh.sequenced",
            "mesh.vouch",
            "mesh.unbind",
            "mesh.commit.query",
            "mesh.commit.ack",
            "mesh.commit.result",
            "mesh.restore.begin",
            "mesh.restore.chunk",
            "mesh.restore.finish",
        ])
    );
}

#[test]
fn mesh_fixed_payloads_decode_with_semantic_and_internal_signature_checks() {
    for vector in suite().vectors {
        let bytes = hex::decode(&vector.payload_hex).unwrap();
        macro_rules! decode {
            ($ty:ty) => {{
                let value = <$ty>::decode(&bytes).unwrap();
                assert_eq!(value.encode().unwrap(), bytes, "{}", vector.name);
                value
            }};
        }
        match vector.api.as_str() {
            "mesh.register" => {
                let value = decode!(Register);
                assert_eq!(value.network_pub, public(12));
                assert_eq!(
                    value.wg_pub,
                    [if vector.name == "register-vouch" {
                        6
                    } else {
                        4
                    }; 32]
                );
                assert_eq!(value.member_incarnation, 1);
                if vector.name == "register-create" {
                    assert_eq!(value.allocate_pin.as_ref().unwrap().ttl_secs, 600);
                    value.verify_network_proof(&[2; 16], &public(11)).unwrap();
                } else {
                    assert_eq!(value.allocate_pin, None);
                    assert_eq!(value.network_proof, None);
                }
                if vector.name == "register-vouch" {
                    let original =
                        ControlEnvelope::from_cbor(value.vouch.as_ref().unwrap()).unwrap();
                    let credential = Vouch::verify_historical(&original).unwrap();
                    assert_eq!(credential.member_wg, value.wg_pub);
                    assert_eq!(credential.network_pub, value.network_pub);
                } else {
                    assert_eq!(value.vouch, None);
                }
            }
            "mesh.registered" => {
                let value = decode!(Registered);
                assert_eq!(value.nonce, [2; 16]);
                assert_eq!(value.network_pub, public(12));
                let genesis = vector.name == "registered-genesis";
                assert_eq!(value.admins, if genesis { vec![] } else { vec![5; 20] });
                assert_eq!(value.admins_revision, if genesis { 0 } else { 1 });
                assert_eq!(value.latest_seq, if genesis { 0 } else { 7 });
                assert_eq!(
                    value.observed_addr,
                    ObservedEndpoint {
                        ip: vec![192, 0, 2, 1],
                        port: 51900
                    }
                );
                assert_eq!(value.relay_key, public(13));
                assert_eq!(value.ttl_secs, 90);
                assert_eq!(value.slot_status, 0);
                if vector.name == "registered-pin" {
                    assert_eq!(value.status, Registered::REGISTERED);
                    assert_eq!(
                        value.pin.as_ref().unwrap(),
                        &PinInfo {
                            value: "KX-83920174".into(),
                            expires_in_secs: 600
                        }
                    );
                    assert_eq!(value.anchor, None);
                } else if !genesis {
                    assert_eq!(value.status, Registered::RECOVERING);
                    assert_eq!(value.pin, None);
                    assert_eq!(
                        value.anchor.as_ref().unwrap(),
                        &AnchorChallenge {
                            anchor_seq: 7,
                            state_digest: [3; 32],
                            format_version: 1
                        }
                    );
                }
                if genesis {
                    assert_eq!(value.status, Registered::REGISTERED);
                    assert_eq!(value.pin, None);
                    assert_eq!(value.anchor, None);
                    let receipt =
                        CommitReceipt::decode(value.creation_receipt.as_ref().unwrap()).unwrap();
                    receipt.verify(&public(13)).unwrap();
                    assert_eq!(receipt.seq, 0);
                    assert_eq!(receipt.network_pub, value.network_pub);
                } else {
                    assert_eq!(value.creation_receipt, None);
                }
            }
            "mesh.cookie" => assert_eq!(
                decode!(Cookie),
                Cookie {
                    nonce: [2; 16],
                    cookie: [6; 16]
                }
            ),
            "mesh.join" => {
                assert_eq!(
                    decode!(Join),
                    Join {
                        pin: "KX-83920174".into(),
                        joiner_wg: [4; 32],
                        capabilities: 1,
                        expires_at: 1120,
                        cookie: (vector.name == "join-cookie").then_some([6; 16]),
                        request_id: [2; 16]
                    }
                );
            }
            "mesh.accept" => {
                let envelope =
                    ControlEnvelope::from_cbor(&hex::decode(vector.envelope_hex).unwrap()).unwrap();
                let value = decode!(Accept);
                assert_eq!(Accept::verify_historical(&envelope).unwrap(), value);
                assert_eq!(value.network_name, "home");
                assert_eq!(value.approver_wg, [4; 32]);
                assert_eq!(value.member_incarnation, 1);
                assert_eq!(value.capabilities, 1);
                let addrs = OverlayAddresses {
                    v4: [10, 1, 2, 3],
                    v4_salt: 0,
                    v6: [0xfd; 16],
                };
                assert_eq!(value.approver_addrs, addrs);
                assert_eq!(value.joiner_addrs, addrs);
                value
                    .verify_join(
                        &JoinBinding {
                            network_pub: public(12),
                            joiner_id: [5; 20],
                            joiner_wg: [6; 32],
                            request_id: [2; 16],
                            deadline: 1120,
                        },
                        1000,
                    )
                    .unwrap();
                assert_eq!(value.added_at, 1000);
                assert_eq!(value.expires_at, 1060);
            }
            "mesh.resolved" => assert_eq!(
                decode!(Resolved),
                Resolved {
                    network_pub: public(12),
                    request_id: [2; 16],
                    joiner_id: [5; 20],
                    approver_id: [7; 20],
                    seq: 7
                }
            ),
            "mesh.deny" => assert_eq!(
                decode!(Deny),
                Deny {
                    request_id: [2; 16],
                    joiner_id: [5; 20],
                    reason: "declined".into()
                }
            ),
            "mesh.vouch" => {
                let envelope =
                    ControlEnvelope::from_cbor(&hex::decode(vector.envelope_hex).unwrap()).unwrap();
                assert_eq!(Vouch::verify_historical(&envelope).unwrap(), decode!(Vouch));
            }
            "mesh.unbind" => assert_eq!(decode!(Unbind).network_pub, public(12)),
            "mesh.evict" | "mesh.admins" => {
                let value = decode!(SignedManagementRecord);
                value.verify().unwrap();
                assert_eq!(value.network_pub, public(12));
                assert_eq!(value.author_pub, public(11));
                assert_eq!(value.op_id, [2; 16]);
                assert_eq!((value.issued_at, value.expires_at), (1000, 1060));
                if vector.api == "mesh.evict" {
                    assert_eq!(value.kind, SignedManagementRecord::EVICT);
                    assert_eq!(
                        Eviction::decode(&value.body).unwrap(),
                        Eviction {
                            member_id: [5; 20],
                            incarnation: 1,
                            reason: "removed".into(),
                            member_pub: [6; 32]
                        }
                    );
                } else {
                    assert_eq!(value.kind, SignedManagementRecord::ADMINS);
                    assert_eq!(
                        Admins::decode(&value.body).unwrap(),
                        Admins {
                            admins: vec![5; 20],
                            admins_revision: 2
                        }
                    );
                }
            }
            "mesh.sequenced" => {
                let value = decode!(Sequenced);
                assert_eq!(value.network_pub, public(12));
                assert_eq!(value.seq, 7);
                SignedManagementRecord::decode(&value.record)
                    .unwrap()
                    .verify()
                    .unwrap();
            }
            "mesh.commit.query" => assert_eq!(
                decode!(CommitQuery),
                CommitQuery {
                    network_pub: public(12),
                    op_id: [2; 16],
                    record_digest: [3; 32]
                }
            ),
            "mesh.commit.ack" => assert_eq!(
                decode!(CommitAck),
                CommitAck {
                    network_pub: public(12),
                    op_id: [2; 16],
                    record_digest: [3; 32],
                    seq: 7
                }
            ),
            "mesh.commit.result" => {
                let value = decode!(CommitResult);
                assert_eq!(value.network_pub, public(12));
                assert_eq!(value.op_id, [2; 16]);
                assert_eq!(value.author_pub, public(11));
                assert_eq!(value.record_digest, [3; 32]);
                if vector.name == "commit-result" {
                    assert_eq!(value.status, CommitResult::COMMITTED);
                    assert_eq!(value.seq, Some(7));
                    value.receipt.unwrap().verify(&public(13)).unwrap();
                } else {
                    assert_eq!(
                        value.status,
                        if vector.name == "commit-unavailable" {
                            1
                        } else {
                            2
                        }
                    );
                    assert_eq!(value.seq, None);
                    assert_eq!(value.receipt, None);
                }
            }
            "mesh.restore.begin" => decode!(RestoreBegin)
                .verify_proof(&public(11), &[4; 32])
                .unwrap(),
            "mesh.restore.chunk" => assert_eq!(
                decode!(RestoreChunk),
                RestoreChunk {
                    network_pub: public(12),
                    request_id: [2; 16],
                    anchor_seq: 7,
                    state_digest: [3; 32],
                    index: 0,
                    bytes: vec![8; 512]
                }
            ),
            "mesh.restore.finish" => assert_eq!(
                decode!(RestoreFinish),
                RestoreFinish {
                    network_pub: public(12),
                    request_id: [2; 16],
                    anchor_seq: 7,
                    state_digest: [3; 32]
                }
            ),
            "" => {
                let value = decode!(WssHello);
                assert_eq!(value.challenge, [2; 32]);
                assert_eq!(value.origin, "wss://relay.example:9443");
                assert_eq!(value.signer_pub, public(11));
                assert_eq!(value.wg_pub, [4; 32]);
                VerifyingKey::from_bytes(&value.signer_pub)
                    .unwrap()
                    .verify_strict(
                        &value.signing_input().unwrap(),
                        &Signature::from_bytes(&value.signature),
                    )
                    .unwrap();
            }
            "info.get" => (),
            other => panic!("missing fixture decoder: {other}"),
        }
    }
}
