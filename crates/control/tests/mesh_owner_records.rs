use std::collections::{BTreeMap, BTreeSet};

use ciborium::value::Value;
use control::envelope::ControlEnvelope;
use control::mesh::*;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

fn public(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

fn state() -> CompactState {
    CompactState {
        network_pub: public(12),
        seq: 7,
        members: BTreeMap::from([
            (
                public(11),
                CompactMember {
                    wg_pub: [4; 32],
                    incarnation: 1,
                },
            ),
            (
                public(14),
                CompactMember {
                    wg_pub: [6; 32],
                    incarnation: 2,
                },
            ),
        ]),
        admins_revision: 1,
        admins: BTreeSet::from([public(14)]),
        evicted_through: BTreeMap::new(),
    }
}

fn sign_payload(api: &str, payload: Vec<u8>, seed: u8, timestamp: u64) -> Vec<u8> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut input = b"nsio-ctrl-v1\0".to_vec();
    input.push(1);
    input.extend_from_slice(&u32::try_from(api.len()).unwrap().to_be_bytes());
    input.extend_from_slice(api.as_bytes());
    input.extend_from_slice(&timestamp.to_be_bytes());
    input.extend_from_slice(&[2; 16]);
    input.push(0);
    input.extend_from_slice(&public(seed));
    input.extend_from_slice(&Sha256::digest(&payload));
    ControlEnvelope {
        v: 1,
        api: api.into(),
        ts: timestamp,
        nonce: [2; 16],
        machine_id: None,
        machine_key_pub: public(seed),
        payload: payload.into(),
        signature: key.sign(&input).to_bytes(),
    }
    .to_cbor()
    .unwrap()
}

fn record(
    api: &str,
    network: [u8; 32],
    incarnation: u64,
    value: u64,
    seed: u8,
    ts: u64,
) -> Vec<u8> {
    let payload = Value::Map(vec![
        (Value::Integer(0.into()), Value::Integer(1.into())),
        (Value::Integer(1.into()), Value::Bytes(network.to_vec())),
        (Value::Integer(2.into()), Value::Integer(incarnation.into())),
        (Value::Integer(3.into()), Value::Integer(value.into())),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&payload, &mut bytes).unwrap();
    sign_payload(api, bytes, seed, ts)
}

#[test]
fn mesh_owner_records_verify_independent_vectors_and_recompute_addresses() {
    let suite: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mesh-v1/vectors.json")).unwrap();
    let vectors: Vec<_> = suite["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| matches!(v["api"].as_str(), Some("mesh.addr" | "mesh.capability")))
        .collect();
    assert_eq!(vectors.len(), 2);
    let state = state();
    for vector in vectors {
        let raw = hex::decode(vector["envelope_hex"].as_str().unwrap()).unwrap();
        let authenticated = AuthenticatedOwnerRecord::verify(&raw, &state).unwrap();
        assert_eq!(authenticated.original().as_ptr(), raw.as_ptr());
        assert_eq!(
            authenticated.digest(),
            &<[u8; 32]>::from(Sha256::digest(&raw))
        );
        assert_eq!(authenticated.network_pub(), &state.network_pub);
        assert_eq!(authenticated.owner_pub(), &public(11));
        assert_eq!(authenticated.incarnation(), 1);
        assert_eq!(authenticated.timestamp(), 1000);
        if vector["api"] == "mesh.addr" {
            assert_eq!(authenticated.kind(), OwnerRecordKind::Address);
            assert_eq!(
                authenticated.contents(),
                &OwnerContents::Address(derive_overlay_addresses(&[4; 32], 7).unwrap())
            );
        } else {
            assert_eq!(authenticated.kind(), OwnerRecordKind::Capability);
            assert_eq!(
                authenticated.contents(),
                &OwnerContents::Capability(CAPABILITY_EXIT)
            );
        }
    }
}

#[test]
fn mesh_owner_records_converge_across_duplicate_and_reordered_versions() {
    let state = state();
    for api in [AddressUpdate::API, CapabilityUpdate::API] {
        let raws = [
            record(api, state.network_pub, 1, 0, 11, 100),
            record(api, state.network_pub, 1, 1, 11, 100),
            record(api, state.network_pub, 1, 0, 11, 99),
        ];
        let expected = if Sha256::digest(&raws[0])[..] > Sha256::digest(&raws[1])[..] {
            0
        } else {
            1
        };
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut winner: Option<AuthenticatedOwnerRecord<'_>> = None;
            for index in order.into_iter().chain(order) {
                let candidate = AuthenticatedOwnerRecord::verify(&raws[index], &state).unwrap();
                if winner
                    .as_ref()
                    .is_none_or(|previous| candidate.supersedes(previous).unwrap())
                {
                    winner = Some(candidate);
                }
            }
            let winner = winner.unwrap();
            assert_eq!(winner.original(), raws[expected]);
            assert!(!winner.supersedes(&winner).unwrap());
            let newest_raw = record(api, state.network_pub, 1, 0, 11, u64::MAX);
            let newest = AuthenticatedOwnerRecord::verify(&newest_raw, &state).unwrap();
            assert!(newest.supersedes(&winner).unwrap());
            assert!(!winner.supersedes(&newest).unwrap());
        }
    }
}

#[test]
fn mesh_owner_records_reject_forgery_revocation_and_cross_scope_replacement() {
    let state = state();
    let raw = record(AddressUpdate::API, state.network_pub, 1, 0, 11, 100);
    let original = AuthenticatedOwnerRecord::verify(&raw, &state).unwrap();
    for field in 0..3 {
        let mut forged = ControlEnvelope::from_cbor(&raw).unwrap();
        match field {
            0 => forged.signature[0] ^= 1,
            1 => forged.machine_key_pub = public(14),
            _ => forged.machine_id = Some("managed".into()),
        }
        assert!(AuthenticatedOwnerRecord::verify(&forged.to_cbor().unwrap(), &state).is_err());
    }
    for (api, network, inc, seed) in [
        (AddressUpdate::API, public(13), 1, 11),
        (AddressUpdate::API, state.network_pub, 2, 11),
        ("mesh.join", state.network_pub, 1, 11),
        (AddressUpdate::API, state.network_pub, 1, 15),
    ] {
        let raw = record(api, network, inc, 0, seed, 100);
        assert!(AuthenticatedOwnerRecord::verify(&raw, &state).is_err());
    }
    for (api, inc, seed) in [(AddressUpdate::API, 2, 14), (CapabilityUpdate::API, 1, 11)] {
        let other_raw = record(api, state.network_pub, inc, 0, seed, 100);
        let other = AuthenticatedOwnerRecord::verify(&other_raw, &state).unwrap();
        assert!(other.supersedes(&original).is_err());
    }
    let mut changed = state.clone();
    changed.network_pub = public(13);
    let other_raw = record(AddressUpdate::API, changed.network_pub, 1, 0, 11, 100);
    assert!(
        AuthenticatedOwnerRecord::verify(&other_raw, &changed)
            .unwrap()
            .supersedes(&original)
            .is_err()
    );
    changed = state.clone();
    changed.members.get_mut(&public(11)).unwrap().wg_pub = [9; 32];
    assert!(
        AuthenticatedOwnerRecord::verify(&raw, &changed)
            .unwrap()
            .supersedes(&original)
            .is_err()
    );
    changed = state.clone();
    changed.members.remove(&public(11));
    changed.evicted_through.insert(public(11), 1);
    assert!(AuthenticatedOwnerRecord::verify(&raw, &changed).is_err());
    changed.members.insert(
        public(11),
        CompactMember {
            wg_pub: [4; 32],
            incarnation: 2,
        },
    );
    assert!(AuthenticatedOwnerRecord::verify(&raw, &changed).is_err());
    let next_raw = record(AddressUpdate::API, changed.network_pub, 2, 0, 11, 100);
    assert!(
        AuthenticatedOwnerRecord::verify(&next_raw, &changed)
            .unwrap()
            .supersedes(&original)
            .is_err()
    );
}

#[test]
fn mesh_owner_records_bound_schema_lengths_and_nested_input() {
    let state = state();
    let raw = record(CapabilityUpdate::API, state.network_pub, 1, 1, 11, 100);
    for end in 0..raw.len() {
        assert!(AuthenticatedOwnerRecord::verify(&raw[..end], &state).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(AuthenticatedOwnerRecord::verify(&trailing, &state).is_err());
    assert!(AuthenticatedOwnerRecord::verify(&vec![0; 1201], &state).is_err());
    for (api, inc, value) in [
        (CapabilityUpdate::API, 1, 2),
        (CapabilityUpdate::API, 0, 1),
        (AddressUpdate::API, 0, 0),
        (AddressUpdate::API, 1, u64::from(u32::MAX) + 1),
    ] {
        assert!(
            AuthenticatedOwnerRecord::verify(
                &record(api, state.network_pub, inc, value, 11, 100),
                &state
            )
            .is_err()
        );
    }
    let envelope = ControlEnvelope::from_cbor(&raw).unwrap();
    let mut payload = envelope.payload.to_vec();
    payload[2] = 2;
    assert!(
        AuthenticatedOwnerRecord::verify(
            &sign_payload(CapabilityUpdate::API, payload, 11, 100),
            &state
        )
        .is_err()
    );
    let mut outer: Value = ciborium::de::from_reader(raw.as_slice()).unwrap();
    let mut nested = Value::Null;
    for _ in 0..32 {
        nested = Value::Array(vec![nested]);
    }
    let Value::Map(ref mut fields) = outer else {
        unreachable!()
    };
    fields.push((Value::Text("future".into()), nested));
    let mut deep = Vec::new();
    ciborium::ser::into_writer(&outer, &mut deep).unwrap();
    assert!(AuthenticatedOwnerRecord::verify(&deep, &state).is_err());
}
