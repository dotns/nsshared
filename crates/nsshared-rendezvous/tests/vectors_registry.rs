//! Generated registry vectors: publish proofs and HRW shard order (quick-v2 §7.1, §7.2,
//! §12.2; rendezvous §5.4).
//!
//! An HRW weight tie cannot be built from real hashes; the `id` tie-break is covered by the
//! unit test in `src/registry.rs`.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use nsshared_rendezvous::{
    directory::Directory,
    error::ErrorCode,
    message::PublishRequest,
    registry,
    transport::{self, Request, Response},
};
use nsshared_wire::{NodeId, NodeRecord, RelayId};
use support::vectors::{Vector, load};

fn directory(v: &Vector) -> Directory {
    match transport::decode_response(v.get("directory")).unwrap() {
        Response::Directory(directory) => directory,
        other => panic!("{}: {other:?}", v.name()),
    }
}

fn ids(v: &Vector, key: &str) -> Vec<u16> {
    v.all(key).iter().map(|id| id.parse().unwrap()).collect()
}

#[test]
fn shard_order_matches_vectors() {
    let vectors = load("registry");
    let dir = directory(&vectors[0]);
    assert_eq!(
        transport::encode_response(&Response::Directory(dir.clone())).unwrap(),
        vectors[0].get("directory")
    );
    let domain = registry::registry_domain(&dir);
    let domain_ids: Vec<u16> = domain.iter().map(|entry| entry.id()).collect();
    assert_eq!(domain_ids, ids(&vectors[0], "domain_id"));
    assert!(dir.relays().len() >= 8 && domain.len() < dir.relays().len());

    let mut nodes = 0;
    for v in vectors.iter().filter(|v| !v.all("order").is_empty()) {
        nodes += 1;
        let name = v.name();
        let node_id = NodeId::derive(&v.hex_array("identity"));
        assert_eq!(node_id.as_bytes(), &v.hex_array::<12>("node_id"), "{name}");
        let entries = ids(v, "entry_id");
        assert_eq!(entries, domain_ids, "{name}");
        for (id, weight) in entries.iter().zip(v.all("weight")) {
            assert_eq!(
                registry::shard_weight(&node_id, *id).to_vec(),
                support::vectors::decode_hex(weight).unwrap(),
                "{name}: entry {id}"
            );
        }
        let order = ids(v, "order");
        assert_eq!(registry::shard_order(&node_id, &domain), order, "{name}");
        assert_eq!(
            registry::shard_relays(&node_id, &domain),
            ids(v, "shard"),
            "{name}"
        );
        let lookup = ids(v, "lookup");
        assert_eq!(registry::lookup_relays(&node_id, &domain), lookup, "{name}");
        for entry in dir.relays() {
            assert_eq!(
                registry::is_responsible(&node_id, entry.id(), &domain),
                lookup.contains(&entry.id()),
                "{name}: entry {}",
                entry.id()
            );
        }
    }
    assert!(nodes >= 4);
}

#[test]
fn publish_proofs_match_vectors() {
    let vectors = load("registry");
    let mut positives = 0;
    for v in vectors
        .iter()
        .filter(|v| !v.is_reject() && v.opt("proof").is_some())
    {
        positives += 1;
        let name = v.name();
        let key = SigningKey::from_bytes(&v.hex_array("seed"));
        let record = NodeRecord::decode(&v.hex("record")).unwrap();
        let nonce = v.hex_array::<32>("nonce");
        let authority = RelayId::parse(v.get("authority")).unwrap();
        let dns = v.bool("dns");
        let now = v.u64("now");

        let message = registry::publish_proof_message(&nonce, &authority, record.as_bytes(), dns);
        assert_eq!(message, v.hex("message"), "{name}");
        assert_eq!(
            &message[message.len() - 33..message.len() - 1],
            v.hex("record_sha256").as_slice()
        );
        VerifyingKey::from_bytes(&v.hex_array("identity"))
            .unwrap()
            .verify_strict(&message, &Signature::from_bytes(&v.hex_array("proof")))
            .unwrap();

        // Encode equals the fixture.
        let request = registry::publish_request(&key, &nonce, &authority, &record, dns);
        assert_eq!(request.proof, v.hex_array::<64>("proof"), "{name}");
        let request = Request::Publish(request);
        assert_eq!(
            transport::encode_request(&request).unwrap(),
            v.get("request"),
            "{name}"
        );

        // Decode then verify.
        let decoded = transport::decode_request(v.get("request")).unwrap();
        assert_eq!(decoded, request, "{name}");
        let Request::Publish(publish) = decoded else {
            panic!("{name}: not a publish");
        };
        let verified = registry::verify_publish(&publish, &nonce, &authority, now).unwrap();
        assert_eq!(verified.dns(), dns);
        assert_eq!(
            verified.node_id().as_bytes(),
            &v.hex_array::<12>("node_id"),
            "{name}"
        );
    }
    assert_eq!(positives, 4);
}

#[test]
fn rejected_publishes_match_vectors() {
    let vectors = load("registry");
    let mut negatives = 0;
    for v in vectors.iter().filter(|v| v.is_reject()) {
        negatives += 1;
        assert!(
            matches!(
                v.reason(),
                "bad_proof" | "record_expired" | "record_bad_signature"
            ),
            "{}: unknown reason {}",
            v.name(),
            v.reason()
        );
        let request = PublishRequest {
            record: v.hex("record"),
            dns: v.bool("dns"),
            proof: v.hex_array("proof"),
        };
        let authority = RelayId::parse(v.get("authority")).unwrap();
        assert_eq!(
            registry::verify_publish(&request, &v.hex_array("nonce"), &authority, v.u64("now")),
            Err(ErrorCode::InvalidMessage),
            "{}",
            v.name()
        );
    }
    assert!(negatives >= 7);
}
