//! Generated DNS TXT discovery vectors (quick-v2 §11.2).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use nsshared_proto::{
    NodeId, NodeRecord,
    discovery::{DnsAnswerError, encode_dns_txt, node_dns_name, verify_dns_answer},
};
use std::net::Ipv6Addr;
use support::vectors::{Vector, load};

fn strings(v: &Vector) -> Vec<String> {
    let count = usize::try_from(v.u64("txt_count")).unwrap();
    (0..count)
        .map(|i| v.get(&format!("txt_{i}")).to_owned())
        .collect()
}

fn verify(v: &Vector) -> Result<NodeRecord, DnsAnswerError> {
    let queried: NodeId = v.get("node_id").parse().unwrap();
    let aaaa: Ipv6Addr = v.get("aaaa").parse().unwrap();
    let txt = strings(v);
    let refs: Vec<&[u8]> = txt.iter().map(String::as_bytes).collect();
    verify_dns_answer(&queried, aaaa, &refs, v.u64("now"))
}

#[test]
fn valid_answers_match_vectors() {
    let vectors = load("dns_txt");
    let mut positives = 0;
    for v in vectors.iter().filter(|v| !v.is_reject()) {
        positives += 1;
        let record = verify(v).unwrap_or_else(|e| panic!("{}: {e}", v.name()));
        assert_eq!(record.as_bytes(), v.hex("record"), "{}", v.name());
        assert_eq!(
            node_dns_name(&record.node_id()),
            format!("{}.n.ns.io", v.get("node_id"))
        );
        if v.name() != "uneven-split" {
            assert_eq!(encode_dns_txt(&record), strings(v), "{}", v.name());
        }
    }
    assert_eq!(positives, 3);
}

#[test]
fn rejected_answers_match_vectors() {
    let vectors = load("dns_txt");
    let mut negatives = 0;
    for v in vectors.iter().filter(|v| v.is_reject()) {
        negatives += 1;
        let error = verify(v).expect_err(v.name());
        let matches = match v.reason() {
            "string_length" => error == DnsAnswerError::StringLength,
            "too_long" => error == DnsAnswerError::TooLong,
            "prefix" => error == DnsAnswerError::Prefix,
            "encoding" => error == DnsAnswerError::Encoding,
            "record" => matches!(error, DnsAnswerError::Record(_)),
            "expired" => matches!(error, DnsAnswerError::Expired(_)),
            "node_id" => error == DnsAnswerError::NodeId,
            "address" => error == DnsAnswerError::Address,
            other => panic!("{}: unknown reason {other}", v.name()),
        };
        assert!(matches, "{}: {} gave {error:?}", v.name(), v.reason());
    }
    assert!(negatives >= 10);
}
