//! Node records: quick-v2 §3.1-§3.2, §11.2 and §12.1-§12.2.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ns_wire::{
    CborError, IssuedAtOverflow, MAX_NODE_RECORD_BYTES, NodeRecord, NodeRecordError,
    NodeRecordFields, RecordExpired, RelayId, RelayIdError, next_issued_at,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

/// The §11.2 TXT `r=` value with `-`/`_` spelled `+`/`/`, so spell checkers skip it as base64.
const VECTOR_R_STANDARD_ALPHABET: &str = "iAJYIMfcKgbeGSnTMYuN6HO/EnAww+4AB/IOBuoPxUBWdFr7WCA1mQwcvVcQmGtwbrxcjN5RmS25H9TVpHZ7q7Z1xEzMOQMaaVW5ABppXvOAgXgYaGtnLWExLnJlbGF5Lm5zLmlvOjUxODIyWECkn2HAyOlMQSYLsKZwSQXVg3BGBKW08g9tslS3ReFfQodZ6hsaJEyCKYY6XCmiAkWY8mXZYSrHunEBmpQfdccP";

fn demo_signer() -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(b"ns-demo-node-v2").into();
    SigningKey::from_bytes(&seed)
}

fn demo_k() -> [u8; 32] {
    STANDARD
        .decode("NZkMHL1XEJhrcG68XIzeUZktuR/U1aR2e6u2dcRMzDk=")
        .unwrap()
        .try_into()
        .unwrap()
}

/// The §11.2 TXT `r=` value exactly as published (unpadded base64url).
fn vector_r() -> String {
    VECTOR_R_STANDARD_ALPHABET
        .replace('+', "-")
        .replace('/', "_")
}

fn vector_bytes() -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(vector_r()).unwrap()
}

fn relay(text: &str) -> RelayId {
    RelayId::parse(text).unwrap()
}

fn vector_fields() -> NodeRecordFields {
    NodeRecordFields {
        wg_key: demo_k(),
        generation: 3,
        issued_at: 1_767_225_600,
        expires: 1_767_830_400,
        relays: vec![relay("hkg-a1.relay.ns.io:51822")],
    }
}

#[test]
fn section_11_2_vector_decodes_and_verifies() {
    let bytes = vector_bytes();
    assert_eq!(bytes.len(), 174);
    let record = NodeRecord::decode(&bytes).unwrap();
    record.verify().unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.encode(record.identity()),
        "x9wqBt4ZKdMxi43oc78ScDDD7gAH8g4G6g_FQFZ0Wvs"
    );
    assert_eq!(record.identity(), &demo_signer().verifying_key().to_bytes());
    assert_eq!(record.wg_key(), &demo_k());
    assert_eq!(record.generation(), 3);
    assert_eq!(record.issued_at(), 1_767_225_600);
    assert_eq!(record.expires(), 1_767_830_400);
    assert_eq!(record.relays(), [relay("hkg-a1.relay.ns.io:51822")]);
    assert_eq!(record.fields(), &vector_fields());
    assert_eq!(record.node_id().to_string(), "5kemem6slxrgyd63rcqa");
    assert_eq!(record.as_bytes(), bytes.as_slice());
    assert_eq!(record.service_period(), 604_800);
}

#[test]
fn section_11_2_vector_resigns_byte_identically() {
    let record = NodeRecord::sign(&demo_signer(), vector_fields()).unwrap();
    assert_eq!(record.as_bytes(), vector_bytes().as_slice());
    assert_eq!(record, NodeRecord::decode(&vector_bytes()).unwrap());
}

/// Canonical element encodings of the §11.2 vector, for building malformed inputs.
struct Parts {
    head: Vec<u8>,
    items: Vec<Vec<u8>>,
}

impl Parts {
    fn vector() -> Self {
        let bytes = vector_bytes();
        let i = bytes[2..36].to_vec();
        let k = bytes[36..70].to_vec();
        Self {
            head: vec![0x88],
            items: vec![
                vec![0x02],
                i,
                k,
                vec![0x03],
                bytes[71..76].to_vec(),
                bytes[76..81].to_vec(),
                bytes[81..108].to_vec(),
                bytes[108..].to_vec(),
            ],
        }
    }

    fn with(mut self, index: usize, item: &[u8]) -> Self {
        self.items[index] = item.to_vec();
        self
    }

    fn build(&self) -> Vec<u8> {
        let mut out = self.head.clone();
        for item in &self.items {
            out.extend_from_slice(item);
        }
        out
    }

    fn decode(&self) -> Result<NodeRecord, NodeRecordError> {
        NodeRecord::decode(&self.build())
    }
}

fn cbor(error: CborError) -> Result<NodeRecord, NodeRecordError> {
    Err(NodeRecordError::Cbor(error))
}

fn bytes_item(bytes: &[u8]) -> Vec<u8> {
    let mut item = if bytes.len() < 24 {
        vec![0x40 | bytes.len() as u8]
    } else {
        vec![0x58, bytes.len() as u8]
    };
    item.extend_from_slice(bytes);
    item
}

fn relays_item(relays: &[&[u8]]) -> Vec<u8> {
    let mut item = vec![0x80 | relays.len() as u8];
    for text in relays {
        if text.len() < 24 {
            item.push(0x60 | text.len() as u8);
        } else {
            item.extend_from_slice(&[0x78, text.len() as u8]);
        }
        item.extend_from_slice(text);
    }
    item
}

#[test]
fn parts_rebuild_the_vector() {
    assert_eq!(Parts::vector().build(), vector_bytes());
}

#[test]
fn refutation_non_shortest_integer() {
    assert_eq!(
        Parts::vector().with(3, &[0x18, 0x03]).decode(),
        cbor(CborError::NonShortest)
    );
    let mut issued = vec![0x1b, 0, 0, 0, 0];
    issued.extend_from_slice(&1_767_225_600_u32.to_be_bytes());
    assert_eq!(
        Parts::vector().with(4, &issued).decode(),
        cbor(CborError::NonShortest)
    );
}

#[test]
fn refutation_non_shortest_length() {
    let mut parts = Parts::vector();
    parts.head = vec![0x98, 0x08];
    assert_eq!(parts.decode(), cbor(CborError::NonShortest));
    let mut relays = Parts::vector().items[6].clone();
    relays.splice(0..1, [0x98, 0x01]);
    assert_eq!(
        Parts::vector().with(6, &relays).decode(),
        cbor(CborError::NonShortest)
    );
}

#[test]
fn refutation_indefinite_length() {
    let mut parts = Parts::vector();
    parts.head = vec![0x9f];
    parts.items.push(vec![0xff]);
    assert_eq!(parts.decode(), cbor(CborError::IndefiniteLength));
    let mut identity = vec![0x5f];
    identity.extend_from_slice(&Parts::vector().items[1]);
    identity.push(0xff);
    assert_eq!(
        Parts::vector().with(1, &identity).decode(),
        cbor(CborError::IndefiniteLength)
    );
}

#[test]
fn refutation_float() {
    assert_eq!(
        Parts::vector().with(3, &[0xf9, 0x42, 0x00]).decode(),
        cbor(CborError::Float)
    );
    assert_eq!(
        Parts::vector()
            .with(3, &[0xfb, 0x40, 0x08, 0, 0, 0, 0, 0, 0])
            .decode(),
        cbor(CborError::Float)
    );
}

#[test]
fn refutation_tag() {
    let mut tagged = vec![0xc1];
    tagged.extend_from_slice(&Parts::vector().items[4]);
    assert_eq!(
        Parts::vector().with(4, &tagged).decode(),
        cbor(CborError::Tag)
    );
}

#[test]
fn refutation_map() {
    assert_eq!(
        Parts::vector().with(6, &[0xa0]).decode(),
        cbor(CborError::Map)
    );
}

#[test]
fn refutation_negative_integer() {
    assert_eq!(
        Parts::vector().with(3, &[0x22]).decode(),
        cbor(CborError::NegativeInteger)
    );
}

#[test]
fn refutation_reserved_additional_information() {
    assert_eq!(
        Parts::vector().with(3, &[0x1c]).decode(),
        cbor(CborError::Reserved)
    );
}

#[test]
fn refutation_unsupported_simple_value() {
    assert_eq!(
        Parts::vector().with(3, &[0xf7]).decode(),
        cbor(CborError::UnsupportedSimple)
    );
}

#[test]
fn refutation_unexpected_type() {
    assert_eq!(
        Parts::vector().with(6, &[0xf6]).decode(),
        cbor(CborError::UnexpectedType)
    );
    let mut k_as_text = Parts::vector().items[2].clone();
    k_as_text[0] = 0x78;
    assert_eq!(
        Parts::vector().with(2, &k_as_text).decode(),
        cbor(CborError::UnexpectedType)
    );
    assert_eq!(
        Parts::vector().with(6, &[0x81, 0x01]).decode(),
        cbor(CborError::UnexpectedType)
    );
}

#[test]
fn refutation_wrong_arity() {
    let mut short = Parts::vector();
    short.head = vec![0x87];
    short.items.pop();
    assert_eq!(
        short.decode(),
        cbor(CborError::ArrayLength {
            expected: 8,
            actual: 7
        })
    );
    let mut long = Parts::vector();
    long.head = vec![0x89];
    long.items.push(vec![0xf6]);
    assert_eq!(
        long.decode(),
        cbor(CborError::ArrayLength {
            expected: 8,
            actual: 9
        })
    );
}

#[test]
fn refutation_wrong_byte_string_length() {
    assert_eq!(
        Parts::vector().with(1, &bytes_item(&[7; 31])).decode(),
        cbor(CborError::StringLength {
            expected: 32,
            actual: 31
        })
    );
    assert_eq!(
        Parts::vector().with(7, &bytes_item(&[7; 65])).decode(),
        cbor(CborError::StringLength {
            expected: 64,
            actual: 65
        })
    );
}

#[test]
fn refutation_invalid_utf8() {
    assert_eq!(
        Parts::vector()
            .with(6, &relays_item(&[b"a\xff.example:1"]))
            .decode(),
        cbor(CborError::InvalidUtf8)
    );
}

#[test]
fn refutation_truncated() {
    let bytes = vector_bytes();
    assert_eq!(
        NodeRecord::decode(&bytes[..bytes.len() - 1]),
        cbor(CborError::Truncated)
    );
    assert_eq!(NodeRecord::decode(&[]), cbor(CborError::Truncated));
}

#[test]
fn refutation_trailing_bytes() {
    let mut bytes = vector_bytes();
    bytes.push(0x00);
    assert_eq!(NodeRecord::decode(&bytes), cbor(CborError::TrailingBytes));
}

#[test]
fn refutation_oversize() {
    let mut bytes = vector_bytes();
    bytes.resize(MAX_NODE_RECORD_BYTES + 1, 0);
    assert_eq!(
        NodeRecord::decode(&bytes),
        Err(NodeRecordError::TooLarge(MAX_NODE_RECORD_BYTES + 1))
    );
}

#[test]
fn refutation_unknown_version() {
    for (item, version) in [
        (&[0x00][..], 0),
        (&[0x01], 1),
        (&[0x03], 3),
        (&[0x18, 0x18], 24),
    ] {
        assert_eq!(
            Parts::vector().with(0, item).decode(),
            Err(NodeRecordError::Version(version))
        );
    }
}

#[test]
fn refutation_too_many_relays() {
    let texts: Vec<&[u8]> = vec![b"a.example:1"; 5];
    assert_eq!(
        Parts::vector().with(6, &relays_item(&texts)).decode(),
        Err(NodeRecordError::TooManyRelays(5))
    );
    let mut fields = vector_fields();
    fields.relays = vec![relay("a.example:1"); 5];
    assert_eq!(
        NodeRecord::sign(&demo_signer(), fields),
        Err(NodeRecordError::TooManyRelays(5))
    );
}

#[test]
fn refutation_bad_relay_id() {
    for (text, error) in [
        (&b"Relay.Example:51822"[..], RelayIdError::DnsName),
        (b"relay.example:051822", RelayIdError::Port),
        (b"192.000.2.10:51822", RelayIdError::Ipv4),
        (b"[2001:0db8::10]:1", RelayIdError::Ipv6),
        (b"relay-a", RelayIdError::Syntax),
        (b"", RelayIdError::Length),
    ] {
        assert_eq!(
            Parts::vector().with(6, &relays_item(&[text])).decode(),
            Err(NodeRecordError::RelayId(error))
        );
    }
}

#[test]
fn refutation_bad_signature() {
    let mut signature = Parts::vector().items[7].clone();
    signature[10] ^= 1;
    assert_eq!(
        Parts::vector().with(7, &signature).decode(),
        Err(NodeRecordError::BadSignature)
    );
    let mut k = Parts::vector().items[2].clone();
    k[2] ^= 1;
    assert_eq!(
        Parts::vector().with(2, &k).decode(),
        Err(NodeRecordError::BadSignature)
    );
    let other = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    assert_eq!(
        Parts::vector().with(1, &bytes_item(&other)).decode(),
        Err(NodeRecordError::BadSignature)
    );
}

#[test]
fn refutation_non_canonical_signature_scalar() {
    // A non-reduced scalar S + L must be rejected (RFC 8032 §5.1.7).
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut signature = Parts::vector().items[7].clone();
    let mut carry = 0_u16;
    for (byte, l) in signature[34..].iter_mut().zip(L) {
        let sum = u16::from(*byte) + u16::from(l) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    assert_eq!(
        Parts::vector().with(7, &signature).decode(),
        Err(NodeRecordError::BadSignature)
    );
}

#[test]
fn refutation_small_order_identity() {
    // The identity point and a point of order 4.
    let mut order_four = [0_u8; 32];
    order_four[31] = 0x80;
    let mut identity_point = [0_u8; 32];
    identity_point[0] = 1;
    for point in [identity_point, order_four] {
        assert!(VerifyingKey::from_bytes(&point).unwrap().is_weak());
        assert_eq!(
            Parts::vector().with(1, &bytes_item(&point)).decode(),
            Err(NodeRecordError::WeakIdentity)
        );
    }
}

#[test]
fn refutation_invalid_identity_point() {
    let point = (2_u8..=255)
        .map(|y| {
            let mut point = [0_u8; 32];
            point[0] = y;
            point
        })
        .find(|point| VerifyingKey::from_bytes(point).is_err())
        .unwrap();
    assert_eq!(
        Parts::vector().with(1, &bytes_item(&point)).decode(),
        Err(NodeRecordError::InvalidIdentity)
    );
}

#[test]
fn refutation_expires_not_after_issued_at() {
    let issued = Parts::vector().items[4].clone();
    for expires in [issued.clone(), vec![0x00]] {
        assert!(matches!(
            Parts::vector().with(5, &expires).decode(),
            Err(NodeRecordError::ExpiresNotAfterIssued { .. })
        ));
    }
    let mut fields = vector_fields();
    fields.expires = fields.issued_at;
    assert_eq!(
        NodeRecord::sign(&demo_signer(), fields),
        Err(NodeRecordError::ExpiresNotAfterIssued {
            issued_at: 1_767_225_600,
            expires: 1_767_225_600
        })
    );
}

#[test]
fn refutation_zero_generation() {
    assert_eq!(
        Parts::vector().with(3, &[0x00]).decode(),
        Err(NodeRecordError::ZeroGeneration)
    );
    let mut fields = vector_fields();
    fields.generation = 0;
    assert_eq!(
        NodeRecord::sign(&demo_signer(), fields),
        Err(NodeRecordError::ZeroGeneration)
    );
}

#[test]
fn expiry_is_exclusive() {
    let record = NodeRecord::decode(&vector_bytes()).unwrap();
    assert!(!record.is_expired(1_767_830_399));
    assert_eq!(record.check_not_expired(1_767_830_399), Ok(()));
    assert!(record.is_expired(1_767_830_400));
    assert_eq!(
        record.check_not_expired(1_767_830_400),
        Err(RecordExpired {
            expires: 1_767_830_400,
            now: 1_767_830_400
        })
    );
}

#[test]
fn refutation_service_period_too_long() {
    // The §11.2 vector already has the longest valid period, 604800 s.
    let mut fields = vector_fields();
    fields.expires += 1;
    assert_eq!(
        NodeRecord::sign(&demo_signer(), fields),
        Err(NodeRecordError::ServicePeriodTooLong(604_801))
    );

    // A correctly signed 604801 s record is rejected by decode, as is one whose signature
    // no longer matches: the period is checked before the signature.
    let mut expires = vec![0x1a];
    expires.extend_from_slice(&1_767_830_401_u32.to_be_bytes());
    let mut parts = Parts::vector().with(5, &expires);
    assert_eq!(
        parts.decode(),
        Err(NodeRecordError::ServicePeriodTooLong(604_801))
    );
    let mut message = b"ns/node-record/v2\x87".to_vec();
    for item in &parts.items[..7] {
        message.extend_from_slice(item);
    }
    let signature = demo_signer().sign(&message).to_bytes();
    parts.items[7] = bytes_item(&signature);
    assert_eq!(
        parts.decode(),
        Err(NodeRecordError::ServicePeriodTooLong(604_801))
    );
}

#[test]
fn resign_when_less_than_half_remains() {
    let mut fields = vector_fields();
    fields.issued_at = 1_000;
    fields.expires = 1_100;
    let record = NodeRecord::sign(&demo_signer(), fields).unwrap();
    assert!(!record.needs_resign(0));
    assert!(!record.needs_resign(1_050));
    assert!(record.needs_resign(1_051));
    assert!(record.needs_resign(1_100));
    assert!(record.needs_resign(u64::MAX));
}

#[test]
fn next_issued_at_is_strictly_increasing() {
    assert_eq!(next_issued_at(5, None), Ok(5));
    assert_eq!(next_issued_at(5, Some(10)), Ok(11));
    assert_eq!(next_issued_at(20, Some(10)), Ok(20));
    assert_eq!(next_issued_at(11, Some(10)), Ok(11));
    assert_eq!(
        next_issued_at(0, Some(u64::MAX)),
        Err(IssuedAtOverflow(u64::MAX))
    );
}

const RELAY_POOL: [&str; 5] = [
    "hkg-a1.relay.ns.io:51822",
    "192.0.2.10:51822",
    "[2001:db8::10]:443",
    "a.b:1",
    "relay.example:65535",
];

prop_compose! {
    fn arb_fields()(
        wg_key in any::<[u8; 32]>(),
        generation in 1_u64..,
        issued_at in 0_u64..u64::MAX,
        period in 1_u64..=604_800,
        relays in prop::collection::vec(0..RELAY_POOL.len(), 0..=4),
    ) -> NodeRecordFields {
        NodeRecordFields {
            wg_key,
            generation,
            issued_at,
            expires: issued_at.saturating_add(period),
            relays: relays.into_iter().map(|index| relay(RELAY_POOL[index])).collect(),
        }
    }
}

proptest! {
    #[test]
    fn record_round_trip(seed in any::<[u8; 32]>(), fields in arb_fields()) {
        let signer = SigningKey::from_bytes(&seed);
        let record = NodeRecord::sign(&signer, fields.clone()).unwrap();
        prop_assert!(record.as_bytes().len() <= MAX_NODE_RECORD_BYTES);
        let decoded = NodeRecord::decode(record.as_bytes()).unwrap();
        prop_assert_eq!(decoded.fields(), &fields);
        prop_assert_eq!(decoded.as_bytes(), record.as_bytes());
        prop_assert_eq!(&decoded, &record);
        prop_assert_eq!(NodeRecord::sign(&signer, fields).unwrap(), record);
    }

    #[test]
    fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = NodeRecord::decode(&bytes);
    }

    #[test]
    fn single_byte_corruption_is_rejected(index in 0_usize..174, flip in 1_u8..) {
        let mut bytes = vector_bytes();
        bytes[index] ^= flip;
        prop_assert!(NodeRecord::decode(&bytes).is_err());
    }
}
