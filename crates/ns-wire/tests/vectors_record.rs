//! Generated NodeRecord vectors (quick-v2 §3.1-§3.2, §12.1-§12.3).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ns_wire::{CborError, NodeRecord, NodeRecordError, NodeRecordFields, RelayId};
use support::vectors::load;

#[test]
fn valid_records_match_vectors() {
    let vectors = load("node_records");
    let mut positives = 0;
    for v in vectors.iter().filter(|v| !v.is_reject()) {
        positives += 1;
        let signer = SigningKey::from_bytes(&v.hex_array("seed"));
        assert_eq!(
            signer.verifying_key().to_bytes(),
            v.hex_array::<32>("identity")
        );
        let relays = v.all("relay");
        assert_eq!(relays.len(), usize::try_from(v.u64("relay_count")).unwrap());
        let fields = NodeRecordFields {
            wg_key: v.hex_array("wg_key"),
            generation: v.u64("gen"),
            issued_at: v.u64("issued_at"),
            expires: v.u64("expires"),
            relays: relays.iter().map(|r| RelayId::parse(r).unwrap()).collect(),
        };
        let encoded = v.hex("encoded");
        assert_eq!(
            encoded.len(),
            usize::try_from(v.u64("encoded_len")).unwrap()
        );

        // Encode equals the fixture, and the fixture signature covers the fixture message.
        let signed = NodeRecord::sign(&signer, fields.clone()).unwrap();
        assert_eq!(signed.as_bytes(), encoded.as_slice(), "{}", v.name());
        assert_eq!(signed.signature(), &v.hex_array::<64>("signature"));
        VerifyingKey::from_bytes(&v.hex_array("identity"))
            .unwrap()
            .verify_strict(
                &v.hex("message"),
                &Signature::from_bytes(signed.signature()),
            )
            .unwrap();

        // Decode then re-encode equals the fixture.
        let decoded = NodeRecord::decode(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), encoded.as_slice(), "{}", v.name());
        assert_eq!(decoded.fields(), &fields);
        assert_eq!(decoded.identity(), &v.hex_array::<32>("identity"));
        assert_eq!(decoded, signed);
    }
    assert!(positives >= 10);
}

#[test]
fn rejected_records_match_vectors() {
    let vectors = load("node_records");
    let mut negatives = 0;
    for v in vectors.iter().filter(|v| v.is_reject()) {
        negatives += 1;
        let encoded = v.hex("encoded");
        let result = NodeRecord::decode(&encoded);
        let name = v.name();
        match v.reason() {
            "service_period" => assert!(
                matches!(result, Err(NodeRecordError::ServicePeriodTooLong(_))),
                "{name}: {result:?}"
            ),
            "bad_signature" => assert_eq!(result, Err(NodeRecordError::BadSignature), "{name}"),
            "non_canonical" | "array_arity" => {
                assert!(
                    matches!(result, Err(NodeRecordError::Cbor(_))),
                    "{name}: {result:?}"
                );
            }
            "trailing_bytes" => {
                assert_eq!(
                    result,
                    Err(NodeRecordError::Cbor(CborError::TrailingBytes)),
                    "{name}"
                );
            }
            "version" => assert!(matches!(result, Err(NodeRecordError::Version(_))), "{name}"),
            "zero_generation" => assert_eq!(result, Err(NodeRecordError::ZeroGeneration), "{name}"),
            "expires_not_after_issued" => assert!(
                matches!(result, Err(NodeRecordError::ExpiresNotAfterIssued { .. })),
                "{name}"
            ),
            "too_many_relays" => {
                assert_eq!(result, Err(NodeRecordError::TooManyRelays(5)), "{name}")
            }
            "too_large" => assert!(
                matches!(result, Err(NodeRecordError::TooLarge(_))),
                "{name}"
            ),
            "weak_identity" => assert_eq!(result, Err(NodeRecordError::WeakIdentity), "{name}"),
            other => panic!("{name}: unknown reason {other}"),
        }
    }
    assert!(negatives >= 15);
}
