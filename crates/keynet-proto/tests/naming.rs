use blake2::{
    Blake2sMac,
    digest::{KeyInit, Mac, consts::U3},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use keynet_proto::{
    AliasCandidateError, AliasPool, LabelError, NameOperation, NameRecord, NameRecordDecodeError,
    NameRecordSignatureError, NameRecordValidationError, OwnerSignedNameRecord, alias_candidate,
    alias_candidates, alias_h22, identity_label, normalize_label, validate_label,
};
use std::{collections::BTreeMap, fs, path::PathBuf};

fn signer(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn signed_record(op: NameOperation) -> NameRecord {
    let network_signer = signer(3);
    let owner_signer = signer(7);
    let mut record = NameRecord {
        ver: 1,
        network_id: network_signer.verifying_key().to_bytes(),
        identity: owner_signer.verifying_key().to_bytes(),
        label: "node-one".to_owned(),
        op,
        version: 24,
        not_after: 1_u64 << 32,
        signature_owner: [0; 64],
        signature_network: [0; 64],
    };
    record.sign_owner(&owner_signer).unwrap();
    record.sign_network(&network_signer).unwrap();
    record
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keynet-v1")
}

fn blocks(text: &str) -> Vec<BTreeMap<&str, &str>> {
    text.split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .map(|block| {
            block
                .lines()
                .filter(|line| !line.starts_with('#'))
                .map(|line| line.split_once('=').unwrap())
                .collect()
        })
        .collect()
}

fn field<'a>(block: &'a BTreeMap<&str, &str>, name: &str) -> &'a str {
    block.get(name).copied().unwrap()
}

fn bytes(input: &str) -> Vec<u8> {
    (0..input.len() / 2)
        .map(|index| u8::from_str_radix(&input[index * 2..index * 2 + 2], 16).unwrap())
        .collect()
}

fn fixed<const N: usize>(input: &str) -> [u8; N] {
    bytes(input).try_into().unwrap()
}

fn numbers(input: &str) -> Vec<u32> {
    input
        .split(',')
        .map(|value| value.parse().unwrap())
        .collect()
}

fn independent_h22(network_id: &[u8; 32], identity: &[u8; 32], kind: u8, index: u8) -> u32 {
    let mut input = [0_u8; 66];
    input[..32].copy_from_slice(network_id);
    input[32..64].copy_from_slice(identity);
    input[64] = kind;
    input[65] = index;
    let mut hash = <Blake2sMac<U3> as KeyInit>::new_from_slice(b"keynet-alias-v1").unwrap();
    hash.update(&input);
    let digest = hash.finalize().into_bytes();
    u32::from_be_bytes([0, digest[0], digest[1], digest[2]]) >> 2
}

#[test]
fn p4a_public_surface_is_present() {
    let record = signed_record(NameOperation::Claim);
    assert_eq!(normalize_label("--node__one--").as_deref(), Ok("node-one"));
    assert_eq!(validate_label("node-one"), Ok(()));
    let pool = AliasPool {
        base: u32::from_be_bytes([100, 64, 0, 0]),
        size: 1 << 22,
    };
    let first = alias_candidate(&record.network_id, &record.identity, 6, 0, pool).unwrap();
    assert_eq!(
        alias_candidates(&record.network_id, &record.identity, 6, pool).unwrap()[0],
        first
    );
    let encoded = record.encode().unwrap();
    assert_eq!(
        NameRecord::decode_and_validate(
            &encoded,
            &record.network_id,
            &record.identity,
            record.not_after - 1,
        )
        .unwrap()
        .record(),
        &record
    );
}

#[test]
fn alias_vectors_are_literal_ordered_and_not_deduplicated() {
    let text = fs::read_to_string(fixtures().join("aliases.vec")).unwrap();
    for vector in blocks(&text) {
        let network_id = fixed(field(&vector, "network_id"));
        let identity = fixed(field(&vector, "identity"));
        let kind = field(&vector, "kind").parse().unwrap();
        let pool = AliasPool {
            base: field(&vector, "pool_base").parse().unwrap(),
            size: field(&vector, "pool_size").parse().unwrap(),
        };
        let expected_h22 = numbers(field(&vector, "h22"));
        let expected_candidates = numbers(field(&vector, "candidates"));
        let actual = alias_candidates(&network_id, &identity, kind, pool).unwrap();
        assert_eq!(actual.as_slice(), expected_candidates);
        for index in 0_u8..16 {
            assert_eq!(
                independent_h22(&network_id, &identity, kind, index),
                expected_h22[usize::from(index)]
            );
            assert_eq!(
                alias_h22(&network_id, &identity, kind, index).unwrap(),
                expected_h22[usize::from(index)]
            );
            assert_eq!(
                alias_candidate(&network_id, &identity, kind, index, pool).unwrap(),
                expected_candidates[usize::from(index)]
            );
        }
    }

    let duplicates =
        alias_candidates(&[1; 32], &[2; 32], 6, AliasPool { base: 7, size: 1 }).unwrap();
    assert_eq!(duplicates, [7; 16]);
}

#[test]
fn identity_labels_have_exact_literal_bits_and_alphabet() {
    let cases = [
        ([0_u8; 32], "fozb5yeuvyc67ixhrt4a"),
        (
            std::array::from_fn(|index| index as u8),
            "k76ssrdfm7nxnfxrpw3q",
        ),
        (
            std::array::from_fn(|index| 31_u8.saturating_sub(index as u8)),
            "htvc6x54hbcnbm5k3mka",
        ),
    ];
    for (identity, expected) in cases {
        let label = identity_label(&identity).unwrap();
        assert_eq!(label, expected);
        assert_eq!(label.len(), 20);
        assert!(
            label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        );
        let last = b"abcdefghijklmnopqrstuvwxyz234567"
            .iter()
            .position(|byte| *byte == label.as_bytes()[19])
            .unwrap();
        assert_eq!(last & 0x0f, 0);
    }
}

#[test]
fn alias_input_and_checked_pool_boundaries_are_enforced() {
    let network_id = [1; 32];
    let identity = [2; 32];
    let full_ipv4 = AliasPool {
        base: 0,
        size: u64::from(u32::MAX) + 1,
    };
    assert!(alias_candidate(&network_id, &identity, 4, 15, full_ipv4).is_ok());
    assert_eq!(
        alias_candidate(&network_id, &identity, 5, 0, AliasPool { base: 0, size: 1 }),
        Err(AliasCandidateError::InvalidKind)
    );
    assert_eq!(
        alias_candidate(
            &network_id,
            &identity,
            6,
            16,
            AliasPool { base: 0, size: 1 }
        ),
        Err(AliasCandidateError::InvalidIndex)
    );
    assert_eq!(
        alias_candidate(&network_id, &identity, 6, 0, AliasPool { base: 0, size: 0 }),
        Err(AliasCandidateError::EmptyPool)
    );
    for pool in [
        AliasPool {
            base: 1,
            size: u64::from(u32::MAX) + 1,
        },
        AliasPool {
            base: u32::MAX,
            size: 2,
        },
    ] {
        assert_eq!(
            alias_candidate(&network_id, &identity, 6, 0, pool),
            Err(AliasCandidateError::PoolOutOfRange)
        );
    }
}

#[test]
fn label_normalization_and_validation_follow_ascii_byte_rules() {
    let text = fs::read_to_string(fixtures().join("labels.vec")).unwrap();
    for vector in blocks(&text) {
        let input = String::from_utf8(bytes(field(&vector, "input_hex"))).unwrap();
        match vector.get("expected_error").copied() {
            Some("empty") => assert_eq!(normalize_label(&input), Err(LabelError::Empty)),
            Some("reserved") => assert_eq!(normalize_label(&input), Err(LabelError::Reserved)),
            Some(error) => panic!("unknown fixture error: {error}"),
            None => assert_eq!(
                normalize_label(&input).as_deref(),
                Ok(field(&vector, "expected"))
            ),
        }
    }

    assert_eq!(normalize_label("a"), Ok("a".to_owned()));
    assert_eq!(normalize_label(&"a".repeat(63)), Ok("a".repeat(63)));
    assert_eq!(normalize_label(&"a".repeat(64)), Ok("a".repeat(63)));
    assert_eq!(normalize_label("a__b---c"), Ok("a-b-c".to_owned()));
    assert_eq!(normalize_label("AÉ__b"), Ok("b".to_owned()));
    assert_eq!(normalize_label("___"), Err(LabelError::Empty));
    assert_eq!(normalize_label("id"), Err(LabelError::Reserved));
    assert_eq!(normalize_label("v4"), Err(LabelError::Reserved));
    assert_eq!(
        normalize_label(&format!("{}__b", "a".repeat(62))),
        Ok("a".repeat(62))
    );

    for accepted in ["a", "a0", "a-b", "a--b", &"z".repeat(63)] {
        assert_eq!(validate_label(accepted), Ok(()));
    }
    assert_eq!(validate_label(""), Err(LabelError::Empty));
    assert_eq!(validate_label(&"a".repeat(64)), Err(LabelError::TooLong));
    for invalid in ["A", "é", "a_b"] {
        assert_eq!(validate_label(invalid), Err(LabelError::InvalidCharacter));
    }
    for invalid in ["-a", "a-"] {
        assert_eq!(
            validate_label(invalid),
            Err(LabelError::LeadingOrTrailingHyphen)
        );
    }
    for reserved in ["id", "v4"] {
        assert_eq!(validate_label(reserved), Err(LabelError::Reserved));
    }
}

#[test]
fn name_record_fixture_pins_both_canonical_signature_layers() {
    let text = fs::read_to_string(fixtures().join("name_records.vec")).unwrap();
    let vectors = blocks(&text);
    assert_eq!(vectors.len(), 1);
    let vector = vectors.first().unwrap();
    assert_eq!(field(vector, "case"), "claim_width_boundaries");
    assert_eq!(field(vector, "op"), "0");
    let owner_signer = SigningKey::from_bytes(&fixed(field(vector, "owner_seed")));
    let network_signer = SigningKey::from_bytes(&fixed(field(vector, "network_seed")));
    let owner = OwnerSignedNameRecord {
        ver: 1,
        network_id: fixed(field(vector, "network_id")),
        identity: fixed(field(vector, "identity")),
        label: field(vector, "label").to_owned(),
        op: NameOperation::Claim,
        version: field(vector, "version").parse().unwrap(),
        not_after: field(vector, "not_after").parse().unwrap(),
        signature_owner: fixed(field(vector, "signature_owner")),
    };
    let unsigned = bytes(field(vector, "unsigned"));
    let owner_preimage = bytes(field(vector, "owner_preimage"));
    let owner_signed = bytes(field(vector, "owner_signed"));
    assert_eq!(owner_signer.verifying_key().to_bytes(), owner.identity);
    assert_eq!(network_signer.verifying_key().to_bytes(), owner.network_id);
    assert_eq!(owner.unsigned_bytes().unwrap(), unsigned);
    assert_eq!(owner.signing_preimage().unwrap(), owner_preimage);
    assert_eq!(owner.encode().unwrap(), owner_signed);
    assert_eq!(
        OwnerSignedNameRecord::decode(&owner_signed),
        Ok(owner.clone())
    );
    VerifyingKey::from_bytes(&owner.identity)
        .unwrap()
        .verify_strict(
            &owner_preimage,
            &Signature::from_bytes(&owner.signature_owner),
        )
        .unwrap();

    let record = NameRecord {
        ver: owner.ver,
        network_id: owner.network_id,
        identity: owner.identity,
        label: owner.label.clone(),
        op: owner.op,
        version: owner.version,
        not_after: owner.not_after,
        signature_owner: owner.signature_owner,
        signature_network: fixed(field(vector, "signature_network")),
    };
    let network_preimage = bytes(field(vector, "network_preimage"));
    let network_signed = bytes(field(vector, "network_signed"));
    assert_eq!(record.owner_signed_bytes().unwrap(), owner_signed);
    assert_eq!(record.encode().unwrap(), network_signed);
    assert_eq!(NameRecord::decode(&network_signed), Ok(record.clone()));
    VerifyingKey::from_bytes(&record.network_id)
        .unwrap()
        .verify_strict(
            &network_preimage,
            &Signature::from_bytes(&record.signature_network),
        )
        .unwrap();
    assert!(record.verify_signatures().is_ok());
}

#[test]
fn all_name_operations_round_trip_without_version_state_semantics() {
    for operation in [
        NameOperation::Claim,
        NameOperation::Rename,
        NameOperation::Release,
    ] {
        let record = signed_record(operation);
        assert_eq!(NameRecord::decode(&record.encode().unwrap()), Ok(record));
    }
}

#[test]
fn name_signatures_reject_context_substitution_signers_and_tampering() {
    let owner_signer = signer(7);
    let network_signer = signer(3);
    let record = signed_record(NameOperation::Claim);

    let mut wrong_owner_context = record.clone();
    let owner = OwnerSignedNameRecord {
        ver: record.ver,
        network_id: record.network_id,
        identity: record.identity,
        label: record.label.clone(),
        op: record.op,
        version: record.version,
        not_after: record.not_after,
        signature_owner: [0; 64],
    };
    let mut preimage = b"keynet/name-record-network/v1".to_vec();
    preimage.extend_from_slice(&owner.unsigned_bytes().unwrap());
    wrong_owner_context.signature_owner = owner_signer.sign(&preimage).to_bytes();
    assert_eq!(
        wrong_owner_context.verify_signatures(),
        Err(NameRecordSignatureError::InvalidOwnerSignature)
    );

    let mut wrong_network_context = record.clone();
    let mut preimage = b"keynet/name-record/v1".to_vec();
    preimage.extend_from_slice(&record.owner_signed_bytes().unwrap());
    wrong_network_context.signature_network = network_signer.sign(&preimage).to_bytes();
    assert_eq!(
        wrong_network_context.verify_signatures(),
        Err(NameRecordSignatureError::InvalidNetworkSignature)
    );

    let mut missing_owner = record.clone();
    missing_owner.signature_owner = [0; 64];
    assert!(missing_owner.verify_signatures().is_err());
    assert_eq!(
        missing_owner.sign_network(&network_signer),
        Err(NameRecordSignatureError::InvalidOwnerSignature)
    );

    let mut altered_owner = record.clone();
    altered_owner.label = "node-two".to_owned();
    altered_owner.sign_owner(&owner_signer).unwrap();
    altered_owner.signature_network = record.signature_network;
    assert_eq!(
        altered_owner.verify_signatures(),
        Err(NameRecordSignatureError::InvalidNetworkSignature)
    );

    assert_eq!(
        altered_owner.sign_owner(&signer(8)),
        Err(NameRecordSignatureError::OwnerSignerMismatch)
    );
    assert_eq!(
        altered_owner.sign_network(&signer(9)),
        Err(NameRecordSignatureError::NetworkSignerMismatch)
    );

    let mut mutations = Vec::new();
    let mut altered = record.clone();
    altered.network_id[0] ^= 1;
    mutations.push(altered);
    let mut altered = record.clone();
    altered.identity[0] ^= 1;
    mutations.push(altered);
    let mut altered = record.clone();
    altered.label = "node-two".to_owned();
    mutations.push(altered);
    let mut altered = record.clone();
    altered.op = NameOperation::Rename;
    mutations.push(altered);
    let mut altered = record.clone();
    altered.version += 1;
    mutations.push(altered);
    let mut altered = record.clone();
    altered.not_after += 1;
    mutations.push(altered);
    assert!(
        mutations
            .into_iter()
            .all(|value| value.verify_signatures().is_err())
    );
}

#[test]
fn checked_name_record_enforces_scope_and_exclusive_expiry_only() {
    let record = signed_record(NameOperation::Claim);
    let encoded = record.encode().unwrap();
    assert!(
        NameRecord::decode_and_validate(
            &encoded,
            &record.network_id,
            &record.identity,
            record.not_after - 1,
        )
        .is_ok()
    );
    assert_eq!(
        NameRecord::decode_and_validate(
            &encoded,
            &record.network_id,
            &record.identity,
            record.not_after,
        ),
        Err(NameRecordValidationError::Expired)
    );
    assert_eq!(
        record.clone().validate(&[0; 32], &record.identity, 0),
        Err(NameRecordValidationError::ScopeMismatch)
    );
    assert_eq!(
        record.clone().validate(&record.network_id, &[0; 32], 0),
        Err(NameRecordValidationError::ScopeMismatch)
    );
}

#[test]
fn name_decoders_reject_noncanonical_malformed_and_hostile_inputs() {
    let record = signed_record(NameOperation::Claim);
    let encoded = record.encode().unwrap();
    let owner = record.owner_signed_bytes().unwrap();

    let mut malformed = Vec::new();
    for prefix in [vec![0xa9], vec![0xc1], vec![0xfb], vec![0x9f]] {
        let mut value = prefix;
        value.extend_from_slice(&encoded);
        malformed.push(value);
    }
    let mut wrong_count = encoded.clone();
    wrong_count[0] = 0x88;
    malformed.push(wrong_count);
    let mut nonminimal_ver = encoded.clone();
    nonminimal_ver.splice(1..2, [0x18, 0x01]);
    malformed.push(nonminimal_ver);
    let mut wrong_network_type = encoded.clone();
    wrong_network_type[2] = 0x78;
    malformed.push(wrong_network_type);
    let mut wrong_network_width = encoded.clone();
    wrong_network_width[3] = 31;
    malformed.push(wrong_network_width);
    let mut wrong_label_type = encoded.clone();
    wrong_label_type[70] = 0x48;
    malformed.push(wrong_label_type);
    let mut indefinite_label = encoded.clone();
    indefinite_label[70] = 0x7f;
    malformed.push(indefinite_label);
    let mut nonminimal_label_length = encoded.clone();
    nonminimal_label_length.splice(70..71, [0x78, 0x08]);
    malformed.push(nonminimal_label_length);
    let mut invalid_utf8 = encoded.clone();
    invalid_utf8[71] = 0xff;
    malformed.push(invalid_utf8);
    let mut nonminimal_op = encoded.clone();
    nonminimal_op.splice(79..80, [0x18, 0x00]);
    malformed.push(nonminimal_op);
    let mut wrong_version_type = encoded.clone();
    wrong_version_type[80] = 0x38;
    malformed.push(wrong_version_type);
    let mut wrong_expiry_type = encoded.clone();
    wrong_expiry_type[82] = 0x5b;
    malformed.push(wrong_expiry_type);
    let mut wrong_owner_signature_width = encoded.clone();
    wrong_owner_signature_width[92] = 63;
    malformed.push(wrong_owner_signature_width);
    let mut wrong_signature_width = encoded.clone();
    let network_signature_length = wrong_signature_width.len();
    wrong_signature_width[network_signature_length - 65] = 63;
    malformed.push(wrong_signature_width);
    let mut trailing = encoded.clone();
    trailing.push(0);
    malformed.push(trailing);
    malformed.push(vec![0; 287]);

    for value in malformed {
        assert!(std::panic::catch_unwind(|| NameRecord::decode(&value)).is_ok());
        assert_eq!(
            NameRecord::decode(&value),
            Err(NameRecordDecodeError::InvalidEncoding)
        );
        assert!(matches!(
            NameRecord::decode_and_validate(
                &value,
                &record.network_id,
                &record.identity,
                record.not_after - 1,
            ),
            Err(NameRecordValidationError::Decode(_))
        ));
    }

    let mut unsupported = encoded.clone();
    unsupported[1] = 2;
    assert_eq!(
        NameRecord::decode(&unsupported),
        Err(NameRecordDecodeError::UnsupportedVersion)
    );
    let mut invalid_label = encoded.clone();
    invalid_label[71] = b'A';
    assert_eq!(
        NameRecord::decode(&invalid_label),
        Err(NameRecordDecodeError::InvalidLabel(
            LabelError::InvalidCharacter
        ))
    );
    assert_eq!(
        NameRecord::decode(&{
            let mut invalid = encoded.clone();
            invalid[79] = 3;
            invalid
        }),
        Err(NameRecordDecodeError::InvalidOperation)
    );

    let mut owner_wrong_count = owner.clone();
    owner_wrong_count[0] = 0x87;
    assert_eq!(
        OwnerSignedNameRecord::decode(&owner_wrong_count),
        Err(NameRecordDecodeError::InvalidEncoding)
    );
    let mut owner_trailing = owner;
    owner_trailing.push(0);
    assert_eq!(
        OwnerSignedNameRecord::decode(&owner_trailing),
        Err(NameRecordDecodeError::InvalidEncoding)
    );
}

#[test]
fn invalid_in_memory_name_shapes_never_sign_or_encode() {
    let owner_signer = signer(7);
    for (label, expected) in [
        ("", LabelError::Empty),
        ("id", LabelError::Reserved),
        ("v4", LabelError::Reserved),
        ("A", LabelError::InvalidCharacter),
    ] {
        let mut record = signed_record(NameOperation::Claim);
        record.label = label.to_owned();
        assert!(record.encode().is_err());
        assert_eq!(
            record.sign_owner(&owner_signer),
            Err(NameRecordSignatureError::InvalidRecord(
                keynet_proto::NameRecordEncodeError::InvalidLabel(expected)
            ))
        );
    }
    let mut wrong_version = signed_record(NameOperation::Claim);
    wrong_version.ver = 2;
    assert!(wrong_version.encode().is_err());
}
