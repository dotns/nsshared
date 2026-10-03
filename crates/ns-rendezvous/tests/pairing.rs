//! Pairing payloads, signatures, PSK and mailbox mapping: quick-v2 §10.2, §12.1-§12.3,
//! rendezvous §9.1-§9.2.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use ns_rendezvous::{
    message::{Admission, MailboxId, MessageError},
    pairing::{
        ACCEPT_CONTEXT, DEFAULT_PAIRING_TTL_SECONDS, INVITE_CONTEXT, Invite, JOIN_CONTEXT, Join,
        KIND_PAIRING, KIND_TRANSFER, MAX_NAME_BYTES, MAX_PAIRING_TTL_SECONDS, MESSAGE_ACCEPT,
        MESSAGE_COMPLETE, PAIRING_VERSION, PSK_CONTEXT, PairingError, PairingMessage,
        pairing_open_request, pairing_psk, transfer_open_request, verify_accept,
    },
};
use ns_wire::{
    CborError, CborWriter, NODE_RECORD_CONTEXT, NodeRecord, NodeRecordError, NodeRecordFields,
    RelayId,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

const NOW: u64 = 2_000;
const RECORD_ISSUED: u64 = 1_000;
const RECORD_EXPIRES: u64 = RECORD_ISSUED + 86_400;
const INVITE_EXPIRES: u64 = NOW + 600;
const MAILBOX: MailboxId = MailboxId([9; 16]);
const E_A: [u8; 32] = [11; 32];
const E_B: [u8; 32] = [12; 32];

fn authority() -> RelayId {
    RelayId::parse("hkg-a1.relay.ns.io:443").unwrap()
}

fn other_relay() -> RelayId {
    RelayId::parse("fra-b2.relay.ns.io:443").unwrap()
}

fn key_a() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

fn key_b() -> SigningKey {
    SigningKey::from_bytes(&[2; 32])
}

fn record(key: &SigningKey) -> NodeRecord {
    record_with(key, RECORD_ISSUED, RECORD_EXPIRES)
}

fn record_with(key: &SigningKey, issued_at: u64, expires: u64) -> NodeRecord {
    NodeRecord::sign(
        key,
        NodeRecordFields {
            wg_key: [7; 32],
            generation: 1,
            issued_at,
            expires,
            relays: vec![authority()],
        },
    )
    .unwrap()
}

fn public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

fn invite() -> Invite {
    Invite::create(
        &key_a(),
        record(&key_a()),
        &public(&E_A),
        &authority(),
        INVITE_EXPIRES,
        Some("laptop"),
    )
    .unwrap()
}

fn join(invite: &Invite) -> Join {
    Join::create(
        &key_b(),
        record(&key_b()),
        &public(&E_B),
        &MAILBOX,
        &invite.hash(),
        Some("phone"),
    )
    .unwrap()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Encodes `[ver, record, tail...]` with the given array length, independently of the
/// library encoder.
fn assemble(length: usize, version: u64, record: &[u8], tail: CborWriter) -> Vec<u8> {
    let mut head = CborWriter::with_capacity(2);
    head.array(length).uint(version);
    [head.into_bytes(), record.to_vec(), tail.into_bytes()].concat()
}

/// A correctly signed record with `expires = issued_at + period`, encoded by hand because
/// [`NodeRecord::sign`] refuses periods above 604800 s (quick-v2 §3.1-§3.2).
fn raw_record(key: &SigningKey, issued_at: u64, period: u64) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(256);
    writer
        .array(7)
        .uint(2)
        .bytes(&key.verifying_key().to_bytes())
        .bytes(&[7; 32])
        .uint(1)
        .uint(issued_at)
        .uint(issued_at + period)
        .array(1)
        .text(authority().as_str());
    let unsigned = writer.into_bytes();
    let signature = key
        .sign(&[NODE_RECORD_CONTEXT, &unsigned].concat())
        .to_bytes();
    let mut tail = CborWriter::with_capacity(66);
    tail.bytes(&signature);
    [&[0x88], &unsigned[1..], &tail.into_bytes()].concat()
}

/// A raw Invite whose record, signer and fields are chosen freely.
fn raw_invite(
    record: &NodeRecord,
    signer: &SigningKey,
    authority: &RelayId,
    expires: u64,
    name: Option<&str>,
) -> Vec<u8> {
    let tail = |signature: Option<&[u8; 64]>| {
        let mut writer = CborWriter::with_capacity(512);
        writer
            .bytes(&public(&E_A))
            .text(authority.as_str())
            .uint(expires);
        match name {
            Some(name) => writer.text(name),
            None => writer.null(),
        };
        if let Some(signature) = signature {
            writer.bytes(signature);
        }
        writer
    };
    let unsigned = assemble(6, 2, record.as_bytes(), tail(None));
    let signature = signer
        .sign(&[INVITE_CONTEXT, &unsigned].concat())
        .to_bytes();
    assemble(7, 2, record.as_bytes(), tail(Some(&signature)))
}

/// A raw Join whose record, signer and fields are chosen freely.
fn raw_join(
    record: &NodeRecord,
    signer: &SigningKey,
    mailbox: &MailboxId,
    invite_hash: &[u8; 32],
) -> Vec<u8> {
    let tail = |signature: Option<&[u8; 64]>| {
        let mut writer = CborWriter::with_capacity(512);
        writer
            .bytes(&public(&E_B))
            .bytes(&mailbox.0)
            .bytes(invite_hash)
            .null();
        if let Some(signature) = signature {
            writer.bytes(signature);
        }
        writer
    };
    let unsigned = assemble(6, 2, record.as_bytes(), tail(None));
    let signature = signer.sign(&[JOIN_CONTEXT, &unsigned].concat()).to_bytes();
    assemble(7, 2, record.as_bytes(), tail(Some(&signature)))
}

fn flip_last(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    bytes
}

#[test]
fn constants_match_the_spec() {
    assert_eq!(KIND_PAIRING, "pairing");
    assert_eq!(KIND_TRANSFER, "transfer");
    assert_eq!(PAIRING_VERSION, 2);
    assert_eq!(INVITE_CONTEXT, b"ns/pairing-invite/v2");
    assert_eq!(JOIN_CONTEXT, b"ns/pairing-join/v2");
    assert_eq!(ACCEPT_CONTEXT, b"ns/pairing-accept/v2");
    assert_eq!(PSK_CONTEXT, b"ns/pairing-psk/v2");
    assert_eq!((MESSAGE_ACCEPT, MESSAGE_COMPLETE), (1, 2));
    assert_eq!(
        (DEFAULT_PAIRING_TTL_SECONDS, MAX_PAIRING_TTL_SECONDS),
        (600, 900)
    );
}

#[test]
fn invite_round_trips_and_matches_an_independent_encoding() {
    let invite = invite();
    let raw = raw_invite(
        &record(&key_a()),
        &key_a(),
        &authority(),
        INVITE_EXPIRES,
        Some("laptop"),
    );
    assert_eq!(invite.as_bytes(), raw.as_slice());
    assert_eq!(invite.hash(), sha256(&raw));
    let decoded = Invite::decode(&raw).unwrap();
    assert_eq!(decoded, invite);
    assert_eq!(decoded.record(), &record(&key_a()));
    assert_eq!(decoded.ephemeral(), &public(&E_A));
    assert_eq!(decoded.authority(), &authority());
    assert_eq!(decoded.expires(), INVITE_EXPIRES);
    assert_eq!(decoded.name(), Some("laptop"));
    assert_eq!(decoded.signature(), &raw[raw.len() - 64..]);
    assert_eq!(decoded.verify(&authority(), NOW), Ok(&record(&key_a())));
}

#[test]
fn invite_without_name_round_trips() {
    let invite = Invite::create(
        &key_a(),
        record(&key_a()),
        &public(&E_A),
        &authority(),
        INVITE_EXPIRES,
        None,
    )
    .unwrap();
    let raw = raw_invite(
        &record(&key_a()),
        &key_a(),
        &authority(),
        INVITE_EXPIRES,
        None,
    );
    assert_eq!(invite.as_bytes(), raw.as_slice());
    let decoded = Invite::decode(&raw).unwrap();
    assert_eq!(decoded.name(), None);
    assert!(decoded.verify(&authority(), NOW).is_ok());
}

#[test]
fn join_round_trips_and_verifies() {
    let invite = invite();
    let join = join(&invite);
    let decoded = Join::decode(join.as_bytes()).unwrap();
    assert_eq!(decoded, join);
    assert_eq!(decoded.hash(), sha256(join.as_bytes()));
    assert_eq!(decoded.record(), &record(&key_b()));
    assert_eq!(decoded.ephemeral(), &public(&E_B));
    assert_eq!(decoded.mailbox_id(), &MAILBOX);
    assert_eq!(decoded.invite_hash(), &invite.hash());
    assert_eq!(decoded.name(), Some("phone"));
    assert_eq!(
        decoded.verify(&MAILBOX, &invite.hash(), NOW),
        Ok(&record(&key_b()))
    );
    // Same bytes as the independent encoder (name null there).
    let unnamed = Join::create(
        &key_b(),
        record(&key_b()),
        &public(&E_B),
        &MAILBOX,
        &invite.hash(),
        None,
    )
    .unwrap();
    let raw = raw_join(&record(&key_b()), &key_b(), &MAILBOX, &invite.hash());
    assert_eq!(unnamed.as_bytes(), raw.as_slice());
    assert_eq!(unnamed.signature(), &raw[raw.len() - 64..]);
}

#[test]
fn messages_round_trip() {
    let invite = invite();
    let join = join(&invite);
    let accept = PairingMessage::accept(&key_a(), &invite, &join).unwrap();
    let PairingMessage::Accept {
        join_hash,
        signature,
    } = &accept
    else {
        panic!("not an accept");
    };
    assert_eq!(join_hash, &join.hash());
    let signed = [ACCEPT_CONTEXT, &invite.hash(), &join.hash()].concat();
    assert_eq!(signature, &key_a().sign(&signed).to_bytes());
    let mut expected = CborWriter::with_capacity(128);
    expected
        .array(3)
        .uint(2)
        .uint(1)
        .array(2)
        .bytes(join_hash)
        .bytes(signature);
    assert_eq!(accept.encode(), expected.into_bytes());
    assert_eq!(PairingMessage::decode(&accept.encode()), Ok(accept.clone()));

    let complete = PairingMessage::Complete.encode();
    assert_eq!(complete, [0x83, 0x02, 0x02, 0x80]);
    assert_eq!(
        PairingMessage::decode(&complete),
        Ok(PairingMessage::Complete)
    );
}

#[test]
fn decode_rejects_trailing_bytes() {
    let invite = invite();
    let join = join(&invite);
    let trailing = |bytes: &[u8]| [bytes, &[0]].concat();
    assert_eq!(
        Invite::decode(&trailing(invite.as_bytes())),
        Err(PairingError::Cbor(CborError::TrailingBytes))
    );
    assert_eq!(
        Join::decode(&trailing(join.as_bytes())),
        Err(PairingError::Cbor(CborError::TrailingBytes))
    );
    assert_eq!(
        PairingMessage::decode(&trailing(&PairingMessage::Complete.encode())),
        Err(PairingError::Cbor(CborError::TrailingBytes))
    );
}

#[test]
fn decode_rejects_unknown_versions() {
    let mut bytes = invite().as_bytes().to_vec();
    bytes[1] = 3;
    assert_eq!(Invite::decode(&bytes), Err(PairingError::Version(3)));
    let mut bytes = join(&invite()).as_bytes().to_vec();
    bytes[1] = 1;
    assert_eq!(Join::decode(&bytes), Err(PairingError::Version(1)));
    assert_eq!(
        PairingMessage::decode(&[0x83, 0x03, 0x02, 0x80]),
        Err(PairingError::Version(3))
    );
}

#[test]
fn decode_rejects_unknown_message_types() {
    assert_eq!(
        PairingMessage::decode(&[0x83, 0x02, 0x00, 0x80]),
        Err(PairingError::MessageType(0))
    );
    assert_eq!(
        PairingMessage::decode(&[0x83, 0x02, 0x03, 0x80]),
        Err(PairingError::MessageType(3))
    );
}

#[test]
fn decode_rejects_wrong_array_lengths() {
    let mut bytes = invite().as_bytes().to_vec();
    bytes[0] = 0x86;
    assert_eq!(
        Invite::decode(&bytes),
        Err(PairingError::Cbor(CborError::ArrayLength {
            expected: 7,
            actual: 6
        }))
    );
    let mut bytes = join(&invite()).as_bytes().to_vec();
    bytes[0] = 0x88;
    assert!(matches!(
        Join::decode(&bytes),
        Err(PairingError::Cbor(CborError::ArrayLength { .. }))
    ));
    assert_eq!(
        PairingMessage::decode(&[0x82, 0x02, 0x02]),
        Err(PairingError::Cbor(CborError::ArrayLength {
            expected: 3,
            actual: 2
        }))
    );
    // COMPLETE has an empty body; ACCEPT a two-element one.
    assert!(matches!(
        PairingMessage::decode(&[0x83, 0x02, 0x02, 0x81, 0x00]),
        Err(PairingError::Cbor(CborError::ArrayLength { .. }))
    ));
    assert!(matches!(
        PairingMessage::decode(&[0x83, 0x02, 0x01, 0x80]),
        Err(PairingError::Cbor(CborError::ArrayLength { .. }))
    ));
    // A malformed nested record is rejected by the outer shape check.
    let mut bytes = invite().as_bytes().to_vec();
    bytes[2] = 0x87;
    assert!(matches!(
        Invite::decode(&bytes),
        Err(PairingError::Cbor(CborError::ArrayLength { .. }))
    ));
}

#[test]
fn decode_rejects_oversize_payloads() {
    let mut bytes = invite().as_bytes().to_vec();
    bytes.resize(4097, 0);
    assert_eq!(
        Invite::decode(&bytes),
        Err(PairingError::TooLarge {
            length: 4097,
            maximum: 4096
        })
    );
    assert_eq!(
        Join::decode(&bytes),
        Err(PairingError::TooLarge {
            length: 4097,
            maximum: 4096
        })
    );
    let mut bytes = PairingMessage::Complete.encode();
    bytes.resize(8193, 0);
    assert_eq!(
        PairingMessage::decode(&bytes),
        Err(PairingError::TooLarge {
            length: 8193,
            maximum: 8192
        })
    );
}

#[test]
fn names_are_bounded() {
    let long = "x".repeat(MAX_NAME_BYTES + 1);
    let fits = "x".repeat(MAX_NAME_BYTES);
    assert_eq!(
        Invite::create(
            &key_a(),
            record(&key_a()),
            &public(&E_A),
            &authority(),
            INVITE_EXPIRES,
            Some(&long),
        ),
        Err(PairingError::NameTooLong(65))
    );
    assert_eq!(
        Join::create(
            &key_b(),
            record(&key_b()),
            &public(&E_B),
            &MAILBOX,
            &[0; 32],
            Some(&long)
        ),
        Err(PairingError::NameTooLong(65))
    );
    let raw = raw_invite(
        &record(&key_a()),
        &key_a(),
        &authority(),
        INVITE_EXPIRES,
        Some(&fits),
    );
    assert!(Invite::decode(&raw).is_ok());
    let raw = raw_invite(
        &record(&key_a()),
        &key_a(),
        &authority(),
        INVITE_EXPIRES,
        Some(&long),
    );
    assert_eq!(
        Invite::decode(&raw),
        Err(PairingError::Cbor(CborError::StringLength {
            expected: 64,
            actual: 65
        }))
    );
}

#[test]
fn decode_rejects_an_invalid_authority_or_record() {
    // A non-canonical authority (uppercase DNS name).
    let mut writer = CborWriter::with_capacity(512);
    writer
        .bytes(&public(&E_A))
        .text("HKG.relay.ns.io:443")
        .uint(INVITE_EXPIRES)
        .null()
        .bytes(&[0; 64]);
    let bytes = assemble(7, 2, record(&key_a()).as_bytes(), writer);
    assert!(matches!(
        Invite::decode(&bytes),
        Err(PairingError::InvalidAuthority(_))
    ));
    // A tampered record signature fails the embedded NodeRecord check.
    let record = record(&key_a());
    let offset = 2 + record.as_bytes().len() - 1;
    let mut bytes = invite().as_bytes().to_vec();
    bytes[offset] ^= 1;
    assert_eq!(
        Invite::decode(&bytes),
        Err(PairingError::Record(NodeRecordError::BadSignature))
    );
}

#[test]
fn invite_verify_rejects_a_tampered_signature() {
    let bytes = flip_last(invite().as_bytes());
    let invite = Invite::decode(&bytes).unwrap();
    assert_eq!(
        invite.verify(&authority(), NOW),
        Err(PairingError::Signature)
    );
}

#[test]
fn invite_verify_rejects_a_signer_other_than_the_record() {
    let bytes = raw_invite(
        &record(&key_a()),
        &key_b(),
        &authority(),
        INVITE_EXPIRES,
        None,
    );
    let invite = Invite::decode(&bytes).unwrap();
    assert_eq!(
        invite.verify(&authority(), NOW),
        Err(PairingError::Signature)
    );
    assert_eq!(
        Invite::create(
            &key_b(),
            record(&key_a()),
            &public(&E_A),
            &authority(),
            INVITE_EXPIRES,
            None
        ),
        Err(PairingError::SignerMismatch)
    );
}

#[test]
fn invite_verify_rejects_another_relay() {
    assert_eq!(
        invite().verify(&other_relay(), NOW),
        Err(PairingError::Authority)
    );
}

#[test]
fn invite_verify_rejects_expiry() {
    assert!(invite().verify(&authority(), INVITE_EXPIRES - 1).is_ok());
    assert_eq!(
        invite().verify(&authority(), INVITE_EXPIRES),
        Err(PairingError::Expired {
            expires: INVITE_EXPIRES,
            now: INVITE_EXPIRES
        })
    );
}

#[test]
fn verify_rejects_an_expired_record() {
    let invite = invite();
    assert!(matches!(
        invite.verify(&authority(), RECORD_EXPIRES),
        Err(PairingError::RecordExpired(_))
    ));
    assert!(matches!(
        join(&invite).verify(&MAILBOX, &invite.hash(), RECORD_EXPIRES),
        Err(PairingError::RecordExpired(_))
    ));
    // 604800 s is the longest valid service period.
    let longest = record_with(&key_a(), RECORD_ISSUED, RECORD_ISSUED + 604_800);
    let invite = Invite::create(
        &key_a(),
        longest,
        &public(&E_A),
        &authority(),
        INVITE_EXPIRES,
        None,
    )
    .unwrap();
    assert!(invite.verify(&authority(), NOW).is_ok());
}

#[test]
fn decode_rejects_a_record_with_an_overlong_service_period() {
    // NodeRecord::decode rejects the embedded record, so Invite and Join never decode.
    let overlong = raw_record(&key_a(), RECORD_ISSUED, 604_801);
    let rejected = PairingError::Record(NodeRecordError::ServicePeriodTooLong(604_801));
    let mut invite = CborWriter::with_capacity(512);
    invite
        .bytes(&public(&E_A))
        .text(authority().as_str())
        .uint(INVITE_EXPIRES)
        .null()
        .bytes(&[0; 64]);
    assert_eq!(
        Invite::decode(&assemble(7, 2, &overlong, invite)).unwrap_err(),
        rejected
    );
    let mut join = CborWriter::with_capacity(512);
    join.bytes(&public(&E_B))
        .bytes(&MAILBOX.0)
        .bytes(&[0; 32])
        .null()
        .bytes(&[0; 64]);
    assert_eq!(
        Join::decode(&assemble(7, 2, &overlong, join)).unwrap_err(),
        rejected
    );
    // The same hand encoding at 604800 s decodes.
    let mut invite = CborWriter::with_capacity(512);
    invite
        .bytes(&public(&E_A))
        .text(authority().as_str())
        .uint(INVITE_EXPIRES)
        .null()
        .bytes(&[0; 64]);
    let longest = raw_record(&key_a(), RECORD_ISSUED, 604_800);
    assert!(Invite::decode(&assemble(7, 2, &longest, invite)).is_ok());
}

#[test]
fn join_verify_rejects_a_tampered_signature() {
    let invite = invite();
    let bytes = flip_last(join(&invite).as_bytes());
    let join = Join::decode(&bytes).unwrap();
    assert_eq!(
        join.verify(&MAILBOX, &invite.hash(), NOW),
        Err(PairingError::Signature)
    );
}

#[test]
fn join_verify_rejects_a_signer_other_than_the_record() {
    let invite = invite();
    let bytes = raw_join(&record(&key_b()), &key_a(), &MAILBOX, &invite.hash());
    let join = Join::decode(&bytes).unwrap();
    assert_eq!(
        join.verify(&MAILBOX, &invite.hash(), NOW),
        Err(PairingError::Signature)
    );
    assert_eq!(
        Join::create(
            &key_a(),
            record(&key_b()),
            &public(&E_B),
            &MAILBOX,
            &invite.hash(),
            None
        ),
        Err(PairingError::SignerMismatch)
    );
}

#[test]
fn join_verify_rejects_another_mailbox() {
    let invite = invite();
    assert_eq!(
        join(&invite).verify(&MailboxId([8; 16]), &invite.hash(), NOW),
        Err(PairingError::MailboxId)
    );
}

#[test]
fn join_verify_rejects_another_invite_hash() {
    let invite = invite();
    let other = raw_invite(
        &record(&key_a()),
        &key_a(),
        &authority(),
        INVITE_EXPIRES,
        None,
    );
    assert_eq!(
        join(&invite).verify(&MAILBOX, &sha256(&other), NOW),
        Err(PairingError::InviteHash)
    );
}

#[test]
fn accept_verifies_for_the_joiner() {
    let invite = invite();
    let join = join(&invite);
    let accept = PairingMessage::accept(&key_a(), &invite, &join).unwrap();
    let decoded = PairingMessage::decode(&accept.encode()).unwrap();
    assert_eq!(verify_accept(&invite, &join, &decoded), Ok(()));
}

#[test]
fn accept_rejects_another_join_hash() {
    let invite = invite();
    let join = join(&invite);
    let other = Join::decode(&raw_join(
        &record(&key_b()),
        &key_b(),
        &MAILBOX,
        &invite.hash(),
    ))
    .unwrap();
    let accept = PairingMessage::accept(&key_a(), &invite, &other).unwrap();
    assert_eq!(
        verify_accept(&invite, &join, &accept),
        Err(PairingError::JoinHash)
    );
}

#[test]
fn accept_rejects_a_tampered_or_foreign_signature() {
    let invite = invite();
    let join = join(&invite);
    let accept = PairingMessage::accept(&key_a(), &invite, &join).unwrap();
    let tampered = PairingMessage::decode(&flip_last(&accept.encode())).unwrap();
    assert_eq!(
        verify_accept(&invite, &join, &tampered),
        Err(PairingError::Signature)
    );
    // Signed by the joiner over the right data.
    let signed = [ACCEPT_CONTEXT, &invite.hash(), &join.hash()].concat();
    let foreign = PairingMessage::Accept {
        join_hash: join.hash(),
        signature: key_b().sign(&signed).to_bytes(),
    };
    assert_eq!(
        verify_accept(&invite, &join, &foreign),
        Err(PairingError::Signature)
    );
    // Signed for another invite of the same inviter.
    let other = Invite::create(
        &key_a(),
        record(&key_a()),
        &public(&E_A),
        &authority(),
        INVITE_EXPIRES + 1,
        None,
    )
    .unwrap();
    let rebound = PairingMessage::accept(&key_a(), &other, &join).unwrap();
    assert_eq!(
        verify_accept(&invite, &join, &rebound),
        Err(PairingError::Signature)
    );
    assert_eq!(
        PairingMessage::accept(&key_b(), &invite, &join),
        Err(PairingError::SignerMismatch)
    );
}

#[test]
fn verify_accept_rejects_complete() {
    let invite = invite();
    let join = join(&invite);
    assert_eq!(
        verify_accept(&invite, &join, &PairingMessage::Complete),
        Err(PairingError::NotAccept)
    );
}

#[test]
fn both_sides_derive_the_same_psk() {
    let invite = invite();
    let join = join(&invite);
    let i_a = key_a().verifying_key().to_bytes();
    let i_b = key_b().verifying_key().to_bytes();
    let (invite_hash, join_hash) = (invite.hash(), join.hash());
    let inviter =
        pairing_psk(&E_A, join.ephemeral(), &i_a, &i_b, &invite_hash, &join_hash).unwrap();
    let joiner = pairing_psk(
        &E_B,
        invite.ephemeral(),
        &i_a,
        &i_b,
        &invite_hash,
        &join_hash,
    )
    .unwrap();
    assert_eq!(*inviter, *joiner);

    let shared = StaticSecret::from(E_A).diffie_hellman(&PublicKey::from(public(&E_B)));
    let info = [PSK_CONTEXT, &i_a, &i_b, &invite_hash, &join_hash].concat();
    let mut expected = [0; 32];
    Hkdf::<Sha256>::new(Some(&[][..]), shared.as_bytes())
        .expand(&info, &mut expected)
        .unwrap();
    assert_eq!(*inviter, expected);

    let swapped =
        pairing_psk(&E_A, join.ephemeral(), &i_b, &i_a, &invite_hash, &join_hash).unwrap();
    assert_ne!(*swapped, *inviter);
}

#[test]
fn psk_rejects_an_all_zero_dh_result() {
    let mut one = [0; 32];
    one[0] = 1;
    for peer in [[0; 32], one] {
        assert_eq!(
            pairing_psk(&E_A, &peer, &[1; 32], &[2; 32], &[3; 32], &[4; 32]),
            Err(PairingError::AllZeroSharedSecret)
        );
    }
}

#[test]
fn pairing_open_request_maps_rendezvous_9_1() {
    let invite = invite();
    let open = pairing_open_request(DEFAULT_PAIRING_TTL_SECONDS, &invite).unwrap();
    assert_eq!(open.kind.as_str(), "pairing");
    assert_eq!(open.ttl, 600);
    assert_eq!(open.admission, Admission::Owner);
    assert_eq!(open.candidates, 4);
    assert_eq!(open.intro, invite.as_bytes());
    assert!(pairing_open_request(MAX_PAIRING_TTL_SECONDS, &invite).is_ok());
    for ttl in [0, MAX_PAIRING_TTL_SECONDS + 1] {
        assert_eq!(
            pairing_open_request(ttl, &invite),
            Err(PairingError::Open(MessageError::Ttl))
        );
    }
}

#[test]
fn transfer_open_request_maps_rendezvous_9_2() {
    let open = transfer_open_request(300, vec![5; 32]).unwrap();
    assert_eq!(open.kind.as_str(), "transfer");
    assert_eq!(open.ttl, 300);
    assert_eq!(open.admission, Admission::First);
    assert_eq!(open.candidates, 1);
    assert_eq!(open.intro, vec![5; 32]);
    assert!(transfer_open_request(1, vec![0; 4096]).is_ok());
    assert_eq!(
        transfer_open_request(300, vec![0; 4097]),
        Err(PairingError::TooLarge {
            length: 4097,
            maximum: 4096
        })
    );
    for ttl in [0, 901] {
        assert_eq!(
            transfer_open_request(ttl, Vec::new()),
            Err(PairingError::Open(MessageError::Ttl))
        );
    }
}
