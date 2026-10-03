//! Generated pairing vectors: Invite, Join, ACCEPT, COMPLETE and the PSK (quick-v2 §10.2,
//! §12.1-§12.3).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixture helpers"
)]

mod support;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ns_rendezvous::{
    message::MailboxId,
    pairing::{
        Invite, Join, PairingError, PairingMessage, pairing_open_request, pairing_psk,
        verify_accept,
    },
    transport::{self, Request},
};
use ns_wire::{CborError, NodeRecord, RelayId};
use support::vectors::{Vector, load};

fn verify(v: &Vector, identity: &str, message: &str, signature: &str) {
    VerifyingKey::from_bytes(&v.hex_array(identity))
        .unwrap()
        .verify_strict(
            &v.hex(message),
            &Signature::from_bytes(&v.hex_array(signature)),
        )
        .unwrap_or_else(|err| panic!("{}: {signature}: {err}", v.name()));
}

#[test]
fn pairing_sessions_match_vectors() {
    let vectors = load("pairing");
    let mut sessions = 0;
    for v in vectors.iter().filter(|v| !v.is_reject()) {
        sessions += 1;
        let name = v.name();
        let now = v.u64("now");
        let authority = RelayId::parse(v.get("authority")).unwrap();
        let key_a = SigningKey::from_bytes(&v.hex_array("seed_a"));
        let key_b = SigningKey::from_bytes(&v.hex_array("seed_b"));
        let mailbox_id = MailboxId(v.hex_array("mailbox_id"));
        verify(v, "identity_a", "invite_message", "invite_signature");
        verify(v, "identity_b", "join_message", "join_signature");
        verify(v, "identity_a", "accept_message", "accept_signature");

        // Invite: encode, signature, hash, decode and re-encode.
        let invite = Invite::create(
            &key_a,
            NodeRecord::decode(&v.hex("record_a")).unwrap(),
            &v.hex_array("e_a"),
            &authority,
            v.u64("expires"),
            v.opt("name_a"),
        )
        .unwrap();
        assert_eq!(invite.as_bytes(), v.hex("invite").as_slice(), "{name}");
        assert_eq!(invite.signature(), &v.hex_array::<64>("invite_signature"));
        assert_eq!(invite.hash(), v.hex_array::<32>("invite_hash"), "{name}");
        let decoded = Invite::decode(&v.hex("invite")).unwrap();
        assert_eq!(decoded, invite, "{name}");
        decoded.verify(&authority, now).unwrap();
        let open = Request::Open(pairing_open_request(v.u64("ttl"), &invite).unwrap());
        assert_eq!(
            transport::encode_request(&open).unwrap(),
            v.get("open_request"),
            "{name}"
        );
        assert_eq!(
            transport::decode_request(v.get("open_request")).unwrap(),
            open
        );

        // Join.
        let join = Join::create(
            &key_b,
            NodeRecord::decode(&v.hex("record_b")).unwrap(),
            &v.hex_array("e_b"),
            &mailbox_id,
            &invite.hash(),
            v.opt("name_b"),
        )
        .unwrap();
        assert_eq!(join.as_bytes(), v.hex("join").as_slice(), "{name}");
        assert_eq!(join.signature(), &v.hex_array::<64>("join_signature"));
        assert_eq!(join.hash(), v.hex_array::<32>("join_hash"), "{name}");
        let decoded = Join::decode(&v.hex("join")).unwrap();
        assert_eq!(decoded, join, "{name}");
        decoded.verify(&mailbox_id, &invite.hash(), now).unwrap();

        // ACCEPT and COMPLETE.
        let accept = PairingMessage::accept(&key_a, &invite, &join).unwrap();
        assert_eq!(accept.encode(), v.hex("accept"), "{name}");
        assert_eq!(
            accept,
            PairingMessage::Accept {
                join_hash: v.hex_array("join_hash"),
                signature: v.hex_array("accept_signature"),
            }
        );
        let decoded = PairingMessage::decode(&v.hex("accept")).unwrap();
        assert_eq!(decoded, accept);
        assert_eq!(decoded.encode(), v.hex("accept"));
        verify_accept(&invite, &join, &decoded).unwrap();
        assert_eq!(PairingMessage::Complete.encode(), v.hex("complete"));
        assert_eq!(
            PairingMessage::decode(&v.hex("complete")).unwrap(),
            PairingMessage::Complete
        );

        // The PSK is the same from both sides.
        let (i_a, i_b) = (v.hex_array("identity_a"), v.hex_array("identity_b"));
        let (ih, jh) = (v.hex_array("invite_hash"), v.hex_array("join_hash"));
        let psk_a = pairing_psk(
            &v.hex_array("e_a_secret"),
            &v.hex_array("e_b"),
            &i_a,
            &i_b,
            &ih,
            &jh,
        )
        .unwrap();
        let psk_b = pairing_psk(
            &v.hex_array("e_b_secret"),
            &v.hex_array("e_a"),
            &i_a,
            &i_b,
            &ih,
            &jh,
        )
        .unwrap();
        assert_eq!(*psk_a, v.hex_array::<32>("psk"), "{name}");
        assert_eq!(*psk_b, *psk_a, "{name}");
    }
    assert_eq!(sessions, 2);
}

#[test]
fn rejected_pairing_payloads_match_vectors() {
    let vectors = load("pairing");
    let mut negatives = 0;
    for v in vectors.iter().filter(|v| v.is_reject()) {
        negatives += 1;
        let name = v.name();
        let result = match v.get("kind") {
            "invite" => Invite::decode(&v.hex("encoded")).and_then(|invite| {
                invite
                    .verify(&RelayId::parse(v.get("authority")).unwrap(), v.u64("now"))
                    .map(|_| ())
            }),
            "join" => Join::decode(&v.hex("encoded")).and_then(|join| {
                join.verify(
                    &MailboxId(v.hex_array("mailbox_id")),
                    &v.hex_array("invite_hash"),
                    v.u64("now"),
                )
                .map(|_| ())
            }),
            "accept" => {
                let invite = Invite::decode(&v.hex("invite")).unwrap();
                let join = Join::decode(&v.hex("join")).unwrap();
                PairingMessage::decode(&v.hex("encoded"))
                    .and_then(|message| verify_accept(&invite, &join, &message))
            }
            "message" => PairingMessage::decode(&v.hex("encoded")).map(|_| ()),
            "psk" => pairing_psk(
                &v.hex_array("own_secret"),
                &v.hex_array("peer_public"),
                &v.hex_array("identity_a"),
                &v.hex_array("identity_b"),
                &v.hex_array("invite_hash"),
                &v.hex_array("join_hash"),
            )
            .map(|_| ()),
            other => panic!("{name}: unknown kind {other}"),
        };
        let error = result.expect_err(name);
        let expected = match v.reason() {
            "signature" => matches!(error, PairingError::Signature),
            "authority" => matches!(error, PairingError::Authority),
            "expired" => matches!(error, PairingError::Expired { .. }),
            "trailing_bytes" => matches!(error, PairingError::Cbor(CborError::TrailingBytes)),
            "version" => matches!(error, PairingError::Version(3)),
            "invite_hash" => matches!(error, PairingError::InviteHash),
            "mailbox_id" => matches!(error, PairingError::MailboxId),
            "join_hash" => matches!(error, PairingError::JoinHash),
            "not_accept" => matches!(error, PairingError::NotAccept),
            "message_type" => matches!(error, PairingError::MessageType(3)),
            "all_zero_shared_secret" => matches!(error, PairingError::AllZeroSharedSecret),
            other => panic!("{name}: unknown reason {other}"),
        };
        assert!(expected, "{name}: {error:?}");
    }
    assert!(negatives >= 15);
}
