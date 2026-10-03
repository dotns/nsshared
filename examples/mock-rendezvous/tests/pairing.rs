//! Quick pairing end to end over the mock (rendezvous §4, §5, §9.1; quick-v2 §10.2):
//! Invite, two joiners, reject and admit, ACCEPT woken by a long poll, COMPLETE, close,
//! and an actor reconnecting on a new connection.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use ed25519_dalek::SigningKey;
use nsshared_rendezvous::{
    error::ErrorCode,
    message::{AdmitRequest, Digits, RejectRequest, Stage},
    pairing::{
        Invite, Join, KIND_PAIRING, PairingMessage, pairing_open_request, pairing_psk,
        verify_accept,
    },
    transport::Request,
};
use nsshared_wire::{NodeRecord, NodeRecordFields, RelayId};
use std::time::Duration;
use support::{Client, Mock, key, now, relaxed_limits};
use x25519_dalek::{PublicKey, StaticSecret};

const TTL: u64 = 600;
const E_A: [u8; 32] = [11; 32];
const E_B: [u8; 32] = [12; 32];
const E_C: [u8; 32] = [13; 32];

fn record(identity: &SigningKey, authority: &RelayId) -> NodeRecord {
    let now = now();
    NodeRecord::sign(
        identity,
        NodeRecordFields {
            wg_key: [7; 32],
            generation: 1,
            issued_at: now - 10,
            expires: now + 3600,
            relays: vec![authority.clone()],
        },
    )
    .unwrap()
}

fn public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// Joiner steps 2-3: look up the digits, verify the Invite, join with a Join bound to
/// the mailbox and the Invite hash.
async fn join(
    joiner: &mut Client,
    digits: &Digits,
    identity: &SigningKey,
    ephemeral: &[u8; 32],
    authority: &RelayId,
) -> (Invite, Join) {
    let found = joiner.lookup(digits).await.unwrap();
    assert_eq!(found.kind.as_str(), KIND_PAIRING);
    let invite = Invite::decode(&found.intro).unwrap();
    invite.verify(authority, now()).unwrap();
    let join = Join::create(
        identity,
        record(identity, authority),
        &public(ephemeral),
        &found.id,
        &invite.hash(),
        None,
    )
    .unwrap();
    joiner
        .join(found.id, join.as_bytes().to_vec())
        .await
        .unwrap();
    (invite, join)
}

#[tokio::test]
async fn pairing_end_to_end() {
    let mock = Mock::start(relaxed_limits()).await;
    let authority = mock.authority();
    let (identity_a, actor_a) = (key(1), key(101));
    let (identity_b, actor_b) = (key(2), key(102));
    let (identity_c, actor_c) = (key(3), key(103));

    // Step 1: the inviter opens the mailbox with a signed Invite.
    let invite = Invite::create(
        &identity_a,
        record(&identity_a, &authority),
        &public(&E_A),
        &authority,
        now() + TTL,
        Some("laptop"),
    )
    .unwrap();
    let mut inviter = mock.actor(&actor_a).await;
    let opened = inviter
        .open(pairing_open_request(TTL, &invite).unwrap())
        .await;
    let id = opened.id;

    // Steps 2-3: two joiners verify the Invite and join.
    let mut joiner_b = mock.actor(&actor_b).await;
    let (seen, join_b) = join(&mut joiner_b, &opened.digits, &identity_b, &E_B, &authority).await;
    assert_eq!(seen, invite);
    let mut joiner_c = mock.actor(&actor_c).await;
    let (_, join_c) = join(&mut joiner_c, &opened.digits, &identity_c, &E_C, &authority).await;

    // The inviter reconnects: a new connection, a new challenge, the same actor key.
    drop(inviter);
    let mut inviter = mock.connect().await;
    inviter.hello(&actor_a).await;

    // Step 4: the inviter sees both candidates, verifies their Joins, rejects one and
    // admits the other.
    let view = inviter.recv(id, 0, 0).await.unwrap();
    assert_eq!(view.stage, Stage::Open);
    let waiting: Vec<_> = view.waiting.iter().map(|waiting| waiting.actor).collect();
    let actor_b_public = actor_b.verifying_key().to_bytes();
    let actor_c_public = actor_c.verifying_key().to_bytes();
    assert_eq!(waiting, [actor_b_public, actor_c_public]);
    for waiting in &view.waiting {
        let join = Join::decode(&waiting.intro).unwrap();
        join.verify(&id, &invite.hash(), now()).unwrap();
    }
    assert_eq!(view.waiting[1].intro, join_c.as_bytes());
    let reject = Request::Reject(RejectRequest {
        id,
        actor: actor_c_public,
    });
    assert!(support::ok(inviter.request(&reject).await).is_ok());
    let admit = Request::Admit(AdmitRequest {
        id,
        actor: actor_b_public,
    });
    assert!(support::ok(inviter.request(&admit).await).is_ok());

    // The rejected actor cannot join again.
    assert_eq!(
        joiner_c.join(id, join_c.as_bytes().to_vec()).await,
        Err(ErrorCode::NotPermitted)
    );

    // The joiner's long poll is woken by the ACCEPT.
    let accept = PairingMessage::accept(&identity_a, &invite, &join_b).unwrap();
    let (polled, sent) = tokio::join!(joiner_b.recv(id, 0, 20_000), async {
        // Let the long poll reach the server first; it is answered either way.
        tokio::time::sleep(Duration::from_millis(100)).await;
        inviter.send(id, accept.encode()).await
    });
    assert_eq!(sent.unwrap().seq, 1);
    let view = polled.unwrap();
    assert_eq!(view.stage, Stage::Admitted);
    assert_eq!(view.peer, Some(actor_b_public));
    assert_eq!(view.messages.len(), 1);
    let received = PairingMessage::decode(&view.messages[0].data).unwrap();
    verify_accept(&invite, &join_b, &received).unwrap();

    // Both sides derive the same PSK.
    let (i_a, i_b) = (invite.record().identity(), join_b.record().identity());
    let psk_a = pairing_psk(
        &E_A,
        join_b.ephemeral(),
        i_a,
        i_b,
        &invite.hash(),
        &join_b.hash(),
    )
    .unwrap();
    let psk_b = pairing_psk(
        &E_B,
        invite.ephemeral(),
        i_a,
        i_b,
        &invite.hash(),
        &join_b.hash(),
    )
    .unwrap();
    assert_eq!(*psk_a, *psk_b);

    // Step 5: the joiner sends COMPLETE and closes; the inviter reads it and closes.
    let complete = joiner_b
        .send(id, PairingMessage::Complete.encode())
        .await
        .unwrap();
    assert_eq!(complete.seq, 1);
    joiner_b.close(id).await.unwrap();
    let view = inviter.recv(id, 0, 20_000).await.unwrap();
    assert_eq!(view.stage, Stage::Closing);
    assert_eq!(
        PairingMessage::decode(&view.messages[0].data).unwrap(),
        PairingMessage::Complete
    );
    inviter.close(id).await.unwrap();

    // The mailbox is gone for both sides.
    assert_eq!(inviter.recv(id, 0, 0).await, Err(ErrorCode::UnknownMailbox));
    assert_eq!(
        joiner_b.recv(id, 0, 0).await,
        Err(ErrorCode::UnknownMailbox)
    );
    assert_eq!(
        joiner_c.lookup(&opened.digits).await,
        Err(ErrorCode::InvalidCode)
    );
    mock.stop().await;
}
