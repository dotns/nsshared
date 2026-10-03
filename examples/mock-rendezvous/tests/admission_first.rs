//! `admission = first` over the mock (rendezvous §5.3, §6): `join`
//! admits at once and unindexes the digits, rejecting the peer reopens the mailbox
//! under the same digits, and the third peer reject closes it.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

mod support;

use nsshared_proto::rendezvous::{
    error::ErrorCode,
    message::{Admission, Kind, OpenRequest, RejectRequest, Stage},
    transport::Request,
};
use support::{Mock, key, ok, relaxed_limits};

#[tokio::test]
async fn first_admission_and_peer_rejects() {
    let mock = Mock::start(relaxed_limits()).await;
    let owner_key = key(1);
    let mut owner = mock.actor(&owner_key).await;
    let opened = owner
        .open(OpenRequest {
            kind: Kind::parse("test").unwrap(),
            ttl: 300,
            admission: Admission::First,
            candidates: 1,
            intro: b"intro-a".to_vec(),
        })
        .await;
    let id = opened.id;
    let mut observer = mock.actor(&key(9)).await;

    for (round, seed) in [2_u8, 3, 4].into_iter().enumerate() {
        let peer_key = key(seed);
        let peer_public = peer_key.verifying_key().to_bytes();
        let mut peer = mock.actor(&peer_key).await;

        // The digits locate the open mailbox, the same one every round.
        let found = peer.lookup(&opened.digits).await.unwrap();
        assert_eq!((found.id, found.kind.as_str()), (id, "test"));
        assert_eq!(found.intro, b"intro-a");

        // `join` admits immediately and the digits stop resolving.
        peer.join(id, b"intro-b".to_vec()).await.unwrap();
        assert_eq!(
            observer.lookup(&opened.digits).await,
            Err(ErrorCode::InvalidCode)
        );
        let view = owner.recv(id, 0, 0).await.unwrap();
        assert_eq!(
            (view.stage, view.peer),
            (Stage::Admitted, Some(peer_public))
        );
        assert!(view.waiting.is_empty());

        let reject = Request::Reject(RejectRequest {
            id,
            actor: peer_public,
        });
        ok(owner.request(&reject).await).unwrap();
        if round < 2 {
            // Back to `open` with the same digits.
            let view = owner.recv(id, 0, 0).await.unwrap();
            assert_eq!((view.stage, view.peer), (Stage::Open, None));
            assert_eq!(observer.lookup(&opened.digits).await.unwrap().id, id);
        } else {
            // The third peer reject closes the mailbox.
            assert_eq!(owner.recv(id, 0, 0).await, Err(ErrorCode::UnknownMailbox));
            assert_eq!(
                observer.lookup(&opened.digits).await,
                Err(ErrorCode::InvalidCode)
            );
        }
    }
    mock.stop().await;
}
