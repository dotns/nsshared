use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{Error, Hello, Role, SealedToken};

/// Endpoint-only ephemeral private key. Never serialized, Debugged or sent to IPC.
pub struct Ephemeral(StaticSecret);

impl Ephemeral {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self(StaticSecret::from(crate::random::<32>()?)))
    }

    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.0).to_bytes()
    }

    fn cipher(
        &self,
        inviter: &Hello,
        joiner: &Hello,
    ) -> Result<(XChaCha20Poly1305, Vec<u8>), Error> {
        if inviter.role != Role::Invite
            || joiner.role != Role::Join
            || inviter.session != joiner.session
            || inviter.authority != joiner.authority
            || inviter.expires != joiner.expires
            || inviter.identity == joiner.identity
        {
            return Err(Error::Encryption);
        }
        let peer = if self.public() == inviter.ephemeral {
            joiner.ephemeral
        } else if self.public() == joiner.ephemeral {
            inviter.ephemeral
        } else {
            return Err(Error::Encryption);
        };
        let shared = self.0.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(Error::Encryption);
        }
        let transcript = serde_json::to_vec(&(inviter, joiner)).map_err(|_| Error::Encryption)?;
        let mut key = Zeroizing::new([0_u8; 32]);
        Hkdf::<Sha256>::new(Some(b"ns-quick-token-v1"), shared.as_bytes())
            .expand(&transcript, key.as_mut())
            .map_err(|_| Error::Encryption)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Encryption)?;
        Ok((cipher, transcript))
    }

    pub fn seal(&self, inviter: &Hello, joiner: &Hello, token: &str) -> Result<SealedToken, Error> {
        if self.public() != inviter.ephemeral || token.len() > 2048 {
            return Err(Error::Encryption);
        }
        let (cipher, aad) = self.cipher(inviter, joiner)?;
        let nonce = crate::random()?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: token.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Encryption)?;
        Ok(SealedToken { nonce, ciphertext })
    }

    pub fn open(
        &self,
        inviter: &Hello,
        joiner: &Hello,
        sealed: &SealedToken,
    ) -> Result<Zeroizing<String>, Error> {
        if self.public() != joiner.ephemeral || sealed.ciphertext.len() > 2064 {
            return Err(Error::Encryption);
        }
        let (cipher, aad) = self.cipher(inviter, joiner)?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(sealed.nonce),
                    Payload {
                        msg: &sealed.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::Encryption)?,
        );
        let text = std::str::from_utf8(&plain).map_err(|_| Error::Encryption)?;
        Ok(Zeroizing::new(text.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hello(role: Role, key: &Ephemeral, identity: u8) -> Hello {
        Hello {
            version: 1,
            session: [1; 16],
            role,
            identity: [identity; 32],
            ephemeral: key.public(),
            authority: "relay.example:443".into(),
            expires: 900,
        }
    }
    #[test]
    fn token_is_bound_to_roles_identities_session_relay_and_ephemeral_keys() {
        let a = Ephemeral::generate().unwrap();
        let b = Ephemeral::generate().unwrap();
        let offer = hello(Role::Invite, &a, 2);
        let recipient = hello(Role::Join, &b, 3);
        let sealed = a.seal(&offer, &recipient, "kn1-private-token").unwrap();
        assert_eq!(
            &*b.open(&offer, &recipient, &sealed).unwrap(),
            "kn1-private-token"
        );
        assert!(!format!("{sealed:?}").contains("private-token"));
        let mut changed = recipient.clone();
        changed.identity[0] ^= 1;
        assert!(b.open(&offer, &changed, &sealed).is_err());
        changed = recipient.clone();
        changed.session[0] ^= 1;
        assert!(b.open(&offer, &changed, &sealed).is_err());
        changed = recipient.clone();
        changed.authority = "other.example:443".into();
        assert!(b.open(&offer, &changed, &sealed).is_err());
        let mut bad = sealed.clone();
        bad.ciphertext[0] ^= 1;
        assert!(b.open(&offer, &recipient, &bad).is_err());
        assert!(a.open(&offer, &recipient, &sealed).is_err());
    }
}
