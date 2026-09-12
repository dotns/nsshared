use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use ring::{hmac, rand::SecureRandom};

use super::codec::{Field, payload};
use super::{Error, validate_relay_origin};

const CHALLENGE_TTL: Duration = Duration::from_secs(30);

/// Public, stable request fields authenticated by the relay's runtime cookie key.
#[derive(Clone, Debug)]
pub struct CookieBinding {
    pub source: SocketAddr,
    pub joiner_pub: [u8; 32],
    pub request_id: [u8; 16],
    pub expires_at: u64,
}

pub struct CookieKey(hmac::Key);

impl CookieKey {
    /// Create a fresh key for each relay process; never restore it from durable state.
    pub fn generate() -> Result<Self, Error> {
        let mut secret = [0; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| Error::Payload("cookie entropy"))?;
        Ok(Self(hmac::Key::new(hmac::HMAC_SHA256, &secret)))
    }

    pub fn issue(&self, binding: &CookieBinding, now: u64) -> Result<[u8; 16], Error> {
        if now >= binding.expires_at {
            return Err(Error::Expired);
        }
        Ok(self.for_bucket(binding, now / 30))
    }

    pub fn verify(
        &self,
        binding: &CookieBinding,
        now: u64,
        cookie: &[u8; 16],
    ) -> Result<(), Error> {
        if now >= binding.expires_at {
            return Err(Error::Expired);
        }
        let current = now / 30;
        for bucket in [Some(current), current.checked_sub(1)]
            .into_iter()
            .flatten()
        {
            let expected = self.for_bucket(binding, bucket);
            // Authenticate both truncated tags again to use ring's constant-time verifier.
            let tag = hmac::sign(&self.0, &expected);
            if hmac::verify(&self.0, cookie, tag.as_ref()).is_ok() {
                return Ok(());
            }
        }
        Err(Error::Payload("cookie authentication"))
    }

    fn for_bucket(&self, binding: &CookieBinding, bucket: u64) -> [u8; 16] {
        let mut input = b"nsmesh-cookie-v1\0".to_vec();
        match binding.source.ip() {
            IpAddr::V4(ip) => {
                input.push(4);
                input.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                input.push(6);
                input.extend_from_slice(&ip.octets());
            }
        }
        input.extend_from_slice(&binding.source.port().to_be_bytes());
        binding.joiner_pub.sign_into(&mut input);
        binding.request_id.sign_into(&mut input);
        binding.expires_at.sign_into(&mut input);
        bucket.sign_into(&mut input);
        let tag = hmac::sign(&self.0, &input);
        let mut cookie = [0; 16];
        cookie.copy_from_slice(&tag.as_ref()[..16]);
        cookie
    }
}

payload!(WssHello, "", {
    1_u64 => challenge: [u8; 32], 2_u64 => origin: String,
    3_u64 => signer_pub: [u8; 32], 4_u64 => wg_pub: [u8; 32],
    5_u64 => signature: [u8; 64],
});

impl WssHello {
    fn validate(&self) -> Result<(), Error> {
        validate_relay_origin(&self.origin)?;
        if !self.origin.starts_with("wss://") {
            return Err(Error::Payload("WSS origin"));
        }
        Ok(())
    }

    pub fn signing_input(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut input = b"nsmesh-wss-v1\0".to_vec();
        self.challenge.sign_into(&mut input);
        self.origin.sign_into(&mut input);
        self.signer_pub.sign_into(&mut input);
        self.wg_pub.sign_into(&mut input);
        Ok(input)
    }
}

/// Owned by exactly one connection; every verification attempt consumes the challenge.
pub struct WssChallenge {
    nonce: [u8; 32],
    origin: String,
    issued_at: Instant,
}

impl WssChallenge {
    pub fn generate(origin: String, now: Instant) -> Result<Self, Error> {
        validate_relay_origin(&origin)?;
        if !origin.starts_with("wss://") {
            return Err(Error::Payload("WSS origin"));
        }
        let mut nonce = [0; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| Error::Payload("WSS entropy"))?;
        Ok(Self {
            nonce,
            origin,
            issued_at: now,
        })
    }

    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    pub fn verify(self, hello: &WssHello, now: Instant) -> Result<(), Error> {
        let elapsed = now
            .checked_duration_since(self.issued_at)
            .ok_or(Error::Expired)?;
        if elapsed >= CHALLENGE_TTL {
            return Err(Error::Expired);
        }
        if hello.challenge != self.nonce || hello.origin != self.origin {
            return Err(Error::Payload("WSS challenge binding"));
        }
        super::recovery::verify(&hello.signer_pub, &hello.signing_input()?, &hello.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_cookie_matches_independent_hmac_input() {
        let key = CookieKey(hmac::Key::new(hmac::HMAC_SHA256, &[7; 32]));
        let binding = CookieBinding {
            source: SocketAddr::from(([192, 0, 2, 1], 51900)),
            joiner_pub: [1; 32],
            request_id: [2; 16],
            expires_at: 120,
        };
        let mut expected = b"nsmesh-cookie-v1\0".to_vec();
        expected.extend_from_slice(&[4, 192, 0, 2, 1, 0xca, 0xbc]);
        expected.extend_from_slice(&[1; 32]);
        expected.extend_from_slice(&[2; 16]);
        expected.extend_from_slice(&120_u64.to_be_bytes());
        expected.extend_from_slice(&2_u64.to_be_bytes());
        let mac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &[7; 32]), &expected);
        assert_eq!(
            hex::encode(&mac.as_ref()[..16]),
            "99c7390cfd81c669a09ce81c0732d8a3"
        );
        assert_eq!(
            key.issue(&binding, 60).ok().as_ref().map(|v| &v[..]),
            Some(&mac.as_ref()[..16])
        );
    }
}
