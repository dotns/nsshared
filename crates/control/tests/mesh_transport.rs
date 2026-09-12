use control::envelope::{ControlEnvelope, DOMAIN_REQUEST, DOMAIN_RESPONSE};
use control::mesh::{self, Error, WssFrame};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

fn envelope(domain: &[u8], machine_id: Option<String>) -> ControlEnvelope {
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut result = ControlEnvelope {
        v: 1,
        api: "mesh.register".into(),
        ts: 100,
        nonce: [2; 16],
        machine_id,
        machine_key_pub: key.verifying_key().to_bytes(),
        payload: vec![0xa1, 0x00, 0x01].into(),
        signature: [0; 64],
    };
    // Independent construction protects the existing envelope signature format.
    let mut input = domain.to_vec();
    input.push(1);
    input.extend_from_slice(&13_u32.to_be_bytes());
    input.extend_from_slice(b"mesh.register");
    input.extend_from_slice(&100_u64.to_be_bytes());
    input.extend_from_slice(&[2; 16]);
    match result.machine_id.as_deref() {
        Some(id) => {
            input.push(1);
            input.extend_from_slice(&u32::try_from(id.len()).unwrap().to_be_bytes());
            input.extend_from_slice(id.as_bytes());
        }
        None => input.push(0),
    }
    input.extend_from_slice(&result.machine_key_pub);
    input.extend_from_slice(&Sha256::digest([0xa1, 0x00, 0x01]));
    result.signature = key.sign(&input).to_bytes();
    result
}

#[test]
fn mesh_udp_size_and_magic_boundaries() {
    let body = vec![0; 1192];
    let encoded = mesh::encode_udp(&body).unwrap();
    assert_eq!(encoded.len(), 1200);
    assert_eq!(&encoded[..8], b"NSGWMSH1");
    assert_eq!(mesh::decode_udp(&encoded).unwrap(), body);
    assert!(matches!(mesh::encode_udp(&[0; 1193]), Err(Error::TooLarge)));
    let mut oversized = encoded;
    oversized.push(0);
    assert!(matches!(mesh::decode_udp(&oversized), Err(Error::TooLarge)));
    for invalid in [&b""[..], &b"NSGWMSH1"[..], &b"NSGWGRS1x"[..]] {
        assert!(mesh::decode_udp(invalid).is_err());
    }
}

#[test]
fn mesh_wss_has_separate_control_and_wg_limits() {
    let control = vec![0; 1198];
    let encoded = mesh::encode_wss(WssFrame::Control(&control), 1500).unwrap();
    assert_eq!(encoded.len(), 1200);
    assert_eq!(&encoded[..2], &[1, 1]);
    assert_eq!(
        mesh::decode_wss(&encoded, 1500).unwrap(),
        WssFrame::Control(&control)
    );
    assert!(mesh::encode_wss(WssFrame::Control(&[0; 1199]), 1500).is_err());
    let mut oversized = encoded;
    oversized.push(0);
    assert!(matches!(
        mesh::decode_wss(&oversized, 1500),
        Err(Error::TooLarge)
    ));

    let data = vec![4; 1500];
    let wireguard = WssFrame::WireGuard {
        source_wg: &[3; 32],
        destination_wg: &[4; 32],
        datagram: &data,
    };
    let encoded = mesh::encode_wss(wireguard, 1500).unwrap();
    assert_eq!(encoded.len(), 1566);
    assert_eq!(&encoded[..2], &[1, 2]);
    assert_eq!(&encoded[2..34], &[3; 32]);
    assert_eq!(&encoded[34..66], &[4; 32]);
    assert_eq!(
        mesh::decode_wss(&encoded, 1500).unwrap(),
        WssFrame::WireGuard {
            source_wg: &[3; 32],
            destination_wg: &[4; 32],
            datagram: &data,
        }
    );
    assert!(matches!(
        mesh::decode_wss(&encoded, 1499),
        Err(Error::TooLarge)
    ));
    for invalid in [
        vec![],
        vec![1],
        vec![1, 1],
        vec![1, 3, 0],
        vec![2, 1, 0],
        vec![1, 2, 0],
    ] {
        assert!(mesh::decode_wss(&invalid, 1500).is_err());
    }
}

#[test]
fn mesh_live_time_boundaries_do_not_renew_history() {
    assert!(mesh::validate_live_credential(100, 160, 159, 160).is_ok());
    assert!(mesh::validate_live_credential(100, 160, 40, 160).is_ok());
    for (issued, expiry, now, deadline) in [
        (100, 160, 160, 160),
        (100, 160, 39, 160),
        (100, 160, 100, 159),
        (100, 100, 100, 160),
        (100, 161, 100, 200),
        (u64::MAX, u64::MAX, u64::MAX, u64::MAX),
    ] {
        assert!(mesh::validate_live_credential(issued, expiry, now, deadline).is_err());
    }
    let original = envelope(DOMAIN_REQUEST, None);
    assert!(mesh::verify_request(&original, 161).is_err());
    assert!(mesh::verify_historical_request(&original).is_ok());
    assert!(mesh::validate_lifetime(100, 160).is_ok());
}

#[test]
fn mesh_signatures_bind_domain_identity_and_original_payload() {
    let request = envelope(DOMAIN_REQUEST, None);
    assert!(mesh::verify_request(&request, 100).is_ok());
    assert!(mesh::verify_response(&request, 100, &request.machine_key_pub).is_err());
    for field in 0..6 {
        let mut tampered = request.clone();
        match field {
            0 => tampered.ts += 1,
            1 => tampered.nonce[0] ^= 1,
            2 => tampered.machine_key_pub[0] ^= 1,
            3 => tampered.payload = vec![0xa1, 0x00, 0x02].into(),
            4 => tampered.api = "mesh.unbind".into(),
            _ => tampered.signature[0] ^= 1,
        }
        assert!(mesh::verify_historical_request(&tampered).is_err());
    }
    let response = envelope(DOMAIN_RESPONSE, None);
    assert!(mesh::verify_response(&response, 100, &response.machine_key_pub).is_ok());
    assert!(mesh::verify_response(&response, 100, &[8; 32]).is_err());
    assert!(mesh::verify_request(&response, 100).is_err());
    let managed = envelope(DOMAIN_REQUEST, Some("managed".into()));
    assert!(managed.verify_request(100).is_ok());
    assert!(matches!(
        mesh::verify_request(&managed, 100),
        Err(Error::Identity)
    ));
    let mut cookie = request;
    cookie.api = "mesh.cookie".into();
    assert!(matches!(
        mesh::verify_request(&cookie, 100),
        Err(Error::Identity)
    ));
}
