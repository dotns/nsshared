use control::mesh::*;

#[test]
fn mesh_fingerprints_and_addresses_match_independent_blake2s_vectors() {
    // Independently generated with Python hashlib.blake2s using output sizes 20/15/4.
    let vectors = [
        (
            0,
            "697852a179fd1670c9609b848d27ab8c045b1b2a",
            "fd2b6640316faf51916c611251dcb132",
            [[0xde, 0x69], [0x8c, 0x25], [0x3d, 0xcd]],
        ),
        (
            1,
            "7d160788e34b0db5fcc780222bb81ee54fd1b4c8",
            "fde90db957f27a60226d1fb47f68e907",
            [[0x06, 0x48], [0x94, 0xed], [0xeb, 0xa5]],
        ),
        (
            255,
            "29970bdaef6e9944b7fe9b2cee4b1e45b21949bb",
            "fd901ccccf9506274bf5f68894abf33a",
            [[0x7c, 0x9b], [0x66, 0x59], [0x31, 0xf2]],
        ),
    ];
    for (byte, id, v6, v4) in vectors {
        let key = [byte; 32];
        assert_eq!(hex::encode(member_id(&key)), id);
        assert_eq!(fingerprint(&key), format!("0x{id}"));
        assert_eq!(
            parse_fingerprint(&fingerprint(&key)).unwrap(),
            member_id(&key)
        );
        assert_eq!(hex::encode(overlay_ipv6(&key)), v6);
        for (salt, suffix) in [0, 1, u32::MAX].into_iter().zip(v4) {
            let expected = [100, 100, suffix[0], suffix[1]];
            assert_eq!(overlay_ipv4(&key, salt).unwrap(), expected);
            let addrs = derive_overlay_addresses(&key, salt).unwrap();
            assert_eq!(addrs.v4, expected);
            assert_eq!(addrs.v4_salt, u64::from(salt));
            verify_overlay_addresses(&key, &addrs).unwrap();
        }
    }
}

#[test]
fn mesh_fingerprint_and_address_bindings_reject_ambiguous_values() {
    for invalid in [
        "0x1234",
        "0X697852a179fd1670c9609b848d27ab8c045b1b2a",
        "0x697852A179fd1670c9609b848d27ab8c045b1b2a",
        "697852a179fd1670c9609b848d27ab8c045b1b2a",
        "0x697852a179fd1670c9609b848d27ab8c045b1b2g",
    ] {
        assert!(parse_fingerprint(invalid).is_err());
    }
    let key = [1; 32];
    for field in 0..4 {
        let mut addrs = derive_overlay_addresses(&key, 0).unwrap();
        match field {
            0 => addrs.v4[3] ^= 1,
            1 => addrs.v6[15] ^= 1,
            2 => addrs.v4_salt += 1,
            _ => addrs.v4_salt = u64::from(u32::MAX) + 1,
        }
        assert!(verify_overlay_addresses(&key, &addrs).is_err());
        if field == 3 {
            assert!(addrs.encode().is_err());
        }
    }
    assert!(
        verify_overlay_addresses(&[2; 32], &derive_overlay_addresses(&key, 0).unwrap()).is_err()
    );
    let mut encoded = derive_overlay_addresses(&key, u32::MAX)
        .unwrap()
        .encode()
        .unwrap();
    let index = encoded
        .windows(5)
        .position(|b| b == [0x1a, 255, 255, 255, 255])
        .unwrap();
    encoded.splice(index..index + 5, [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
    assert!(OverlayAddresses::decode(&encoded).is_err());
}

#[test]
fn mesh_address_allocation_bounds_attempts_and_collision_order() {
    assert!(overlay_ipv4(&[0; 32], 73198).is_err());
    assert!(overlay_ipv4(&[0; 32], 238339).is_err());
    assert_eq!(
        allocate_overlay_addresses(&[0; 32], 73198, |_| false)
            .unwrap()
            .v4_salt,
        73199
    );
    let mut attempts = 0;
    let value = allocate_overlay_addresses(&[1; 32], 0, |_| {
        attempts += 1;
        attempts < 4
    })
    .unwrap();
    assert_eq!(attempts, 4);
    assert_eq!(value.v4_salt, 3);
    let mut attempts = 0;
    assert!(
        allocate_overlay_addresses(&[1; 32], 0, |_| {
            attempts += 1;
            true
        })
        .is_err()
    );
    assert_eq!(attempts, 4);
    let mut attempts = 0;
    assert!(
        allocate_overlay_addresses(&[1; 32], u32::MAX, |_| {
            attempts += 1;
            true
        })
        .is_err()
    );
    assert_eq!(attempts, 1);
    assert!(must_yield_collision(2, &[0; 32], 1, &[255; 32]));
    assert!(must_yield_collision(1, &[2; 32], 1, &[1; 32]));
    assert!(!must_yield_collision(1, &[1; 32], 1, &[2; 32]));
    assert!(!must_yield_collision(1, &[1; 32], 1, &[1; 32]));
}
