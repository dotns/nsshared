use keynet_proto::{
    Intro, IntroductionValidationError, PairingToken, PairingTokenDecodeError,
    PairingTokenTextError,
};

fn fixture_field<'a>(fixture: &'a str, name: &str) -> &'a str {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .expect("fixture field exists")
}

fn bytes(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                .expect("hex byte")
        })
        .collect()
}

#[test]
fn token_decoder_refutes_noncanonical_shapes_and_widths() {
    let fixture = include_str!("fixtures/keynet-v1/pairing_tokens.vec");
    let valid = bytes(fixture_field(fixture, "signed"));
    assert!(PairingToken::decode(&valid).is_ok());
    let binding = bytes(fixture_field(fixture, "binding"));
    let binding_offset = valid
        .windows(binding.len())
        .position(|window| window == binding)
        .expect("nested binding exists");

    let mut cases = Vec::new();
    let mut nested_bstr = valid.clone();
    nested_bstr[binding_offset] = 0x58;
    cases.push(nested_bstr);
    let mut wrong_key_width = valid.clone();
    wrong_key_width[2] = 0x1f;
    cases.push(wrong_key_width);
    let mut wrong_key_type = valid.clone();
    wrong_key_type[1] = 0x61;
    cases.push(wrong_key_type);
    let mut invalid_utf8 = valid.clone();
    invalid_utf8[36] = 0xff;
    cases.push(invalid_utf8);
    let mut trailing = valid.clone();
    trailing.push(0xf6);
    cases.push(trailing);
    cases.push([&[0x9f][..], &valid[1..]].concat());
    cases.push([&[0x8b][..], &valid[1..]].concat());
    cases.push([&[0x98, 0x0c][..], &valid[1..]].concat());
    cases.push([&[0x8c, 0x18, 0x01][..], &valid[2..]].concat());
    cases.extend([vec![0xa0], vec![0xc0, 0x80], vec![0xf9, 0x00, 0x00]]);

    for malformed in cases {
        assert!(matches!(
            PairingToken::decode(&malformed),
            Err(PairingTokenDecodeError::InvalidEncoding)
        ));
    }
}

#[test]
fn token_text_refutes_nonzero_unused_bits_and_trailing_data() {
    assert_eq!(
        PairingToken::from_text("kn1AB"),
        Err(PairingTokenTextError::InvalidText)
    );
    let fixture = include_str!("fixtures/keynet-v1/pairing_tokens.vec");
    let text = String::from_utf8(bytes(fixture_field(fixture, "text_hex"))).expect("text UTF-8");
    assert!(PairingToken::from_text(&text).is_ok());
    assert!(PairingToken::from_text(&format!("{text}AA")).is_err());
}

#[test]
fn intro_mac_refutes_token_id_omission() {
    let fixture = include_str!("fixtures/keynet-v1/introductions.vec");
    let mut intro = Intro::decode(&bytes(fixture_field(fixture, "intro"))).expect("literal INTRO");
    let secret: [u8; 32] = bytes(fixture_field(fixture, "secret"))
        .try_into()
        .expect("secret width");
    intro.token_id[0] ^= 1;
    let changed_token_id = intro.token_id;
    assert_eq!(
        intro.validate(
            &secret,
            &intro.network_id,
            &intro.recipient,
            &changed_token_id,
            500
        ),
        Err(IntroductionValidationError::InvalidMac)
    );
}

#[test]
fn introduction_decoder_refutes_wrong_counts_types_widths_and_trailing_bytes() {
    let fixture = include_str!("fixtures/keynet-v1/introductions.vec");
    let valid = bytes(fixture_field(fixture, "intro"));
    let mut wrong_type = valid.clone();
    wrong_type[1] = 0x61;
    let mut wrong_width = valid.clone();
    wrong_width[2] = 0x1f;
    let mut trailing = valid.clone();
    trailing.push(0);
    for malformed in [
        wrong_type,
        wrong_width,
        trailing,
        [&[0x85][..], &valid[1..]].concat(),
        [&[0x9f][..], &valid[1..]].concat(),
        [&[0x98, 0x06][..], &valid[1..]].concat(),
    ] {
        assert!(Intro::decode(&malformed).is_err());
    }
}
