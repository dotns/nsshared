#![allow(clippy::unwrap_used)]

use nsshared_codec::{base64::encode_base64url, cbor::CborWriter};
use nsshared_control::{
    account::control::BootstrapDiscovery, account::control::BootstrapEndpoint,
    account::control::BootstrapError, account::control::ConfidentialCarrier,
};

fn discovery() -> BootstrapDiscovery {
    let pin = encode_base64url(&[7; 32]);
    BootstrapDiscovery {
        https_origin: "https://control.example/".to_owned(),
        endpoints: vec![
            BootstrapEndpoint {
                kind: ConfidentialCarrier::Https,
                origin: "https://control.example/".to_owned(),
            },
            BootstrapEndpoint {
                kind: ConfidentialCarrier::Noise,
                origin: "noise://control.example:8443/".to_owned(),
            },
            BootstrapEndpoint {
                kind: ConfidentialCarrier::Quic,
                origin: "quic://control.example:8444/".to_owned(),
            },
        ],
        noise_key: Some([3; 32]),
        quic_spki_pins: vec![pin.clone()],
        envelope_pins: vec![pin],
    }
}

fn publication(value: &BootstrapDiscovery) -> Vec<u8> {
    let mut output = CborWriter::default();
    output
        .array(8)
        .uint(1)
        .uint(1)
        .text(&value.https_origin)
        .array(1)
        .uint(1)
        .array(value.endpoints.len());
    for endpoint in &value.endpoints {
        output
            .array(2)
            .uint(endpoint.kind as u64)
            .text(&endpoint.origin);
    }
    output.bytes(&value.noise_key.unwrap());
    for pins in [&value.quic_spki_pins, &value.envelope_pins] {
        output.array(pins.len());
        for pin in pins {
            output.text(pin);
        }
    }
    output.into_bytes()
}

fn set_host(value: &mut BootstrapDiscovery, site: usize, host: &str) {
    match site {
        0 => value.https_origin = format!("https://{host}/"),
        1 => value.endpoints[0].origin = format!("https://{host}/"),
        2 => value.endpoints[1].origin = format!("noise://{host}:8443/"),
        3 => value.endpoints[2].origin = format!("quic://{host}:8444/"),
        _ => unreachable!(),
    }
}

#[test]
fn ascii_idna_origins_reject_invalid_a_labels() {
    for host in ["control.example", "xn--bcher-kva.example"] {
        for site in 0..4 {
            let mut value = discovery();
            set_host(&mut value, site, host);
            let raw = publication(&value);
            assert_eq!(value.canonical().unwrap(), raw);
            assert_eq!(BootstrapDiscovery::decode(&raw).unwrap(), value);
            assert!(
                value
                    .first_supported(&[ConfidentialCarrier::Https])
                    .unwrap()
                    .is_some()
            );
            assert!(value.effective_envelope_pins(&[]).is_ok());
        }
    }

    // These A-labels respectively encode a forbidden control character, an
    // incomplete Punycode sequence, and forbidden control characters.
    let mut unexpected = Vec::new();
    for host in ["xn--a.example", "xn--0.example", "xn--abc.example"] {
        for site in 0..4 {
            let mut value = discovery();
            set_host(&mut value, site, host);
            let refusals = [
                matches!(
                    BootstrapDiscovery::decode(&publication(&value)),
                    Err(BootstrapError::Origin)
                ),
                matches!(value.canonical(), Err(BootstrapError::Origin)),
                matches!(
                    value.first_supported(&[ConfidentialCarrier::Https]),
                    Err(BootstrapError::Origin)
                ),
                matches!(
                    value.effective_envelope_pins(&[]),
                    Err(BootstrapError::Origin)
                ),
            ];
            if refusals != [true; 4] {
                unexpected.push((host, site, refusals));
            }
        }
    }
    assert!(
        unexpected.is_empty(),
        "invalid IDNA origins accepted by decode/encode/select/pins: {unexpected:?}"
    );
}
