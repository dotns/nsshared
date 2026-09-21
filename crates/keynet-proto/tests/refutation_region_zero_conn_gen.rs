use keynet_proto::{RegionChannel, RegionFrame, RegionHello};

#[test]
fn hello_encoder_rejects_zero_connection_generation() {
    let hello = RegionFrame::Hello(RegionHello {
        region_name: "relay-a".to_owned(),
        member_id: 1,
        boot_epoch: 2,
        channel: RegionChannel::Control,
        conn_gen: 0,
    });

    assert!(
        hello.encode(RegionChannel::Control).is_err(),
        "HELLO connection generation zero is reserved"
    );
}

#[test]
fn hello_decoder_rejects_zero_connection_generation() {
    let encoded = [
        0x00, 0x00, 0x00, 0x10, 0x83, 0x01, 0x01, 0x85, 0x67, b'r', b'e', b'l', b'a', b'y', b'-',
        b'a', 0x01, 0x02, 0x00, 0x00,
    ];

    assert!(
        RegionFrame::decode(&encoded, RegionChannel::Control).is_err(),
        "HELLO connection generation zero is reserved"
    );
}
