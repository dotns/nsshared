use keynet_proto::{RegionChannel, RegionFrameType};

#[test]
fn control_hello_is_not_legal_after_handshake() {
    assert!(
        !RegionFrameType::Hello.is_legal_after_hello_on(RegionChannel::Control),
        "HELLO is only legal as the first frame on a control channel"
    );
}
