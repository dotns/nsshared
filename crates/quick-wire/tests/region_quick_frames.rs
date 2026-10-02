use quick_wire::{
    CONTROL_REGION_FRAME_TYPES, MAX_REGION_FRAME_BYTES, MAX_REGION_QUICK_ACTOR_BYTES,
    MAX_REGION_QUICK_FRAME_BYTES, MAX_REGION_QUICK_MESSAGE_BYTES,
    REGION_CAPABILITY_QUICK_FORWARDING, RegionChannel, RegionDecodeError, RegionEncodeError,
    RegionFrame, RegionFrameType, RegionHello, RegionHelloExtension, RegionQuickRequest,
    RegionQuickResponse, RegionQuickStatus, decode_region_frame_prefix,
    decode_region_quick_frame_prefix,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

const REGION_QUICK_FRAME_CASES: &str = "hello_control_extended,hello_control_unknown_capabilities,hello_control_legacy,hello_data_legacy,hello_data_extended,hello_owner_zero,hello_owner_seventeen,hello_epoch_zero,hello_extension_short,hello_extension_long,hello_seven_fields,quick_request_ipv4,quick_request_ipv6_actor,quick_response_completed,quick_response_not_owner,quick_response_busy,quick_request_data_channel,quick_response_data_channel,quick_request_before_hello,quick_response_before_hello,quick_request_zero_id,quick_response_zero_id,quick_request_address_empty,quick_request_address_3,quick_request_address_5,quick_request_address_15,quick_request_address_17,quick_request_challenge_31,quick_response_status_zero,quick_response_status_four,quick_response_not_owner_actor,quick_response_not_owner_response,quick_response_busy_actor,quick_response_busy_response,quick_request_actor_limit,quick_request_actor_over,quick_response_actor_limit,quick_response_actor_over,quick_payload_limit,quick_frame_limit";

/// The value of `quick_rendezvous::MAX_MESSAGE_BYTES`, restated without depending on that crate.
const QUICK_MESSAGE_BYTES: usize = 16 * 1024;
/// The actor bound: the largest compact JSON `quick_rendezvous::Hello` (687 bytes) rounded up to the
/// next power of two.
const QUICK_ACTOR_BYTES: usize = 1024;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keynet-region-quick-v1")
}

fn blocks(text: &str) -> Result<Vec<BTreeMap<&str, &str>>, String> {
    text.split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .map(|block| {
            let mut fields = BTreeMap::new();
            for line in block.lines().filter(|line| !line.starts_with('#')) {
                let (key, value) = line
                    .split_once('=')
                    .ok_or_else(|| "invalid region quick frame vector line".to_owned())?;
                if fields.insert(key, value).is_some() {
                    return Err(format!("duplicate region quick frame vector field: {key}"));
                }
            }
            Ok(fields)
        })
        .collect()
}

fn vectors() -> Result<BTreeMap<String, BTreeMap<String, String>>, String> {
    let text = fs::read_to_string(fixture_root().join("region_quick_frames.vec"))
        .map_err(|error| error.to_string())?;
    let mut output = BTreeMap::new();
    for block in blocks(&text)? {
        let case = block
            .get("case")
            .ok_or_else(|| "missing region quick frame case".to_owned())?;
        let fields = block
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        if output.insert((*case).to_owned(), fields).is_some() {
            return Err(format!("duplicate region quick frame case: {case}"));
        }
    }
    Ok(output)
}

fn field<'a>(vector: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    vector
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("missing region quick frame vector field: {name}"))
}

fn vector_frame(case: &str) -> Result<Vec<u8>, String> {
    let vectors = vectors()?;
    let vector = vectors
        .get(case)
        .ok_or_else(|| format!("missing region quick frame case: {case}"))?;
    hex_bytes(field(vector, "frame")?)
}

fn hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    if !input.len().is_multiple_of(2) {
        return Err("odd region quick frame vector hex length".to_owned());
    }
    (0..input.len() / 2)
        .map(|index| {
            u8::from_str_radix(&input[index * 2..index * 2 + 2], 16)
                .map_err(|error| error.to_string())
        })
        .collect()
}

fn channel(input: &str) -> Result<RegionChannel, String> {
    match input {
        "control" => Ok(RegionChannel::Control),
        "data" => Ok(RegionChannel::Data),
        _ => Err("invalid region quick frame vector channel".to_owned()),
    }
}

fn frame_type_name(frame_type: RegionFrameType) -> &'static str {
    match frame_type {
        RegionFrameType::Hello => "hello",
        RegionFrameType::QuickRequest => "quick_request",
        RegionFrameType::QuickResponse => "quick_response",
        _ => "other",
    }
}

fn decode_error_name(error: RegionDecodeError) -> &'static str {
    match error {
        RegionDecodeError::IncompletePrefix => "IncompletePrefix",
        RegionDecodeError::InvalidPrefix => "InvalidPrefix",
        RegionDecodeError::InvalidLength => "InvalidLength",
        RegionDecodeError::InvalidEncoding => "InvalidEncoding",
        RegionDecodeError::UnsupportedVersion => "UnsupportedVersion",
        RegionDecodeError::UnsupportedType => "UnsupportedType",
        RegionDecodeError::WrongChannel => "WrongChannel",
    }
}

fn hello(channel: RegionChannel, extension: Option<RegionHelloExtension>) -> RegionFrame {
    RegionFrame::Hello(RegionHello {
        region_name: "relay-a".to_owned(),
        member_id: 1,
        boot_epoch: 2,
        channel,
        conn_gen: 3,
        extension,
    })
}

fn extension(capabilities: u64, quick_owner: u8, quick_owner_epoch: u64) -> RegionHelloExtension {
    RegionHelloExtension {
        capabilities,
        quick_owner,
        quick_owner_epoch,
    }
}

fn ipv6() -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
}

fn quick_request(actor: Vec<u8>, request: Vec<u8>) -> RegionFrame {
    RegionFrame::QuickRequest(RegionQuickRequest {
        request_id: 1,
        client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        challenge: [0x55; 32],
        actor,
        request,
    })
}

fn quick_response(status: RegionQuickStatus, actor: Vec<u8>, response: Vec<u8>) -> RegionFrame {
    RegionFrame::QuickResponse(RegionQuickResponse {
        request_id: 1,
        status,
        actor,
        response,
    })
}

fn largest_quick_request() -> RegionFrame {
    RegionFrame::QuickRequest(RegionQuickRequest {
        request_id: u64::MAX,
        client_ip: ipv6(),
        challenge: [0x55; 32],
        actor: vec![0; MAX_REGION_QUICK_ACTOR_BYTES],
        request: vec![0; MAX_REGION_QUICK_MESSAGE_BYTES],
    })
}

fn round_trip(frame: &RegionFrame, channel: RegionChannel) -> Result<Vec<u8>, String> {
    let encoded = frame
        .encode(channel)
        .map_err(|error| format!("{error:?}"))?;
    let decoded = if encoded.len() > MAX_REGION_FRAME_BYTES + 4 {
        RegionFrame::decode_quick_control(&encoded)
    } else {
        RegionFrame::decode(&encoded, channel)
    }
    .map_err(|error| format!("{error:?}"))?;
    if decoded != *frame {
        return Err("region quick frame round trip changed the frame".to_owned());
    }
    Ok(encoded)
}

fn prefixed(body: &[u8]) -> Result<Vec<u8>, String> {
    let length = u32::try_from(body.len()).map_err(|error| error.to_string())?;
    let mut output = Vec::with_capacity(body.len() + 4);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(body);
    Ok(output)
}

fn assert_rejected(input: &[u8], channel: RegionChannel, label: &str) -> Result<(), String> {
    if RegionFrame::decode(input, channel).is_ok() {
        return Err(format!("accepted malformed region frame: {label}"));
    }
    if channel == RegionChannel::Control && RegionFrame::decode_quick_control(input).is_ok() {
        return Err(format!(
            "quick decoder accepted malformed region frame: {label}"
        ));
    }
    Ok(())
}

/// Grows the byte string whose two-byte CBOR length sits at `offset` by one zero byte.
fn grow_payload(encoded: &[u8], offset: usize) -> Result<Vec<u8>, String> {
    let mut body = encoded[4..].to_vec();
    if body[offset] != 0x59 {
        return Err("payload head is not a two-byte byte-string length".to_owned());
    }
    let length = u16::from_be_bytes([body[offset + 1], body[offset + 2]]);
    let grown = length
        .checked_add(1)
        .ok_or_else(|| "payload length overflow".to_owned())?;
    body[offset + 1..offset + 3].copy_from_slice(&grown.to_be_bytes());
    body.insert(offset + 3 + usize::from(length), 0);
    prefixed(&body)
}

#[test]
fn sealed_legacy_hello_vector_calibrates_the_fixture_reader() -> Result<(), String> {
    // The legacy HELLO vectors must equal the sealed keynet-v1 hello_control and hello_data
    // bytes, which were fixed before the extension existed.
    let control = "00000010830101856772656c61792d6101020003";
    let data = "00000010830101856772656c61792d6101020103";
    if hex_bytes(control)? != vector_frame("hello_control_legacy")?
        || hex_bytes(data)? != vector_frame("hello_data_legacy")?
    {
        return Err("legacy HELLO vectors differ from the sealed keynet-v1 bytes".to_owned());
    }
    if hello(RegionChannel::Control, None)
        .encode(RegionChannel::Control)
        .map_err(|error| format!("{error:?}"))?
        != hex_bytes(control)?
        || hello(RegionChannel::Data, None)
            .encode(RegionChannel::Data)
            .map_err(|error| format!("{error:?}"))?
            != hex_bytes(data)?
    {
        return Err("a HELLO without extension changed its bytes".to_owned());
    }
    Ok(())
}

#[test]
fn sealed_region_quick_frame_vectors_match_the_declared_cases() -> Result<(), String> {
    let vectors = vectors()?;
    let expected = REGION_QUICK_FRAME_CASES
        .split(',')
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if vectors.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(
            "sealed region quick frame cases differ from the declared inventory".to_owned(),
        );
    }
    for (case, vector) in &vectors {
        let channel = channel(field(vector, "channel")?)?;
        let before_hello = match field(vector, "stage")? {
            "before_hello" => true,
            "after_hello" => false,
            _ => return Err(format!("invalid region quick frame stage: {case}")),
        };
        match field(vector, "outcome")? {
            "accept" => {
                let encoded = hex_bytes(field(vector, "frame")?)?;
                let decoded = RegionFrame::decode(&encoded, channel)
                    .map_err(|error| format!("{case}: {error:?}"))?;
                let frame_type = decoded.frame_type();
                if frame_type_name(frame_type) != field(vector, "type")? {
                    return Err(format!("sealed region quick frame type mismatch: {case}"));
                }
                let legal = if before_hello {
                    frame_type.is_legal_before_hello_on(channel)
                } else {
                    frame_type.is_legal_after_hello_on(channel)
                };
                if !legal {
                    return Err(format!("accepted frame is illegal at its stage: {case}"));
                }
                if decoded
                    .encode(channel)
                    .map_err(|error| format!("{error:?}"))?
                    != encoded
                {
                    return Err(format!(
                        "sealed region quick frame is not canonical: {case}"
                    ));
                }
                if channel == RegionChannel::Control
                    && RegionFrame::decode_quick_control(&encoded) != Ok(decoded.clone())
                {
                    return Err(format!("quick decoder disagrees: {case}"));
                }
                if let Some(capabilities) = vector.get("capabilities") {
                    let capabilities = capabilities
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?;
                    let RegionFrame::Hello(RegionHello {
                        extension: Some(extension),
                        ..
                    }) = decoded
                    else {
                        return Err(format!("capability vector without an extension: {case}"));
                    };
                    if extension.capabilities != capabilities {
                        return Err(format!("capability bits were not kept: {case}"));
                    }
                }
            }
            "reject" => {
                let encoded = hex_bytes(field(vector, "frame")?)?;
                let error = RegionFrame::decode(&encoded, channel)
                    .err()
                    .ok_or_else(|| format!("accepted rejected vector: {case}"))?;
                if decode_error_name(error) != field(vector, "error")? {
                    return Err(format!("{case}: unexpected error {error:?}"));
                }
                assert_rejected(&encoded, channel, case)?;
            }
            "reject_before_hello" => {
                let encoded = hex_bytes(field(vector, "frame")?)?;
                let decoded = RegionFrame::decode(&encoded, channel)
                    .map_err(|error| format!("{case}: {error:?}"))?;
                if frame_type_name(decoded.frame_type()) != field(vector, "type")?
                    || !before_hello
                    || decoded.frame_type().is_legal_before_hello_on(channel)
                    || !decoded.frame_type().is_legal_after_hello_on(channel)
                {
                    return Err(format!("quick frame was legal before HELLO: {case}"));
                }
            }
            "generated" => assert_generated_case(case, vector)?,
            _ => return Err(format!("invalid sealed region quick frame outcome: {case}")),
        }
    }
    Ok(())
}

fn fixture_usize(vector: &BTreeMap<String, String>, name: &str) -> Result<usize, String> {
    field(vector, name)?
        .parse()
        .map_err(|error: std::num::ParseIntError| error.to_string())
}

fn assert_generated_case(case: &str, vector: &BTreeMap<String, String>) -> Result<(), String> {
    match case {
        "quick_payload_limit" => {
            let limit = fixture_usize(vector, "limit")?;
            let one_over = fixture_usize(vector, "one_over")?;
            let actor_limit = fixture_usize(vector, "actor_limit")?;
            let actor_one_over = fixture_usize(vector, "actor_one_over")?;
            if limit != QUICK_MESSAGE_BYTES
                || limit != MAX_REGION_QUICK_MESSAGE_BYTES
                || one_over != limit + 1
                || actor_limit != QUICK_ACTOR_BYTES
                || actor_limit != MAX_REGION_QUICK_ACTOR_BYTES
                || actor_one_over != actor_limit + 1
            {
                return Err("sealed quick payload boundary changed".to_owned());
            }
            assert_payload_limits()
        }
        "quick_frame_limit" => {
            let limit = fixture_usize(vector, "limit")?;
            let one_over = fixture_usize(vector, "one_over")?;
            let base_limit = fixture_usize(vector, "base_limit")?;
            if limit != MAX_REGION_QUICK_FRAME_BYTES
                || one_over != limit + 1
                || base_limit != MAX_REGION_FRAME_BYTES
            {
                return Err("sealed quick frame boundary changed".to_owned());
            }
            assert_frame_limits()
        }
        _ => Err(format!("unknown generated region quick frame case: {case}")),
    }
}

fn assert_payload_limits() -> Result<(), String> {
    let at_limit = vec![0; MAX_REGION_QUICK_MESSAGE_BYTES];
    let over_limit = vec![0; MAX_REGION_QUICK_MESSAGE_BYTES + 1];
    let actor_at_limit = vec![0; MAX_REGION_QUICK_ACTOR_BYTES];
    let actor_over_limit = vec![0; MAX_REGION_QUICK_ACTOR_BYTES + 1];
    let encoded_request = round_trip(
        &quick_request(actor_at_limit.clone(), at_limit.clone()),
        RegionChannel::Control,
    )?;
    let encoded_response = round_trip(
        &quick_response(RegionQuickStatus::Completed, actor_at_limit, at_limit),
        RegionChannel::Control,
    )?;
    for over in [
        quick_request(actor_over_limit.clone(), Vec::new()),
        quick_request(Vec::new(), over_limit.clone()),
        quick_response(RegionQuickStatus::Completed, actor_over_limit, Vec::new()),
        quick_response(RegionQuickStatus::Completed, Vec::new(), over_limit.clone()),
    ] {
        if over.encode(RegionChannel::Control) != Err(RegionEncodeError::InvalidFrame) {
            return Err("a quick payload one byte over the limit was encoded".to_owned());
        }
    }
    // Request body: array(5), request_id 1, 4-byte address, 32-byte challenge, then actor.
    let request_actor = 3 + 1 + 1 + 5 + 34;
    let request_payload = request_actor + 3 + MAX_REGION_QUICK_ACTOR_BYTES;
    // Response body: array(4), request_id 1, status 1, then actor.
    let response_actor = 3 + 1 + 1 + 1;
    let response_payload = response_actor + 3 + MAX_REGION_QUICK_ACTOR_BYTES;
    for (encoded, offset, label) in [
        (&encoded_request, request_actor, "request actor"),
        (&encoded_request, request_payload, "request payload"),
        (&encoded_response, response_actor, "response actor"),
        (&encoded_response, response_payload, "response payload"),
    ] {
        let grown = grow_payload(encoded, offset)?;
        if RegionFrame::decode_quick_control(&grown) != Err(RegionDecodeError::InvalidEncoding) {
            return Err(format!(
                "decoder accepted a {label} one byte over the limit"
            ));
        }
    }
    Ok(())
}

fn assert_frame_limits() -> Result<(), String> {
    let largest = largest_quick_request();
    let encoded = largest
        .encode(RegionChannel::Control)
        .map_err(|error| format!("{error:?}"))?;
    let measured = encoded.len() - 4;
    if measured != MAX_REGION_QUICK_FRAME_BYTES {
        return Err(format!(
            "largest valid QuickRequest measures {measured} bytes, limit is {MAX_REGION_QUICK_FRAME_BYTES}"
        ));
    }
    let largest_response = RegionFrame::QuickResponse(RegionQuickResponse {
        request_id: u64::MAX,
        status: RegionQuickStatus::Completed,
        actor: vec![0; MAX_REGION_QUICK_ACTOR_BYTES],
        response: vec![0; MAX_REGION_QUICK_MESSAGE_BYTES],
    });
    if largest_response
        .encode(RegionChannel::Control)
        .map_err(|error| format!("{error:?}"))?
        .len()
        > encoded.len()
    {
        return Err("a QuickResponse outgrows the largest QuickRequest".to_owned());
    }

    let limit = u32::try_from(MAX_REGION_QUICK_FRAME_BYTES).map_err(|error| error.to_string())?;
    let base = u32::try_from(MAX_REGION_FRAME_BYTES).map_err(|error| error.to_string())?;
    if decode_region_frame_prefix(base.to_be_bytes()) != Ok(MAX_REGION_FRAME_BYTES)
        || decode_region_frame_prefix((base + 1).to_be_bytes())
            != Err(RegionDecodeError::InvalidPrefix)
        || decode_region_frame_prefix(limit.to_be_bytes()) != Err(RegionDecodeError::InvalidPrefix)
    {
        return Err("the base prefix decoder admits more than 4096 bytes".to_owned());
    }
    if decode_region_quick_frame_prefix(limit.to_be_bytes()) != Ok(MAX_REGION_QUICK_FRAME_BYTES)
        || decode_region_quick_frame_prefix((limit + 1).to_be_bytes())
            != Err(RegionDecodeError::InvalidPrefix)
        || decode_region_quick_frame_prefix([0; 4]) != Err(RegionDecodeError::InvalidPrefix)
    {
        return Err("the quick prefix decoder boundary is wrong".to_owned());
    }
    if RegionFrame::decode_quick_control(&encoded) != Ok(largest) {
        return Err("the largest valid QuickRequest did not decode".to_owned());
    }
    if RegionFrame::decode(&encoded, RegionChannel::Control)
        != Err(RegionDecodeError::InvalidPrefix)
    {
        return Err("the base decoder accepted a frame above 4096 bytes".to_owned());
    }
    let mut one_more = encoded.clone();
    one_more[..4].copy_from_slice(&(limit + 1).to_be_bytes());
    one_more.push(0);
    if RegionFrame::decode_quick_control(&one_more) != Err(RegionDecodeError::InvalidPrefix) {
        return Err("the quick decoder accepted one byte more than the limit".to_owned());
    }
    Ok(())
}

#[test]
fn quick_limits_are_measured_from_the_largest_quick_request() -> Result<(), String> {
    assert_payload_limits()?;
    assert_frame_limits()
}

#[test]
fn non_quick_frames_keep_the_base_limit_on_the_quick_decoder() -> Result<(), String> {
    // A PING body padded past 4096 bytes: [1, 8, [0, 0, 0]] followed by filler that the decoder
    // must never reach, because the type limit is checked before the body is parsed.
    let mut body = vec![0x83, 0x01, 0x08, 0x83, 0x00, 0x00, 0x00];
    body.resize(MAX_REGION_FRAME_BYTES + 1, 0);
    if RegionFrame::decode_quick_control(&prefixed(&body)?) != Err(RegionDecodeError::InvalidPrefix)
    {
        return Err("a PING above 4096 bytes passed the quick decoder".to_owned());
    }
    let mut hello_body = hello(RegionChannel::Control, Some(extension(1, 2, 5)))
        .encode(RegionChannel::Control)
        .map_err(|error| format!("{error:?}"))?[4..]
        .to_vec();
    hello_body.resize(MAX_REGION_FRAME_BYTES + 1, 0);
    if RegionFrame::decode_quick_control(&prefixed(&hello_body)?)
        != Err(RegionDecodeError::InvalidPrefix)
    {
        return Err("a HELLO above 4096 bytes passed the quick decoder".to_owned());
    }
    // A quick frame below the base limit decodes with either decoder.
    let small = quick_request(Vec::new(), vec![1, 2, 3]);
    let encoded = round_trip(&small, RegionChannel::Control)?;
    if RegionFrame::decode_quick_control(&encoded) != Ok(small) {
        return Err("the quick decoder rejected a small quick frame".to_owned());
    }
    Ok(())
}

#[test]
fn extended_hello_round_trips_on_control_and_is_rejected_on_data() -> Result<(), String> {
    let extended = hello(
        RegionChannel::Control,
        Some(extension(REGION_CAPABILITY_QUICK_FORWARDING, 2, 5)),
    );
    if round_trip(&extended, RegionChannel::Control)? != vector_frame("hello_control_extended")? {
        return Err("extended HELLO bytes differ from the sealed vector".to_owned());
    }
    let unknown = hello(
        RegionChannel::Control,
        Some(extension(0x8000_0000_0000_0003, 16, u64::MAX)),
    );
    if round_trip(&unknown, RegionChannel::Control)?
        != vector_frame("hello_control_unknown_capabilities")?
    {
        return Err("unknown capability bits were not kept".to_owned());
    }
    if hello(RegionChannel::Data, Some(extension(1, 2, 5))).encode(RegionChannel::Data)
        != Err(RegionEncodeError::InvalidFrame)
    {
        return Err("extended HELLO was encoded on the data channel".to_owned());
    }
    for (owner, epoch) in [(0, 5), (17, 5), (2, 0)] {
        if hello(RegionChannel::Control, Some(extension(1, owner, epoch)))
            .encode(RegionChannel::Control)
            != Err(RegionEncodeError::InvalidFrame)
        {
            return Err(format!(
                "extended HELLO with owner {owner} and epoch {epoch} was encoded"
            ));
        }
    }
    Ok(())
}

#[test]
fn quick_frames_round_trip_and_match_the_sealed_vectors() -> Result<(), String> {
    let cases = [
        (
            "quick_request_ipv4",
            quick_request(Vec::new(), vec![1, 2, 3]),
        ),
        (
            "quick_request_ipv6_actor",
            RegionFrame::QuickRequest(RegionQuickRequest {
                request_id: u64::MAX,
                client_ip: ipv6(),
                challenge: [0x55; 32],
                actor: vec![0x61; 8],
                request: vec![1, 2, 3],
            }),
        ),
        (
            "quick_response_completed",
            quick_response(RegionQuickStatus::Completed, vec![0x61; 8], vec![4, 5]),
        ),
        (
            "quick_response_not_owner",
            quick_response(RegionQuickStatus::NotOwner, Vec::new(), Vec::new()),
        ),
        (
            "quick_response_busy",
            quick_response(RegionQuickStatus::Busy, Vec::new(), Vec::new()),
        ),
        (
            "quick_request_actor_limit",
            quick_request(vec![0x61; MAX_REGION_QUICK_ACTOR_BYTES], vec![1, 2, 3]),
        ),
        (
            "quick_response_actor_limit",
            quick_response(
                RegionQuickStatus::Completed,
                vec![0x61; MAX_REGION_QUICK_ACTOR_BYTES],
                vec![4, 5],
            ),
        ),
    ];
    for (case, frame) in cases {
        if round_trip(&frame, RegionChannel::Control)? != vector_frame(case)? {
            return Err(format!(
                "quick frame bytes differ from the sealed vector: {case}"
            ));
        }
        if frame.encode(RegionChannel::Data) != Err(RegionEncodeError::InvalidFrame) {
            return Err(format!(
                "quick frame was encoded on the data channel: {case}"
            ));
        }
    }
    Ok(())
}

#[test]
fn quick_frames_reject_reserved_and_inconsistent_fields_on_encode() -> Result<(), String> {
    let mut zero_request = quick_request(Vec::new(), vec![1]);
    if let RegionFrame::QuickRequest(request) = &mut zero_request {
        request.request_id = 0;
    }
    let mut zero_response = quick_response(RegionQuickStatus::Completed, Vec::new(), vec![1]);
    if let RegionFrame::QuickResponse(response) = &mut zero_response {
        response.request_id = 0;
    }
    for (label, frame) in [
        ("zero request id", zero_request),
        ("zero response id", zero_response),
        (
            "not-owner actor",
            quick_response(RegionQuickStatus::NotOwner, vec![1], Vec::new()),
        ),
        (
            "not-owner response",
            quick_response(RegionQuickStatus::NotOwner, Vec::new(), vec![1]),
        ),
        (
            "busy actor",
            quick_response(RegionQuickStatus::Busy, vec![1], Vec::new()),
        ),
        (
            "busy response",
            quick_response(RegionQuickStatus::Busy, Vec::new(), vec![1]),
        ),
        (
            "request actor over the actor bound",
            quick_request(vec![0x61; MAX_REGION_QUICK_ACTOR_BYTES + 1], vec![1]),
        ),
        (
            "response actor over the actor bound",
            quick_response(
                RegionQuickStatus::Completed,
                vec![0x61; MAX_REGION_QUICK_ACTOR_BYTES + 1],
                vec![1],
            ),
        ),
    ] {
        if frame.encode(RegionChannel::Control) != Err(RegionEncodeError::InvalidFrame) {
            return Err(format!("quick frame with {label} was encoded"));
        }
    }
    Ok(())
}

#[test]
fn quick_frames_are_control_only_and_only_after_hello() -> Result<(), String> {
    for frame_type in [
        RegionFrameType::QuickRequest,
        RegionFrameType::QuickResponse,
    ] {
        if !CONTROL_REGION_FRAME_TYPES.contains(&frame_type)
            || !frame_type.is_legal_on(RegionChannel::Control)
            || frame_type.is_legal_on(RegionChannel::Data)
            || frame_type.is_legal_before_hello_on(RegionChannel::Control)
            || frame_type.is_legal_before_hello_on(RegionChannel::Data)
            || !frame_type.is_legal_after_hello_on(RegionChannel::Control)
            || frame_type.is_legal_after_hello_on(RegionChannel::Data)
        {
            return Err(format!("{frame_type:?} channel typing is wrong"));
        }
    }
    if CONTROL_REGION_FRAME_TYPES.len() != 11
        || !RegionFrameType::Hello.is_legal_before_hello_on(RegionChannel::Control)
        || !RegionFrameType::Hello.is_legal_before_hello_on(RegionChannel::Data)
        || RegionFrameType::Ping.is_legal_before_hello_on(RegionChannel::Control)
        || RegionFrameType::Forward.is_legal_before_hello_on(RegionChannel::Data)
        || RegionFrameType::try_from(11) != Ok(RegionFrameType::QuickRequest)
        || RegionFrameType::try_from(12) != Ok(RegionFrameType::QuickResponse)
        || RegionFrameType::try_from(13) != Err(RegionDecodeError::UnsupportedType)
    {
        return Err("declared region frame inventory is wrong".to_owned());
    }
    Ok(())
}

#[test]
fn malformed_encoding_sweep_covers_both_hello_lengths_and_quick_frames() -> Result<(), String> {
    let frames = [
        hello(RegionChannel::Control, None),
        hello(RegionChannel::Control, Some(extension(1, 2, 5))),
        quick_request(vec![0x61; 8], vec![1, 2, 3]),
        quick_response(RegionQuickStatus::Completed, vec![0x61; 8], vec![4, 5]),
    ];
    for frame in frames {
        let channel = RegionChannel::Control;
        let encoded = round_trip(&frame, channel)?;
        let body = encoded[4..].to_vec();

        let mut non_shortest = body.clone();
        non_shortest[1] = 0x18;
        non_shortest.insert(2, 1);
        assert_rejected(&prefixed(&non_shortest)?, channel, "non-shortest integer")?;

        let mut indefinite = body.clone();
        indefinite[0] = 0x9f;
        assert_rejected(&prefixed(&indefinite)?, channel, "indefinite envelope")?;

        let mut indefinite_body = body.clone();
        indefinite_body[3] = 0x9f;
        assert_rejected(&prefixed(&indefinite_body)?, channel, "indefinite body")?;

        for arity in 0x80..=0x87 {
            if arity == body[3] {
                continue;
            }
            let mut wrong_arity = body.clone();
            wrong_arity[3] = arity;
            assert_rejected(&prefixed(&wrong_arity)?, channel, "wrong body arity")?;
        }

        let mut wrong_type = body.clone();
        wrong_type[1] = 0xf5;
        assert_rejected(&prefixed(&wrong_type)?, channel, "wrong CBOR type")?;

        let mut wrong_width = body.clone();
        wrong_width[1] = 0x19;
        wrong_width.insert(2, 1);
        wrong_width.insert(3, 0);
        assert_rejected(&prefixed(&wrong_width)?, channel, "wrong integer width")?;

        let mut trailing = body.clone();
        trailing.push(0);
        assert_rejected(&prefixed(&trailing)?, channel, "trailing byte")?;

        for length in 1..body.len() {
            assert_rejected(&prefixed(&body[..length])?, channel, "truncated body")?;
        }
    }

    // The extension array itself: [1, 2, 5] starts after the five legacy HELLO fields.
    let extended = hello(RegionChannel::Control, Some(extension(1, 2, 5)))
        .encode(RegionChannel::Control)
        .map_err(|error| format!("{error:?}"))?[4..]
        .to_vec();
    let extension_offset = extended.len() - 4;
    if extended[extension_offset] != 0x83 {
        return Err("extension array offset moved".to_owned());
    }
    for (label, replacement) in [
        ("indefinite extension", 0x9f),
        ("extension as bytes", 0x43),
        ("extension as uint", 0x03),
        ("extension as map", 0xa3),
    ] {
        let mut changed = extended.clone();
        changed[extension_offset] = replacement;
        assert_rejected(&prefixed(&changed)?, RegionChannel::Control, label)?;
    }
    let mut wide_capabilities = extended.clone();
    wide_capabilities[extension_offset + 1] = 0x18;
    wide_capabilities.insert(extension_offset + 2, 1);
    assert_rejected(
        &prefixed(&wide_capabilities)?,
        RegionChannel::Control,
        "non-shortest capabilities",
    )?;
    let mut negative_owner = extended;
    negative_owner[extension_offset + 2] = 0x21;
    assert_rejected(
        &prefixed(&negative_owner)?,
        RegionChannel::Control,
        "negative owner",
    )?;
    Ok(())
}
