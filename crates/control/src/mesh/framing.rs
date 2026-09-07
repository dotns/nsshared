use super::Error;

pub const UDP_MAGIC: &[u8; 8] = b"NSGWMSH1";
pub const MAX_CONTROL_FRAME: usize = 1200;
pub const WSS_VERSION: u8 = 1;
const WSS_CONTROL: u8 = 1;
const WSS_WG: u8 = 2;
const WSS_WG_HEADER: usize = 2 + 32 + 32;

/// Validate the transport bound before allocating or decoding CBOR.
pub fn decode_udp(datagram: &[u8]) -> Result<&[u8], Error> {
    if datagram.len() > MAX_CONTROL_FRAME {
        return Err(Error::TooLarge);
    }
    if datagram.len() <= UDP_MAGIC.len() || !datagram.starts_with(UDP_MAGIC) {
        return Err(Error::Framing);
    }
    Ok(&datagram[UDP_MAGIC.len()..])
}

pub fn encode_udp(envelope: &[u8]) -> Result<Vec<u8>, Error> {
    if envelope.len() > MAX_CONTROL_FRAME - UDP_MAGIC.len() {
        return Err(Error::TooLarge);
    }
    if envelope.is_empty() {
        return Err(Error::Framing);
    }
    let mut result = Vec::with_capacity(UDP_MAGIC.len() + envelope.len());
    result.extend_from_slice(UDP_MAGIC);
    result.extend_from_slice(envelope);
    Ok(result)
}

#[derive(Debug, PartialEq, Eq)]
pub enum WssFrame<'a> {
    Control(&'a [u8]),
    WireGuard {
        source_wg: &'a [u8; 32],
        destination_wg: &'a [u8; 32],
        datagram: &'a [u8],
    },
}

/// `max_wg_datagram` is the existing data-plane limit, independent of control.
pub fn decode_wss(frame: &[u8], max_wg_datagram: usize) -> Result<WssFrame<'_>, Error> {
    if frame.first() != Some(&WSS_VERSION) {
        return Err(Error::Framing);
    }
    match frame.get(1) {
        Some(&WSS_CONTROL) => {
            if frame.len() > MAX_CONTROL_FRAME {
                return Err(Error::TooLarge);
            }
            if frame.len() <= 2 {
                return Err(Error::Framing);
            }
            Ok(WssFrame::Control(&frame[2..]))
        }
        Some(&WSS_WG) => {
            if frame.len() <= WSS_WG_HEADER {
                return Err(Error::Framing);
            }
            if frame.len() - WSS_WG_HEADER > max_wg_datagram {
                return Err(Error::TooLarge);
            }
            Ok(WssFrame::WireGuard {
                source_wg: frame[2..34].try_into().map_err(|_| Error::Framing)?,
                destination_wg: frame[34..66].try_into().map_err(|_| Error::Framing)?,
                datagram: &frame[WSS_WG_HEADER..],
            })
        }
        _ => Err(Error::Framing),
    }
}

pub fn encode_wss(frame: WssFrame<'_>, max_wg_datagram: usize) -> Result<Vec<u8>, Error> {
    match frame {
        WssFrame::Control(envelope) => {
            if envelope.len() > MAX_CONTROL_FRAME - 2 {
                return Err(Error::TooLarge);
            }
            if envelope.is_empty() {
                return Err(Error::Framing);
            }
            let mut result = Vec::with_capacity(2 + envelope.len());
            result.extend_from_slice(&[WSS_VERSION, WSS_CONTROL]);
            result.extend_from_slice(envelope);
            Ok(result)
        }
        WssFrame::WireGuard {
            source_wg,
            destination_wg,
            datagram,
        } => {
            if datagram.len() > max_wg_datagram {
                return Err(Error::TooLarge);
            }
            if datagram.is_empty() {
                return Err(Error::Framing);
            }
            let capacity = WSS_WG_HEADER
                .checked_add(datagram.len())
                .ok_or(Error::TooLarge)?;
            let mut result = Vec::with_capacity(capacity);
            result.extend_from_slice(&[WSS_VERSION, WSS_WG]);
            result.extend_from_slice(source_wg);
            result.extend_from_slice(destination_wg);
            result.extend_from_slice(datagram);
            Ok(result)
        }
    }
}
