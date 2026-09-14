use blake2::{
    Blake2s, Digest,
    digest::consts::{U4, U15, U20},
};

use super::{Error, OverlayAddresses};

/// Mesh v2 is deliberately distinct from the v1 per-network address scheme.
/// Its stable addresses derive solely from the node's WireGuard public key.
pub const MESH_V2_PROTOCOL_VERSION: u8 = 2;
pub const MESH_V2_REGISTER_API: &str = "mesh.v2.register";

/// A one-time RFC 4193 random Global ID, frozen as a protocol constant rather
/// than generated during installation or group creation.
pub const MESH_V2_OVERLAY_PREFIX: [u8; 6] = [0xfd, 0x3b, 0x98, 0x58, 0x77, 0x36];

/// The relay may authenticate and pin a different root, but absent that
/// descriptor Mesh v2 names live under this product-owned split-DNS zone.
pub const MESH_V2_DEFAULT_DNS_ROOT: &str = "mesh.ns.io";

/// BLAKE2s-256 has exactly this many lowercase base32 characters without
/// padding. A name record stores its chosen length so it never changes later.
pub const MESH_V2_MAX_NAME_LABEL_LEN: usize = 52;

const MESH_V2_ADDRESS_DOMAIN: &[u8] = b"nsmesh-v2-overlay-ip\0";
const MESH_V2_REGISTRATION_PROOF_DOMAIN: &[u8] = b"nsmesh-v2-registration-proof\0";

/// Two separately addressed paths share a stable identity but never a /128.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MeshV2AddressPurpose {
    Native,
    Ipv4Translated,
}

impl MeshV2AddressPurpose {
    const fn bit(self) -> u8 {
        match self {
            Self::Native => 0,
            Self::Ipv4Translated => 1,
        }
    }
}

/// Derive one canonical Mesh v2 IPv6 address.
///
/// The subnet's high bit is the purpose and its remaining 15 bits plus the
/// interface ID come from one version-domain-separated BLAKE2s digest. This
/// preserves stable identity while giving native and translated traffic two
/// non-overlapping exact `/128` destinations.
pub fn mesh_v2_overlay_ipv6(wg_pub: &[u8; 32], purpose: MeshV2AddressPurpose) -> [u8; 16] {
    let mut hash = Blake2s::<blake2::digest::consts::U32>::new();
    hash.update(MESH_V2_ADDRESS_DOMAIN);
    hash.update(wg_pub);
    let digest = hash.finalize();
    let subnet =
        (u16::from(purpose.bit()) << 15) | (u16::from_be_bytes([digest[0], digest[1]]) & 0x7fff);
    let mut address = [0; 16];
    address[..MESH_V2_OVERLAY_PREFIX.len()].copy_from_slice(&MESH_V2_OVERLAY_PREFIX);
    address[6..8].copy_from_slice(&subnet.to_be_bytes());
    address[8..].copy_from_slice(&digest[2..10]);
    address
}

/// Derive a stable, unpadded lowercase base32 Mesh v2 node label.
///
/// `name_salt` comes from the registration authority; callers must persist
/// both it and the selected length rather than regenerate either on reconnect.
pub fn mesh_v2_name_label(
    wg_pub: &[u8; 32],
    name_salt: &[u8; 16],
    length: usize,
) -> Result<String, Error> {
    if length == 0 || length > MESH_V2_MAX_NAME_LABEL_LEN {
        return Err(Error::Payload("Mesh v2 name label length"));
    }
    let mut hash = Blake2s::<blake2::digest::consts::U32>::new();
    hash.update(b"nsmesh-v2-name\0");
    hash.update(wg_pub);
    hash.update(name_salt);
    let encoded = base32_lower_no_pad(&hash.finalize());
    Ok(encoded[..length].to_owned())
}

fn base32_lower_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut output = String::with_capacity(MESH_V2_MAX_NAME_LABEL_LEN);
    let mut buffer = 0u64;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | u64::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(char::from(ALPHABET[((buffer >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        output.push(char::from(
            ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
    }
    output
}

/// Canonical bytes signed to prove one stable v2 node identity during
/// registration. The group is intentionally absent: the proof establishes
/// key possession, while group membership remains a separately authorized
/// ledger concern.
pub fn mesh_v2_registration_proof_input(
    signing_pub: &[u8; 32],
    wg_pub: &[u8; 32],
    nonce: &[u8; 16],
) -> Vec<u8> {
    let mut input = MESH_V2_REGISTRATION_PROOF_DOMAIN.to_vec();
    input.push(MESH_V2_PROTOCOL_VERSION);
    input.extend_from_slice(signing_pub);
    input.extend_from_slice(wg_pub);
    input.extend_from_slice(nonce);
    input
}

pub fn member_id(signing_pub: &[u8; 32]) -> [u8; 20] {
    Blake2s::<U20>::digest(signing_pub).into()
}

pub fn fingerprint(public_key: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(member_id(public_key)))
}

pub fn parse_fingerprint(value: &str) -> Result<[u8; 20], Error> {
    let hex = value
        .strip_prefix("0x")
        .ok_or(Error::Payload("fingerprint prefix"))?;
    if hex.len() != 40
        || !hex
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Payload("canonical fingerprint"));
    }
    let mut id = [0; 20];
    hex::decode_to_slice(hex, &mut id).map_err(|_| Error::Payload("fingerprint"))?;
    Ok(id)
}

pub fn overlay_ipv6(wg_pub: &[u8; 32]) -> [u8; 16] {
    let mut hash = Blake2s::<U15>::new();
    hash.update(b"nsmesh-ipv6-v1\0");
    hash.update(wg_pub);
    let mut address = [0; 16];
    address[0] = 0xfd;
    address[1..].copy_from_slice(&hash.finalize());
    address
}

pub fn overlay_ipv4(wg_pub: &[u8; 32], salt: u32) -> Result<[u8; 4], Error> {
    let mut hash = Blake2s::<U4>::new();
    hash.update(b"nsmesh-ipv4-v1\0");
    hash.update(wg_pub);
    hash.update(salt.to_be_bytes());
    let digest = hash.finalize();
    if matches!((digest[2], digest[3]), (0, 0) | (255, 255)) {
        return Err(Error::Payload("reserved overlay IPv4"));
    }
    Ok([100, 100, digest[2], digest[3]])
}

pub fn derive_overlay_addresses(wg_pub: &[u8; 32], salt: u32) -> Result<OverlayAddresses, Error> {
    Ok(OverlayAddresses {
        v4: overlay_ipv4(wg_pub, salt)?,
        v4_salt: u64::from(salt),
        v6: overlay_ipv6(wg_pub),
    })
}

pub fn verify_overlay_addresses(
    wg_pub: &[u8; 32],
    addresses: &OverlayAddresses,
) -> Result<(), Error> {
    let salt = u32::try_from(addresses.v4_salt).map_err(|_| Error::Payload("IPv4 salt width"))?;
    if &derive_overlay_addresses(wg_pub, salt)? != addresses {
        return Err(Error::Payload("overlay address binding"));
    }
    Ok(())
}

/// Test at most four consecutive salts; the caller supplies its own collision inventory.
pub fn allocate_overlay_addresses(
    wg_pub: &[u8; 32],
    first_salt: u32,
    mut occupied: impl FnMut(&OverlayAddresses) -> bool,
) -> Result<OverlayAddresses, Error> {
    for offset in 0..4 {
        let salt = first_salt
            .checked_add(offset)
            .ok_or(Error::Payload("IPv4 salt exhausted"))?;
        if let Ok(candidate) = derive_overlay_addresses(wg_pub, salt)
            && !occupied(&candidate)
        {
            return Ok(candidate);
        }
    }
    Err(Error::Payload("overlay address candidates exhausted"))
}

pub fn must_yield_collision(
    own_incarnation: u64,
    own_signing_key: &[u8; 32],
    other_incarnation: u64,
    other_signing_key: &[u8; 32],
) -> bool {
    (own_incarnation, own_signing_key) > (other_incarnation, other_signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_v2_addresses_are_stable_purpose_separated_golden_vectors() {
        let key = [0x42; 32];
        assert_eq!(MESH_V2_PROTOCOL_VERSION, 2);
        assert_eq!(
            mesh_v2_overlay_ipv6(&key, MeshV2AddressPurpose::Native),
            [
                0xfd, 0x3b, 0x98, 0x58, 0x77, 0x36, 0x71, 0x5a, 0x04, 0xcc, 0x91, 0x91, 0xa1, 0xe8,
                0x78, 0x09,
            ]
        );
        assert_eq!(
            mesh_v2_overlay_ipv6(&key, MeshV2AddressPurpose::Ipv4Translated),
            [
                0xfd, 0x3b, 0x98, 0x58, 0x77, 0x36, 0xf1, 0x5a, 0x04, 0xcc, 0x91, 0x91, 0xa1, 0xe8,
                0x78, 0x09,
            ]
        );
    }

    #[test]
    fn mesh_v2_addresses_do_not_depend_on_a_group_or_runtime_salt() {
        let native = mesh_v2_overlay_ipv6(&[7; 32], MeshV2AddressPurpose::Native);
        assert_eq!(native[..6], MESH_V2_OVERLAY_PREFIX);
        assert_ne!(
            native,
            mesh_v2_overlay_ipv6(&[8; 32], MeshV2AddressPurpose::Native)
        );
        assert_ne!(
            native,
            mesh_v2_overlay_ipv6(&[7; 32], MeshV2AddressPurpose::Ipv4Translated)
        );
    }

    #[test]
    fn mesh_v2_name_labels_are_stable_lowercase_base32_golden_vectors() {
        let key = [0x42; 32];
        let salt = [0x11; 16];
        assert_eq!(MESH_V2_DEFAULT_DNS_ROOT, "mesh.ns.io");
        assert_eq!(mesh_v2_name_label(&key, &salt, 5).unwrap(), "dmhbv");
        assert_eq!(
            mesh_v2_name_label(&key, &salt, MESH_V2_MAX_NAME_LABEL_LEN).unwrap(),
            "dmhbvyp2pdgknug7sfhm5ml6x7wixzl5ac3x655jlzjtam3yoijq"
        );
        assert!(mesh_v2_name_label(&key, &salt, 0).is_err());
        assert!(mesh_v2_name_label(&key, &salt, MESH_V2_MAX_NAME_LABEL_LEN + 1).is_err());
        assert_ne!(
            mesh_v2_name_label(&key, &salt, 5).unwrap(),
            mesh_v2_name_label(&key, &[0x12; 16], 5).unwrap()
        );
    }

    #[test]
    fn mesh_v2_registration_proof_binds_both_public_keys_and_nonce() {
        let signing = [0x11; 32];
        let wg = [0x22; 32];
        let nonce = [0x33; 16];
        let input = mesh_v2_registration_proof_input(&signing, &wg, &nonce);
        assert_eq!(
            &input[..MESH_V2_REGISTRATION_PROOF_DOMAIN.len()],
            MESH_V2_REGISTRATION_PROOF_DOMAIN
        );
        assert_eq!(input[MESH_V2_REGISTRATION_PROOF_DOMAIN.len()], 2);
        assert_eq!(
            &input[MESH_V2_REGISTRATION_PROOF_DOMAIN.len() + 1..],
            [&signing[..], &wg[..], &nonce[..]].concat()
        );
        assert_ne!(
            input,
            mesh_v2_registration_proof_input(&signing, &[0x23; 32], &nonce)
        );
    }

    #[test]
    fn mesh_v2_registration_api_is_not_the_v1_wire_api() {
        assert_eq!(MESH_V2_REGISTER_API, "mesh.v2.register");
        assert_ne!(MESH_V2_REGISTER_API, super::super::Register::API);
    }
}
