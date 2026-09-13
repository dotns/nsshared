use blake2::{
    Blake2sMac,
    digest::{
        KeyInit, Mac,
        consts::{U12, U15},
    },
};
use keynet_proto::{
    AddressGroup, GroupOwner, check_new_local_group, check_peer_group, derive_address_group,
    group_bytes, group_ipv6, identity_label, n4, n4_bytes, n6, n6_bytes,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::Ipv6Addr,
    path::{Path, PathBuf},
};

const DESIGN_SHA256: &str = "7c99ffb2e03c0728128da7270754aa065148e263fdc7c3aef233ff9696fa8a9f";
const ROOT: &str = "tests/fixtures/keynet-v1";
const ADDRESS_CASES: &str = "ascending,zeros,reverse";
const IDENTITY_CASES: &str = "ascending,zeros,reverse";
const CONFLICT_CASES: &str = "idempotent_peer,self_collision,all_group_distinct_owner_collision,own_network_join_collision,own_network_join_clear";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(ROOT)
}
fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn blocks(text: &str) -> Result<Vec<BTreeMap<&str, &str>>, String> {
    text.split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .map(|block| {
            let mut fields = BTreeMap::new();
            for line in block.lines().filter(|line| !line.starts_with('#')) {
                let (key, value) = line
                    .split_once('=')
                    .ok_or_else(|| "invalid vector line".to_owned())?;
                if fields.insert(key, value).is_some() {
                    return Err(format!("duplicate vector field: {key}"));
                }
            }
            Ok(fields)
        })
        .collect()
}
fn field<'a>(block: &'a BTreeMap<&str, &str>, name: &str) -> Result<&'a str, String> {
    block
        .get(name)
        .copied()
        .ok_or_else(|| format!("missing field: {name}"))
}
fn hex<const N: usize>(input: &str) -> Result<[u8; N], String> {
    if input.len() != N * 2 {
        return Err(format!("wrong hex length for {N} bytes"));
    }
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16)
            .map_err(|error| error.to_string())?;
    }
    Ok(bytes)
}
fn independent_blake2s_15(input: &[u8]) -> Result<[u8; 15], String> {
    let mut hash = <Blake2sMac<U15> as KeyInit>::new_from_slice(b"keynet-addr-v1")
        .map_err(|error| error.to_string())?;
    hash.update(input);
    let mut output = [0; 15];
    output.copy_from_slice(&hash.finalize().into_bytes());
    Ok(output)
}
fn independent_blake2s_12(input: &[u8]) -> Result<[u8; 12], String> {
    let mut hash = <Blake2sMac<U12> as KeyInit>::new_from_slice(b"keynet-id-v1")
        .map_err(|error| error.to_string())?;
    hash.update(input);
    let mut output = [0; 12];
    output.copy_from_slice(&hash.finalize().into_bytes());
    Ok(output)
}
fn owner(input: &str) -> Result<GroupOwner, String> {
    let mut fields = input.split('|');
    let network_byte = u8::from_str_radix(
        fields.next().ok_or_else(|| "network missing".to_owned())?,
        16,
    )
    .map_err(|error| error.to_string())?;
    let identity_byte = u8::from_str_radix(
        fields.next().ok_or_else(|| "identity missing".to_owned())?,
        16,
    )
    .map_err(|error| error.to_string())?;
    let group = hex(fields.next().ok_or_else(|| "group missing".to_owned())?)?;
    if fields.next().is_some() {
        return Err("too many owner fields".to_owned());
    }
    Ok(GroupOwner {
        network_id: [network_byte; 32],
        identity: [identity_byte; 32],
        group: AddressGroup::from_address_bytes(group),
    })
}
fn owners(input: &str) -> Result<Vec<GroupOwner>, String> {
    if input.is_empty() {
        Ok(Vec::new())
    } else {
        input.split(';').map(owner).collect()
    }
}
fn inventory(value: &str) -> Result<BTreeSet<String>, String> {
    let cases = value.split(',').map(str::to_owned).collect::<BTreeSet<_>>();
    if cases.is_empty() || cases.contains("") || cases.len() != value.split(',').count() {
        return Err("invalid required case inventory".to_owned());
    }
    Ok(cases)
}
fn validate_case_inventory(root: &Path, file: &str, required: &str) -> Result<(), String> {
    let expected = inventory(required)?;
    let text = fs::read_to_string(root.join(file)).map_err(|error| error.to_string())?;
    let vectors = blocks(&text)?;
    if vectors.is_empty() {
        return Err(format!("empty required vector family: {file}"));
    }
    let mut actual = BTreeSet::new();
    for vector in vectors {
        let case = field(&vector, "case")?.to_owned();
        if !actual.insert(case.clone()) {
            return Err(format!("duplicate vector case in {file}: {case}"));
        }
    }
    if actual != expected {
        return Err(format!("missing or unlisted vector case in {file}"));
    }
    Ok(())
}
fn load(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let manifest =
        fs::read_to_string(root.join("manifest.txt")).map_err(|error| error.to_string())?;
    let mut required = BTreeMap::from([
        ("suite_version", "keynet-v1"),
        ("section_13_revision", "13.1-13.6"),
        ("design_sha256", DESIGN_SHA256),
        ("coverage", "addresses,identities,conflicts,integrity"),
        ("address_cases", ADDRESS_CASES),
        ("identity_cases", IDENTITY_CASES),
        ("conflict_cases", CONFLICT_CASES),
    ]);
    let mut entries = BTreeMap::new();
    for line in manifest.lines().filter(|line| !line.is_empty()) {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| "invalid manifest line".to_owned())?;
        if key == "file" {
            let (name, hash) = value
                .split_once('|')
                .ok_or_else(|| "invalid file entry".to_owned())?;
            if entries.insert(name.to_owned(), hash.to_owned()).is_some() {
                return Err("duplicate manifest vector".to_owned());
            }
        } else if required
            .remove(key)
            .is_none_or(|expected| expected != value)
        {
            return Err(format!("invalid manifest field: {key}"));
        }
    }
    if !required.is_empty() || entries.is_empty() {
        return Err("incomplete manifest".to_owned());
    }
    let actual = fs::read_dir(root)
        .map_err(|error| error.to_string())?
        .map(|entry| entry.map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name != "manifest.txt")
        .collect::<BTreeSet<_>>();
    if actual != entries.keys().cloned().collect() {
        return Err("missing or unlisted vector".to_owned());
    }
    for (name, expected_hash) in &entries {
        if sha256(&fs::read(root.join(name)).map_err(|error| error.to_string())?) != *expected_hash
        {
            return Err(format!("corrupted vector: {name}"));
        }
    }
    validate_case_inventory(root, "addresses.vec", ADDRESS_CASES)?;
    validate_case_inventory(root, "identities.vec", IDENTITY_CASES)?;
    validate_case_inventory(root, "conflicts.vec", CONFLICT_CASES)?;
    Ok(entries)
}
fn copy_root(destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|error| error.to_string())?;
    for entry in fs::read_dir(root()).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        fs::copy(entry.path(), destination.join(entry.file_name()))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[test]
fn manifest_integrity_and_inventory_are_enforced() -> Result<(), String> {
    load(&root())?;
    let temp = std::env::temp_dir().join(format!("keynet-proto-vector-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp);
    copy_root(&temp)?;
    fs::remove_file(temp.join("identities.vec")).map_err(|error| error.to_string())?;
    if load(&temp).is_ok() {
        return Err("missing file accepted".to_owned());
    }
    let _ = fs::remove_dir_all(&temp);
    copy_root(&temp)?;
    let manifest =
        fs::read_to_string(temp.join("manifest.txt")).map_err(|error| error.to_string())?;
    fs::write(
        temp.join("manifest.txt"),
        format!("{manifest}file=addresses.vec|00\n"),
    )
    .map_err(|error| error.to_string())?;
    if load(&temp).is_ok() {
        return Err("duplicate file accepted".to_owned());
    }
    let _ = fs::remove_dir_all(&temp);
    copy_root(&temp)?;
    fs::write(temp.join("unlisted.vec"), "x\n").map_err(|error| error.to_string())?;
    if load(&temp).is_ok() {
        return Err("unlisted file accepted".to_owned());
    }
    let _ = fs::remove_dir_all(&temp);
    copy_root(&temp)?;
    fs::write(temp.join("addresses.vec"), "bad\n").map_err(|error| error.to_string())?;
    if load(&temp).is_ok() {
        return Err("corrupted file accepted".to_owned());
    }
    fs::remove_dir_all(temp).map_err(|error| error.to_string())
}

#[test]
fn fixed_address_and_identity_vectors_are_literal() -> Result<(), String> {
    load(&root())?;
    let address_text =
        fs::read_to_string(root().join("addresses.vec")).map_err(|error| error.to_string())?;
    for vector in blocks(&address_text)? {
        let network = hex(field(&vector, "network_id")?)?;
        let identity = hex(field(&vector, "identity")?)?;
        let mut input = [0; 65];
        input[0] = 1;
        input[1..33].copy_from_slice(&network);
        input[33..].copy_from_slice(&identity);
        let digest = independent_blake2s_15(&input)?;
        if digest != hex(field(&vector, "address_digest")?)? {
            return Err("fixed address digest mismatch".to_owned());
        }
        let group =
            derive_address_group(&network, &identity).map_err(|error| format!("{error:?}"))?;
        let expected_group = hex(field(&vector, "group_bytes")?)?;
        let expected_n4 = hex(field(&vector, "n4_bytes")?)?;
        if group.into_bytes() != expected_group
            || n6_bytes(&network, &identity).map_err(|error| format!("{error:?}"))?
                != expected_group
            || n4_bytes(&network, &identity).map_err(|error| format!("{error:?}"))? != expected_n4
        {
            return Err("address literal mismatch".to_owned());
        }
        let n6_text: Ipv6Addr = field(&vector, "n6_text")?
            .parse()
            .map_err(|error: std::net::AddrParseError| error.to_string())?;
        let n4_text: Ipv6Addr = field(&vector, "n4_text")?
            .parse()
            .map_err(|error: std::net::AddrParseError| error.to_string())?;
        if n6(&network, &identity).map_err(|error| format!("{error:?}"))? != n6_text
            || n4(&network, &identity).map_err(|error| format!("{error:?}"))? != n4_text
            || group_ipv6(n4_text) != n6_text
            || group_bytes(expected_n4) != expected_group
        {
            return Err("address text or mode mismatch".to_owned());
        }
    }
    let identity_text =
        fs::read_to_string(root().join("identities.vec")).map_err(|error| error.to_string())?;
    for vector in blocks(&identity_text)? {
        let identity = hex(field(&vector, "identity")?)?;
        if independent_blake2s_12(&identity)? != hex(field(&vector, "identity_digest")?)?
            || identity_label(&identity).map_err(|error| format!("{error:?}"))?
                != field(&vector, "name")?
        {
            return Err("identity literal mismatch".to_owned());
        }
    }
    Ok(())
}

#[test]
fn owner_conflict_vectors_cover_peer_and_join_paths() -> Result<(), String> {
    load(&root())?;
    for vector in blocks(
        &fs::read_to_string(root().join("conflicts.vec")).map_err(|error| error.to_string())?,
    )? {
        let candidate = owner(field(&vector, "candidate")?)?;
        let locals = owners(field(&vector, "locals")?)?;
        let peers = owners(field(&vector, "peers")?)?;
        let actual = match field(&vector, "operation")? {
            "peer" => check_peer_group(candidate, &locals, &peers),
            "new_local" => check_new_local_group(candidate, &locals, &peers),
            _ => return Err("unknown operation".to_owned()),
        };
        match (field(&vector, "expected")?, actual) {
            ("ok", Ok(())) => {}
            ("conflict", Err(conflict))
                if conflict.conflicting_owner == owner(field(&vector, "conflicting_owner")?)? => {}
            _ => return Err("unexpected owner-conflict result".to_owned()),
        }
    }
    Ok(())
}
