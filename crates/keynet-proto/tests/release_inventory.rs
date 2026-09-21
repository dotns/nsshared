use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

const ROOT: &str = "tests/fixtures/keynet-v1";
const EXPECTED_MANIFEST_SHA256: &str =
    "d94567e13d26b85ca2ae26ee1b78f1ecf2a883c884c534b832da6df7771b4820";

const METADATA: &[(&str, &str)] = &[
    ("manifest_format", "keynet-fixture-manifest-v1"),
    ("suite_version", "keynet-v1"),
    ("fixture_release", "keynet-v1-v0.9"),
    ("section_13_revision", "v0.9"),
    ("design_path", "docs/ns/keynet.md"),
    ("design_commit", "abb1dad"),
    (
        "design_sha256",
        "a763e6db341b429361558df9ae81ca7d130cda7fb63ae912c2cf1f77638e27f2",
    ),
    ("data_file_count", "15"),
    (
        "coverage",
        "addresses,identities,conflicts,key_bindings,pairing_tokens,introductions,aliases,labels,name_records,relay,revocation,relay_identifiers,control_records,region_frames,region_marks,region_presence,integrity",
    ),
    ("address_cases", "ascending,zeros,reverse"),
    ("identity_cases", "ascending,zeros,reverse"),
    (
        "conflict_cases",
        "idempotent_peer,peer_exact_local_owner,self_collision,all_group_distinct_owner_collision,own_network_join_collision,own_network_join_clear",
    ),
    (
        "key_binding_cases",
        "minimum,maximum,width_23,width_24,width_255,width_256,width_65535,width_65536,width_4294967295,width_4294967296,conflict,latched_committed_rejected,latched_conflicting_rejected,latched_lower_rejected,latched_higher_installs,invalid_signature",
    ),
    ("pairing_token_cases", "full"),
    ("introduction_cases", "full"),
    ("alias_cases", "kind6_non_power_two,kind4_non_power_two"),
    (
        "label_cases",
        "ascii_runs,uppercase_non_ascii,empty,one_byte,length_63,truncate_64,truncate_trailing_hyphen,reserved_id,reserved_v4",
    ),
    ("name_record_cases", "claim_width_boundaries"),
    (
        "relay_revocation_fields",
        "network,identity,slot,node_private,node_ephemeral,relay_private,relay_ephemeral,register_unsigned,register_signature,reg_hash,shared_secret,session_key,register_datagram,registered_mac,registered_datagram,presence_mac,presence_datagram,reflect_mac,reflect_datagram,reflected_mac,reflected_datagram,intro_datagram,intro_ack_datagram,data_datagram,status_datagram,revoke_mac,revoke_datagram,revocation_unsigned,revocation_signature,revocation",
    ),
    (
        "relay_identifier_cases",
        "relay_dns,relay_ipv4,relay_ipv6,relay_short,endpoint_dns,endpoint_ipv4,endpoint_ipv6,local_dns_case_dot,local_ipv6_case_zeros,invalid_scheme,invalid_port_zero,invalid_port_leading_zero,invalid_unbracketed_ipv6,invalid_zone,invalid_ipv4_leading_zero,invalid_dns_uppercase,invalid_dns_terminal_dot,invalid_short_uppercase,invalid_short_trailing_hyphen,invalid_short_endpoint,invalid_unicode,invalid_whitespace,invalid_mapped_ipv6,invalid_unspecified_ipv6,invalid_multicast_ipv6,invalid_site_local_ipv6",
    ),
    (
        "control_record_fields",
        "ack,legacy_endpoints,binding,revocation,name,ordered_endpoints,probe_request,probe_reply,ordered_hash,greedy_ordered_endpoints,greedy_omitted_relays",
    ),
    (
        "region_frame_cases",
        "hello_control,hello_data,snapshot_nested,present,gone,marks,forward,miss,ping,pong,non_shortest,indefinite_length,wrong_arity,wrong_type,wrong_width,trailing_bytes,wrong_channel,zero_prefix,oversized_prefix,frame_limit,datagram_limit,snapshot_entry_limit",
    ),
    (
        "region_marks_cases",
        "permutations,reordered,duplicate_inputs,independent_revocation,higher_generation_reset,equal_generation_conflict,deterministic_representative",
    ),
    (
        "region_presence_cases",
        "origin_ownership,full_owner_collision,generation_before_incarnation,incarnation_before_member_id,durable_mark_filtering,member_id_tie_break,exact_gone_removal,revision_high_water,stale_stream,epoch_replacement,local_loser_effects,grace_channel_down,durable_floors_retained,capacity_bound,higher_generation_channel_down,same_origin_lower_generation,snapshot_empty,snapshot_size_bound,snapshot_unchanged_cuts,snapshot_contiguous_indices,snapshot_final_chunk,snapshot_deferred_routes,snapshot_changed_cuts,snapshot_changed_id,snapshot_duplicate_index,snapshot_gap,snapshot_exhaustion,snapshot_duplicate_presence_owner,snapshot_duplicate_mark_owner,snapshot_wrong_epoch,snapshot_wrong_slot,snapshot_invalid_revision,snapshot_cut_regression,snapshot_mark_compatibility,snapshot_interruption,snapshot_completion,snapshot_reconnect_restart,snapshot_post_completion,snapshot_stale_id",
    ),
];

const FILES: &[(&str, &str)] = &[
    (
        "addresses.vec",
        "4be3448808959b8ad8bb301c7ed3e88bcf100cd68be13faf114b284d4ada2333",
    ),
    (
        "identities.vec",
        "806d82478f9a665b12ba13302f78d590969a6c5371240fc183df9a1aa1f25841",
    ),
    (
        "conflicts.vec",
        "87056bf4e15dfa63c67fcaea587ef68dec1c38b625fa713e166c9f12f6aa3b84",
    ),
    (
        "key_bindings.vec",
        "0b6378af48eed1b49c96c34f016415e140860c32845e2cae73742d22d2fc46ba",
    ),
    (
        "pairing_tokens.vec",
        "e2933b83298772e7fd36b6418f73d899cf4b08cf733e1fe324bdee025f2a571d",
    ),
    (
        "introductions.vec",
        "6d0c1ca8f8a3e9199077077e78e543f305b80f7df5a5a61e1ca6463adc45d2e8",
    ),
    (
        "aliases.vec",
        "0406dd0e60de7133e92323cdb3c391a17235b747cdd95a5167fb3d02ed6f3916",
    ),
    (
        "labels.vec",
        "2b0328e0c3fc700929d58dee51a1a3fbda48518f9304200a2ce3773fa86f5330",
    ),
    (
        "name_records.vec",
        "74584e2e68f2eaf382a63d4829b4ea9e92346bd37239208bba6a6e063d3a03e2",
    ),
    (
        "relay_revocation.vec",
        "4f36ef6e4e5f07cdb778aea2855f0ffbd9b1597f35f1530ad69dcc092bbe345a",
    ),
    (
        "control_records.vec",
        "4197b46b58694796d25a6592a4f1fc795c0a564973716d06eb6687d55b256ba9",
    ),
    (
        "relay_identifiers.vec",
        "d5b3c2a0a5ded38201ad8f57ac437f8067d6461125086a0fa5bd854de1183595",
    ),
    (
        "region_frames.vec",
        "ecae34dc8a6818422c8328dc5a64494b0d01134069267da0ddf00563af7bc065",
    ),
    (
        "region_marks.vec",
        "40cbac6a53edc4a636265497e4daeb8186d0f0742de4a325ae1023e91aef17e6",
    ),
    (
        "region_presence.vec",
        "f3cd8db4ac371c87537fae7cdde54882f287cef76ad1ea0878ee11e92d9d1a91",
    ),
];

const BLOCK_INVENTORIES: &[(&str, &str)] = &[
    ("addresses.vec", "address_cases"),
    ("identities.vec", "identity_cases"),
    ("conflicts.vec", "conflict_cases"),
    ("key_bindings.vec", "key_binding_cases"),
    ("pairing_tokens.vec", "pairing_token_cases"),
    ("introductions.vec", "introduction_cases"),
    ("aliases.vec", "alias_cases"),
    ("labels.vec", "label_cases"),
    ("name_records.vec", "name_record_cases"),
    ("region_frames.vec", "region_frame_cases"),
    ("region_marks.vec", "region_marks_cases"),
    ("region_presence.vec", "region_presence_cases"),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(ROOT)
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn listed(value: &str) -> Result<BTreeSet<&str>, String> {
    let items = value.split(',').collect::<BTreeSet<_>>();
    if items.is_empty() || items.contains("") || items.len() != value.split(',').count() {
        return Err("invalid manifest inventory".to_owned());
    }
    Ok(items)
}

fn metadata_value<'a>(metadata: &'a [(&str, &str)], key: &str) -> Result<&'a str, String> {
    metadata
        .iter()
        .find_map(|(candidate, value)| (*candidate == key).then_some(*value))
        .ok_or_else(|| format!("missing manifest inventory: {key}"))
}

fn block_cases(root: &Path, name: &str) -> Result<BTreeSet<String>, String> {
    let text = fs::read_to_string(root.join(name)).map_err(|error| error.to_string())?;
    let mut cases = BTreeSet::new();
    for block in text.split("\n\n").filter(|block| !block.trim().is_empty()) {
        let mut fields = BTreeSet::new();
        let mut case = None;
        for line in block.lines().filter(|line| !line.starts_with('#')) {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("invalid vector line in {name}"))?;
            if !fields.insert(key) {
                return Err(format!("invalid vector field in {name}: {key}"));
            }
            if key == "case" {
                if value.is_empty() {
                    return Err(format!("empty vector case in {name}"));
                }
                case = Some(value.to_owned());
            }
        }
        let case = case.ok_or_else(|| format!("missing vector case in {name}"))?;
        if !cases.insert(case.clone()) {
            return Err(format!("duplicate vector case in {name}: {case}"));
        }
    }
    if cases.is_empty() {
        return Err(format!("empty vector family: {name}"));
    }
    Ok(cases)
}

fn flat_fields(root: &Path, name: &str) -> Result<BTreeSet<String>, String> {
    let text = fs::read_to_string(root.join(name)).map_err(|error| error.to_string())?;
    let mut fields = BTreeSet::new();
    for line in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (field, value) = line
            .split_once('|')
            .ok_or_else(|| format!("invalid flat vector line in {name}"))?;
        if value.is_empty() || !fields.insert(field.to_owned()) {
            return Err(format!("invalid flat vector field in {name}: {field}"));
        }
    }
    Ok(fields)
}

fn identifier_cases(root: &Path) -> Result<BTreeSet<String>, String> {
    let text = fs::read_to_string(root.join("relay_identifiers.vec"))
        .map_err(|error| error.to_string())?;
    let mut cases = BTreeSet::new();
    for line in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let mut fields = line.split('|');
        let kind = fields.next().ok_or("missing relay identifier kind")?;
        let case = fields.next().ok_or("missing relay identifier case")?;
        if !cases.insert(format!("{kind}_{case}")) {
            return Err("duplicate relay identifier case".to_owned());
        }
    }
    Ok(cases)
}

fn verify(root: &Path) -> Result<(), String> {
    let root_metadata = fs::symlink_metadata(root).map_err(|error| error.to_string())?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err("fixture root must be a local directory".to_owned());
    }

    let mut actual_files = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "fixture filename must be UTF-8".to_owned())?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!("fixture entry must be a regular file: {name}"));
        }
        if !actual_files.insert(name.clone()) {
            return Err(format!("duplicate fixture entry: {name}"));
        }
    }

    let manifest_bytes = fs::read(root.join("manifest.txt")).map_err(|error| error.to_string())?;
    if manifest_bytes.last() != Some(&b'\n') || manifest_bytes.contains(&b'\r') {
        return Err("manifest must use terminal LF lines".to_owned());
    }
    let manifest = std::str::from_utf8(&manifest_bytes).map_err(|error| error.to_string())?;
    let mut metadata = Vec::new();
    let mut files = Vec::new();
    let mut seen_metadata = BTreeSet::new();
    let mut seen_files = BTreeSet::new();
    let mut file_section = false;
    for line in manifest.strip_suffix('\n').unwrap_or(manifest).split('\n') {
        if line.is_empty() {
            return Err("manifest contains an empty line".to_owned());
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| "invalid manifest line".to_owned())?;
        if key == "file" {
            file_section = true;
            let (name, digest) = value
                .split_once('|')
                .ok_or_else(|| "invalid manifest file entry".to_owned())?;
            if !seen_files.insert(name) {
                return Err(format!("duplicate manifest file entry: {name}"));
            }
            files.push((name, digest));
        } else {
            if file_section || !seen_metadata.insert(key) {
                return Err(format!("invalid manifest metadata entry: {key}"));
            }
            metadata.push((key, value));
        }
    }
    if metadata != METADATA || files != FILES {
        return Err("release manifest does not match the sealed inventory".to_owned());
    }
    if sha256(&manifest_bytes) != EXPECTED_MANIFEST_SHA256 {
        return Err("release manifest digest mismatch".to_owned());
    }

    let expected_files = FILES
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .chain(std::iter::once("manifest.txt".to_owned()))
        .collect::<BTreeSet<_>>();
    if actual_files != expected_files {
        return Err("missing or unlisted release file".to_owned());
    }
    for (name, digest) in FILES {
        if sha256(&fs::read(root.join(name)).map_err(|error| error.to_string())?) != *digest {
            return Err(format!("sealed fixture digest mismatch: {name}"));
        }
    }

    for (name, inventory_key) in BLOCK_INVENTORIES {
        let expected = listed(metadata_value(METADATA, inventory_key)?)?
            .into_iter()
            .map(str::to_owned)
            .collect();
        if block_cases(root, name)? != expected {
            return Err(format!("sealed case inventory mismatch: {name}"));
        }
    }
    for (name, inventory_key) in [
        ("relay_revocation.vec", "relay_revocation_fields"),
        ("control_records.vec", "control_record_fields"),
    ] {
        let expected = listed(metadata_value(METADATA, inventory_key)?)?
            .into_iter()
            .map(str::to_owned)
            .collect();
        if flat_fields(root, name)? != expected {
            return Err(format!("sealed field inventory mismatch: {name}"));
        }
    }
    let expected_identifiers = listed(metadata_value(METADATA, "relay_identifier_cases")?)?
        .into_iter()
        .map(str::to_owned)
        .collect();
    if identifier_cases(root)? != expected_identifiers {
        return Err("sealed relay identifier inventory mismatch".to_owned());
    }
    Ok(())
}

fn copy_release(destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|error| error.to_string())?;
    for entry in fs::read_dir(root()).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        fs::copy(entry.path(), destination.join(entry.file_name()))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn rejects(attack: &str, alter: impl FnOnce(&Path) -> Result<(), String>) -> Result<(), String> {
    let temp = std::env::temp_dir().join(format!("keynet-release-{attack}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp);
    copy_release(&temp)?;
    alter(&temp)?;
    let result = verify(&temp);
    fs::remove_dir_all(&temp).map_err(|error| error.to_string())?;
    if result.is_ok() {
        return Err(format!("release seal accepted {attack}"));
    }
    Ok(())
}

#[test]
fn complete_v09_release_matches_the_sealed_inventory() -> Result<(), String> {
    verify(&root())
}

#[test]
fn release_seal_rejects_manifest_file_and_link_drift() -> Result<(), String> {
    rejects("missing", |temp| {
        fs::remove_file(temp.join("addresses.vec")).map_err(|error| error.to_string())
    })?;
    rejects("unlisted", |temp| {
        fs::write(temp.join("extra.vec"), "literal|00\n").map_err(|error| error.to_string())
    })?;
    rejects("directory", |temp| {
        fs::create_dir(temp.join("nested.vec")).map_err(|error| error.to_string())
    })?;
    rejects("corrupted", |temp| {
        fs::write(temp.join("addresses.vec"), "changed\n").map_err(|error| error.to_string())
    })?;
    rejects("rehashed", |temp| {
        let path = temp.join("addresses.vec");
        fs::write(&path, "changed\n").map_err(|error| error.to_string())?;
        let digest = sha256(&fs::read(&path).map_err(|error| error.to_string())?);
        let manifest_path = temp.join("manifest.txt");
        let manifest = fs::read_to_string(&manifest_path).map_err(|error| error.to_string())?;
        fs::write(manifest_path, manifest.replace(FILES[0].1, &digest))
            .map_err(|error| error.to_string())
    })?;
    rejects("duplicate-metadata", |temp| {
        let path = temp.join("manifest.txt");
        let manifest = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        fs::write(path, format!("suite_version=keynet-v1\n{manifest}"))
            .map_err(|error| error.to_string())
    })?;
    rejects("duplicate-file", |temp| {
        let path = temp.join("manifest.txt");
        let manifest = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        fs::write(
            path,
            format!("{manifest}file={}|{}\n", FILES[0].0, FILES[0].1),
        )
        .map_err(|error| error.to_string())
    })?;
    #[cfg(unix)]
    rejects("symlink", |temp| {
        use std::os::unix::fs::symlink;

        let path = temp.join("addresses.vec");
        fs::remove_file(&path).map_err(|error| error.to_string())?;
        symlink(root().join("addresses.vec"), path).map_err(|error| error.to_string())
    })?;
    Ok(())
}
