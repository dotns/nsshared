include!("vectors.rs");

fn altered_inventory(
    attack: &str,
    alter: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let temp =
        std::env::temp_dir().join(format!("keynet-inventory-{attack}-{}", std::process::id()));
    copy_root(&temp)?;
    alter(&temp)?;
    let manifest_path = temp.join("manifest.txt");
    let manifest = fs::read_to_string(&manifest_path).map_err(|error| error.to_string())?;
    let mut updated = String::new();
    for line in manifest.lines() {
        if let Some(entry) = line.strip_prefix("file=") {
            let (name, _) = entry.split_once('|').ok_or("invalid fixture entry")?;
            let digest = sha256(&fs::read(temp.join(name)).map_err(|error| error.to_string())?);
            updated.push_str(&format!("file={name}|{digest}\n"));
        } else {
            updated.push_str(line);
            updated.push('\n');
        }
    }
    fs::write(manifest_path, updated).map_err(|error| error.to_string())?;
    let actual = load(&temp);
    fs::remove_dir_all(&temp).map_err(|error| error.to_string())?;
    if actual.is_ok() {
        return Err(format!(
            "{attack}: loader accepted invalid vector inventory with valid file hashes"
        ));
    }
    Ok(())
}

#[test]
fn r1_empty_vector_families_must_be_rejected() -> Result<(), String> {
    altered_inventory("empty-families", |temp| {
        for name in [
            "addresses.vec",
            "identities.vec",
            "conflicts.vec",
            "key_bindings.vec",
            "aliases.vec",
            "labels.vec",
            "name_records.vec",
            "region_frames.vec",
            "region_marks.vec",
            "region_presence.vec",
            "relay_revocation.vec",
        ] {
            fs::write(temp.join(name), "").map_err(|error| error.to_string())?;
        }
        Ok(())
    })
}

#[test]
fn p4a_duplicate_missing_and_unlisted_cases_must_be_rejected() -> Result<(), String> {
    altered_inventory("duplicate-name-record", |temp| {
        let path = temp.join("name_records.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        fs::write(path, format!("{original}\n{original}")).map_err(|error| error.to_string())
    })?;
    altered_inventory("missing-alias-kind", |temp| {
        let path = temp.join("aliases.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let remaining = original
            .split("\n\n")
            .filter(|block| !block.contains("case=kind4_non_power_two\n"))
            .collect::<Vec<_>>()
            .join("\n\n");
        fs::write(path, remaining).map_err(|error| error.to_string())
    })?;
    altered_inventory("unlisted-label", |temp| {
        let path = temp.join("labels.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let unlisted = original
            .split("\n\n")
            .next()
            .ok_or("missing label vector")?
            .replacen("case=ascii_runs", "case=unlisted", 1);
        fs::write(path, format!("{original}\n\n{unlisted}\n")).map_err(|error| error.to_string())
    })
}

#[test]
fn p5a_relay_fixture_field_inventory_must_be_exact() -> Result<(), String> {
    altered_inventory("missing-relay-field", |temp| {
        let path = temp.join("relay_revocation.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let remaining = original
            .lines()
            .filter(|line| !line.starts_with("status_datagram|"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(path, format!("{remaining}\n")).map_err(|error| error.to_string())
    })?;
    altered_inventory("duplicate-relay-field", |temp| {
        let path = temp.join("relay_revocation.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let first = original.lines().next().ok_or("missing relay vector")?;
        fs::write(path, format!("{original}{first}\n")).map_err(|error| error.to_string())
    })?;
    altered_inventory("unlisted-relay-field", |temp| {
        let path = temp.join("relay_revocation.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        fs::write(path, format!("{original}unexpected|00\n")).map_err(|error| error.to_string())
    })
}

#[test]
fn p5b_rework_fixture_inventory_must_be_exact() -> Result<(), String> {
    altered_inventory("missing-greedy-selection", |temp| {
        let path = temp.join("control_records.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let remaining = original
            .lines()
            .filter(|line| !line.starts_with("greedy_ordered_endpoints|"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(path, format!("{remaining}\n")).map_err(|error| error.to_string())
    })?;
    altered_inventory("missing-site-local-identifier", |temp| {
        let path = temp.join("relay_identifiers.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let remaining = original
            .lines()
            .filter(|line| !line.starts_with("invalid|site_local_ipv6|"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(path, format!("{remaining}\n")).map_err(|error| error.to_string())
    })
}

#[test]
fn r1_duplicate_vector_cases_must_be_rejected() -> Result<(), String> {
    altered_inventory("duplicate-cases", |temp| {
        let path = temp.join("identities.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        fs::write(path, format!("{original}\n{original}")).map_err(|error| error.to_string())
    })
}

#[test]
fn r1_missing_self_collision_case_must_be_rejected() -> Result<(), String> {
    altered_inventory("missing-self-collision", |temp| {
        let path = temp.join("conflicts.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let remaining = original
            .split("\n\n")
            .filter(|block| !block.contains("case=self_collision\n"))
            .collect::<Vec<_>>()
            .join("\n\n");
        fs::write(path, remaining).map_err(|error| error.to_string())
    })
}

#[test]
fn r2_missing_key_binding_case_must_be_rejected() -> Result<(), String> {
    altered_inventory("missing-key-binding", |temp| {
        let path = temp.join("key_bindings.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let remaining = original
            .split("\n\n")
            .filter(|block| !block.contains("case=maximum\n"))
            .collect::<Vec<_>>()
            .join("\n\n");
        fs::write(path, remaining).map_err(|error| error.to_string())
    })
}

#[test]
fn r1_unlisted_vector_case_must_be_rejected() -> Result<(), String> {
    altered_inventory("unlisted-case", |temp| {
        let path = temp.join("addresses.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let unlisted = original
            .split("\n\n")
            .next()
            .ok_or("missing address vector")?
            .replacen("case=ascending", "case=unlisted", 1);
        fs::write(path, format!("{original}\n\n{unlisted}\n")).map_err(|error| error.to_string())
    })
}

#[test]
fn region_frame_fixture_and_case_inventory_must_be_exact() -> Result<(), String> {
    altered_inventory("missing-region-frame-fixture", |temp| {
        fs::remove_file(temp.join("region_frames.vec")).map_err(|error| error.to_string())?;
        let manifest_path = temp.join("manifest.txt");
        let manifest = fs::read_to_string(&manifest_path).map_err(|error| error.to_string())?;
        let updated = manifest
            .lines()
            .filter(|line| !line.starts_with("file=region_frames.vec|"))
            .map(|line| {
                if line == "data_file_count=15" {
                    "data_file_count=14"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(manifest_path, format!("{updated}\n")).map_err(|error| error.to_string())
    })?;
    altered_inventory("empty-region-frame-fixture", |temp| {
        fs::write(temp.join("region_frames.vec"), "").map_err(|error| error.to_string())
    })?;
    altered_inventory("duplicate-region-frame-case", |temp| {
        let path = temp.join("region_frames.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        fs::write(path, format!("{original}\n{original}")).map_err(|error| error.to_string())
    })?;
    altered_inventory("unlisted-region-frame-case", |temp| {
        let path = temp.join("region_frames.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let updated = original.replacen("case=ping\n", "case=unlisted\n", 1);
        fs::write(path, updated).map_err(|error| error.to_string())
    })
}

#[test]
fn region_marks_fixture_and_case_inventory_must_be_exact() -> Result<(), String> {
    altered_inventory("missing-region-marks-fixture", |temp| {
        fs::remove_file(temp.join("region_marks.vec")).map_err(|error| error.to_string())?;
        let manifest_path = temp.join("manifest.txt");
        let manifest = fs::read_to_string(&manifest_path).map_err(|error| error.to_string())?;
        let updated = manifest
            .lines()
            .filter(|line| !line.starts_with("file=region_marks.vec|"))
            .map(|line| {
                if line == "data_file_count=15" {
                    "data_file_count=14"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(manifest_path, format!("{updated}\n")).map_err(|error| error.to_string())
    })?;
    altered_inventory("empty-region-marks-fixture", |temp| {
        fs::write(temp.join("region_marks.vec"), "").map_err(|error| error.to_string())
    })?;
    altered_inventory("duplicate-region-marks-case", |temp| {
        let path = temp.join("region_marks.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        fs::write(path, format!("{original}\n{original}")).map_err(|error| error.to_string())
    })?;
    altered_inventory("unlisted-region-marks-case", |temp| {
        let path = temp.join("region_marks.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let updated = original.replacen("case=permutations\n", "case=unlisted\n", 1);
        fs::write(path, updated).map_err(|error| error.to_string())
    })
}

#[test]
fn region_presence_fixture_and_case_inventory_must_be_exact() -> Result<(), String> {
    altered_inventory("missing-region-presence-fixture", |temp| {
        fs::remove_file(temp.join("region_presence.vec")).map_err(|error| error.to_string())?;
        let manifest_path = temp.join("manifest.txt");
        let manifest = fs::read_to_string(&manifest_path).map_err(|error| error.to_string())?;
        let updated = manifest
            .lines()
            .filter(|line| !line.starts_with("file=region_presence.vec|"))
            .map(|line| {
                if line == "data_file_count=15" {
                    "data_file_count=14"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(manifest_path, format!("{updated}\n")).map_err(|error| error.to_string())
    })?;
    altered_inventory("empty-region-presence-fixture", |temp| {
        fs::write(temp.join("region_presence.vec"), "").map_err(|error| error.to_string())
    })?;
    altered_inventory("duplicate-region-presence-case", |temp| {
        let path = temp.join("region_presence.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        fs::write(path, format!("{original}\n{original}")).map_err(|error| error.to_string())
    })?;
    altered_inventory("unlisted-region-presence-case", |temp| {
        let path = temp.join("region_presence.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let updated = original.replacen("case=origin_ownership\n", "case=unlisted\n", 1);
        fs::write(path, updated).map_err(|error| error.to_string())
    })?;
    altered_inventory("missing-snapshot-completion-case", |temp| {
        let path = temp.join("region_presence.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let remaining = original
            .split("\n\n")
            .filter(|block| !block.contains("case=snapshot_completion\n"))
            .collect::<Vec<_>>()
            .join("\n\n");
        fs::write(path, remaining).map_err(|error| error.to_string())
    })?;
    altered_inventory("missing-snapshot-chunk-mark-persistence-case", |temp| {
        let path = temp.join("region_presence.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let remaining = original
            .split("\n\n")
            .filter(|block| !block.contains("case=snapshot_chunk_mark_persistence\n"))
            .collect::<Vec<_>>()
            .join("\n\n");
        fs::write(path, remaining).map_err(|error| error.to_string())
    })?;
    altered_inventory("missing-snapshot-cut-receipt-case", |temp| {
        let path = temp.join("region_presence.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let remaining = original
            .split("\n\n")
            .filter(|block| !block.contains("case=snapshot_cut_receipt\n"))
            .collect::<Vec<_>>()
            .join("\n\n");
        fs::write(path, remaining).map_err(|error| error.to_string())
    })?;
    altered_inventory("missing-snapshot-owner-index-case", |temp| {
        let path = temp.join("region_presence.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let remaining = original
            .split("\n\n")
            .filter(|block| !block.contains("case=snapshot_owner_index_scope\n"))
            .collect::<Vec<_>>()
            .join("\n\n");
        fs::write(path, remaining).map_err(|error| error.to_string())
    })?;
    altered_inventory("unlisted-snapshot-staging-case", |temp| {
        let path = temp.join("region_presence.vec");
        let original = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let updated = original.replacen(
            "case=snapshot_empty\n",
            "case=unlisted_snapshot_staging\n",
            1,
        );
        fs::write(path, updated).map_err(|error| error.to_string())
    })
}
