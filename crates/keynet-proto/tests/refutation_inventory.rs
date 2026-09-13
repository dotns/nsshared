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
        for name in ["addresses.vec", "identities.vec", "conflicts.vec"] {
            fs::write(temp.join(name), "").map_err(|error| error.to_string())?;
        }
        Ok(())
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
