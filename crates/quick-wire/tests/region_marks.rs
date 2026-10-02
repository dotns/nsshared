use quick_wire::{RegionMarks, RegionMarksJoinError, join_region_marks};
use std::{collections::BTreeMap, fs, path::PathBuf};

const ROOT: &str = "tests/fixtures/keynet-v1";

fn marks(
    generation: u64,
    key_byte: u8,
    conflicted: bool,
    revoked_through: Option<u64>,
    incarnation_high_water: u64,
) -> RegionMarks {
    RegionMarks {
        network_id: [0x11; 32],
        identity: [0x22; 32],
        committed_generation: generation,
        committed_key: [key_byte; 32],
        conflicted,
        revoked_through,
        incarnation_high_water,
    }
}

fn joined(current: RegionMarks, incoming: RegionMarks) -> Result<RegionMarks, String> {
    let result = join_region_marks(current, incoming).map_err(|error| format!("{error:?}"))?;
    assert_eq!(result.changed, result.state != current);
    Ok(result.state)
}

fn join_sequence(inputs: &[RegionMarks]) -> Result<(RegionMarks, bool), String> {
    let original = *inputs.first().ok_or("empty marks sequence")?;
    let mut state = original;
    for incoming in &inputs[1..] {
        state = joined(state, *incoming)?;
    }
    Ok((state, state != original))
}

fn every_order(inputs: &[RegionMarks]) -> Vec<Vec<RegionMarks>> {
    fn collect(
        prefix: &mut Vec<RegionMarks>,
        remaining: &mut Vec<RegionMarks>,
        orders: &mut Vec<Vec<RegionMarks>>,
    ) {
        if remaining.is_empty() {
            orders.push(prefix.clone());
            return;
        }
        for index in 0..remaining.len() {
            let input = remaining.remove(index);
            prefix.push(input);
            collect(prefix, remaining, orders);
            let restored = prefix.pop();
            if let Some(restored) = restored {
                remaining.insert(index, restored);
            }
        }
    }

    let mut orders = Vec::new();
    let mut prefix = Vec::new();
    let mut remaining = inputs.to_vec();
    collect(&mut prefix, &mut remaining, &mut orders);
    orders
}

#[test]
fn region_marks_join_laws_hold_for_every_fixed_order() -> Result<(), String> {
    let inputs = [
        marks(7, 0x30, false, None, 4),
        marks(7, 0x20, false, Some(3), 9),
        marks(7, 0x10, false, Some(5), 2),
    ];
    let expected = marks(7, 0x10, true, Some(5), 9);

    for input in inputs {
        assert_eq!(joined(input, input)?, input);
    }
    for left in inputs {
        for right in inputs {
            assert_eq!(joined(left, right)?, joined(right, left)?);
            for third in inputs {
                let left_associated = joined(joined(left, right)?, third)?;
                let right_associated = joined(left, joined(right, third)?)?;
                assert_eq!(left_associated, right_associated);
            }
        }
    }
    for order in every_order(&inputs) {
        assert_eq!(join_sequence(&order)?.0, expected);
    }
    assert_eq!(every_order(&inputs).len(), 6);
    Ok(())
}

#[test]
fn region_marks_join_keeps_revocation_when_generation_advances() -> Result<(), String> {
    let old = marks(4, 0x40, true, Some(11), u64::MAX);
    let newer = marks(9, 0x90, false, None, 2);
    let joined_marks = joined(old, newer)?;
    assert_eq!(joined_marks, marks(9, 0x90, false, Some(11), 2));

    let older_with_higher_revocation = marks(4, 0x41, true, Some(19), u64::MAX);
    assert_eq!(
        joined(joined_marks, older_with_higher_revocation)?,
        marks(9, 0x90, false, Some(19), 2)
    );
    Ok(())
}

#[test]
fn region_marks_join_latches_equal_generation_key_conflicts() -> Result<(), String> {
    let larger_key = marks(6, 0xf0, false, None, 4);
    let smaller_key = marks(6, 0x0f, false, Some(3), 8);
    let expected = marks(6, 0x0f, true, Some(3), 8);

    assert_eq!(joined(larger_key, smaller_key)?, expected);
    assert_eq!(joined(smaller_key, larger_key)?, expected);
    assert_eq!(joined(expected, smaller_key)?, expected);
    Ok(())
}

#[test]
fn region_marks_join_rejects_a_different_network_id() {
    let current = marks(7, 0x20, false, Some(3), 9);
    let mut incoming = current;
    incoming.network_id = [0x12; 32];

    assert_eq!(
        join_region_marks(current, incoming),
        Err(RegionMarksJoinError::ScopeMismatch)
    );
}

#[test]
fn region_marks_join_rejects_a_different_identity() {
    let current = marks(7, 0x20, false, Some(3), 9);
    let mut incoming = current;
    incoming.identity = [0x23; 32];

    assert_eq!(
        join_region_marks(current, incoming),
        Err(RegionMarksJoinError::ScopeMismatch)
    );
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(ROOT)
}

fn blocks(text: &str) -> Result<Vec<BTreeMap<&str, &str>>, String> {
    text.split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .map(|block| {
            let mut fields = BTreeMap::new();
            for line in block.lines().filter(|line| !line.starts_with('#')) {
                let (key, value) = line
                    .split_once('=')
                    .ok_or_else(|| "invalid marks vector line".to_owned())?;
                if fields.insert(key, value).is_some() {
                    return Err(format!("duplicate marks vector field: {key}"));
                }
            }
            Ok(fields)
        })
        .collect()
}

fn field<'a>(fields: &'a BTreeMap<&str, &str>, name: &str) -> Result<&'a str, String> {
    fields
        .get(name)
        .copied()
        .ok_or_else(|| format!("missing marks vector field: {name}"))
}

fn parse_marks(input: &str) -> Result<RegionMarks, String> {
    let mut fields = input.split(':');
    let generation = field_value(&mut fields, "generation")?
        .parse()
        .map_err(|error: std::num::ParseIntError| format!("invalid marks generation: {error}"))?;
    let key_byte = u8::from_str_radix(field_value(&mut fields, "key")?, 16)
        .map_err(|error| format!("invalid marks key: {error}"))?;
    let conflicted = match field_value(&mut fields, "conflicted")? {
        "false" => false,
        "true" => true,
        _ => return Err("invalid marks conflict flag".to_owned()),
    };
    let revoked_through = match field_value(&mut fields, "revoked_through")? {
        "-" => None,
        value => Some(value.parse().map_err(|error: std::num::ParseIntError| {
            format!("invalid marks revocation: {error}")
        })?),
    };
    let incarnation_high_water = field_value(&mut fields, "incarnation")?
        .parse()
        .map_err(|error: std::num::ParseIntError| format!("invalid marks incarnation: {error}"))?;
    if fields.next().is_some() {
        return Err("extra marks vector values".to_owned());
    }
    Ok(marks(
        generation,
        key_byte,
        conflicted,
        revoked_through,
        incarnation_high_water,
    ))
}

fn field_value<'a>(
    fields: &mut impl Iterator<Item = &'a str>,
    name: &str,
) -> Result<&'a str, String> {
    fields
        .next()
        .ok_or_else(|| format!("missing marks vector value: {name}"))
}

fn parse_sequence(input: &str) -> Result<Vec<RegionMarks>, String> {
    input.split(';').map(parse_marks).collect()
}

#[test]
fn sealed_region_marks_vectors_are_literal() -> Result<(), String> {
    let text =
        fs::read_to_string(root().join("region_marks.vec")).map_err(|error| error.to_string())?;
    for vector in blocks(&text)? {
        if vector.len() != 4 {
            return Err("unexpected marks vector field count".to_owned());
        }
        let case = field(&vector, "case")?;
        let sequence = parse_sequence(field(&vector, "sequence")?)?;
        let expected = parse_marks(field(&vector, "expected")?)?;
        let expected_changed = match field(&vector, "changed_from_initial")? {
            "false" => false,
            "true" => true,
            _ => return Err("invalid marks vector changed flag".to_owned()),
        };
        let (actual, changed_from_initial) = join_sequence(&sequence)?;
        assert_eq!(actual, expected, "marks vector case: {case}");
        assert_eq!(
            changed_from_initial, expected_changed,
            "marks vector case: {case}"
        );
        if case == "permutations" {
            for order in every_order(&sequence) {
                assert_eq!(join_sequence(&order)?.0, expected);
            }
        }
    }
    Ok(())
}
