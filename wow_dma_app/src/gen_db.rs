// language: Rust, file: src/gen_db.rs, target: Windows 11, MSVC x64
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Write};

fn parse_csv_simple(content: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut current_row = Vec::new();
    let mut current_field = String::new();
    let mut in_quotes = false;
    let mut chars = content.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current_field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                current_field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => {
                    current_row.push(current_field.trim().to_string());
                    current_field.clear();
                }
                '\r' => {}
                '\n' => {
                    current_row.push(current_field.trim().to_string());
                    current_field.clear();
                    if !current_row.is_empty() && (current_row.len() > 1 || !current_row[0].is_empty()) {
                        rows.push(current_row);
                    }
                    current_row = Vec::new();
                }
                _ => current_field.push(c),
            }
        }
    }
    if !current_field.is_empty() || !current_row.is_empty() {
        current_row.push(current_field.trim().to_string());
        rows.push(current_row);
    }
    rows
}

fn main() {
    println!("=== WOW CLASSIC SPELL DATABASE COMPILER ===");

    let spell_name_path = "data/SpellName.csv";
    let spell_path = "data/Spell.csv";
    let out_bin_path = "data/spells.bin";

    println!("[*] Reading {}...", spell_name_path);
    let mut name_file = File::open(spell_name_path).expect("Failed to open SpellName.csv");
    let mut name_str = String::new();
    name_file.read_to_string(&mut name_str).expect("Failed to read SpellName.csv");

    let name_rows = parse_csv_simple(&name_str);
    println!("[+] Parsed {} rows from SpellName.csv", name_rows.len());

    let mut names: HashMap<u32, String> = HashMap::new();
    for row in name_rows.into_iter().skip(1) {
        if row.len() >= 2 {
            if let Ok(id) = row[0].parse::<u32>() {
                let name = row[1].trim();
                if !name.is_empty() {
                    names.insert(id, name.to_string());
                }
            }
        }
    }
    println!("[+] Extracted {} valid spell names", names.len());

    println!("[*] Reading {}...", spell_path);
    let mut spell_file = File::open(spell_path).expect("Failed to open Spell.csv");
    let mut spell_str = String::new();
    spell_file.read_to_string(&mut spell_str).expect("Failed to read Spell.csv");

    let spell_rows = parse_csv_simple(&spell_str);
    println!("[+] Parsed {} rows from Spell.csv", spell_rows.len());

    let mut subtexts: HashMap<u32, String> = HashMap::new();
    for row in spell_rows.into_iter().skip(1) {
        if row.len() >= 2 {
            if let Ok(id) = row[0].parse::<u32>() {
                let sub = row[1].trim();
                if !sub.is_empty() {
                    subtexts.insert(id, sub.to_string());
                }
            }
        }
    }
    println!("[+] Extracted {} spell subtexts (ranks)", subtexts.len());

    // Merge names and ranks
    let mut merged: Vec<(u32, String)> = Vec::new();
    for (id, name) in names {
        let full_name = if let Some(sub) = subtexts.get(&id) {
            let rank_str = if let Some(stripped) = sub.strip_prefix("Уровень ") {
                format!("Р{}", stripped.trim())
            } else if let Some(stripped) = sub.strip_prefix("Ранг ") {
                format!("Р{}", stripped.trim())
            } else if let Some(stripped) = sub.strip_prefix("Rank ") {
                format!("R{}", stripped.trim())
            } else {
                sub.clone()
            };
            format!("{} ({})", name, rank_str)
        } else {
            name
        };
        merged.push((id, full_name));
    }

    merged.sort_by_key(|&(id, _)| id);
    println!("[+] Merged {} complete spell definitions", merged.len());

    // Write binary database
    let out_file = File::create(out_bin_path).expect("Failed to create spells.bin");
    let mut writer = BufWriter::new(out_file);

    // Magic header (8 bytes) + count (4 bytes)
    writer.write_all(b"SPELLDB1").unwrap();
    writer.write_all(&(merged.len() as u32).to_le_bytes()).unwrap();

    for (id, name) in &merged {
        let name_bytes = name.as_bytes();
        let len = name_bytes.len() as u16;
        writer.write_all(&id.to_le_bytes()).unwrap();
        writer.write_all(&len.to_le_bytes()).unwrap();
        writer.write_all(name_bytes).unwrap();
    }
    writer.flush().unwrap();

    println!("[+] Successfully generated {} ({} entries)", out_bin_path, merged.len());

    // Verification check
    for test_id in [172, 348, 687, 980, 1454, 5782, 30794] {
        if let Some((_, n)) = merged.iter().find(|(id, _)| *id == test_id) {
            println!("    [ID: {:5}] -> {}", test_id, n);
        }
    }
}

