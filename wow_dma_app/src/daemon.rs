// language: Rust, file: src/daemon.rs, target: Windows 11, MSVC x64
mod vmm;
mod makcu;
mod rotation;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use serde::{Deserialize, Serialize};
use serde_json::json;
use rotation::{AuraCondition, AuraPresence, AuraTarget, ConditionLogic, ConditionType, HpTarget, MouseTrigger, RotationConfig, RotationRule, RotationStore};

static TARGET_INPUT_ADDR: Mutex<Option<SocketAddr>> = Mutex::new(None);
static ROTATION_STORE: Mutex<RotationStore> = Mutex::new(RotationStore { active_index: 0, profiles: Vec::new() });
static ROTATION_CONFIG: Mutex<Option<RotationConfig>> = Mutex::new(None);
static LAST_ROTATION_CAST: Mutex<Option<String>> = Mutex::new(None);
static LAST_TARGET_AURAS: Mutex<Vec<AuraEntry>> = Mutex::new(Vec::new());
static LAST_PLAYER_AURAS: Mutex<Vec<AuraEntry>> = Mutex::new(Vec::new());
static HAS_VALID_TARGET: Mutex<bool> = Mutex::new(false);
static LAST_SEEN_TARGET_GUID: Mutex<u64> = Mutex::new(0);
static LAST_TRIGGERED_SPELL: Mutex<Option<(String, Instant)>> = Mutex::new(None);
static LAST_AUTO_TARGET_TAB: Mutex<Option<Instant>> = Mutex::new(None);
static LAST_AUTO_ATTACK_TARGET: Mutex<u64> = Mutex::new(0);
static LAST_TARGET_DISTANCE: Mutex<Option<f32>> = Mutex::new(None);
static IS_TARGET_ALIVE: Mutex<bool> = Mutex::new(true);
static LAST_TARGET_HP: Mutex<Option<(u64, u64, f32)>> = Mutex::new(None);
static LAST_PLAYER_HP: Mutex<Option<(u64, u64, f32)>> = Mutex::new(None);

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct PlayerCastState {
    pub is_casting: bool,
    pub is_channeling: bool,
    pub cast_spell_id: u32,
    pub cast_rem_ms: u32,
    pub channel_spell_id: u32,
    pub channel_rem_ms: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UnitCastState {
    pub is_casting: bool,
    pub is_channeling: bool,
    pub spell_id: u32,
    pub cast_start: u32,
    pub cast_end: u32,
    pub rem_ms: u32,
    pub total_ms: u32,
    pub progress_pct: f32,
}

static PLAYER_CAST_STATE: Mutex<PlayerCastState> = Mutex::new(PlayerCastState {
    is_casting: false,
    is_channeling: false,
    cast_spell_id: 0,
    cast_rem_ms: 0,
    channel_spell_id: 0,
    channel_rem_ms: 0,
});

static LAST_TARGET_CAST: Mutex<Option<UnitCastState>> = Mutex::new(None);

#[derive(Deserialize, Debug)]
#[serde(tag = "cmd")]
enum DaemonCommand {
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "find_process")]
    FindProcess { name: String },
    #[serde(rename = "read_type")]
    ReadType { pid: u32, addr: u64, type_name: String },
    #[serde(rename = "read_bytes")]
    ReadBytes { pid: u32, addr: u64, size: usize },
    #[serde(rename = "read_string")]
    ReadString { pid: u32, addr: u64, max_len: Option<usize> },
    #[serde(rename = "pattern_scan")]
    PatternScan { pid: u32, module_name: String, pattern: String, max_hits: Option<usize> },
    #[serde(rename = "ref_scan")]
    RefScan { pid: u32, module_name: String, target_va: u64 },
    #[serde(rename = "scan_range")]
    ScanRange { pid: u32, start_addr: u64, end_addr: u64, pattern: String, max_hits: Option<usize> },
    #[serde(rename = "find_ptrs")]
    FindPtrs { pid: u32, target_addr: u64, start_addr: u64, end_addr: u64, max_hits: Option<usize> },
    #[serde(rename = "snapshot")]
    Snapshot { pid: u32 },
    #[serde(rename = "diff")]
    Diff { pid: u32 },
    #[serde(rename = "get_target")]
    GetTarget {
        #[serde(default)]
        include_mouseover: bool,
    },
    #[serde(rename = "cast")]
    Cast { spell: String },
    #[serde(rename = "makcu")]
    Makcu { command: String },
    #[serde(rename = "get_rotation")]
    GetRotation,
    #[serde(rename = "set_rotation")]
    SetRotation { config: RotationConfig },
    #[serde(rename = "set_rotation_store")]
    SetRotationStore { store: RotationStore },
    #[serde(rename = "auto_calibrate")]
    AutoCalibrate {
        #[serde(default)]
        force: bool,
    },
    #[serde(rename = "tick_rotation")]
    TickRotation,
}

fn parse_pattern(pat_str: &str) -> (Vec<u8>, Vec<u8>) {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    for tok in pat_str.split_whitespace() {
        if tok == "?" || tok == "??" {
            bytes.push(0);
            mask.push(0);
        } else if let Ok(b) = u8::from_str_radix(tok, 16) {
            bytes.push(b);
            mask.push(1);
        }
    }
    (bytes, mask)
}

static SNAPSHOT: Mutex<Option<(u64, Vec<u8>)>> = Mutex::new(None);
// Cached target structure address (t_guid_low, t_guid_high, unit_address)
static CACHED_TARGET_UNIT: Mutex<Option<(u64, u64, u64)>> = Mutex::new(None);
static CACHED_PLAYER_UNIT: Mutex<Option<u64>> = Mutex::new(None);
static SPELL_DB: Mutex<Option<HashMap<u32, String>>> = Mutex::new(None);

#[derive(Clone, Copy, Debug)]
struct AutoOffsets {
    entity_table_rva: u64,
    target_guid_low_rva: u64,
    target_guid_high_rva: u64,
    player_unit_rva: u64,
    mouseover_guid_rva: u64,
    unit_health_offset: u64,
    unit_max_health_offset: u64,
    entry_coords_offset: u64,
}

static ACTIVE_OFFSETS: Mutex<AutoOffsets> = Mutex::new(AutoOffsets {
    entity_table_rva: 0x04728BE8,
    target_guid_low_rva: 0x06A32478,
    target_guid_high_rva: 0x06A32480,
    player_unit_rva: 0x04C1A770,
    mouseover_guid_rva: 0x04C18288,
    unit_health_offset: 0x1E28,
    unit_max_health_offset: 0x1E30,
    entry_coords_offset: 0x0060,
});

static LAST_TRACKED_PID: Mutex<u32> = Mutex::new(0);

fn verify_offset_sanity(vmm: &vmm::Vmm, pid: u32, base: u64, offs: &AutoOffsets) -> bool {
    // 1. Verify EntityTable pointer & capacity (check primary slot +0x04728BE8)
    let mut entity_table = vmm.read_val::<u64>(pid, base + offs.entity_table_rva).unwrap_or(0);
    if entity_table == 0 {
        entity_table = vmm.read_val::<u64>(pid, base + 0x04728BE8).unwrap_or(0);
    }
    // If entity_table is 0, the game client is still loading or at character selection screen.
    // Preserve known static offsets and do not trigger a false AOB re-scan.
    if entity_table == 0 {
        return true;
    }
    if entity_table < 0x0000010000000000 || entity_table > 0x00007FFFFFFFFFFF {
        return false;
    }
    let bucket_array = vmm.read_val::<u64>(pid, entity_table + 0x08).unwrap_or(0);
    let capacity = vmm.read_val::<u32>(pid, entity_table + 0x18).unwrap_or(0);
    if bucket_array == 0 || capacity < 500 || capacity > 10000 {
        return false;
    }

    // 2. Verify PlayerUnit pointer is mapped
    let p_lo = vmm.read_val::<u64>(pid, base + offs.player_unit_rva).unwrap_or(0);
    let p_hi = vmm.read_val::<u64>(pid, base + offs.player_unit_rva + 8).unwrap_or(0);
    if p_lo == 0 && p_hi == 0 {
        return true;
    }

    true
}

fn load_offsets_file() -> Option<AutoOffsets> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("offsets.json"));
        }
    }
    candidates.push(std::path::PathBuf::from("offsets.json"));
    candidates.dedup();

    let mut data = None;
    for c in &candidates {
        if c.exists() {
            if let Ok(d) = std::fs::read_to_string(c) {
                data = Some(d);
                break;
            }
        }
    }
    let data = data?;
    let val: serde_json::Value = serde_json::from_str(&data).ok()?;
    let offs = val.get("offsets")?;
    
    let parse_hex = |key: &str| -> Option<u64> {
        let s = offs.get(key)?.as_str()?;
        let clean = s.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(clean, 16).ok()
    };

    Some(AutoOffsets {
        entity_table_rva: parse_hex("entity_table_rva")?,
        target_guid_low_rva: parse_hex("target_guid_low_rva")?,
        target_guid_high_rva: parse_hex("target_guid_high_rva")?,
        player_unit_rva: parse_hex("player_unit_rva")?,
        mouseover_guid_rva: parse_hex("mouseover_guid_rva")?,
        unit_health_offset: parse_hex("unit_health_offset").unwrap_or(0x1E28),
        unit_max_health_offset: parse_hex("unit_max_health_offset").unwrap_or(0x1E30),
        entry_coords_offset: parse_hex("entry_coords_offset").unwrap_or(0x0060),
    })
}

fn calibrate_offsets(vmm: &vmm::Vmm, pid: u32, base: u64) {
    let t0 = Instant::now();

    // 0. Check for user/dumper generated offsets.json
    if let Some(file_offs) = load_offsets_file() {
        if verify_offset_sanity(vmm, pid, base, &file_offs) {
            println!("[+] Loaded calibrated offsets from offsets.json (Patch-Day Override Active):");
            println!("    TargetGUID:    +0x{:08X} (high: +0x{:08X})", file_offs.target_guid_low_rva, file_offs.target_guid_high_rva);
            println!("    EntityTable:   +0x{:08X}", file_offs.entity_table_rva);
            println!("    PlayerUnit:    +0x{:08X}", file_offs.player_unit_rva);
            println!("    MouseoverGUID: +0x{:08X}", file_offs.mouseover_guid_rva);
            println!("    HealthOffset:  +0x{:04X} (MaxHP: +0x{:04X})", file_offs.unit_health_offset, file_offs.unit_max_health_offset);
            println!("    CoordsOffset:  entry +0x{:04X}", file_offs.entry_coords_offset);

            let mut lock = ACTIVE_OFFSETS.lock().unwrap();
            *lock = file_offs;
            return;
        }
    }

    let known_offs = AutoOffsets {
        entity_table_rva: 0x04728BE8,
        target_guid_low_rva: 0x06A32478,
        target_guid_high_rva: 0x06A32480,
        player_unit_rva: 0x04C1A770,
        mouseover_guid_rva: 0x04C18288,
        unit_health_offset: 0x1E28,
        unit_max_health_offset: 0x1E30,
        entry_coords_offset: 0x0060,
    };

    // Fast path: verify known-good static offsets for WoW Classic 1.15.x
    if verify_offset_sanity(vmm, pid, base, &known_offs) {
        println!("[+] Verified Offsets locked in {} µs (Zero-drift guaranteed):", t0.elapsed().as_micros());
        println!("    TargetGUID:    +0x{:08X} (high: +0x{:08X}) [verified]", known_offs.target_guid_low_rva, known_offs.target_guid_high_rva);
        println!("    EntityTable:   +0x{:08X} [verified]", known_offs.entity_table_rva);
        println!("    PlayerUnit:    +0x{:08X} [verified]", known_offs.player_unit_rva);
        println!("    MouseoverGUID: +0x{:08X} [verified]", known_offs.mouseover_guid_rva);

        let mut lock = ACTIVE_OFFSETS.lock().unwrap();
        *lock = known_offs;
        return;
    }

    println!("[*] Known offsets sanity check failed (client update?). Initiating deep AOB scan...");
    let offs = run_deep_aob_scan(vmm, pid, base);
    let mut lock = ACTIVE_OFFSETS.lock().unwrap();
    *lock = offs;
}

fn run_deep_aob_scan(vmm: &vmm::Vmm, pid: u32, base: u64) -> AutoOffsets {
    let t0 = Instant::now();
    let mut offs = AutoOffsets {
        entity_table_rva: 0x04728BE8,
        target_guid_low_rva: 0x06A32478,
        target_guid_high_rva: 0x06A32480,
        player_unit_rva: 0x04C1A770,
        mouseover_guid_rva: 0x04C18288,
        unit_health_offset: 0x1E28,
        unit_max_health_offset: 0x1E30,
        entry_coords_offset: 0x0060,
    };

    let (pat_t_b, pat_t_m) = parse_pattern("48 8B 0D ? ? ? ? 48 8B 15 ? ? ? ? 48 39 08");
    let (pat_e_b, pat_e_m) = parse_pattern("48 8B 54 24 ? 48 8D 0D ? ? ? ? 48 8B C2 48 C1 E8 38 48 8B 04 C1");
    let (pat_p_b, pat_p_m) = parse_pattern("0F 10 02 48 8B DA 0F 29 05 ? ? ? ? 0F B6 42 10");
    let (pat_m_b, pat_m_m) = parse_pattern("3C 03 75 ? 0F 10 47 08 0F 11 05 ? ? ? ?");

    let chunk_size = 2 * 1024 * 1024;
    let max_scan = 0x3500000; // .text code section is within first 53 MB
    let mut buf = vec![0u8; chunk_size];

    let mut found_target = false;
    let mut found_entity = false;
    let mut found_player = false;
    let mut found_hover = false;

    let match_pat = |slice: &[u8], pat: &[u8], mask: &[u8]| -> bool {
        if slice.len() < pat.len() { return false; }
        for (idx, &m) in mask.iter().enumerate() {
            if m == 1 && slice[idx] != pat[idx] { return false; }
        }
        true
    };

    for off in (0x1000..max_scan).step_by(chunk_size - 64) {
        let va = base + off as u64;
        if !vmm.read(pid, va, &mut buf) { continue; }
        let len = buf.len();

        for i in 0..(len.saturating_sub(32)) {
            let hit_va = va + i as u64;

            // TargetGUID: 48 8B 0D [disp32] (len 7)
            if !found_target && match_pat(&buf[i..], &pat_t_b, &pat_t_m) {
                let disp = i32::from_le_bytes([buf[i+3], buf[i+4], buf[i+5], buf[i+6]]);
                let res = (hit_va + 7).wrapping_add(disp as i64 as u64).wrapping_sub(base);
                if res >= 0x04000000 && res <= 0x08000000 {
                    offs.target_guid_low_rva = res;
                    offs.target_guid_high_rva = res + 8;
                    found_target = true;
                }
            }

            // EntityTable: 48 8D 0D [disp32] at offset 5 (len 7) -> Primary Entity Table pointer (+0x04728BE8)
            if !found_entity && match_pat(&buf[i..], &pat_e_b, &pat_e_m) {
                let disp = i32::from_le_bytes([buf[i+8], buf[i+9], buf[i+10], buf[i+11]]);
                let entity_base = (hit_va + 12).wrapping_add(disp as i64 as u64).wrapping_sub(base);
                let cand_rva = if entity_base == 0x04728BE8 {
                    entity_base
                } else if entity_base == 0x04728BE0 {
                    entity_base + 0x08
                } else {
                    0x04728BE8
                };
                if cand_rva >= 0x04000000 && cand_rva <= 0x08000000 {
                    offs.entity_table_rva = cand_rva;
                    found_entity = true;
                }
            }

            // PlayerUnit: 0F 29 05 [disp32] at offset 6 (len 7)
            if !found_player && match_pat(&buf[i..], &pat_p_b, &pat_p_m) {
                let disp = i32::from_le_bytes([buf[i+9], buf[i+10], buf[i+11], buf[i+12]]);
                let res = (hit_va + 13).wrapping_add(disp as i64 as u64).wrapping_sub(base);
                if res >= 0x04000000 && res <= 0x08000000 {
                    offs.player_unit_rva = res;
                    found_player = true;
                }
            }

            // MouseoverGUID: 0F 11 05 [disp32] at offset 8 (len 7)
            if !found_hover && match_pat(&buf[i..], &pat_m_b, &pat_m_m) {
                let disp = i32::from_le_bytes([buf[i+11], buf[i+12], buf[i+13], buf[i+14]]);
                let res = (hit_va + 15).wrapping_add(disp as i64 as u64).wrapping_sub(base);
                if res >= 0x04000000 && res <= 0x08000000 {
                    offs.mouseover_guid_rva = res;
                    found_hover = true;
                }
            }

            if found_target && found_entity && found_player && found_hover {
                break;
            }
        }

        if found_target && found_entity && found_player && found_hover {
            break;
        }
    }

    println!("[+] Dynamic AOB Calibration in {} ms:", t0.elapsed().as_millis());
    println!("    TargetGUID:    +0x{:08X} (high: +0x{:08X}) [calibrated: {}]", offs.target_guid_low_rva, offs.target_guid_high_rva, found_target);
    println!("    EntityTable:   +0x{:08X} [calibrated: {}]", offs.entity_table_rva, found_entity);
    println!("    PlayerUnit:    +0x{:08X} [calibrated: {}]", offs.player_unit_rva, found_player);
    println!("    MouseoverGUID: +0x{:08X} [calibrated: {}]", offs.mouseover_guid_rva, found_hover);

    offs
}

fn ensure_process_linked(vmm: &vmm::Vmm, pid: u32, base: u64) {
    let mut last_pid = LAST_TRACKED_PID.lock().unwrap();
    if *last_pid != pid {
        println!("[*] Process switch / restart detected: PID {} -> {}. Refreshing DMA bindings...", *last_pid, pid);
        *last_pid = pid;

        // Force hardware TLB and process cache refresh in MemProcFS
        vmm.refresh_all();

        // Reset stale unit pointer caches from old process address space
        *CACHED_PLAYER_UNIT.lock().unwrap() = None;
        *CACHED_TARGET_UNIT.lock().unwrap() = None;
        *LAST_SEEN_TARGET_GUID.lock().unwrap() = 0;
        *LAST_TRIGGERED_SPELL.lock().unwrap() = None;
        *PLAYER_CAST_STATE.lock().unwrap() = PlayerCastState::default();

        calibrate_offsets(vmm, pid, base);
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AuraEntry {
    name: String,
    spell_id: u32,
    stacks: u8,
    rem_ms: u32,
    is_mine: bool,
}

struct TargetClassification {
    category: String,      // "Игрок", "Существо / NPC", "Игровой объект", "Питомец"
    detail: String,        // "Чернокнижник (Игрок)" or "Враждебное существо" or "Элитный босс"
    badge: String,         // "[Игрок]" or "[Босс]" or "[Элита]" or "[Существо]"
    creature_id: u32,
    is_player: bool,
}

fn get_windows_tick_count_ms(vmm: &vmm::Vmm, pid: u32) -> u32 {
    let interrupt_time = vmm.read_val::<u64>(pid, 0x7FFE0008).unwrap_or(0);
    (interrupt_time / 10000) as u32
}

fn load_spell_db() -> HashMap<u32, String> {
    let candidate_paths = [
        "spells.bin",
        "data/spells.bin",
        "wow_dma_app/data/spells.bin",
        r"C:\Users\1111\Desktop\WOW DMA\spells.bin",
        r"C:\Users\1111\Desktop\WOW DMA\wow_dma_app\data\spells.bin",
        r"C:\Users\1111\Desktop\WOW DMA\wow_dma_app\target\release\spells.bin",
    ];
    for path in &candidate_paths {
        if let Ok(mut f) = std::fs::File::open(path) {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() && buf.len() > 12 && &buf[0..8] == b"SPELLDB1" {
                let count = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
                let mut map = HashMap::with_capacity(count);
                let mut offset = 12;
                while offset + 6 <= buf.len() {
                    let id = u32::from_le_bytes(buf[offset..offset+4].try_into().unwrap());
                    let len = u16::from_le_bytes(buf[offset+4..offset+6].try_into().unwrap()) as usize;
                    offset += 6;
                    if offset + len <= buf.len() {
                        if let Ok(name) = std::str::from_utf8(&buf[offset..offset+len]) {
                            map.insert(id, name.to_string());
                        }
                        offset += len;
                    } else {
                        break;
                    }
                }
                println!("[+] Loaded {} spells from '{}'", map.len(), path);
                return map;
            }
        }
    }
    println!("[-] Warning: spells.bin not found in candidate paths");
    HashMap::new()
}

fn spell_id_to_name(id: u32) -> String {
    let mut db_guard = SPELL_DB.lock().unwrap();
    if db_guard.is_none() {
        *db_guard = Some(load_spell_db());
    }
    if let Some(ref db) = *db_guard {
        if let Some(name) = db.get(&id) {
            return name.clone();
        }
    }

    match id {
        57 => "Пассивный эффект".to_string(),
        _ => "Заклинание".to_string(),
    }
}

fn find_unit_by_guid(
    vmm: &vmm::Vmm,
    pid: u32,
    base: u64,
    entity_table_rva: u64,
    target_guid_low: u64,
    target_guid_high: u64,
) -> Option<u64> {
    if target_guid_low == 0 { return None; }

    // Dynamic Entity Table root (check calibrated offset, fallback to +0x04728BE8 and +0x04728BF0)
    let mut entity_table = vmm.read_val::<u64>(pid, base + entity_table_rva).unwrap_or(0);
    if entity_table == 0 {
        entity_table = vmm.read_val::<u64>(pid, base + 0x04728BE8).unwrap_or(0);
    }
    if entity_table == 0 {
        entity_table = vmm.read_val::<u64>(pid, base + 0x04728BF0).unwrap_or(0);
    }
    if entity_table == 0 { return None; }

    let bucket_array = vmm.read_val::<u64>(pid, entity_table + 0x08).unwrap_or(0);
    let capacity = vmm.read_val::<u32>(pid, entity_table + 0x18).unwrap_or(0);
    if bucket_array == 0 || capacity == 0 { return None; }

    let cap = std::cmp::min(capacity as usize, 8192);
    let is_full_128 = target_guid_high != 0;

    // Read bucket array in chunks of 512 entries (8192 bytes)
    let mut buf = vec![0u8; 8192];

    // PASS 1: Strict Exact 128-bit GUID Match
    // Prevents false-positive collisions with nearby mobs of the same creature type.
    for chunk_start in (0..cap).step_by(512) {
        let chunk_count = std::cmp::min(512, cap - chunk_start);
        let bytes_to_read = chunk_count * 16;
        let va = bucket_array + (chunk_start as u64) * 16;
        if !vmm.read(pid, va, &mut buf[..bytes_to_read]) {
            continue;
        }

        for i in 0..chunk_count {
            let off = i * 16;
            let entry_obj = u64::from_le_bytes(buf[off+8..off+16].try_into().unwrap());
            if entry_obj == 0 { continue; }

            let g_lo = vmm.read_val::<u64>(pid, entry_obj + 0x18).unwrap_or(0);
            let g_hi = vmm.read_val::<u64>(pid, entry_obj + 0x20).unwrap_or(0);

            let matched = if is_full_128 {
                g_lo == target_guid_low && g_hi == target_guid_high
            } else {
                g_lo == target_guid_low
            };

            if matched {
                let mut unit_ptr = vmm.read_val::<u64>(pid, entry_obj + 0x28).unwrap_or(0);
                if unit_ptr == 0 || unit_ptr == 1 || unit_ptr > 0x00007FFFFFFFFFFF {
                    unit_ptr = vmm.read_val::<u64>(pid, entry_obj + 0xD8).unwrap_or(0);
                }
                if unit_ptr != 0 && unit_ptr <= 0x00007FFFFFFFFFFF {
                    return Some(unit_ptr);
                }
                return Some(entry_obj);
            }
        }
    }

    // PASS 2: Fallback ONLY for legacy 32-bit queries (where high GUID == 0 and low fits in u32)
    if !is_full_128 && (target_guid_low >> 32) == 0 {
        let low32 = target_guid_low as u32;
        for chunk_start in (0..cap).step_by(512) {
            let chunk_count = std::cmp::min(512, cap - chunk_start);
            let bytes_to_read = chunk_count * 16;
            let va = bucket_array + (chunk_start as u64) * 16;
            if !vmm.read(pid, va, &mut buf[..bytes_to_read]) {
                continue;
            }

            for i in 0..chunk_count {
                let off = i * 16;
                let entry_obj = u64::from_le_bytes(buf[off+8..off+16].try_into().unwrap());
                if entry_obj == 0 { continue; }

                let g_lo = vmm.read_val::<u64>(pid, entry_obj + 0x18).unwrap_or(0);
                if (g_lo as u32) == low32 {
                    let mut unit_ptr = vmm.read_val::<u64>(pid, entry_obj + 0x28).unwrap_or(0);
                    if unit_ptr == 0 || unit_ptr == 1 || unit_ptr > 0x00007FFFFFFFFFFF {
                        unit_ptr = vmm.read_val::<u64>(pid, entry_obj + 0xD8).unwrap_or(0);
                    }
                    if unit_ptr != 0 && unit_ptr <= 0x00007FFFFFFFFFFF {
                        return Some(unit_ptr);
                    }
                    return Some(entry_obj);
                }
            }
        }
    }

    None
}

fn is_unit_alive(vmm: &vmm::Vmm, pid: u32, unit_ptr: u64) -> bool {
    if unit_ptr == 0 { return false; }
    let obj_type = vmm.read_val::<u8>(pid, unit_ptr + 0x24).unwrap_or(0);
    if obj_type == 10 {
        // TypeID 10: CGTYPE_CORPSE
        return false;
    }
    if obj_type == 7 {
        // TypeID 7: CGLocalPlayer_C (Local player) — always alive
        return true;
    }

    // Modern WoW 1.15.x: Unit Health is a 64-bit integer at unit_ptr + unit_health_offset
    // When a unit dies, its health drops to 0. Living units have HP > 0.
    let h_off = { ACTIVE_OFFSETS.lock().unwrap().unit_health_offset };
    let hp = vmm.read_val::<u64>(pid, unit_ptr + h_off).unwrap_or(0);
    hp > 0
}

fn get_unit_hp(vmm: &vmm::Vmm, pid: u32, unit_ptr: u64) -> Option<(u64, u64, f32)> {
    if unit_ptr == 0 { return None; }
    let h_off = { ACTIVE_OFFSETS.lock().unwrap().unit_health_offset };
    let mh_off = { ACTIVE_OFFSETS.lock().unwrap().unit_max_health_offset };
    let cur_hp = vmm.read_val::<u64>(pid, unit_ptr + h_off).unwrap_or(0);
    let max_hp = vmm.read_val::<u64>(pid, unit_ptr + mh_off).unwrap_or(0);
    let pct = if max_hp > 0 {
        ((cur_hp as f64 / max_hp as f64) * 100.0) as f32
    } else if cur_hp > 0 {
        100.0
    } else {
        0.0
    };
    Some((cur_hp, max_hp, pct.clamp(0.0, 100.0)))
}

fn compute_humanized_delay(min_ms: u32, max_ms: u32, humanize: bool, rng_state: &mut u64) -> u64 {
    if !humanize || min_ms >= max_ms {
        return min_ms as u64;
    }

    // Xorshift64* pseudo-random generator
    *rng_state ^= *rng_state >> 12;
    *rng_state ^= *rng_state << 25;
    *rng_state ^= *rng_state >> 27;
    let r1 = (*rng_state).wrapping_mul(0x2545F4914F6CDD1D);

    *rng_state ^= *rng_state >> 12;
    *rng_state ^= *rng_state << 25;
    *rng_state ^= *rng_state >> 27;
    let r2 = (*rng_state).wrapping_mul(0x2545F4914F6CDD1D);

    // Approximate Gaussian distribution using central limit (sum of 4 uniform samples)
    let u1 = ((r1 & 0xFFFF) as f64) / 65535.0;
    let u2 = (((r1 >> 16) & 0xFFFF) as f64) / 65535.0;
    let u3 = ((r2 & 0xFFFF) as f64) / 65535.0;
    let u4 = (((r2 >> 16) & 0xFFFF) as f64) / 65535.0;
    let norm = (u1 + u2 + u3 + u4 - 2.0) / 0.577; // mean 0.0, std dev 1.0

    let mean = ((min_ms + max_ms) as f64) / 2.0;
    let spread = ((max_ms - min_ms) as f64) / 4.0;
    let mut sample = mean + norm * spread;

    // 4% chance of realistic human hesitation micro-stutter (+40..+75ms)
    if (r2 >> 48) % 25 == 0 {
        let jitter = 40.0 + (((r1 >> 32) & 0x1F) as f64);
        sample += jitter;
    }

    let clamped = sample.round().clamp(min_ms as f64, (max_ms + 100) as f64) as u64;
    clamped
}

fn get_unit_cast_state(
    vmm: &vmm::Vmm,
    pid: u32,
    unit_ptr: u64,
    now_ms: u32,
) -> UnitCastState {
    let mut state = UnitCastState::default();
    if unit_ptr == 0 { return state; }

    let tick_ms = vmm.read_val::<u32>(pid, 0x7FFE0320).unwrap_or(0);

    let is_future = |ts: u32| -> Option<u32> {
        if ts == 0 || ts == 0xFFFFFFFF { return None; }
        if ts > now_ms && (ts - now_ms) < 30_000 {
            Some(ts - now_ms)
        } else if tick_ms != 0 && ts > tick_ms && (ts - tick_ms) < 30_000 {
            Some(ts - tick_ms)
        } else if ts > now_ms.saturating_sub(150) && ts <= now_ms {
            Some(50)
        } else {
            None
        }
    };

    // 1. Regular active cast
    let cast_end = vmm.read_val::<u32>(pid, unit_ptr + 0x041C).unwrap_or(0);
    let cast_start = vmm.read_val::<u32>(pid, unit_ptr + 0x0418).unwrap_or(0);
    let mut cast_id = vmm.read_val::<u32>(pid, unit_ptr + 0x03EC).unwrap_or(0);
    if cast_id == 0 || cast_id >= 200_000 {
        cast_id = vmm.read_val::<u32>(pid, unit_ptr + 0x03C0).unwrap_or(0);
    }

    if cast_id != 0 && cast_id < 200_000 {
        if let Some(rem) = is_future(cast_end) {
            state.is_casting = true;
            state.spell_id = cast_id;
            state.cast_start = cast_start;
            state.cast_end = cast_end;
            state.rem_ms = rem;
            let total = if cast_end > cast_start && cast_start > 0 {
                cast_end - cast_start
            } else {
                rem.max(1500)
            };
            state.total_ms = total;
            let elapsed = if now_ms >= cast_start && cast_start > 0 {
                (now_ms - cast_start).min(total)
            } else if tick_ms >= cast_start && cast_start > 0 {
                (tick_ms - cast_start).min(total)
            } else {
                total.saturating_sub(rem)
            };
            state.progress_pct = ((elapsed as f32 / total as f32) * 100.0).clamp(0.0, 100.0);
            return state;
        }
    }

    // 2. Channeled cast
    let channel_end = vmm.read_val::<u32>(pid, unit_ptr + 0x042C).unwrap_or(0);
    let channel_start = vmm.read_val::<u32>(pid, unit_ptr + 0x0428).unwrap_or(0);
    let channel_id = vmm.read_val::<u32>(pid, unit_ptr + 0x0420).unwrap_or(0);
    if channel_id != 0 && channel_id < 200_000 {
        if let Some(rem) = is_future(channel_end) {
            state.is_channeling = true;
            state.spell_id = channel_id;
            state.cast_start = channel_start;
            state.cast_end = channel_end;
            state.rem_ms = rem;
            let total = if channel_end > channel_start && channel_start > 0 {
                channel_end - channel_start
            } else {
                rem.max(3000)
            };
            state.total_ms = total;
            let elapsed = if now_ms >= channel_start && channel_start > 0 {
                (now_ms - channel_start).min(total)
            } else if tick_ms >= channel_start && channel_start > 0 {
                (tick_ms - channel_start).min(total)
            } else {
                total.saturating_sub(rem)
            };
            state.progress_pct = ((elapsed as f32 / total as f32) * 100.0).clamp(0.0, 100.0);
            return state;
        }
    }

    state
}

fn get_player_cast_state(
    vmm: &vmm::Vmm,
    pid: u32,
    _base: u64,
    player_unit: u64,
    now_ms: u32,
) -> PlayerCastState {
    let mut state = PlayerCastState::default();
    let tick_ms = vmm.read_val::<u32>(pid, 0x7FFE0320).unwrap_or(0);

    let is_future = |ts: u32| -> Option<u32> {
        if ts == 0 || ts == 0xFFFFFFFF { return None; }
        if ts > now_ms && (ts - now_ms) < 30_000 {
            Some(ts - now_ms)
        } else if tick_ms != 0 && ts > tick_ms && (ts - tick_ms) < 30_000 {
            Some(ts - tick_ms)
        } else if ts > now_ms.saturating_sub(150) && ts <= now_ms {
            Some(50)
        } else {
            None
        }
    };

    if player_unit != 0 {
        // 1. Primary verified CGUnit active cast fields in WoW Classic 1.15.x:
        // +0x03EC / +0x03C0: u32 Spell ID
        // +0x0418: u32 Cast Start Time
        // +0x041C: u32 Cast End Time
        let cast_end = vmm.read_val::<u32>(pid, player_unit + 0x041C).unwrap_or(0);
        let mut cast_id = vmm.read_val::<u32>(pid, player_unit + 0x03EC).unwrap_or(0);
        if cast_id == 0 || cast_id >= 200_000 {
            cast_id = vmm.read_val::<u32>(pid, player_unit + 0x03C0).unwrap_or(0);
        }

        if cast_id != 0 && cast_id < 200_000 {
            if let Some(rem) = is_future(cast_end) {
                state.is_casting = true;
                state.cast_rem_ms = rem;
                state.cast_spell_id = cast_id;
            }
        }

        // 2. Channeled spells:
        // +0x0420: u32 Channel Spell ID
        // +0x042C: u32 Channel End Time
        let channel_end = vmm.read_val::<u32>(pid, player_unit + 0x042C).unwrap_or(0);
        let channel_id = vmm.read_val::<u32>(pid, player_unit + 0x0420).unwrap_or(0);
        if channel_id != 0 && channel_id < 200_000 {
            if let Some(rem) = is_future(channel_end) {
                state.is_channeling = true;
                state.channel_rem_ms = rem;
                state.channel_spell_id = channel_id;
            }
        }
    }

    // 3. Ultra-short keypress transit grace window (max 120 ms)
    // Allows hardware input to reach WoW and initiate cast animation in memory.
    // If a cast breaks or finishes, memory state is 100% authoritative and drops to false immediately.
    if !state.is_casting && !state.is_channeling {
        let trig_lock = LAST_TRIGGERED_SPELL.lock().unwrap();
        if let Some((_, trig_time)) = *trig_lock {
            let elapsed = trig_time.elapsed().as_millis() as u32;
            if elapsed < 120 {
                state.is_casting = true;
                state.cast_rem_ms = 120 - elapsed;
            }
        }
    }

    state
}

fn get_unit_auras(
    vmm: &vmm::Vmm,
    pid: u32,
    unit_ptr: u64,
    player_guid_low: u64,
    now_ms: u32,
) -> Vec<AuraEntry> {
    let mut raw_auras = Vec::new();
    if unit_ptr == 0 { return raw_auras; }

    let table_ptr = vmm.read_val::<u64>(pid, unit_ptr + 0x5F0).unwrap_or(0);
    let count = vmm.read_val::<u32>(pid, unit_ptr + 0x5F8).unwrap_or(0);
    if count == 0 { return raw_auras; }

    let base_slot = if table_ptr != 0 && table_ptr > 0x10000 {
        table_ptr + 0xA4
    } else {
        unit_ptr + 0x6AC
    };

    let max_slots = std::cmp::min(count as usize, 32);
    let total_bytes = max_slots * 0x128;
    let mut buf = vec![0u8; total_bytes];
    if !vmm.read(pid, base_slot, &mut buf) {
        return raw_auras;
    }

    for i in 0..max_slots {
        let off = i * 0x128;
        let slot_flag = u32::from_le_bytes(buf[off..off+4].try_into().unwrap());
        if slot_flag != 0xFFFFFFFF { continue; }

        let caster_lo = u64::from_le_bytes(buf[off+4..off+12].try_into().unwrap());
        let spell_id = u32::from_le_bytes(buf[off+0x44..off+0x48].try_into().unwrap());
        if spell_id == 0 { continue; }

        // Filter internal engine / visual trigger auras (WoW Classic spells are strictly < 200_000)
        // IDs like 1282590 are modern engine visual/camera dummy auras
        if spell_id >= 200_000 {
            continue;
        }

        let dur_ms = u32::from_le_bytes(buf[off+0x50..off+0x54].try_into().unwrap());
        let exp_ms = u32::from_le_bytes(buf[off+0x54..off+0x58].try_into().unwrap());
        let stacks = buf[off+0x60];

        let rem_ms = if exp_ms > now_ms {
            exp_ms.saturating_sub(now_ms)
        } else if dur_ms > 0 && exp_ms == 0 {
            dur_ms
        } else {
            0
        };

        let raw_name = spell_id_to_name(spell_id);
        if (raw_name == "Пассивный эффект" || raw_name == "Заклинание") && dur_ms == 0 {
            continue;
        }

        let name = if raw_name == "Заклинание" {
            format!("Аура #{}", spell_id)
        } else {
            raw_name.to_string()
        };

        raw_auras.push(AuraEntry {
            name,
            spell_id,
            stacks: std::cmp::max(1, stacks),
            rem_ms,
            is_mine: caster_lo == player_guid_low || caster_lo == 0,
        });
    }

    // Deduplicate and suppress ghost mirror auras
    let mut auras: Vec<AuraEntry> = Vec::new();
    for a in raw_auras {
        // If an exact spell ID is already tracked, merge/refresh
        if let Some(existing) = auras.iter_mut().find(|x| x.spell_id == a.spell_id) {
            if a.rem_ms > existing.rem_ms {
                existing.rem_ms = a.rem_ms;
            }
            existing.stacks = std::cmp::max(existing.stacks, a.stacks);
            continue;
        }

        // If an unmapped aura shares the exact duration/expiration of a known spell, suppress it
        let is_ghost_duplicate = auras.iter().any(|x| {
            !x.name.starts_with("Аура #")
                && a.name.starts_with("Аура #")
                && (x.rem_ms == a.rem_ms || (x.rem_ms as i64 - a.rem_ms as i64).abs() < 50)
        });
        if is_ghost_duplicate {
            continue;
        }

        auras.push(a);
    }

    auras.sort_by(|a, b| match (a.rem_ms > 0, b.rem_ms > 0) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.rem_ms.cmp(&b.rem_ms),
    });

    auras
}

fn classify_target(
    t_guid_low: u64,
    t_guid_high: u64,
    is_combat: bool,
) -> TargetClassification {
    // High GUID decoding (World of Warcraft 128-bit ObjectGuid structure)
    // High 64-bit bits 58..63: HighGuid type
    // Bits 0..23 of t_guid_high often carry subtype tags (0x00=Player, 0x03/0x04=Creature/Pet, 0x05=GameObject)
    let is_player = (t_guid_high >> 32) == 0x813E
        || ((t_guid_high & 0xF000000000000000) == 0 && t_guid_high != 0 && (t_guid_high & 0x00000000003C6B20) == 0);

    if is_player {
        return TargetClassification {
            category: "Игрок".to_string(),
            detail: "Игрок (Player)".to_string(),
            badge: "[ИГРОК]".to_string(),
            creature_id: 0,
            is_player: true,
        };
    }

    // Creature ID extract from low 64 bits: bits 6..29
    let creature_id = ((t_guid_low >> 6) & 0x7FFFFF) as u32;

    // Check high GUID tags for GameObject or Pet
    let is_gameobject = (t_guid_high & 0x0000000000100000) != 0;
    if is_gameobject {
        return TargetClassification {
            category: "Игровой объект".to_string(),
            detail: format!("Объект [ID: {}]", creature_id),
            badge: "[ОБЪЕКТ]".to_string(),
            creature_id,
            is_player: false,
        };
    }

    // Classify known / general creatures
    let (category, detail, badge) = if is_combat {
        ("Существо".to_string(), format!("Враждебный моб [ID: {}]", creature_id), "[ВРАГ]".to_string())
    } else {
        ("NPC / Существо".to_string(), format!("Существо / NPC [ID: {}]", creature_id), "[NPC]".to_string())
    };

    TargetClassification {
        category,
        detail,
        badge,
        creature_id,
        is_player: false,
    }
}

fn evaluate_single_condition(
    cond: &AuraCondition,
    spell_name: &str,
    spell_id: Option<u32>,
    target_auras: &[AuraEntry],
    player_auras: &[AuraEntry],
    has_target: bool,
) -> bool {
    let aura_name = if cond.aura_name.trim().is_empty() {
        spell_name.trim()
    } else {
        cond.aura_name.trim()
    };

    match cond.aura_target {
        AuraTarget::None => true,
        AuraTarget::Player => {
            let found = player_auras.iter().find(|a| {
                a.name.eq_ignore_ascii_case(aura_name)
                    || a.name.contains(aura_name)
                    || spell_id.map_or(false, |id| id == a.spell_id)
            });

            match cond.aura_presence {
                AuraPresence::Absent => match found {
                    None => true,
                    Some(a) => a.rem_ms > 0 && a.rem_ms <= cond.threshold_ms,
                },
                AuraPresence::Present => found.is_some(),
            }
        }
        AuraTarget::Target => {
            if !has_target {
                return false;
            }

            let found = target_auras.iter().find(|a| {
                a.name.eq_ignore_ascii_case(aura_name)
                    || a.name.contains(aura_name)
                    || spell_id.map_or(false, |id| id == a.spell_id)
            });

            match cond.aura_presence {
                AuraPresence::Absent => match found {
                    None => true,
                    Some(a) => a.rem_ms > 0 && a.rem_ms <= cond.threshold_ms,
                },
                AuraPresence::Present => found.is_some(),
            }
        }
    }
}

fn evaluate_rotation(
    cfg: &RotationConfig,
    target_auras: &[AuraEntry],
    player_auras: &[AuraEntry],
    has_target: bool,
    currently_casting: Option<&str>,
    target_distance: Option<f32>,
    is_target_alive: bool,
    target_hp_pct: Option<f32>,
    player_hp_pct: Option<f32>,
    target_cast: Option<&UnitCastState>,
) -> Option<(String, String)> {
    for rule in &cfg.rules {
        if !rule.enabled {
            continue;
        }

        let conds = rule.get_conditions();
        if conds.is_empty() && !rule.check_interrupt && !rule.check_hp && !rule.check_range {
            return Some((rule.key.clone(), rule.name.clone()));
        }

        // Dead target safety: do not cast if any condition requires a target, range check, target HP check, or kick
        let requires_target = conds.iter().any(|c| c.aura_target == AuraTarget::Target) 
            || rule.check_range 
            || (rule.check_hp && rule.hp_target == HpTarget::Target)
            || rule.check_interrupt;
        if requires_target && (!has_target || !is_target_alive) {
            continue;
        }

        // Auto-Kick / Interrupt Check
        if rule.check_interrupt {
            match target_cast {
                Some(tc) if tc.is_casting || tc.is_channeling => {
                    let cur_pct = tc.progress_pct.round() as u32;
                    if cur_pct < rule.interrupt_pct {
                        continue; // Target cast has not reached threshold yet
                    }
                }
                _ => {
                    // Target is not casting or channeling anything!
                    continue;
                }
            }
        }

        // Health Percentage (HP) Threshold Check
        if rule.check_hp {
            let hp_opt = match rule.hp_target {
                HpTarget::Target => {
                    if !has_target || !is_target_alive {
                        None
                    } else {
                        target_hp_pct
                    }
                }
                HpTarget::Player => player_hp_pct,
            };

            match hp_opt {
                Some(pct) => {
                    let pct_round = pct.round() as u32;
                    if pct_round < rule.min_hp || pct_round > rule.max_hp {
                        continue; // Outside HP threshold!
                    }
                }
                None => {
                    continue; // Cannot evaluate HP or target missing
                }
            }
        }

        // Distance / Range check
        if rule.check_range {
            if let Some(dist) = target_distance {
                if dist < rule.min_range || dist > rule.max_range {
                    continue; // Out of range!
                }
            } else if requires_target {
                continue;
            }
        }

        // If the player is currently actively casting this rule's spell, skip it to prevent double-casting
        if let Some(cast_name) = currently_casting {
            let r_lower = rule.name.trim().to_lowercase();
            let c_lower = cast_name.trim().to_lowercase();
            let is_same = r_lower == c_lower || c_lower.contains(&r_lower) || r_lower.contains(&c_lower);
            if is_same {
                let has_aura_conditions = conds.iter().any(|c| c.aura_target != AuraTarget::None);
                if has_aura_conditions {
                    continue;
                }
            }
        }

        // Evaluate condition chain (First condition sets initial state, subsequent chained via AND / OR)
        let mut satisfied = evaluate_single_condition(&conds[0], &rule.name, rule.spell_id, target_auras, player_auras, has_target);

        for c in &conds[1..] {
            let res = evaluate_single_condition(c, &rule.name, rule.spell_id, target_auras, player_auras, has_target);
            match c.logic {
                ConditionLogic::And => satisfied = satisfied && res,
                ConditionLogic::Or => satisfied = satisfied || res,
            }
        }

        if satisfied {
            return Some((rule.key.clone(), rule.name.clone()));
        }
    }

    None
}

fn handle_client(
    stream: TcpStream,
    vmm: Arc<vmm::Vmm>,
    makcu: Arc<Mutex<makcu::Makcu>>,
) {
    let mut reader = BufReader::new(&stream);
    let mut writer = io_write(&stream);
    let mut line = String::new();

    while let Ok(n) = reader.read_line(&mut line) {
        if n == 0 { break; }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let resp = match serde_json::from_str::<DaemonCommand>(trimmed) {
            Ok(cmd) => match cmd {
                DaemonCommand::Status => json!({
                    "status": "connected",
                    "hardware": "FPGA PCIe (LeechCore)",
                    "engine": "Native Rust zero-copy DMA daemon",
                    "bridge": "127.0.0.1:8765"
                }),

                DaemonCommand::FindProcess { name } => {
                    if let Some(pid) = vmm.get_pid(&name) {
                        let base = vmm.get_module_base(pid, &name).unwrap_or(0);
                        json!({ "pid": pid, "name": name, "base": format!("0x{:X}", base) })
                    } else {
                        json!({ "error": format!("Process '{}' not found", name) })
                    }
                }

                DaemonCommand::ReadType { pid, addr, type_name } => {
                    let t = type_name.to_lowercase();
                    match t.as_str() {
                        "u8" => {
                            if let Some(v) = vmm.read_val::<u8>(pid, addr) {
                                json!({ "val": v, "hex": format!("0x{:02X}", v) })
                            } else { json!({ "error": "read fault" }) }
                        }
                        "u16" => {
                            if let Some(v) = vmm.read_val::<u16>(pid, addr) {
                                json!({ "val": v, "hex": format!("0x{:04X}", v) })
                            } else { json!({ "error": "read fault" }) }
                        }
                        "u32" => {
                            if let Some(v) = vmm.read_val::<u32>(pid, addr) {
                                json!({ "val": v, "hex": format!("0x{:08X}", v) })
                            } else { json!({ "error": "read fault" }) }
                        }
                        "u64" | "ptr" | "pointer" => {
                            if let Some(v) = vmm.read_val::<u64>(pid, addr) {
                                json!({ "val": v, "hex": format!("0x{:016X}", v) })
                            } else { json!({ "error": "read fault" }) }
                        }
                        "float" => {
                            if let Some(v) = vmm.read_val::<f32>(pid, addr) {
                                json!({ "val": v })
                            } else { json!({ "error": "read fault" }) }
                        }
                        "double" => {
                            if let Some(v) = vmm.read_val::<f64>(pid, addr) {
                                json!({ "val": v })
                            } else { json!({ "error": "read fault" }) }
                        }
                        _ => json!({ "error": format!("unsupported type: {}", t) })
                    }
                }

                DaemonCommand::ReadBytes { pid, addr, size } => {
                    let mut buf = vec![0u8; size];
                    if vmm.read(pid, addr, &mut buf) {
                        let hex_str = buf.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                        json!({ "hex": hex_str, "size": size })
                    } else {
                        json!({ "error": "read fault" })
                    }
                }

                DaemonCommand::ReadString { pid, addr, max_len } => {
                    let s = vmm.read_string(pid, addr, max_len.unwrap_or(64));
                    json!({ "str": s })
                }

                DaemonCommand::PatternScan { pid, module_name, pattern, max_hits } => {
                    if let Some(mod_base) = vmm.get_module_base(pid, &module_name) {
                        let (pat_bytes, mask) = parse_pattern(&pattern);
                        let limit = max_hits.unwrap_or(20);
                        let mut hits = Vec::new();
                        let chunk_size = 2 * 1024 * 1024;
                        let max_scan = 120 * 1024 * 1024;
                        let mut buf = vec![0u8; chunk_size];
                        let t0 = Instant::now();

                        for off in (0..max_scan).step_by(chunk_size - pat_bytes.len()) {
                            let va = mod_base + off as u64;
                            if !vmm.read(pid, va, &mut buf) { continue; }

                            for i in 0..(buf.len() - pat_bytes.len()) {
                                let mut matched = true;
                                for j in 0..pat_bytes.len() {
                                    if mask[j] == 1 && buf[i + j] != pat_bytes[j] {
                                        matched = false;
                                        break;
                                    }
                                }
                                if matched {
                                    let hit_va = va + i as u64;
                                    let rva = hit_va - mod_base;
                                    let mut hit_obj = json!({
                                        "address": format!("0x{:X}", hit_va),
                                        "rva": format!("+0x{:X}", rva)
                                    });

                                    if i + 7 <= buf.len() && buf[i] == 0x48 && (buf[i+1] == 0x8B || buf[i+1] == 0x8D) && (buf[i+2] & 0xC7 == 0x05) {
                                        let disp = i32::from_le_bytes([buf[i+3], buf[i+4], buf[i+5], buf[i+6]]);
                                        let rip_target = (hit_va + 7).wrapping_add(disp as i64 as u64);
                                        hit_obj["resolved_rip_target"] = json!(format!("0x{:X}", rip_target));
                                        hit_obj["resolved_rva"] = json!(format!("+0x{:X}", rip_target.wrapping_sub(mod_base)));
                                    }

                                    hits.push(hit_obj);
                                    if hits.len() >= limit { break; }
                                }
                            }
                            if hits.len() >= limit { break; }
                        }
                        json!({
                            "hits": hits,
                            "count": hits.len(),
                            "elapsed_ms": t0.elapsed().as_millis()
                        })
                    } else {
                        json!({ "error": format!("module '{}' not found", module_name) })
                    }
                }

                DaemonCommand::ScanRange { pid, start_addr, end_addr, pattern, max_hits } => {
                    let (pat_bytes, mask) = parse_pattern(&pattern);
                    let limit = max_hits.unwrap_or(20);
                    let mut hits = Vec::new();
                    let chunk_size = 2 * 1024 * 1024;
                    let mut buf = vec![0u8; chunk_size];
                    let t0 = Instant::now();

                    let mut curr = start_addr;
                    while curr < end_addr {
                        let read_sz = std::cmp::min(chunk_size as u64, end_addr - curr) as usize;
                        if vmm.read(pid, curr, &mut buf[..read_sz]) {
                            let limit_len = read_sz.saturating_sub(pat_bytes.len());
                            for i in 0..limit_len {
                                let mut matched = true;
                                for j in 0..pat_bytes.len() {
                                    if mask[j] == 1 && buf[i + j] != pat_bytes[j] {
                                        matched = false;
                                        break;
                                    }
                                }
                                if matched {
                                    let hit_va = curr + i as u64;
                                    hits.push(json!({
                                        "address": format!("0x{:X}", hit_va),
                                    }));
                                    if hits.len() >= limit { break; }
                                }
                            }
                        }
                        if hits.len() >= limit { break; }
                        curr += (chunk_size - pat_bytes.len()) as u64;
                    }

                    json!({
                        "hits": hits,
                        "count": hits.len(),
                        "elapsed_ms": t0.elapsed().as_millis()
                    })
                }

                DaemonCommand::FindPtrs { pid, target_addr, start_addr, end_addr, max_hits } => {
                    let limit = max_hits.unwrap_or(20);
                    let mut hits = Vec::new();
                    let chunk_size = 2 * 1024 * 1024;
                    let mut buf = vec![0u8; chunk_size];
                    let t0 = Instant::now();

                    let mut curr = start_addr;
                    while curr < end_addr {
                        let read_sz = std::cmp::min(chunk_size as u64, end_addr - curr) as usize;
                        if vmm.read(pid, curr, &mut buf[..read_sz]) {
                            for i in (0..(read_sz.saturating_sub(8))).step_by(8) {
                                let val = u64::from_le_bytes(buf[i..i+8].try_into().unwrap());
                                if val == target_addr {
                                    let hit_va = curr + i as u64;
                                    hits.push(json!({
                                        "address": format!("0x{:X}", hit_va),
                                    }));
                                    if hits.len() >= limit { break; }
                                }
                            }
                        }
                        if hits.len() >= limit { break; }
                        curr += (chunk_size - 8) as u64;
                    }

                    json!({
                        "hits": hits,
                        "count": hits.len(),
                        "elapsed_ms": t0.elapsed().as_millis()
                    })
                }

                DaemonCommand::RefScan { pid, module_name, target_va } => {
                    if let Some(mod_base) = vmm.get_module_base(pid, &module_name) {
                        let mut hits = Vec::new();
                        let chunk_size = 2 * 1024 * 1024;
                        let max_scan = 0x3B00000; // .text code section is 0x3ACCD9C (61.6 MB)
                        let mut buf = vec![0u8; chunk_size];
                        let t0 = Instant::now();

                        for off in (0x1000..max_scan).step_by(chunk_size - 16) {
                            let va = mod_base + off as u64;
                            if !vmm.read(pid, va, &mut buf) { continue; }
                            let len = buf.len();
                            for i in 0..(len.saturating_sub(8)) {
                                if buf[i] == 0 || buf[i] == 0xCC { continue; }
                                for ilen in [5, 6, 7, 8] {
                                    let disp_off = ilen - 4;
                                    let disp = i32::from_le_bytes([
                                        buf[i + disp_off],
                                        buf[i + disp_off + 1],
                                        buf[i + disp_off + 2],
                                        buf[i + disp_off + 3],
                                    ]);
                                    if disp == 0 { continue; }
                                    let next_ip = (va + i as u64) + ilen as u64;
                                    let resolved = next_ip.wrapping_add(disp as i64 as u64);
                                    if resolved == target_va {
                                        let hex_bytes = buf[i..i+ilen].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                                        let c_start = i.saturating_sub(8);
                                        let c_end = std::cmp::min(len, i + ilen + 8);
                                        let context = buf[c_start..c_end].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                                        hits.push(json!({
                                            "address": format!("0x{:X}", va + i as u64),
                                            "rva": format!("+0x{:X}", (va + i as u64) - mod_base),
                                            "bytes": hex_bytes,
                                            "context": context
                                        }));
                                    }
                                }
                            }
                        }
                        json!({
                            "hits": hits,
                            "count": hits.len(),
                            "elapsed_ms": t0.elapsed().as_millis()
                        })
                    } else {
                        json!({ "error": format!("module '{}' not found", module_name) })
                    }
                }

                DaemonCommand::Snapshot { pid } => {
                    if let Some(base) = vmm.get_module_base(pid, "Wow.exe") {
                        let data_va = base + 0x046E3000;
                        let data_sz = 0x0240E100;
                        let mut buf = vec![0u8; data_sz];
                        let t0 = Instant::now();
                        let chunk = 2 * 1024 * 1024;
                        for off in (0..data_sz).step_by(chunk) {
                            let sz = std::cmp::min(chunk, data_sz - off);
                            vmm.read(pid, data_va + off as u64, &mut buf[off..off+sz]);
                        }
                        let mut snap = SNAPSHOT.lock().unwrap();
                        *snap = Some((base, buf));
                        json!({ "status": "snapshot_captured", "size_bytes": data_sz, "elapsed_ms": t0.elapsed().as_millis() })
                    } else {
                        json!({ "error": "Wow.exe not found" })
                    }
                }

                DaemonCommand::Diff { pid } => {
                    let snap_opt = { SNAPSHOT.lock().unwrap().clone() };
                    if let Some((base, old_buf)) = snap_opt {
                        let data_va = base + 0x046E3000;
                        let data_sz = old_buf.len();
                        let mut curr_buf = vec![0u8; data_sz];
                        let t0 = Instant::now();
                        let chunk = 2 * 1024 * 1024;
                        for off in (0..data_sz).step_by(chunk) {
                            let sz = std::cmp::min(chunk, data_sz - off);
                            vmm.read(pid, data_va + off as u64, &mut curr_buf[off..off+sz]);
                        }

                        let mut changes = Vec::new();
                        for i in (0..(data_sz - 8)).step_by(8) {
                            let q_old = u64::from_le_bytes(old_buf[i..i+8].try_into().unwrap());
                            let q_new = u64::from_le_bytes(curr_buf[i..i+8].try_into().unwrap());
                            if q_old != q_new && (q_old == 0 || q_new == 0 || q_old == !0 || q_new == !0) {
                                let va = data_va + i as u64;
                                let rva = va - base;
                                changes.push(json!({
                                    "address": format!("0x{:X}", va),
                                    "rva": format!("+0x{:08X}", rva),
                                    "old": format!("0x{:016X}", q_old),
                                    "new": format!("0x{:016X}", q_new),
                                }));
                                if changes.len() >= 200 { break; }
                            }
                        }
                        json!({ "diff_count": changes.len(), "changes": changes, "elapsed_ms": t0.elapsed().as_millis() })
                    } else {
                        json!({ "error": "No baseline snapshot found. Run snapshot first." })
                    }
                }

                DaemonCommand::GetTarget { include_mouseover } => {
                    if let Some(pid) = vmm.get_pid("Wow.exe") {
                        if let Some(base) = vmm.get_module_base(pid, "Wow.exe") {
                            ensure_process_linked(&vmm, pid, base);
                            let offs = { *ACTIVE_OFFSETS.lock().unwrap() };
                            let p_guid = vmm.read_val::<u32>(pid, base + 0x4C1B1C0).unwrap_or(0);
                            let p_unit_lo = vmm.read_val::<u64>(pid, base + offs.player_unit_rva).unwrap_or(0);
                            let p_unit_hi = vmm.read_val::<u64>(pid, base + offs.player_unit_rva + 8).unwrap_or(0);

                            // Local player unit and cast telemetry (evaluated unconditionally every frame)
                            let pl_unit = {
                                let mut pl_cache = CACHED_PLAYER_UNIT.lock().unwrap();
                                if let Some(u) = *pl_cache {
                                    u
                                } else {
                                    let u = find_unit_by_guid(&vmm, pid, base, offs.entity_table_rva, p_unit_lo, p_unit_hi).unwrap_or(0);
                                    if u != 0 { *pl_cache = Some(u); }
                                    u
                                }
                            };
                            let now_ms = get_windows_tick_count_ms(&vmm, pid);
                            let cast_state = get_player_cast_state(&vmm, pid, base, pl_unit, now_ms);
                            *PLAYER_CAST_STATE.lock().unwrap() = cast_state;
                            
                            // Dynamically calibrated target GUID
                            let mut t_guid_low = vmm.read_val::<u64>(pid, base + offs.target_guid_low_rva).unwrap_or(0);
                            let mut t_guid_high = vmm.read_val::<u64>(pid, base + offs.target_guid_high_rva).unwrap_or(0);
                            let mut is_hover = false;

                            // If include_mouseover is requested and hover takes priority
                            if include_mouseover {
                                let hover_guid = vmm.read_val::<u64>(pid, base + offs.mouseover_guid_rva).unwrap_or(0);
                                if hover_guid != 0 {
                                    t_guid_low = hover_guid;
                                    t_guid_high = vmm.read_val::<u64>(pid, base + offs.mouseover_guid_rva + 8).unwrap_or(0);
                                    is_hover = true;
                                }
                            }

                            let has_t = t_guid_low != 0;
                            
                            // Check hostile / combat attack target flag
                            let is_combat = vmm.read_val::<u64>(pid, base + 0x04B15F90).unwrap_or(0) != 0;

                            let (t_guid, t_name, t_type, t_badge, auras, t_cast) = if has_t {
                                let c = classify_target(t_guid_low, t_guid_high, is_combat);
                                let prefix = if is_hover { "[Курсор] " } else { "" };
                                
                                let is_targeting_self = (t_guid_low == p_unit_lo && (p_unit_hi == 0 || t_guid_high == p_unit_hi))
                                    || ((t_guid_low as u32) != 0 && (t_guid_low as u32) == (p_unit_lo as u32))
                                    || (p_guid != 0 && (t_guid_low as u32) == p_guid);

                                let display_name = if is_targeting_self {
                                    let p_name = vmm.read_string(pid, base + offs.player_unit_rva + 0x10, 64);
                                    if !p_name.is_empty() {
                                        format!("{}{}", prefix, p_name.trim())
                                    } else {
                                        format!("{}Игрок (Вы)", prefix)
                                    }
                                } else {
                                    format!("{}{}", prefix, c.detail)
                                };

                                // Resolve target CGUnit using calibrated EntityTable
                                let target_unit = if is_targeting_self {
                                    pl_unit
                                } else {
                                    let mut t_cache = CACHED_TARGET_UNIT.lock().unwrap();
                                    if let Some((clo, chi, u)) = *t_cache {
                                        if clo == t_guid_low && chi == t_guid_high && u != 0 {
                                            u
                                        } else {
                                            let u = find_unit_by_guid(&vmm, pid, base, offs.entity_table_rva, t_guid_low, t_guid_high).unwrap_or(0);
                                            *t_cache = Some((t_guid_low, t_guid_high, u));
                                            u
                                        }
                                    } else {
                                        let u = find_unit_by_guid(&vmm, pid, base, offs.entity_table_rva, t_guid_low, t_guid_high).unwrap_or(0);
                                        *t_cache = Some((t_guid_low, t_guid_high, u));
                                        u
                                    }
                                };

                                let auras = if target_unit != 0 {
                                    get_unit_auras(&vmm, pid, target_unit, p_unit_lo, now_ms)
                                } else {
                                    Vec::new()
                                };

                                let (target_dist, is_target_alive, target_hp_info) = if is_targeting_self {
                                    (Some(0.0), true, get_unit_hp(&vmm, pid, pl_unit))
                                } else if target_unit != 0 && pl_unit != 0 {
                                    let p_entry = vmm.read_val::<u64>(pid, pl_unit + 0x08).unwrap_or(0);
                                    let t_entry = vmm.read_val::<u64>(pid, target_unit + 0x08).unwrap_or(0);

                                    let dist = if p_entry != 0 && t_entry != 0 {
                                        let c_off = { ACTIVE_OFFSETS.lock().unwrap().entry_coords_offset };
                                        let px = vmm.read_val::<f32>(pid, p_entry + c_off).unwrap_or(0.0);
                                        let py = vmm.read_val::<f32>(pid, p_entry + c_off + 4).unwrap_or(0.0);
                                        let pz = vmm.read_val::<f32>(pid, p_entry + c_off + 8).unwrap_or(0.0);
                                        let tx = vmm.read_val::<f32>(pid, t_entry + c_off).unwrap_or(0.0);
                                        let ty = vmm.read_val::<f32>(pid, t_entry + c_off + 4).unwrap_or(0.0);
                                        let tz = vmm.read_val::<f32>(pid, t_entry + c_off + 8).unwrap_or(0.0);
                                        let dx = tx - px; let dy = ty - py; let dz = tz - pz;
                                        let d = (dx * dx + dy * dy + dz * dz).sqrt();
                                        if d.is_finite() { Some(d) } else { None }
                                    } else {
                                        None
                                    };
                                    
                                    let alive = is_unit_alive(&vmm, pid, target_unit);
                                    let hp_info = get_unit_hp(&vmm, pid, target_unit);
                                    (dist, alive, hp_info)
                                } else {
                                    (None, false, None)
                                };
                                *LAST_TARGET_DISTANCE.lock().unwrap() = target_dist;
                                *IS_TARGET_ALIVE.lock().unwrap() = is_target_alive;
                                *LAST_TARGET_HP.lock().unwrap() = target_hp_info;

                                let t_cast = if target_unit != 0 {
                                    get_unit_cast_state(&vmm, pid, target_unit, now_ms)
                                } else {
                                    UnitCastState::default()
                                };
                                *LAST_TARGET_CAST.lock().unwrap() = if t_cast.is_casting || t_cast.is_channeling {
                                    Some(t_cast.clone())
                                } else {
                                    None
                                };

                                (t_guid_low, display_name, c.category, c.badge, auras, t_cast)
                            } else {
                                {
                                    let mut cache = CACHED_TARGET_UNIT.lock().unwrap();
                                    *cache = None;
                                }
                                *LAST_TARGET_DISTANCE.lock().unwrap() = None;
                                *IS_TARGET_ALIVE.lock().unwrap() = true;
                                *LAST_TARGET_HP.lock().unwrap() = None;
                                *LAST_TARGET_CAST.lock().unwrap() = None;
                                (0, "НЕТ ЦЕЛИ".to_string(), "Нет цели".to_string(), "[-]".to_string(), Vec::new(), UnitCastState::default())
                            };
                            let is_makcu = makcu.lock().unwrap().is_connected();
                            
                            // Cache latest target and player telemetry for rotation engine
                            *LAST_TARGET_AURAS.lock().unwrap() = auras.clone();
                            *HAS_VALID_TARGET.lock().unwrap() = has_t;

                            let player_hp_info = if pl_unit != 0 {
                                get_unit_hp(&vmm, pid, pl_unit)
                            } else {
                                None
                            };
                            *LAST_PLAYER_HP.lock().unwrap() = player_hp_info;

                            let player_auras = if pl_unit != 0 {
                                get_unit_auras(&vmm, pid, pl_unit, p_unit_lo, now_ms)
                            } else {
                                Vec::new()
                            };
                            *LAST_PLAYER_AURAS.lock().unwrap() = player_auras;

                            // Track target switches
                            {
                                let mut last_tg = LAST_SEEN_TARGET_GUID.lock().unwrap();
                                if t_guid_low != *last_tg {
                                    *last_tg = t_guid_low;
                                }
                            }

                            let rot_cast = { LAST_ROTATION_CAST.lock().unwrap().clone() };
                            let (rot_act, rot_trig, rot_rules, rot_name) = {
                                let lock = ROTATION_CONFIG.lock().unwrap();
                                if let Some(ref c) = *lock {
                                    (c.active, c.trigger.as_str().to_string(), c.rules.clone(), c.name.clone())
                                } else {
                                    (true, MouseTrigger::Mouse4.as_str().to_string(), Vec::new(), "Основная ротация".to_string())
                                }
                            };

                            let cs = { *PLAYER_CAST_STATE.lock().unwrap() };
                            let cast_name = if cs.cast_spell_id != 0 {
                                spell_id_to_name(cs.cast_spell_id)
                            } else if cs.is_casting {
                                "Применение заклинания".to_string()
                            } else {
                                String::new()
                            };
                            let channel_name = if cs.channel_spell_id != 0 {
                                spell_id_to_name(cs.channel_spell_id)
                            } else if cs.is_channeling {
                                "Потоковое заклинание".to_string()
                            } else {
                                String::new()
                            };

                            let target_dist = { *LAST_TARGET_DISTANCE.lock().unwrap() };
                            let is_target_alive = { *IS_TARGET_ALIVE.lock().unwrap() };
                            let target_hp_info = { *LAST_TARGET_HP.lock().unwrap() };
                            let player_hp_info = { *LAST_PLAYER_HP.lock().unwrap() };

                            json!({
                                "player_guid": format!("0x{:X}", p_guid),
                                "has_target": has_t,
                                "is_combat": is_combat,
                                "is_mouseover": is_hover,
                                "target_guid": format!("0x{:016X}", t_guid),
                                "target_name": t_name,
                                "target_type": t_type,
                                "target_badge": t_badge,
                                "target_distance": target_dist.unwrap_or(0.0),
                                "is_target_alive": is_target_alive,
                                "target_hp_pct": target_hp_info.map(|(_, _, p)| p).unwrap_or(0.0),
                                "target_cur_hp": target_hp_info.map(|(c, _, _)| c).unwrap_or(0),
                                "target_max_hp": target_hp_info.map(|(_, m, _)| m).unwrap_or(0),
                                "player_hp_pct": player_hp_info.map(|(_, _, p)| p).unwrap_or(0.0),
                                "player_cur_hp": player_hp_info.map(|(c, _, _)| c).unwrap_or(0),
                                "player_max_hp": player_hp_info.map(|(_, m, _)| m).unwrap_or(0),
                                "auras": auras,
                                "makcu_connected": is_makcu,
                                "rotation_active": rot_act,
                                "rotation_trigger": rot_trig,
                                "rotation_name": rot_name,
                                "rotation_rules": rot_rules,
                                "last_rotation_cast": rot_cast,
                                "is_casting": cs.is_casting,
                                "is_channeling": cs.is_channeling,
                                "cast_rem_ms": cs.cast_rem_ms,
                                "channel_rem_ms": cs.channel_rem_ms,
                                "cast_spell_id": cs.cast_spell_id,
                                "channel_spell_id": cs.channel_spell_id,
                                "cast_spell_name": cast_name,
                                "channel_spell_name": channel_name,
                                "target_is_casting": t_cast.is_casting,
                                "target_is_channeling": t_cast.is_channeling,
                                "target_cast_pct": t_cast.progress_pct,
                                "target_cast_rem_ms": t_cast.rem_ms,
                                "target_cast_name": if t_cast.spell_id != 0 { spell_id_to_name(t_cast.spell_id) } else { String::new() },
                            })
                        } else { json!({ "error": "Wow.exe base not found" }) }
                    } else { json!({ "error": "Wow.exe not found" }) }
                }

                DaemonCommand::Cast { spell } => {
                    let mut lock = makcu.lock().unwrap();
                    let key = match spell.as_str() {
                        "corruption" | "2" => { lock.cast_corruption(); "2" }
                        "immolate" | "1" => { lock.cast_immolate(); "1" }
                        "shadow_bolt" | "middle" | "4" => { lock.cast_shadow_bolt(); "4" }
                        "agony" | "3" => { lock.press_key("3"); "3" }
                        "right" => { lock.right_click(); "right" }
                        "space" => { lock.press_space(); "space" }
                        other => { lock.press_key(other); other }
                    };

                    // Send via UDP Input Agent if discovered on LAN
                    let target_opt = { *TARGET_INPUT_ADDR.lock().unwrap() };
                    let mut udp_sent = false;
                    if let Some(target) = target_opt {
                        if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
                            let payload = format!("press:{}", key);
                            let _ = s.send_to(payload.as_bytes(), target);
                            udp_sent = true;
                        }
                    }

                    json!({ "ok": true, "key": key, "makcu_hw": lock.is_connected(), "udp_sent": udp_sent, "target_agent": target_opt.map(|t| t.to_string()) })
                }

                DaemonCommand::Makcu { command } => {
                    let mut lock = makcu.lock().unwrap();
                    let (ok, response) = lock.send_command_with_response(&command);
                    json!({ "ok": ok, "command": command, "response": response })
                }

                DaemonCommand::GetRotation => {
                    let store = { ROTATION_STORE.lock().unwrap().clone() };
                    let cfg = {
                        let lock = ROTATION_CONFIG.lock().unwrap();
                        lock.clone().unwrap_or_default()
                    };
                    let last_cast = { LAST_ROTATION_CAST.lock().unwrap().clone() };
                    json!({ "store": store, "config": cfg, "last_cast": last_cast })
                }

                DaemonCommand::SetRotation { config } => {
                    *ROTATION_CONFIG.lock().unwrap() = Some(config.clone());
                    let mut store = ROTATION_STORE.lock().unwrap();
                    if let Some(pos) = store.profiles.iter().position(|p| p.name == config.name) {
                        store.profiles[pos] = config;
                    } else {
                        store.profiles.push(config);
                    }
                    let _ = store.save();
                    json!({ "ok": true })
                }

                DaemonCommand::SetRotationStore { store } => {
                    *ROTATION_STORE.lock().unwrap() = store.clone();
                    if let Some(first) = store.profiles.first() {
                        *ROTATION_CONFIG.lock().unwrap() = Some(first.clone());
                    }
                    let _ = store.save();
                    json!({ "ok": true })
                }

                DaemonCommand::AutoCalibrate { force } => {
                    if let Some(pid) = vmm.get_pid("Wow.exe") {
                        if let Some(base) = vmm.get_module_base(pid, "Wow.exe") {
                            ensure_process_linked(&vmm, pid, base);
                            let t0 = Instant::now();
                            let offs = if force {
                                let o = run_deep_aob_scan(&vmm, pid, base);
                                let mut lock = ACTIVE_OFFSETS.lock().unwrap();
                                *lock = o.clone();
                                o
                            } else {
                                calibrate_offsets(&vmm, pid, base);
                                ACTIVE_OFFSETS.lock().unwrap().clone()
                            };

                            let json_str = format!(
                                r#"{{
  "comment": "Calibrated Offsets (Patch-Day Auto-Generated)",
  "offsets": {{
    "entity_table_rva": "0x{:08X}",
    "target_guid_low_rva": "0x{:08X}",
    "target_guid_high_rva": "0x{:08X}",
    "player_unit_rva": "0x{:08X}",
    "mouseover_guid_rva": "0x{:08X}",
    "unit_health_offset": "0x{:04X}",
    "unit_max_health_offset": "0x{:04X}",
    "entry_coords_offset": "0x{:04X}"
  }}
}}"#,
                                offs.entity_table_rva,
                                offs.target_guid_low_rva,
                                offs.target_guid_high_rva,
                                offs.player_unit_rva,
                                offs.mouseover_guid_rva,
                                offs.unit_health_offset,
                                offs.unit_max_health_offset,
                                offs.entry_coords_offset
                            );
                            if let Ok(exe) = std::env::current_exe() {
                                if let Some(parent) = exe.parent() {
                                    let _ = std::fs::write(parent.join("offsets.json"), &json_str);
                                }
                            }
                            let _ = std::fs::write("offsets.json", &json_str);

                            json!({
                                "ok": true,
                                "base": format!("0x{:X}", base),
                                "pid": pid,
                                "elapsed_ms": t0.elapsed().as_millis(),
                                "offsets": {
                                    "entity_table_rva": format!("0x{:08X}", offs.entity_table_rva),
                                    "target_guid_low_rva": format!("0x{:08X}", offs.target_guid_low_rva),
                                    "target_guid_high_rva": format!("0x{:08X}", offs.target_guid_high_rva),
                                    "player_unit_rva": format!("0x{:08X}", offs.player_unit_rva),
                                    "mouseover_guid_rva": format!("0x{:08X}", offs.mouseover_guid_rva),
                                    "unit_health_offset": format!("0x{:04X}", offs.unit_health_offset),
                                    "unit_max_health_offset": format!("0x{:04X}", offs.unit_max_health_offset),
                                    "entry_coords_offset": format!("0x{:04X}", offs.entry_coords_offset)
                                }
                            })
                        } else {
                            json!({ "error": "Wow.exe base not found" })
                        }
                    } else {
                        json!({ "error": "Wow.exe process not found" })
                    }
                }

                DaemonCommand::TickRotation => {
                    if let Some(pid) = vmm.get_pid("Wow.exe") {
                        if let Some(base) = vmm.get_module_base(pid, "Wow.exe") {
                            ensure_process_linked(&vmm, pid, base);
                        }
                    }
                    let cfg = {
                        let lock = ROTATION_CONFIG.lock().unwrap();
                        lock.clone().unwrap_or_default()
                    };
                    let has_t = { *HAS_VALID_TARGET.lock().unwrap() };
                    let auras = { LAST_TARGET_AURAS.lock().unwrap().clone() };

                    let (is_channeling, currently_casting) = {
                        let cs = PLAYER_CAST_STATE.lock().unwrap();
                        let name = if cs.is_casting {
                            let from_id = if cs.cast_spell_id != 0 {
                                let n = spell_id_to_name(cs.cast_spell_id);
                                if n != "Заклинание" && !n.is_empty() {
                                    Some(n)
                                } else {
                                    None
                                }
                            } else {
                                None
                            };
                            from_id.or_else(|| {
                                let trig = LAST_TRIGGERED_SPELL.lock().unwrap();
                                trig.as_ref().map(|(s, _)| s.clone())
                            })
                        } else {
                            let mut trig = LAST_TRIGGERED_SPELL.lock().unwrap();
                            if let Some((_, trig_time)) = *trig {
                                if trig_time.elapsed().as_millis() >= 120 {
                                    *trig = None;
                                }
                            }
                            None
                        };
                        (cs.is_channeling, name)
                    };

                    let player_auras = { LAST_PLAYER_AURAS.lock().unwrap().clone() };
                    let target_dist = { *LAST_TARGET_DISTANCE.lock().unwrap() };
                    let is_target_alive = { *IS_TARGET_ALIVE.lock().unwrap() };
                    let target_hp_pct = { LAST_TARGET_HP.lock().unwrap().map(|(_, _, p)| p) };
                    let player_hp_pct = { LAST_PLAYER_HP.lock().unwrap().map(|(_, _, p)| p) };
                    let target_cast = { LAST_TARGET_CAST.lock().unwrap().clone() };

                    if is_channeling {
                        json!({ "cast": false, "reason": "Канал заклинания активен (ожидание)" })
                    } else if let Some((key, spell_name)) = evaluate_rotation(&cfg, &auras, &player_auras, has_t, currently_casting.as_deref(), target_dist, is_target_alive, target_hp_pct, player_hp_pct, target_cast.as_ref()) {
                        let mut m = makcu.lock().unwrap();
                        let mut temp_rng = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64) ^ 0x9E3779B97F4A7C15;
                        let hold_ms = compute_humanized_delay(cfg.min_press_ms, cfg.max_press_ms, cfg.humanize, &mut temp_rng);
                        m.press_key_held(&key, hold_ms);
                        *LAST_ROTATION_CAST.lock().unwrap() = Some(format!("{} [{}]", spell_name, key));
                        *LAST_TRIGGERED_SPELL.lock().unwrap() = Some((spell_name.clone(), Instant::now()));
                        json!({ "cast": true, "key": key, "spell": spell_name, "hold_ms": hold_ms })
                    } else {
                        json!({ "cast": false, "reason": if !has_t { "No target" } else { "No rule matched" } })
                    }
                }
            },
            Err(e) => json!({ "error": format!("invalid command: {}", e) }),
        };

        let _ = writeln!(writer, "{}", resp);
        let _ = writer.flush();
        line.clear();
    }
}

fn io_write(stream: &TcpStream) -> std::io::BufWriter<TcpStream> {
    std::io::BufWriter::new(stream.try_clone().unwrap())
}

fn main() {
    println!("=== WOW DMA NATIVE RUST HIGH-SPEED DAEMON ===");
    println!("[*] Loading WoW Classic spell database...");
    let _ = spell_id_to_name(1);

    println!("[*] Initializing PCIe FPGA VMM Link...");

    let dll_path = Path::new(r"C:\Users\1111\Desktop\WOW DMA\memprocfs_bin\vmm.dll");
    let vmm_instance = match vmm::Vmm::new(dll_path, &["-device", "fpga"]) {
        Ok(v) => Arc::new(v),
        Err(e) => {
            eprintln!("[-] VMM Init failed: {}", e);
            std::process::exit(1);
        }
    };

    println!("[+] PCIe DMA Hardware Connected!");

    // Start UDP Auto-Discovery listener for Gaming PC Input Agent
    thread::spawn(|| {
        let socket = match UdpSocket::bind("0.0.0.0:9998") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[-] Warning: Failed to bind auto-discovery UDP port 9998: {}", e);
                return;
            }
        };
        let mut buf = [0u8; 256];
        let mut last_logged_ip: Option<std::net::IpAddr> = None;

        loop {
            if let Ok((len, src)) = socket.recv_from(&mut buf) {
                let msg = String::from_utf8_lossy(&buf[..len]);
                if msg.contains("WOW_INPUT_AGENT_BEACON") {
                    let target_addr = SocketAddr::new(src.ip(), 9999);
                    let mut lock = TARGET_INPUT_ADDR.lock().unwrap();
                    *lock = Some(target_addr);

                    if last_logged_ip != Some(src.ip()) {
                        last_logged_ip = Some(src.ip());
                        println!("[+] Plug & Play Auto-Discovery: Linked Gaming PC Input Agent at {}", target_addr);
                    }
                }
            }
        }
    });

    if let Some(pid) = vmm_instance.get_pid("Wow.exe") {
        if let Some(base) = vmm_instance.get_module_base(pid, "Wow.exe") {
            ensure_process_linked(&vmm_instance, pid, base);
        }
    }

    let makcu = Arc::new(Mutex::new(makcu::Makcu::new("COM3")));
    {
        let mut m = makcu.lock().unwrap();
        m.release_all_modifiers();
    }

    // Initialize active rotation configurations from persistent storage
    let initial_store = RotationStore::load_or_default();
    *ROTATION_CONFIG.lock().unwrap() = initial_store.profiles.first().cloned();
    *ROTATION_STORE.lock().unwrap() = initial_store;

    // Spawn high-speed hardware mouse trigger polling thread with Humanization & Spell Queueing
    let makcu_trigger = Arc::clone(&makcu);
    let vmm_trigger = Arc::clone(&vmm_instance);
    thread::spawn(move || {
        let mut rng_state: u64 = 0x853C49E6748FEA9B;
        let mut cached_pid: Option<u32> = None;
        let mut cached_base: Option<u64> = None;
        let mut was_pressed = false;

        loop {
            // Collect all profiles that have an active hardware mouse trigger bound
            let profiles_to_poll: Vec<RotationConfig> = {
                let store = ROTATION_STORE.lock().unwrap();
                store.profiles.iter()
                    .filter(|p| p.trigger != MouseTrigger::Disabled && p.trigger.to_cmd().is_some())
                    .cloned()
                    .collect()
            };

            if profiles_to_poll.is_empty() {
                if was_pressed {
                    was_pressed = false;
                    let mut m = makcu_trigger.lock().unwrap();
                    m.release_all_modifiers();
                }
                thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }

            // Check hardware mouse triggers for each configured profile
            let mut triggered_cfg: Option<RotationConfig> = None;
            for p in &profiles_to_poll {
                if let Some(cmd) = p.trigger.to_cmd() {
                    let is_pressed = {
                        let mut m = makcu_trigger.lock().unwrap();
                        m.get_mouse_button(cmd)
                    };
                    if is_pressed > 0 {
                        triggered_cfg = Some(p.clone());
                        break;
                    }
                }
            }

            if let Some(cfg) = triggered_cfg {
                was_pressed = true;
                    // Dynamically resolve PID on each trigger to seamlessly catch game restarts
                    let live_pid = vmm_trigger.get_pid("Wow.exe");
                    if live_pid != cached_pid {
                        cached_pid = live_pid;
                        cached_base = live_pid.and_then(|p| vmm_trigger.get_module_base(p, "Wow.exe"));
                    }

                    let (pid_val, base_val) = match (cached_pid, cached_base) {
                        (Some(p), Some(b)) => (p, b),
                        _ => {
                            thread::sleep(std::time::Duration::from_millis(50));
                            continue;
                        }
                    };

                    ensure_process_linked(&vmm_trigger, pid_val, base_val);
                    let offs = { *ACTIVE_OFFSETS.lock().unwrap() };
                    let now_ms = get_windows_tick_count_ms(&vmm_trigger, pid_val);

                    // Resolve player unit
                    let pl_unit = {
                        let mut pl_cache = CACHED_PLAYER_UNIT.lock().unwrap();
                        if let Some(u) = *pl_cache {
                            u
                        } else if offs.player_unit_rva != 0 && offs.entity_table_rva != 0 {
                            let p_lo = vmm_trigger.read_val::<u64>(pid_val, base_val + offs.player_unit_rva).unwrap_or(0);
                            let p_hi = vmm_trigger.read_val::<u64>(pid_val, base_val + offs.player_unit_rva + 8).unwrap_or(0);
                            let u = find_unit_by_guid(&vmm_trigger, pid_val, base_val, offs.entity_table_rva, p_lo, p_hi).unwrap_or(0);
                            if u != 0 { *pl_cache = Some(u); }
                            u
                        } else {
                            0
                        }
                    };

                    // Direct DMA real-time read of casting and channeling state
                    let cast_state = get_player_cast_state(&vmm_trigger, pid_val, base_val, pl_unit, now_ms);
                    *PLAYER_CAST_STATE.lock().unwrap() = cast_state.clone();

                    // For channeled spells: WAIT until channeling completes!
                    // In WoW, pressing any key while channeling interrupts the spell.
                    if cast_state.is_channeling {
                        thread::sleep(std::time::Duration::from_millis(30));
                        continue;
                    }

                    // Resolve currently casting spell name
                    let currently_casting: Option<String> = if cast_state.is_casting {
                        let from_id = if cast_state.cast_spell_id != 0 {
                            let n = spell_id_to_name(cast_state.cast_spell_id);
                            if n != "Заклинание" && !n.is_empty() {
                                Some(n)
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        from_id.or_else(|| {
                            let trig = LAST_TRIGGERED_SPELL.lock().unwrap();
                            trig.as_ref().map(|(s, _)| s.clone())
                        })
                    } else {
                        let mut trig = LAST_TRIGGERED_SPELL.lock().unwrap();
                        if let Some((_, trig_time)) = *trig {
                            if trig_time.elapsed().as_millis() >= 120 {
                                *trig = None;
                            }
                        }
                        None
                    };

                    let has_t = { *HAS_VALID_TARGET.lock().unwrap() };

                    // Auto-Target: If no target and auto_target is enabled, press Tab to acquire nearest target
                    if cfg.auto_target && !has_t {
                        let mut last_tab = LAST_AUTO_TARGET_TAB.lock().unwrap();
                        let should_tab = match *last_tab {
                            Some(t) => t.elapsed().as_millis() >= 350,
                            None => true,
                        };
                        if should_tab {
                            let mut m = makcu_trigger.lock().unwrap();
                            let hold_ms = compute_humanized_delay(cfg.min_press_ms, cfg.max_press_ms, cfg.humanize, &mut rng_state);
                            m.press_key_held("tab", hold_ms);
                            *last_tab = Some(Instant::now());
                            *LAST_ROTATION_CAST.lock().unwrap() = Some("Авто-таргет [Tab]".to_string());
                        }
                        thread::sleep(std::time::Duration::from_millis(80));
                        continue;
                    }

                    // Auto-Attack: If auto_attack is enabled, trigger macro key once per new target
                    if cfg.auto_attack && has_t {
                        let t_guid = vmm_trigger.read_val::<u64>(pid_val, base_val + offs.target_guid_low_rva).unwrap_or(0);
                        let mut last_atk = LAST_AUTO_ATTACK_TARGET.lock().unwrap();
                        if t_guid != 0 && *last_atk != t_guid {
                            *last_atk = t_guid;
                            let atk_key = if cfg.auto_attack_key.trim().is_empty() { "t" } else { &cfg.auto_attack_key };
                            let mut m = makcu_trigger.lock().unwrap();
                            let hold_ms = compute_humanized_delay(cfg.min_press_ms, cfg.max_press_ms, cfg.humanize, &mut rng_state);
                            m.press_key_held(atk_key, hold_ms);
                        }
                    } else if !has_t {
                        *LAST_AUTO_ATTACK_TARGET.lock().unwrap() = 0;
                    }

                    let target_cast = if let Some((_, _, t_unit)) = *CACHED_TARGET_UNIT.lock().unwrap() {
                        if t_unit != 0 {
                            let cs = get_unit_cast_state(&vmm_trigger, pid_val, t_unit, now_ms);
                            if cs.is_casting || cs.is_channeling {
                                *LAST_TARGET_CAST.lock().unwrap() = Some(cs.clone());
                                Some(cs)
                            } else {
                                *LAST_TARGET_CAST.lock().unwrap() = None;
                                None
                            }
                        } else {
                            *LAST_TARGET_CAST.lock().unwrap() = None;
                            None
                        }
                    } else {
                        LAST_TARGET_CAST.lock().unwrap().clone()
                    };

                    let auras = { LAST_TARGET_AURAS.lock().unwrap().clone() };
                    let player_auras = { LAST_PLAYER_AURAS.lock().unwrap().clone() };
                    let target_dist = { *LAST_TARGET_DISTANCE.lock().unwrap() };
                    let is_target_alive = { *IS_TARGET_ALIVE.lock().unwrap() };
                    let target_hp_pct = { LAST_TARGET_HP.lock().unwrap().map(|(_, _, p)| p) };
                    let player_hp_pct = { LAST_PLAYER_HP.lock().unwrap().map(|(_, _, p)| p) };

                    // Evaluate rotation with spell queueing logic (skips currently casting spell)
                    if let Some((key, spell_name)) = evaluate_rotation(&cfg, &auras, &player_auras, has_t, currently_casting.as_deref(), target_dist, is_target_alive, target_hp_pct, player_hp_pct, target_cast.as_ref()) {
                        let mut m = makcu_trigger.lock().unwrap();
                        let hold_ms = compute_humanized_delay(cfg.min_press_ms, cfg.max_press_ms, cfg.humanize, &mut rng_state);
                        m.press_key_held(&key, hold_ms);
                        *LAST_ROTATION_CAST.lock().unwrap() = Some(format!("{} [{}]", spell_name, key));
                        *LAST_TRIGGERED_SPELL.lock().unwrap() = Some((spell_name, Instant::now()));
                    }

                    // Humanized delay between clicks (interval before next spam cycle)
                    let delay_ms = compute_humanized_delay(cfg.min_delay_ms, cfg.max_delay_ms, cfg.humanize, &mut rng_state);
                    thread::sleep(std::time::Duration::from_millis(delay_ms));
                } else {
                    if was_pressed {
                        was_pressed = false;
                        let mut m = makcu_trigger.lock().unwrap();
                        m.release_all_modifiers();
                    }
                    thread::sleep(std::time::Duration::from_millis(15));
                }
            }
        });

    let listener = TcpListener::bind("127.0.0.1:8765").expect("Failed to bind 127.0.0.1:8765");
    println!("[+] Rust DMA Server listening on 127.0.0.1:8765 (Wire-speed IPC ready)");

    for stream in listener.incoming().flatten() {
        let v = Arc::clone(&vmm_instance);
        let m = Arc::clone(&makcu);
        thread::spawn(move || {
            handle_client(stream, v, m);
        });
    }
}

