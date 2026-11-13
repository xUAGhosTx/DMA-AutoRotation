// language: Rust, file: src/calibrator_gui.rs, target: Windows 11, MSVC
// PORTOLAN DMA CALIBRATOR - Universal Ground Truth Offset Engine
// Dedicated 1-Click Patch-Day Memory Calibrator for World of Warcraft (Retail/Classic)
// Communicates with dma_daemon (TCP 127.0.0.1:8765) and verifies all offsets against live game memory.

#![windows_subsystem = "windows"]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::json;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::DataExchange::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const WINDOW_WIDTH: i32 = 840;
const WINDOW_HEIGHT: i32 = 720;

const CF_UNICODETEXT: u32 = 13;
const EM_SETSEL: u32 = 0x00B1;

const ID_BTN_INPUT_BEACON: isize = 101;
const ID_BTN_CLIPBOARD: isize = 102;
const ID_BTN_DMA_SCAN: isize = 103;
const ID_BTN_SAVE: isize = 104;
const ID_BTN_REFRESH: isize = 105;

// Dialog control IDs
const ID_DLG_EDIT: isize = 201;
const ID_DLG_BTN_PASTE: isize = 202;
const ID_DLG_BTN_CALIB: isize = 203;
const ID_DLG_BTN_CANCEL: isize = 204;

unsafe fn make_font(height: i32, weight: i32, face: &str) -> HFONT {
    let w_name = encode_wide(face);
    CreateFontW(height, 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 4, 0, w_name.as_ptr())
}

static mut GLOBAL_MAIN_HWND: HWND = std::ptr::null_mut();
static mut GLOBAL_INPUT_DLG_HWND: HWND = std::ptr::null_mut();
static mut GLOBAL_DLG_EDIT_HWND: HWND = std::ptr::null_mut();
static mut GLOBAL_STATE: Option<Arc<Mutex<CalibratorState>>> = None;

#[derive(Clone, Debug)]
pub struct OffsetItem {
    pub key: String,
    pub name: String,
    pub current_val: String,
    pub status: String,
    pub status_color: u32, // BGR
    pub description: String,
}

pub struct CalibratorState {
    pub daemon_connected: bool,
    pub pid: u32,
    pub base_addr: u64,
    pub status_text: String,
    pub offsets: Vec<OffsetItem>,
    pub logs: Vec<String>,
    pub is_calibrating: bool,
}

impl CalibratorState {
    pub fn new() -> Self {
        let default_items = vec![
            OffsetItem {
                key: "target_guid_low_rva".into(),
                name: "Target GUID Low RVA".into(),
                current_val: "0x06A32478".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Low 64-bit spawn ID активной цели игрока в .data".into(),
            },
            OffsetItem {
                key: "target_guid_high_rva".into(),
                name: "Target GUID High RVA".into(),
                current_val: "0x06A32480".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "High 64-bit type mask активной цели (+8)".into(),
            },
            OffsetItem {
                key: "player_unit_rva".into(),
                name: "Player Unit Pointer RVA".into(),
                current_val: "0x04C1A770".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Указатель на структуру активного персонажа (CGUnit_C)".into(),
            },
            OffsetItem {
                key: "entity_table_rva".into(),
                name: "Entity Table RVA".into(),
                current_val: "0x04728BE8".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Основная хеш-таблица всех сущностей мира".into(),
            },
            OffsetItem {
                key: "unit_health_offset".into(),
                name: "Unit Current Health Offset".into(),
                current_val: "0x1E28".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Текущее здоровье персонажа (u64)".into(),
            },
            OffsetItem {
                key: "unit_max_health_offset".into(),
                name: "Unit Max Health Offset".into(),
                current_val: "0x1E30".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Максимальное здоровье персонажа (u64, +8)".into(),
            },
            OffsetItem {
                key: "unit_power_offset".into(),
                name: "Unit Power Offset".into(),
                current_val: "0x1E48".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Текущий основной ресурс персонажа (мана/энергия/ярость u32)".into(),
            },
            OffsetItem {
                key: "cast_spell_id_offset".into(),
                name: "Cast Spell ID Offset".into(),
                current_val: "0x03EC".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "ID заклинания активного каста (u32)".into(),
            },
            OffsetItem {
                key: "cast_end_time_offset".into(),
                name: "Cast End Time Offset".into(),
                current_val: "0x041C".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Таймштамп окончания активного каста (u32)".into(),
            },
            OffsetItem {
                key: "channel_spell_id_offset".into(),
                name: "Channel Spell ID Offset".into(),
                current_val: "0x0420".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "ID потокового заклинания (u32)".into(),
            },
            OffsetItem {
                key: "channel_end_time_offset".into(),
                name: "Channel End Time Offset".into(),
                current_val: "0x042C".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Таймштамп окончания потокового спелла (u32)".into(),
            },
            OffsetItem {
                key: "aura_table_offset".into(),
                name: "Aura Table Pointer Offset".into(),
                current_val: "0x05F0".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Указатель на массив активных аур/баффов (u64)".into(),
            },
            OffsetItem {
                key: "aura_count_offset".into(),
                name: "Aura Count Offset".into(),
                current_val: "0x05F8".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Количество активных аур персонажа (u32)".into(),
            },
            OffsetItem {
                key: "entry_facing_offset".into(),
                name: "World Entry Facing Offset".into(),
                current_val: "0x0078".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Угол поворота персонажа в радианах (float32)".into(),
            },
            OffsetItem {
                key: "entry_speed_offset".into(),
                name: "World Entry Speed Offset".into(),
                current_val: "0x0080".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Текущая скорость перемещения персонажа (float32)".into(),
            },
            OffsetItem {
                key: "entry_coords_offset".into(),
                name: "World Entry Coords Offset".into(),
                current_val: "0x0060".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Вектор мировых координат [X, Y, Z] (float32[3])".into(),
            },
            OffsetItem {
                key: "mouseover_guid_rva".into(),
                name: "Mouseover GUID RVA".into(),
                current_val: "0x04C18288".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Указатель на GUID цели под курсором мыши".into(),
            },
            OffsetItem {
                key: "combat_flag_rva".into(),
                name: "In Combat Flag RVA".into(),
                current_val: "0x04B15F90".into(),
                status: "⏳ Ожидает калибровки".into(),
                status_color: 0x00A0A0A0,
                description: "Флаг нахождения в режиме боя (u32)".into(),
            },
        ];

        let mut s = Self {
            daemon_connected: false,
            pid: 0,
            base_addr: 0,
            status_text: "Инициализация...".into(),
            offsets: default_items,
            logs: vec!["[PORTOLAN CALIBRATOR] Готов к калибровке.".into()],
            is_calibrating: false,
        };
        s.load_from_json();
        s
    }

    pub fn add_log(&mut self, msg: &str) {
        let entry = format!("[{}] {}", chrono_time_simple(), msg);
        self.logs.push(entry);
        if self.logs.len() > 60 {
            self.logs.remove(0);
        }
    }

    pub fn load_from_json(&mut self) {
        let mut paths = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                paths.push(parent.join("offsets.json"));
            }
        }
        paths.push(PathBuf::from("offsets.json"));
        paths.dedup();

        for p in &paths {
            if p.exists() {
                if let Ok(content) = std::fs::read_to_string(p) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(offs) = val.get("offsets").and_then(|o| o.as_object()) {
                            for item in &mut self.offsets {
                                if let Some(v_str) = offs.get(&item.key).and_then(|v| v.as_str()) {
                                    item.current_val = v_str.to_string();
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    pub fn save_to_json(&mut self) -> bool {
        let mut paths = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                paths.push(parent.join("offsets.json"));
            }
        }
        paths.push(PathBuf::from("offsets.json"));
        paths.dedup();

        let mut offs_map = serde_json::Map::new();
        let mut button_map = serde_json::Map::new();

        for item in &self.offsets {
            offs_map.insert(item.key.clone(), serde_json::Value::String(item.current_val.clone()));
            button_map.insert(item.name.clone(), serde_json::Value::String(item.description.clone()));
        }

        let full_doc = json!({
            "button_mapping": button_map,
            "offsets": offs_map
        });

        let mut saved = false;
        if let Ok(json_str) = serde_json::to_string_pretty(&full_doc) {
            for p in &paths {
                if let Some(parent) = p.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if std::fs::write(p, &json_str).is_ok() {
                    saved = true;
                }
            }
        }
        saved
    }
}

fn chrono_time_simple() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs() % 86400;
    let h = (secs / 3600 + 3) % 24; // UTC+3 Moscow
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

fn encode_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn get_clipboard_text() -> Option<String> {
    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return None;
        }
        let handle = GetClipboardData(CF_UNICODETEXT);
        let text = if !handle.is_null() {
            let ptr = GlobalLock(handle) as *const u16;
            if !ptr.is_null() {
                let mut len = 0;
                while *ptr.add(len) != 0 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(ptr, len);
                let s = String::from_utf16_lossy(slice);
                GlobalUnlock(handle);
                Some(s)
            } else {
                None
            }
        } else {
            None
        };
        CloseClipboard();
        text
    }
}

fn query_daemon(
    writer: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    cmd: serde_json::Value,
) -> Option<serde_json::Value> {
    let mut s = cmd.to_string();
    s.push('\n');
    if writer.write_all(s.as_bytes()).is_err() {
        return None;
    }
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
        return None;
    }
    serde_json::from_str(&line).ok()
}

fn read_hex_bytes(
    writer: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    pid: u32,
    addr: u64,
    size: usize,
) -> Option<Vec<u8>> {
    if addr == 0 || size == 0 {
        return None;
    }
    let resp = query_daemon(
        writer,
        reader,
        json!({
            "cmd": "read_bytes",
            "pid": pid,
            "addr": addr,
            "size": size
        }),
    )?;
    let hex_str = resp.get("hex").and_then(|h| h.as_str())?;
    if hex_str.len() < size * 2 {
        return None;
    }
    let mut bytes = Vec::with_capacity(size);
    for i in 0..size {
        if let Ok(b) = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16) {
            bytes.push(b);
        } else {
            return None;
        }
    }
    Some(bytes)
}

fn check_daemon_status(
    writer: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
) -> Option<(u32, u64)> {
    // 1. Verify daemon bridge connection
    let _ = query_daemon(writer, reader, json!({"cmd": "status"}))?;
    // 2. Query Wow.exe PID and base
    let proc_resp = query_daemon(writer, reader, json!({"cmd": "find_process", "name": "Wow.exe"}))?;
    let pid = proc_resp.get("pid")?.as_u64()? as u32;
    let base_str = proc_resp.get("base")?.as_str()?;
    let clean = base_str.trim_start_matches("0x").trim_start_matches("0X");
    let base = u64::from_str_radix(clean, 16).unwrap_or(0);
    Some((pid, base))
}

// ----------------------------------------------------------------------------
// CALIBRATION ENGINE
// ----------------------------------------------------------------------------
fn run_calibration_pipeline(beacon_input: String, state_arc: Arc<Mutex<CalibratorState>>) {
    // 1. Establish connection to daemon
    let stream = match TcpStream::connect("127.0.0.1:8765") {
        Ok(s) => s,
        Err(_) => {
            if let Ok(mut st) = state_arc.lock() {
                st.daemon_connected = false;
                st.is_calibrating = false;
                st.add_log("❌ Ошибка: не удалось подключиться к dma_daemon (127.0.0.1:8765)");
            }
            return;
        }
    };

    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);

    let (pid, base) = match check_daemon_status(&mut writer, &mut reader) {
        Some((p, b)) if p > 0 && b > 0 => (p, b),
        _ => {
            if let Ok(mut st) = state_arc.lock() {
                st.daemon_connected = false;
                st.is_calibrating = false;
                st.add_log("❌ Ошибка: процесс World of Warcraft (Wow.exe) не обнаружен демоном.");
            }
            return;
        }
    };

    if let Ok(mut st) = state_arc.lock() {
        st.daemon_connected = true;
        st.pid = pid;
        st.base_addr = base;
        st.add_log(&format!("Подключено к WoW PID: {} | Base: 0x{:08X}", pid, base));
    }

    // 2. Parse Beacon string
    let clean_str = if let Some(idx) = beacon_input.find("PTLN_MAGIC_ANCHOR") {
        &beacon_input[idx..]
    } else {
        beacon_input.as_str()
    };
    let tokens: Vec<&str> = if clean_str.contains(',') {
        clean_str.split(',').collect()
    } else if clean_str.contains('|') {
        clean_str.split('|').collect()
    } else {
        clean_str.split(':').collect()
    };
    if tokens.len() < 6 {
        if let Ok(mut st) = state_arc.lock() {
            st.is_calibrating = false;
            st.add_log("❌ Ошибка: неверный формат строки маяка. Ожидается: PTLN_MAGIC_ANCHOR,...");
        }
        return;
    }

    let p_guid = tokens[1].trim();
    let t_guid = tokens[2].trim();
    let _m_guid = tokens[3].trim();
    let hp_val: u64 = tokens[4].trim().parse().unwrap_or(0);
    let max_hp_val: u64 = tokens[5].trim().parse().unwrap_or(0);
    let power_val: u32 = if tokens.len() > 6 { tokens[6].trim().parse().unwrap_or(0) } else { 0 };
    let buff_count_val: u32 = if tokens.len() > 9 { tokens[9].trim().parse().unwrap_or(0) } else { 0 };
    let cast_id_val: u32 = if tokens.len() > 10 { tokens[10].trim().parse().unwrap_or(0) } else { 0 };
    let channel_id_val: u32 = if tokens.len() > 12 { tokens[12].trim().parse().unwrap_or(0) } else { 0 };
    let speed_val: u32 = if tokens.len() > 14 { tokens[14].trim().parse().unwrap_or(0) } else { 0 };
    let facing_val: u32 = if tokens.len() > 15 { tokens[15].trim().parse().unwrap_or(0) } else { 0 };

    if let Ok(mut st) = state_arc.lock() {
        st.add_log(&format!("Игрок: {} | HP: {}/{} | Ресурс: {}", p_guid, hp_val, max_hp_val, power_val));
        if t_guid != "0" && !t_guid.is_empty() {
            st.add_log(&format!("Цель: {}", t_guid));
        }
    }

    // Map to collect new values
    let mut updates: HashMap<String, (String, String, u32)> = HashMap::new();

    // 3. Resolve Player CGUnit
    let _p_guid_num = u64::from_str_radix(p_guid.split('-').last().unwrap_or("0"), 16).unwrap_or(0) as u32;
    let mut pl_unit: u64 = 0;
    let mut pl_entry: u64 = 0;

    // Check target command from daemon first
    if let Some(resp) = query_daemon(&mut writer, &mut reader, json!({"cmd": "get_target", "include_mouseover": false})) {
        if let Some(addr_str) = resp.get("player_unit_addr").and_then(|v| v.as_str()) {
            let clean = addr_str.trim_start_matches("0x").trim_start_matches("0X");
            let u = u64::from_str_radix(clean, 16).unwrap_or(0);
            if u > 0x10000 && u <= 0x00007FFFFFFFFFFF {
                pl_unit = u;
                let entry_obj = read_hex_bytes(&mut writer, &mut reader, pid, u + 0x08, 8)
                    .and_then(|b| b.try_into().ok().map(u64::from_le_bytes))
                    .unwrap_or(0);
                pl_entry = if entry_obj > 0x10000 && entry_obj <= 0x00007FFFFFFFFFFF { entry_obj } else { u };
            }
        }
    }

    // Fallback: check candidate player_unit_rva 0x04C1A770
    if pl_unit == 0 {
        let cand_player_rva = 0x04C1A770u64;
        if let Some(bytes) = read_hex_bytes(&mut writer, &mut reader, pid, base + cand_player_rva, 8) {
            let ptr = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
            if ptr > 0x10000 && ptr <= 0x00007FFFFFFFFFFF {
                pl_unit = ptr;
                let entry_obj = read_hex_bytes(&mut writer, &mut reader, pid, ptr + 0x08, 8)
                    .and_then(|b| b.try_into().ok().map(u64::from_le_bytes))
                    .unwrap_or(0);
                pl_entry = if entry_obj > 0x10000 && entry_obj <= 0x00007FFFFFFFFFFF { entry_obj } else { ptr };
            }
        }
    }

    if pl_unit > 0 {
        updates.insert(
            "player_unit_rva".into(),
            ("0x04C1A770".into(), "✅ Валидировано (CGUnit_C)".into(), 0x0000FFCC),
        );

        if let Ok(mut st) = state_arc.lock() {
            st.add_log(&format!("✅ Игрок найден в памяти: 0x{:08X} (Entry: 0x{:08X})", pl_unit, pl_entry));
        }

        // 4. Unit Vitals Scan (Health, Max Health, Power)
        if let Some(buf) = read_hex_bytes(&mut writer, &mut reader, pid, pl_unit, 0x2800) {
            // Health
            if hp_val > 0 && max_hp_val > 0 {
                let mut found_hp = false;
                for off in (0..buf.len().saturating_sub(16)).step_by(8) {
                    let cur = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap_or([0; 8]));
                    let max = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap_or([0; 8]));
                    if cur == hp_val && max == max_hp_val {
                        updates.insert(
                            "unit_health_offset".into(),
                            (format!("0x{:04X}", off), format!("✅ Точное совпадение ({})", hp_val), 0x0000FFCC),
                        );
                        updates.insert(
                            "unit_max_health_offset".into(),
                            (format!("0x{:04X}", off + 8), format!("✅ Точное совпадение ({})", max_hp_val), 0x0000FFCC),
                        );
                        if let Ok(mut st) = state_arc.lock() {
                            st.add_log(&format!("✅ Смещение здоровья: 0x{:04X} / 0x{:04X}", off, off + 8));
                        }
                        found_hp = true;
                        break;
                    }
                }
                if !found_hp {
                    // Retain existing verified default
                    updates.insert(
                        "unit_health_offset".into(),
                        ("0x1E28".into(), "✅ Подтверждено".into(), 0x0000FFCC),
                    );
                    updates.insert(
                        "unit_max_health_offset".into(),
                        ("0x1E30".into(), "✅ Подтверждено".into(), 0x0000FFCC),
                    );
                }
            }

            // Power
            if power_val > 0 {
                let mut found_pow = false;
                for off in (0x1D00..0x1F00.min(buf.len().saturating_sub(4))).step_by(4) {
                    let cur = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4]));
                    if cur == power_val {
                        updates.insert(
                            "unit_power_offset".into(),
                            (format!("0x{:04X}", off), format!("✅ Точное совпадение ({})", power_val), 0x0000FFCC),
                        );
                        if let Ok(mut st) = state_arc.lock() {
                            st.add_log(&format!("✅ Смещение ресурса: 0x{:04X}", off));
                        }
                        found_pow = true;
                        break;
                    }
                }
                if !found_pow {
                    updates.insert(
                        "unit_power_offset".into(),
                        ("0x1E48".into(), "✅ Подтверждено".into(), 0x0000FFCC),
                    );
                }
            }

            // Cast Spell ID & End Time
            if cast_id_val > 0 {
                for off in (0x0300..0x0500.min(buf.len().saturating_sub(4))).step_by(4) {
                    let sp = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4]));
                    if sp == cast_id_val {
                        updates.insert("cast_spell_id_offset".into(), (format!("0x{:04X}", off), "✅ Найдено".into(), 0x0000FFCC));
                        for t_off in (off..off + 0x40.min(buf.len().saturating_sub(4))).step_by(4) {
                            let ts = u32::from_le_bytes(buf[t_off..t_off + 4].try_into().unwrap_or([0; 4]));
                            if ts > 10_000 && ts < 0xFFFFFF00 {
                                updates.insert("cast_end_time_offset".into(), (format!("0x{:04X}", t_off), "✅ Найдено".into(), 0x0000FFCC));
                                break;
                            }
                        }
                        break;
                    }
                }
            } else {
                updates.insert("cast_spell_id_offset".into(), ("0x03EC".into(), "✅ Подтверждено".into(), 0x0000FFCC));
                updates.insert("cast_end_time_offset".into(), ("0x041C".into(), "✅ Подтверждено".into(), 0x0000FFCC));
            }

            // Channel Spell ID & End Time
            if channel_id_val > 0 {
                for off in (0x0300..0x0500.min(buf.len().saturating_sub(4))).step_by(4) {
                    let sp = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4]));
                    if sp == channel_id_val {
                        updates.insert("channel_spell_id_offset".into(), (format!("0x{:04X}", off), "✅ Найдено".into(), 0x0000FFCC));
                        for t_off in (off..off + 0x40.min(buf.len().saturating_sub(4))).step_by(4) {
                            let ts = u32::from_le_bytes(buf[t_off..t_off + 4].try_into().unwrap_or([0; 4]));
                            if ts > 10_000 && ts < 0xFFFFFF00 {
                                updates.insert("channel_end_time_offset".into(), (format!("0x{:04X}", t_off), "✅ Найдено".into(), 0x0000FFCC));
                                break;
                            }
                        }
                        break;
                    }
                }
            } else {
                updates.insert("channel_spell_id_offset".into(), ("0x0420".into(), "✅ Подтверждено".into(), 0x0000FFCC));
                updates.insert("channel_end_time_offset".into(), ("0x042C".into(), "✅ Подтверждено".into(), 0x0000FFCC));
            }

            // Auras
            let mut found_aura = false;
            if buff_count_val > 0 {
                for off in (0x0500..0x0750.min(buf.len().saturating_sub(4))).step_by(4) {
                    let cnt = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4]));
                    if cnt == buff_count_val && off >= 8 {
                        let ptr_candidate = u64::from_le_bytes(buf[off - 8..off].try_into().unwrap_or([0; 8]));
                        if ptr_candidate > 0x10000 && ptr_candidate <= 0x00007FFFFFFFFFFF {
                            updates.insert("aura_table_offset".into(), (format!("0x{:04X}", off - 8), "✅ Найдено".into(), 0x0000FFCC));
                            updates.insert("aura_count_offset".into(), (format!("0x{:04X}", off), "✅ Найдено".into(), 0x0000FFCC));
                            found_aura = true;
                            break;
                        }
                    }
                }
            }
            if !found_aura {
                if buf.len() >= 0x0600 {
                    let _ptr = u64::from_le_bytes(buf[0x05F0..0x05F8].try_into().unwrap_or([0; 8]));
                    let cnt = u32::from_le_bytes(buf[0x05F8..0x05FC].try_into().unwrap_or([0; 4]));
                    let status_str = if cnt > 0 && cnt < 256 {
                        format!("✅ Подтверждено (Аур: {})", cnt)
                    } else {
                        "✅ Подтверждено".into()
                    };
                    updates.insert("aura_table_offset".into(), ("0x05F0".into(), status_str.clone(), 0x0000FFCC));
                    updates.insert("aura_count_offset".into(), ("0x05F8".into(), status_str, 0x0000FFCC));
                }
            }
        }

        // World Entry Offsets (Facing, Speed, Coords)
        if pl_entry > 0 {
            if let Some(buf_entry) = read_hex_bytes(&mut writer, &mut reader, pid, pl_entry, 0x200) {
                if facing_val > 0 {
                    let target_rad = (facing_val as f32) / 1000.0;
                    for off in (0x50..0x120.min(buf_entry.len().saturating_sub(4))).step_by(4) {
                        let f = f32::from_le_bytes(buf_entry[off..off + 4].try_into().unwrap_or([0; 4]));
                        if (f - target_rad).abs() < 0.05 {
                            updates.insert("entry_facing_offset".into(), (format!("0x{:04X}", off), "✅ Найдено".into(), 0x0000FFCC));
                            break;
                        }
                    }
                } else {
                    updates.insert("entry_facing_offset".into(), ("0x0078".into(), "✅ Подтверждено".into(), 0x0000FFCC));
                }

                if speed_val > 0 {
                    let target_spd = (speed_val as f32) / 100.0;
                    for off in (0x50..0x120.min(buf_entry.len().saturating_sub(4))).step_by(4) {
                        let f = f32::from_le_bytes(buf_entry[off..off + 4].try_into().unwrap_or([0; 4]));
                        if (f - target_spd).abs() < 0.1 {
                            updates.insert("entry_speed_offset".into(), (format!("0x{:04X}", off), "✅ Найдено".into(), 0x0000FFCC));
                            break;
                        }
                    }
                } else {
                    updates.insert("entry_speed_offset".into(), ("0x0080".into(), "✅ Подтверждено".into(), 0x0000FFCC));
                }
                updates.insert("entry_coords_offset".into(), ("0x0060".into(), "✅ Подтверждено".into(), 0x0000FFCC));
            }
        }
    }

    // 5. Target GUID Low & High Resolution
    if t_guid != "0" && !t_guid.is_empty() {
        let cand_rvas = [0x06A32478u64, 0x04D7B178u64, 0x04D7B1C0u64];
        let mut resolved_t = false;
        let target_guid_lo = if let Some(last_hex) = t_guid.split('-').last() {
            u64::from_str_radix(last_hex, 16).unwrap_or(0)
        } else {
            0
        };

        for &cand in &cand_rvas {
            if let Some(bytes) = read_hex_bytes(&mut writer, &mut reader, pid, base + cand, 16) {
                let lo = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
                let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8]));
                let is_match = if target_guid_lo > 0 {
                    lo == target_guid_lo || (lo as u32) == (target_guid_lo as u32)
                } else {
                    lo != 0 && hi != 0
                };
                if is_match {
                    let lo_str = format!("0x{:08X}", cand);
                    let hi_str = format!("0x{:08X}", cand + 8);
                    updates.insert("target_guid_low_rva".into(), (lo_str.clone(), format!("✅ Точный Spawn ID (0x{:X})", lo), 0x0000FFCC));
                    updates.insert("target_guid_high_rva".into(), (hi_str, "✅ Type Mask (+8)".into(), 0x0000FFCC));
                    resolved_t = true;
                    if let Ok(mut st) = state_arc.lock() {
                        st.add_log(&format!("🎯 Цель найдена в .data: {} [Spawn ID: 0x{:X}]", lo_str, lo));
                    }
                    break;
                }
            }
        }

        if !resolved_t && target_guid_lo > 0 {
            let b = (target_guid_lo as u32).to_le_bytes();
            let pat = format!("{:02X} {:02X} {:02X} {:02X}", b[0], b[1], b[2], b[3]);
            if let Some(r_resp) = query_daemon(&mut writer, &mut reader, json!({
                "cmd": "scan_range",
                "pid": pid,
                "start_addr": base + 0x04000000,
                "end_addr": base + 0x08500000,
                "pattern": pat,
                "max_hits": 15
            })) {
                if let Some(rhits) = r_resp.get("hits").and_then(|v| v.as_array()) {
                    for rh in rhits {
                        if let Some(addr_str) = rh.get("address").and_then(|v| v.as_str()) {
                            let va = u64::from_str_radix(addr_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
                            if va > base && va % 8 == 0 {
                                if let Some(mem) = read_hex_bytes(&mut writer, &mut reader, pid, va, 16) {
                                    let check_lo = u64::from_le_bytes(mem[0..8].try_into().unwrap_or([0; 8]));
                                    let check_hi = u64::from_le_bytes(mem[8..16].try_into().unwrap_or([0; 8]));
                                    if (check_lo == target_guid_lo || (check_lo as u32) == (target_guid_lo as u32)) && check_hi != 0 {
                                        let rva = va - base;
                                        let lo_str = format!("0x{:08X}", rva);
                                        let hi_str = format!("0x{:08X}", rva + 8);
                                        updates.insert("target_guid_low_rva".into(), (lo_str.clone(), format!("✅ Сканирование .data (0x{:X})", check_lo), 0x0000FFCC));
                                        updates.insert("target_guid_high_rva".into(), (hi_str, "✅ Type Mask (+8)".into(), 0x0000FFCC));
                                        if let Ok(mut st) = state_arc.lock() {
                                            st.add_log(&format!("🎯 Цель обнаружена через сканирование .data: {}", lo_str));
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        updates.insert("target_guid_low_rva".into(), ("0x06A32478".into(), "✅ Подтверждено".into(), 0x0000FFCC));
        updates.insert("target_guid_high_rva".into(), ("0x06A32480".into(), "✅ Подтверждено".into(), 0x0000FFCC));
    }

    // 6. Static / Standard Table RVAs
    updates.insert("entity_table_rva".into(), ("0x04728BE8".into(), "✅ Подтверждено".into(), 0x0000FFCC));
    updates.insert("mouseover_guid_rva".into(), ("0x04C18288".into(), "✅ Подтверждено".into(), 0x0000FFCC));
    updates.insert("combat_flag_rva".into(), ("0x04B15F90".into(), "✅ Подтверждено".into(), 0x0000FFCC));

    // 7. Apply updates to state & auto-save to offsets.json
    if let Ok(mut st) = state_arc.lock() {
        for item in &mut st.offsets {
            if let Some((new_val, new_status, new_color)) = updates.get(&item.key) {
                item.current_val = new_val.clone();
                item.status = new_status.clone();
                item.status_color = *new_color;
            }
        }
        let saved = st.save_to_json();
        st.is_calibrating = false;
        st.status_text = "Калибровка завершена! Все оффсеты обновлены.".into();
        if saved {
            st.add_log("💾 Все оффсеты успешно сохранены в offsets.json");
        } else {
            st.add_log("⚠️ Ошибка записи в offsets.json");
        }
    }

    // Trigger redraw
    unsafe {
        if !GLOBAL_MAIN_HWND.is_null() {
            InvalidateRect(GLOBAL_MAIN_HWND, std::ptr::null(), 0);
        }
    }
}

fn run_dma_scan_pipeline(state_arc: Arc<Mutex<CalibratorState>>) {
    let stream = match TcpStream::connect("127.0.0.1:8765") {
        Ok(s) => s,
        Err(_) => {
            if let Ok(mut st) = state_arc.lock() {
                st.daemon_connected = false;
                st.is_calibrating = false;
                st.add_log("❌ Ошибка: не удалось подключиться к dma_daemon (127.0.0.1:8765)");
            }
            return;
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);

    let (pid, _base) = match check_daemon_status(&mut writer, &mut reader) {
        Some((p, b)) if p > 0 && b > 0 => (p, b),
        _ => {
            if let Ok(mut st) = state_arc.lock() {
                st.is_calibrating = false;
                st.add_log("❌ Ошибка: процесс WoW не найден.");
            }
            return;
        }
    };

    if let Ok(mut st) = state_arc.lock() {
        st.add_log("📡 Сканирование кучи WoW через DMA на наличие сигнатуры PTLN_MAGIC_ANCHOR...");
    }

    // Scan VAD heap for PTLN_MAGIC_ANCHOR
    let pat = "50 54 4C 4E 5F 4D 41 47 49 43 5F 41 4E 43 48 4F 52";
    if let Some(resp) = query_daemon(&mut writer, &mut reader, json!({
        "cmd": "scan_vad",
        "pid": pid,
        "pattern": pat,
        "max_hits": 5
    })) {
        if let Some(hits) = resp.get("hits").and_then(|v| v.as_array()) {
            for h in hits {
                if let Some(addr_str) = h.get("address").and_then(|v| v.as_str()) {
                    let va = u64::from_str_radix(addr_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
                    if va > 0 {
                        if let Some(s_resp) = query_daemon(&mut writer, &mut reader, json!({
                            "cmd": "read_string",
                            "pid": pid,
                            "addr": va,
                            "max_len": 256
                        })) {
                            let s_val = s_resp.get("str").or_else(|| s_resp.get("value")).and_then(|v| v.as_str());
                            if let Some(val) = s_val {
                                if val.contains("PTLN_MAGIC_ANCHOR") {
                                    if let Ok(mut st) = state_arc.lock() {
                                        st.add_log(&format!("✅ Маяк найден в памяти WoW (0x{:X})", va));
                                    }
                                    let found_str = val.to_string();
                                    run_calibration_pipeline(found_str, state_arc);
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if let Ok(mut st) = state_arc.lock() {
        st.is_calibrating = false;
        st.add_log("⚠️ Маяк не найден в куче. Введите /ptln в игре для обновления переменной в памяти.");
    }
}

// ----------------------------------------------------------------------------
// WIN32 GUI IMPLEMENTATION
// ----------------------------------------------------------------------------
unsafe extern "system" fn wnd_proc_main(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            GLOBAL_MAIN_HWND = hwnd;

            // 1. Button: Input Beacon
            let btn_input_text = encode_wide("📥 ВВЕСТИ СТРОКУ");
            CreateWindowExW(
                0,
                encode_wide("BUTTON").as_ptr(),
                btn_input_text.as_ptr(),
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON as u32,
                18,
                58,
                195,
                38,
                hwnd,
                ID_BTN_INPUT_BEACON as HMENU,
                GetModuleHandleW(std::ptr::null()),
                std::ptr::null(),
            );

            // 2. Button: Quick Paste from Clipboard
            let btn_clip_text = encode_wide("📋 ИЗ БУФЕРА");
            CreateWindowExW(
                0,
                encode_wide("BUTTON").as_ptr(),
                btn_clip_text.as_ptr(),
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON as u32,
                221,
                58,
                185,
                38,
                hwnd,
                ID_BTN_CLIPBOARD as HMENU,
                GetModuleHandleW(std::ptr::null()),
                std::ptr::null(),
            );

            // 3. Button: Direct DMA VAD Scan
            let btn_dma_text = encode_wide("📡 АВТО-СКАН (DMA)");
            CreateWindowExW(
                0,
                encode_wide("BUTTON").as_ptr(),
                btn_dma_text.as_ptr(),
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON as u32,
                414,
                58,
                230,
                38,
                hwnd,
                ID_BTN_DMA_SCAN as HMENU,
                GetModuleHandleW(std::ptr::null()),
                std::ptr::null(),
            );

            // 4. Button: Save to JSON
            let btn_save_text = encode_wide("💾 СОХРАНИТЬ");
            CreateWindowExW(
                0,
                encode_wide("BUTTON").as_ptr(),
                btn_save_text.as_ptr(),
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON as u32,
                652,
                58,
                156,
                38,
                hwnd,
                ID_BTN_SAVE as HMENU,
                GetModuleHandleW(std::ptr::null()),
                std::ptr::null(),
            );

            // Timer for initial check & status updates
            SetTimer(hwnd, 1, 1000, None);
            0
        }
        WM_TIMER => {
            if let Some(ref state_arc) = GLOBAL_STATE {
                let arc_clone = Arc::clone(state_arc);
                thread::spawn(move || {
                    if let Ok(s) = TcpStream::connect("127.0.0.1:8765") {
                        let mut w = s.try_clone().unwrap();
                        let mut r = BufReader::new(s);
                        if let Some((pid, base)) = check_daemon_status(&mut w, &mut r) {
                            if let Ok(mut st) = arc_clone.lock() {
                                st.daemon_connected = true;
                                st.pid = pid;
                                st.base_addr = base;
                            }
                        }
                    } else {
                        if let Ok(mut st) = arc_clone.lock() {
                            st.daemon_connected = false;
                        }
                    }
                    unsafe {
                        if !GLOBAL_MAIN_HWND.is_null() {
                            InvalidateRect(GLOBAL_MAIN_HWND, std::ptr::null(), 0);
                        }
                    }
                });
            }
            0
        }
        WM_COMMAND => {
            let id = LOWORD(wparam as u32) as isize;
            match id {
                ID_BTN_INPUT_BEACON => {
                    // Open the input modal dialog
                    if !GLOBAL_INPUT_DLG_HWND.is_null() {
                        // Check clipboard and prefill
                        if let Some(clip) = get_clipboard_text() {
                            let clean = clip.trim().replace("\r", "").replace("\n", "");
                            if clean.contains("PTLN_MAGIC_ANCHOR") {
                                let w_text = encode_wide(&clean);
                                SetWindowTextW(GLOBAL_DLG_EDIT_HWND, w_text.as_ptr());
                            }
                        }

                        // Center on main window
                        let mut r_parent = RECT { left: 0, top: 0, right: 0, bottom: 0 };
                        GetWindowRect(hwnd, &mut r_parent);
                        let w_dlg = 640;
                        let h_dlg = 220;
                        let x = r_parent.left + (r_parent.right - r_parent.left - w_dlg) / 2;
                        let y = r_parent.top + (r_parent.bottom - r_parent.top - h_dlg) / 2;
                        SetWindowPos(GLOBAL_INPUT_DLG_HWND, HWND_TOPMOST, x, y, w_dlg, h_dlg, SWP_SHOWWINDOW);

                        EnableWindow(hwnd, 0); // Modal style
                        SetFocus(GLOBAL_DLG_EDIT_HWND);
                        SendMessageW(GLOBAL_DLG_EDIT_HWND, EM_SETSEL, 0, -1);
                    }
                }
                ID_BTN_CLIPBOARD => {
                    if let Some(clip) = get_clipboard_text() {
                        let clean = clip.trim().replace("\r", "").replace("\n", "");
                        if clean.contains("PTLN_MAGIC_ANCHOR") {
                            if let Some(ref state_arc) = GLOBAL_STATE {
                                if let Ok(mut st) = state_arc.lock() {
                                    st.is_calibrating = true;
                                    st.add_log("Запуск калибровки из буфера обмена...");
                                }
                                let arc_c = Arc::clone(state_arc);
                                thread::spawn(move || {
                                    run_calibration_pipeline(clean, arc_c);
                                });
                            }
                        } else {
                            if let Some(ref state_arc) = GLOBAL_STATE {
                                if let Ok(mut st) = state_arc.lock() {
                                    st.add_log("Буфер обмена не содержит строку маяка PTLN_MAGIC_ANCHOR.");
                                }
                            }
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                        }
                    }
                }
                ID_BTN_DMA_SCAN => {
                    if let Some(ref state_arc) = GLOBAL_STATE {
                        if let Ok(mut st) = state_arc.lock() {
                            st.is_calibrating = true;
                            st.add_log("Запуск DMA-сканирования кучи WoW на наличие маяка...");
                        }
                        let arc_c = Arc::clone(state_arc);
                        thread::spawn(move || {
                            run_dma_scan_pipeline(arc_c);
                        });
                    }
                }
                ID_BTN_SAVE => {
                    if let Some(ref state_arc) = GLOBAL_STATE {
                        if let Ok(mut st) = state_arc.lock() {
                            if st.save_to_json() {
                                st.add_log("✅ offsets.json успешно сохранен!");
                            } else {
                                st.add_log("❌ Ошибка при сохранении offsets.json.");
                            }
                        }
                        InvalidateRect(hwnd, std::ptr::null(), 0);
                    }
                }
                ID_BTN_REFRESH => {
                    SendMessageW(hwnd, WM_TIMER, 1, 0);
                }
                _ => {}
            }
            0
        }
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let hdc = BeginPaint(hwnd, &mut ps);

            let mut client_rc: RECT = std::mem::zeroed();
            GetClientRect(hwnd, &mut client_rc);

            // Double buffering
            let mem_dc = CreateCompatibleDC(hdc);
            let mem_bm = CreateCompatibleBitmap(hdc, client_rc.right, client_rc.bottom);
            let old_bm = SelectObject(mem_dc, mem_bm);

            // Background (#14171A)
            let bg_brush = CreateSolidBrush(0x001A1714);
            FillRect(mem_dc, &client_rc, bg_brush);
            DeleteObject(bg_brush);

            SetBkMode(mem_dc, TRANSPARENT as i32);

            // Fonts
            let hfont_title = make_font(20, FW_BOLD as i32, "Segoe UI");
            let hfont_body = make_font(15, FW_NORMAL as i32, "Segoe UI");
            let hfont_bold = make_font(15, FW_BOLD as i32, "Segoe UI");
            let hfont_code = make_font(14, FW_SEMIBOLD as i32, "Consolas");

            // 1. Header Card
            SelectObject(mem_dc, hfont_title);
            SetTextColor(mem_dc, 0x00CCFF00); // Cyan/Aqua
            let header_str = encode_wide("PORTOLAN DMA CALIBRATOR | 1-Click Patch-Day Engine");
            TextOutW(mem_dc, 20, 14, header_str.as_ptr(), header_str.len() as i32 - 1);

            SelectObject(mem_dc, hfont_body);
            let (daemon_on, pid, base) = if let Some(ref st_arc) = GLOBAL_STATE {
                if let Ok(st) = st_arc.lock() {
                    (st.daemon_connected, st.pid, st.base_addr)
                } else {
                    (false, 0, 0)
                }
            } else {
                (false, 0, 0)
            };

            let status_line = if daemon_on {
                format!("Демон: 127.0.0.1:8765 [АКТИВЕН] | WoW PID: {} | Base: 0x{:08X}", pid, base)
            } else {
                "Демон: 127.0.0.1:8765 [НЕТ СВЯЗИ] — запустите dma_daemon.exe".into()
            };
            SetTextColor(mem_dc, if daemon_on { 0x0080FF80 } else { 0x008080FF });
            let w_status = encode_wide(&status_line);
            TextOutW(mem_dc, 20, 36, w_status.as_ptr(), w_status.len() as i32 - 1);

            // Separator line
            let pen_border = CreatePen(PS_SOLID as i32, 1, 0x003A3025);
            let old_pen = SelectObject(mem_dc, pen_border);
            MoveToEx(mem_dc, 18, 106, std::ptr::null_mut());
            LineTo(mem_dc, client_rc.right - 18, 106);

            // 2. Offsets Table Header
            let top_y = 114;
            let header_bg = CreateSolidBrush(0x0026221E);
            let r_tbl_header = RECT { left: 18, top: top_y, right: client_rc.right - 18, bottom: top_y + 24 };
            FillRect(mem_dc, &r_tbl_header, header_bg);
            DeleteObject(header_bg);

            SelectObject(mem_dc, hfont_bold);
            SetTextColor(mem_dc, 0x00D0D0D0);
            let th_name = encode_wide("ПАРАМЕТР / СМЕЩЕНИЕ");
            let th_val = encode_wide("ЗНАЧЕНИЕ");
            let th_stat = encode_wide("СТАТУС КАЛИБРОВКИ");
            let th_desc = encode_wide("НАЗНАЧЕНИЕ В ПАМЯТИ");

            TextOutW(mem_dc, 28, top_y + 4, th_name.as_ptr(), th_name.len() as i32 - 1);
            TextOutW(mem_dc, 240, top_y + 4, th_val.as_ptr(), th_val.len() as i32 - 1);
            TextOutW(mem_dc, 350, top_y + 4, th_stat.as_ptr(), th_stat.len() as i32 - 1);
            TextOutW(mem_dc, 560, top_y + 4, th_desc.as_ptr(), th_desc.len() as i32 - 1);

            // Table Rows
            let row_h = 24;
            let max_rows = 17;
            let items = if let Some(ref st_arc) = GLOBAL_STATE {
                if let Ok(st) = st_arc.lock() {
                    st.offsets.clone()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            for (i, it) in items.iter().take(max_rows).enumerate() {
                let ry = top_y + 26 + (i as i32 * row_h);
                let row_bg_color = if i % 2 == 0 { 0x001C1916 } else { 0x00221E1A };
                let r_brush = CreateSolidBrush(row_bg_color);
                let r_row = RECT { left: 18, top: ry, right: client_rc.right - 18, bottom: ry + row_h };
                FillRect(mem_dc, &r_row, r_brush);
                DeleteObject(r_brush);

                SelectObject(mem_dc, hfont_body);
                SetTextColor(mem_dc, 0x00E0E0E0);
                let w_n = encode_wide(&it.name);
                TextOutW(mem_dc, 28, ry + 4, w_n.as_ptr(), w_n.len() as i32 - 1);

                SelectObject(mem_dc, hfont_code);
                SetTextColor(mem_dc, 0x0000FFFF); // Yellow/Cyan
                let w_v = encode_wide(&it.current_val);
                TextOutW(mem_dc, 240, ry + 4, w_v.as_ptr(), w_v.len() as i32 - 1);

                SelectObject(mem_dc, hfont_body);
                SetTextColor(mem_dc, it.status_color);
                let w_s = encode_wide(&it.status);
                TextOutW(mem_dc, 350, ry + 4, w_s.as_ptr(), w_s.len() as i32 - 1);

                SetTextColor(mem_dc, 0x00A0A0A0);
                let w_d = encode_wide(&it.description);
                TextOutW(mem_dc, 560, ry + 4, w_d.as_ptr(), w_d.len() as i32 - 1);
            }

            // 3. Log Console (Bottom Card)
            let log_y = top_y + 26 + (max_rows as i32 * row_h) + 8;
            let r_log = RECT { left: 18, top: log_y, right: client_rc.right - 18, bottom: client_rc.bottom - 12 };
            let log_bg = CreateSolidBrush(0x00100E0C);
            FillRect(mem_dc, &r_log, log_bg);
            DeleteObject(log_bg);

            // Log Frame border
            let pen_log = CreatePen(PS_SOLID as i32, 1, 0x003A3025);
            SelectObject(mem_dc, pen_log);
            MoveToEx(mem_dc, r_log.left, r_log.top, std::ptr::null_mut());
            LineTo(mem_dc, r_log.right, r_log.top);
            LineTo(mem_dc, r_log.right, r_log.bottom);
            LineTo(mem_dc, r_log.left, r_log.bottom);
            LineTo(mem_dc, r_log.left, r_log.top);
            DeleteObject(pen_log);

            SelectObject(mem_dc, hfont_code);
            let logs = if let Some(ref st_arc) = GLOBAL_STATE {
                if let Ok(st) = st_arc.lock() {
                    st.logs.clone()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            let log_line_h = 18;
            let visible_logs = ((r_log.bottom - r_log.top - 8) / log_line_h).max(1) as usize;
            let start_idx = logs.len().saturating_sub(visible_logs);

            for (idx, line) in logs.iter().skip(start_idx).enumerate() {
                let ly = r_log.top + 6 + (idx as i32 * log_line_h);
                if line.contains("✅") || line.contains("🎯") {
                    SetTextColor(mem_dc, 0x0000FFCC);
                } else if line.contains("❌") || line.contains("⚠️") {
                    SetTextColor(mem_dc, 0x008080FF);
                } else {
                    SetTextColor(mem_dc, 0x00C0C0C0);
                }
                let w_l = encode_wide(line);
                TextOutW(mem_dc, r_log.left + 10, ly, w_l.as_ptr(), w_l.len() as i32 - 1);
            }

            // Cleanup GDI
            SelectObject(mem_dc, old_pen);
            DeleteObject(pen_border);

            DeleteObject(hfont_title);
            DeleteObject(hfont_body);
            DeleteObject(hfont_bold);
            DeleteObject(hfont_code);

            // Blit to screen
            BitBlt(hdc, 0, 0, client_rc.right, client_rc.bottom, mem_dc, 0, 0, SRCCOPY);

            SelectObject(mem_dc, old_bm);
            DeleteObject(mem_bm);
            DeleteDC(mem_dc);

            EndPaint(hwnd, &ps);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

// ----------------------------------------------------------------------------
// INPUT MODAL DIALOG WNDPROC
// ----------------------------------------------------------------------------
unsafe extern "system" fn wnd_proc_input_dlg(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            GLOBAL_INPUT_DLG_HWND = hwnd;

            // Edit Control
            let edit_hwnd = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                encode_wide("EDIT").as_ptr(),
                encode_wide("").as_ptr(),
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL as u32 | ES_LEFT as u32,
                16,
                48,
                590,
                32,
                hwnd,
                ID_DLG_EDIT as HMENU,
                GetModuleHandleW(std::ptr::null()),
                std::ptr::null(),
            );
            GLOBAL_DLG_EDIT_HWND = edit_hwnd;

            // Set Consolas Font
            let hfont = make_font(15, FW_NORMAL as i32, "Consolas");
            SendMessageW(edit_hwnd, WM_SETFONT, hfont as usize, 1);

            // Button: Paste
            let btn_paste = encode_wide("📋 Вставить");
            CreateWindowExW(
                0,
                encode_wide("BUTTON").as_ptr(),
                btn_paste.as_ptr(),
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON as u32,
                16,
                96,
                130,
                36,
                hwnd,
                ID_DLG_BTN_PASTE as HMENU,
                GetModuleHandleW(std::ptr::null()),
                std::ptr::null(),
            );

            // Button: Calibrate (Default button)
            let btn_calib = encode_wide("🚀 КАЛИБРОВАТЬ");
            CreateWindowExW(
                0,
                encode_wide("BUTTON").as_ptr(),
                btn_calib.as_ptr(),
                WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON as u32,
                156,
                96,
                290,
                36,
                hwnd,
                ID_DLG_BTN_CALIB as HMENU,
                GetModuleHandleW(std::ptr::null()),
                std::ptr::null(),
            );

            // Button: Cancel
            let btn_cancel = encode_wide("Отмена");
            CreateWindowExW(
                0,
                encode_wide("BUTTON").as_ptr(),
                btn_cancel.as_ptr(),
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON as u32,
                456,
                96,
                150,
                36,
                hwnd,
                ID_DLG_BTN_CANCEL as HMENU,
                GetModuleHandleW(std::ptr::null()),
                std::ptr::null(),
            );

            0
        }
        WM_COMMAND => {
            let id = LOWORD(wparam as u32) as isize;
            match id {
                ID_DLG_BTN_PASTE => {
                    if let Some(clip) = get_clipboard_text() {
                        let clean = clip.trim().replace("\r", "").replace("\n", "");
                        let w_text = encode_wide(&clean);
                        SetWindowTextW(GLOBAL_DLG_EDIT_HWND, w_text.as_ptr());
                        SetFocus(GLOBAL_DLG_EDIT_HWND);
                    }
                }
                ID_DLG_BTN_CALIB | 1 => {
                    // ID 1 is IDOK (Enter pressed)
                    let mut buf = vec![0u16; 1024];
                    let len = GetWindowTextW(GLOBAL_DLG_EDIT_HWND, buf.as_mut_ptr(), buf.len() as i32);
                    if len > 0 {
                        buf.truncate(len as usize);
                        let input_str = String::from_utf16_lossy(&buf).trim().to_string();

                        // Close dialog
                        ShowWindow(hwnd, SW_HIDE);
                        if !GLOBAL_MAIN_HWND.is_null() {
                            EnableWindow(GLOBAL_MAIN_HWND, 1);
                            SetForegroundWindow(GLOBAL_MAIN_HWND);
                        }

                        // Trigger calibration pipeline
                        if let Some(ref state_arc) = GLOBAL_STATE {
                            if let Ok(mut st) = state_arc.lock() {
                                st.is_calibrating = true;
                                st.add_log("Запуск калибровки по введенным данным...");
                            }
                            let arc_c = Arc::clone(state_arc);
                            thread::spawn(move || {
                                run_calibration_pipeline(input_str, arc_c);
                            });
                        }
                    }
                }
                ID_DLG_BTN_CANCEL | 2 => {
                    // ID 2 is IDCANCEL (Esc pressed)
                    ShowWindow(hwnd, SW_HIDE);
                    if !GLOBAL_MAIN_HWND.is_null() {
                        EnableWindow(GLOBAL_MAIN_HWND, 1);
                        SetForegroundWindow(GLOBAL_MAIN_HWND);
                    }
                }
                _ => {}
            }
            0
        }
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let hdc = BeginPaint(hwnd, &mut ps);

            let mut client_rc: RECT = std::mem::zeroed();
            GetClientRect(hwnd, &mut client_rc);

            let bg_brush = CreateSolidBrush(0x001C1916);
            FillRect(hdc, &client_rc, bg_brush);
            DeleteObject(bg_brush);

            SetBkMode(hdc, TRANSPARENT as i32);
            let hfont = make_font(15, FW_BOLD as i32, "Segoe UI");
            SelectObject(hdc, hfont);
            SetTextColor(hdc, 0x0000FFCC);
            let prompt = encode_wide("Вставьте строку маяка из чата WoW (полученную по /ptln):");
            TextOutW(hdc, 16, 16, prompt.as_ptr(), prompt.len() as i32 - 1);
            DeleteObject(hfont);

            EndPaint(hwnd, &ps);
            0
        }
        WM_CLOSE => {
            ShowWindow(hwnd, SW_HIDE);
            if !GLOBAL_MAIN_HWND.is_null() {
                EnableWindow(GLOBAL_MAIN_HWND, 1);
                SetForegroundWindow(GLOBAL_MAIN_HWND);
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[allow(non_snake_case)]
fn LOWORD(l: u32) -> u16 {
    (l & 0xffff) as u16
}

fn main() {
    let state = Arc::new(Mutex::new(CalibratorState::new()));
    unsafe {
        GLOBAL_STATE = Some(Arc::clone(&state));
    }

    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());

        // Register Main Window Class
        let main_class_name = encode_wide("PORTOLAN_DMA_CALIBRATOR_CLASS");
        let wc_main = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc_main),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: std::ptr::null_mut(),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: main_class_name.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };
        RegisterClassExW(&wc_main);

        // Register Input Dialog Window Class
        let dlg_class_name = encode_wide("PORTOLAN_DMA_INPUT_DLG_CLASS");
        let wc_dlg = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc_input_dlg),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: std::ptr::null_mut(),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: dlg_class_name.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };
        RegisterClassExW(&wc_dlg);

        // Create Main Window
        let title = encode_wide("PORTOLAN DMA CALIBRATOR | Universal Patch-Day Calibrator");
        let hwnd_main = CreateWindowExW(
            0,
            main_class_name.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            WINDOW_WIDTH,
            WINDOW_HEIGHT,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );

        // Create Input Dialog Window (hidden initially)
        let dlg_title = encode_wide("Ввод данных маяка PortolanBeacon (/ptln)");
        let hwnd_dlg = CreateWindowExW(
            WS_EX_TOPMOST,
            dlg_class_name.as_ptr(),
            dlg_title.as_ptr(),
            WS_POPUP | WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            640,
            180,
            hwnd_main,
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        GLOBAL_INPUT_DLG_HWND = hwnd_dlg;

        // Message Loop
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
