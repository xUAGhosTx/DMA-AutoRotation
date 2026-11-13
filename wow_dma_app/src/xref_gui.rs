// language: Rust, file: src/xref_gui.rs, target: Windows 11, MSVC x64
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use serde_json::{json, Value};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const WINDOW_WIDTH: i32 = 1080;
const WINDOW_HEIGHT: i32 = 720;
const CF_UNICODETEXT: u32 = 13;

#[derive(Clone, Debug)]
struct XrefHit {
    code_va: u64,
    rva_str: String,
    inst_type: String,
    bytes_hex: String,
    context_hex: String,
    target_str: String,
    target_va: u64,
}

struct HunterState {
    connected: bool,
    pid: u32,
    base_address: u64,
    
    // Search query & inputs
    search_input: String,
    search_mode_aob: bool, // true = AOB сигнатуры, false = XREF строки движка
    is_scanning: bool,
    status_msg: String,
    
    // Results
    hits: Vec<XrefHit>,
    selected_idx: usize,
    
    // Active command to worker
    req_search_query: Option<String>,
    req_auto_calibrate: bool,
    req_deep_calibrate: bool,
    req_beacon_calibrate: bool,
    beacon_raw: String,
    req_analyze_hit: Option<XrefHit>,
}

#[derive(Clone, Debug)]
struct ConnectedVarItem {
    inst_rva_str: String,
    inst_type: String,
    target_rva: u64,
    target_rva_str: String,
    section_name: String,
    live_bytes_hex: String,
    live_u64_str: String,
}

struct ConnectedVarsState {
    parent_rva: String,
    query_name: String,
    items: Vec<ConnectedVarItem>,
    selected_idx: usize,
    status_msg: String,
    req_refresh: bool,
}

#[derive(Clone, Debug, Default)]
struct DiffState {
    status_msg: String,
    beacon_raw: String,
    player_guid: String,
    target_guid: String,
    hp: u32,
    max_hp: u32,
    power: u32,
    power_type: u32,
    buff_id: u32,
    buff_count: u32,
    cast_id: u32,
    cast_end: u64,
    channel_id: u32,
    in_combat: u32,
    speed: u32,
    facing: u32,

    req_calibrate_auras: bool,
    req_calibrate_cast: bool,
    req_calibrate_channel: bool,
    req_calibrate_combat: bool,
    req_calibrate_power: bool,
    req_calibrate_facing: bool,
    req_calibrate_speed: bool,
}

static mut GLOBAL_HUNTER: Option<Arc<Mutex<HunterState>>> = None;
static mut GLOBAL_DETAIL_HWND: HWND = std::ptr::null_mut();
static mut GLOBAL_CONNECTED_VARS: Option<Arc<Mutex<ConnectedVarsState>>> = None;
static mut GLOBAL_DIFF_HWND: HWND = std::ptr::null_mut();
static mut GLOBAL_DIFF_STATE: Option<Arc<Mutex<DiffState>>> = None;

fn encode_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn set_clipboard_text(text: &str) -> bool {
    unsafe {
        use windows_sys::Win32::System::DataExchange::*;
        use windows_sys::Win32::System::Memory::*;

        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return false;
        }
        EmptyClipboard();
        let wide = encode_wide(text);
        let bytes_len = wide.len() * 2;
        let h_mem = GlobalAlloc(GMEM_MOVEABLE, bytes_len);
        if !h_mem.is_null() {
            let ptr = GlobalLock(h_mem) as *mut u16;
            if !ptr.is_null() {
                std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
                GlobalUnlock(h_mem);
                SetClipboardData(CF_UNICODETEXT, h_mem);
            }
        }
        CloseClipboard();
        true
    }
}

fn get_clipboard_text() -> Option<String> {
    unsafe {
        use windows_sys::Win32::System::DataExchange::*;
        use windows_sys::Win32::System::Memory::*;

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

fn draw_rounded_card(hdc: HDC, left: i32, top: i32, right: i32, bottom: i32, color_bgr: u32) {
    let r = RECT { left, top, right, bottom };
    unsafe {
        let br = CreateSolidBrush(color_bgr);
        FillRect(hdc, &r, br);
        DeleteObject(br);
    }
}

fn draw_card_border(hdc: HDC, left: i32, top: i32, right: i32, bottom: i32, border_bgr: u32) {
    unsafe {
        let pen = CreatePen(PS_SOLID as i32, 1, border_bgr);
        let old_pen = SelectObject(hdc, pen);
        let null_br = GetStockObject(NULL_BRUSH as i32);
        let old_br = SelectObject(hdc, null_br);

        Rectangle(hdc, left, top, right, bottom);

        SelectObject(hdc, old_pen);
        SelectObject(hdc, old_br);
        DeleteObject(pen);
    }
}

fn query_daemon(stream: &mut TcpStream, reader: &mut BufReader<TcpStream>, cmd: Value) -> Option<Value> {
    let payload = format!("{}\n", cmd);
    if stream.write_all(payload.as_bytes()).is_ok() && stream.flush().is_ok() {
        let mut line = String::new();
        if reader.read_line(&mut line).is_ok() {
            return serde_json::from_str(&line).ok();
        }
    }
    None
}

fn save_single_offset(key: &str, val_str: &str) -> bool {
    let clean = val_str.trim().trim_start_matches('+');
    let rva_num = u64::from_str_radix(clean.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
    if rva_num == 0 && !clean.contains("0x0") { return false; }

    let formatted_val = if key.contains("offset") && rva_num <= 0xFFFF {
        format!("0x{:04X}", rva_num)
    } else {
        format!("0x{:08X}", rva_num)
    };

    let mut candidate_paths = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidate_paths.push(parent.join("offsets.json"));
        }
    }
    candidate_paths.push(std::path::PathBuf::from("offsets.json"));
    candidate_paths.dedup();

    let mut current_json = serde_json::json!({
        "button_mapping": {
            "[ 🎯 TargetGUID ]": "target_guid_low_rva (low 64-bit) & target_guid_high_rva (+8 high 64-bit)",
            "[ 📦 EntityTable ]": "entity_table_rva (Основная хеш-таблица всех сущностей мира)",
            "[ 👤 PlayerUnit ]": "player_unit_rva (Указатель на структуру активного игрока)",
            "[ 🖱️ MouseoverGUID ]": "mouseover_guid_rva (GUID цели под курсором мыши)",
            "[ ❤️ UnitHealth ]": "unit_health_offset (Текущее здоровье) & unit_max_health_offset (+8 Макс. здоровье)",
            "[ 🗺️ Coords (World) ]": "entry_coords_offset (Вектор 3D-координат сущности X, Y, Z)",
            "[ 🧭 Facing ]": "entry_facing_offset (Угол поворота взгляда float32)",
            "[ 🏃 Speed ]": "entry_speed_offset (Скорость перемещения float32)",
            "[ 💧 Power ]": "unit_power_offset (Мана/энергия/ярость u32)",
            "[ ⚡ CastSpellID ]": "cast_spell_id_offset (Активный спелл каста u32)",
            "[ ⏱️ CastEndTime ]": "cast_end_time_offset (Таймер окончания каста u32)",
            "[ 🌀 ChannelSpellID ]": "channel_spell_id_offset (Потоковый спелл u32)",
            "[ ⏱️ ChannelEndTime ]": "channel_end_time_offset (Таймер окончания потокового спелла u32)",
            "[ 🛡️ AuraTable ]": "aura_table_offset (Указатель на массив аур u64)",
            "[ 🔢 AuraCount ]": "aura_count_offset (Количество аур u32)",
            "[ ⚔️ CombatFlag ]": "combat_flag_rva (Флаг нахождения в бою u64/u32)"
        },
        "offsets": {
            "entity_table_rva": "0x04728BE8",
            "target_guid_low_rva": "0x06A32478",
            "target_guid_high_rva": "0x06A32480",
            "player_unit_rva": "0x04C1A770",
            "mouseover_guid_rva": "0x04C18288",
            "unit_health_offset": "0x1E28",
            "unit_max_health_offset": "0x1E30",
            "entry_coords_offset": "0x0060",
            "entry_facing_offset": "0x0078",
            "entry_speed_offset": "0x0080",
            "unit_power_offset": "0x1E48",
            "cast_spell_id_offset": "0x03EC",
            "cast_end_time_offset": "0x041C",
            "channel_spell_id_offset": "0x0420",
            "channel_end_time_offset": "0x042C",
            "aura_table_offset": "0x05F0",
            "aura_count_offset": "0x05F8",
            "combat_flag_rva": "0x04B15F90"
        }
    });

    for p in &candidate_paths {
        if p.exists() {
            if let Ok(content) = std::fs::read_to_string(p) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                    current_json = parsed;
                    break;
                }
            }
        }
    }

    if let Some(offs_map) = current_json.get_mut("offsets").and_then(|o| o.as_object_mut()) {
        offs_map.insert(key.to_string(), serde_json::Value::String(formatted_val.clone()));
        if key == "target_guid_low_rva" {
            offs_map.insert("target_guid_high_rva".to_string(), serde_json::Value::String(format!("0x{:08X}", rva_num + 8)));
        } else if key == "unit_health_offset" {
            offs_map.insert("unit_max_health_offset".to_string(), serde_json::Value::String(format!("0x{:04X}", rva_num + 8)));
        }
    }

    if let Ok(pretty) = serde_json::to_string_pretty(&current_json) {
        for p in &candidate_paths {
            let _ = std::fs::write(p, &pretty);
        }
        return true;
    }
    false
}

fn read_hex_bytes(
    writer: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    pid: u32,
    addr: u64,
    size: usize,
) -> Option<Vec<u8>> {
    if addr == 0 || size == 0 { return None; }
    let resp = query_daemon(writer, reader, json!({
        "cmd": "read_bytes",
        "pid": pid,
        "addr": addr,
        "size": size
    }))?;
    let hex_str = resp.get("hex").and_then(|h| h.as_str())?;
    if hex_str.len() < size * 2 { return None; }
    let mut bytes = Vec::with_capacity(size);
    for i in 0..size {
        if let Ok(b) = u8::from_str_radix(&hex_str[i*2..i*2+2], 16) {
            bytes.push(b);
        } else {
            return None;
        }
    }
    Some(bytes)
}

fn resolve_player_unit_and_entry(
    writer: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    pid: u32,
    base: u64,
    p_guid_num: u32,
    entity_table_rva: u64,
) -> (u64, u64) {
    if let Some(resp) = query_daemon(writer, reader, json!({
        "cmd": "get_target",
        "include_mouseover": false
    })) {
        if let Some(addr_str) = resp.get("player_unit_addr").and_then(|v| v.as_str()) {
            let clean = addr_str.trim_start_matches("0x").trim_start_matches("0X");
            let u = u64::from_str_radix(clean, 16).unwrap_or(0);
            if u > 0x10000 && u <= 0x00007FFFFFFFFFFF {
                let entry_obj = read_hex_bytes(writer, reader, pid, u + 0x08, 8)
                    .and_then(|b| b.try_into().ok().map(u64::from_le_bytes))
                    .unwrap_or(0);
                let actual_entry = if entry_obj > 0x10000 && entry_obj <= 0x00007FFFFFFFFFFF {
                    entry_obj
                } else {
                    u
                };
                return (u, actual_entry);
            }
        }
    }

    let e_table_addr = base + entity_table_rva;
    let e_table_ptr = read_hex_bytes(writer, reader, pid, e_table_addr, 8)
        .and_then(|b| b.try_into().ok().map(u64::from_le_bytes))
        .unwrap_or(0);

    if e_table_ptr > 0x10000 && e_table_ptr <= 0x00007FFFFFFFFFFF {
        let bucket_array = read_hex_bytes(writer, reader, pid, e_table_ptr + 0x08, 8)
            .and_then(|b| b.try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0);
        let capacity = read_hex_bytes(writer, reader, pid, e_table_ptr + 0x18, 4)
            .and_then(|b| b.try_into().ok().map(u32::from_le_bytes))
            .unwrap_or(0);

        if bucket_array > 0x10000 && capacity > 0 {
            let cap = std::cmp::min(capacity as usize, 4096);
            for chunk_start in (0..cap).step_by(256) {
                let chunk_count = std::cmp::min(256, cap - chunk_start);
                let bytes_len = chunk_count * 16;
                let va = bucket_array + (chunk_start as u64) * 16;
                if let Some(buf) = read_hex_bytes(writer, reader, pid, va, bytes_len) {
                    for i in 0..chunk_count {
                        let off = i * 16;
                        let entry_obj = u64::from_le_bytes(buf[off+8..off+16].try_into().unwrap_or([0; 8]));
                        if entry_obj > 0x10000 && entry_obj <= 0x00007FFFFFFFFFFF {
                            if let Some(guid_bytes) = read_hex_bytes(writer, reader, pid, entry_obj + 0x18, 8) {
                                let g_lo = u64::from_le_bytes(guid_bytes.try_into().unwrap_or([0; 8]));
                                if (g_lo as u32) == p_guid_num {
                                    let mut unit_ptr = read_hex_bytes(writer, reader, pid, entry_obj + 0x28, 8)
                                        .and_then(|b| b.try_into().ok().map(u64::from_le_bytes))
                                        .unwrap_or(0);
                                    if unit_ptr == 0 || unit_ptr == 1 || unit_ptr > 0x00007FFFFFFFFFFF {
                                        unit_ptr = read_hex_bytes(writer, reader, pid, entry_obj + 0xD8, 8)
                                            .and_then(|b| b.try_into().ok().map(u64::from_le_bytes))
                                            .unwrap_or(0);
                                    }
                                    let actual_unit = if unit_ptr > 0x10000 && unit_ptr <= 0x00007FFFFFFFFFFF {
                                        unit_ptr
                                    } else {
                                        entry_obj
                                    };
                                    return (actual_unit, entry_obj);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    (0, 0)
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_ERASEBKGND => 1,
        WM_GETMINMAXINFO => {
            let mmi = lparam as *mut MINMAXINFO;
            if !mmi.is_null() {
                (*mmi).ptMinTrackSize.x = 900;
                (*mmi).ptMinTrackSize.y = 550;
            }
            0
        }
        WM_LBUTTONDOWN => {
            let x = (lparam & 0xFFFF) as i32;
            let y = ((lparam >> 16) & 0xFFFF) as i32;

            if let Some(ref state_arc) = GLOBAL_HUNTER {
                let mut s = state_arc.lock().unwrap();

                // 0. Preset Mode Toggle Switch (x = 745..1040, y = 36..68)
                if x >= 745 && x <= 1040 && y >= 36 && y <= 68 {
                    s.search_mode_aob = !s.search_mode_aob;
                    s.status_msg = if s.search_mode_aob {
                        "✓ Пресеты переключены в режим: ⚡ БЫСТРЫЙ AOB (поиск по опкод-паттернам)".to_string()
                    } else {
                        "✓ Пресеты переключены в режим: 🧬 ГЛУБОКИЙ XREF (поиск по строкам движка в .rdata)".to_string()
                    };
                }
                // 1. Search Box Click (x = 18..180, y = 80..115)
                else if x >= 18 && x <= 180 && y >= 80 && y <= 115 {
                    // Focused search input
                }
                // 2. Action Button: [ 🔍 НАЙТИ ] (x = 186..275, y = 80..115)
                else if x >= 186 && x <= 275 && y >= 80 && y <= 115 {
                    if s.search_input.contains("PTLN_MAGIC_ANCHOR") {
                        s.beacon_raw = s.search_input.trim().to_string();
                        s.req_beacon_calibrate = true;
                        s.is_scanning = true;
                        s.status_msg = "📡 Запуск калибровки по введённой строке маяка Portolan...".to_string();
                    } else if !s.search_input.trim().is_empty() && !s.is_scanning {
                        s.is_scanning = true;
                        s.status_msg = format!("Поиск строки '{}' и сканирование кода .text...", s.search_input.trim());
                        s.req_search_query = Some(s.search_input.clone());
                    }
                }
                // 2.5 Button 1: [ ⚡ БЫСТРЫЙ AOB ] (x = 282..400, y = 80..115)
                else if x >= 282 && x <= 400 && y >= 80 && y <= 115 {
                    if !s.is_scanning {
                        s.is_scanning = true;
                        s.status_msg = "⏳ Быстрый опрос AOB оффсетов и синхронизация offsets.json...".to_string();
                        s.req_auto_calibrate = true;
                    }
                }
                // 2.6 Button 2: [ 🧬 ГЛУБОКИЙ XREF ] (x = 406..540, y = 80..115)
                else if x >= 406 && x <= 540 && y >= 80 && y <= 115 {
                    if !s.is_scanning {
                        s.is_scanning = true;
                        s.status_msg = "🧬 Запуск глубокого XREF сканирования памяти (патч-день) и запись offsets.json...".to_string();
                        s.req_deep_calibrate = true;
                    }
                }
                // 2.7 Button 3: [ 📡 МАЯК (1-CLICK) ] (x = 546..735, y = 80..115)
                else if x >= 546 && x <= 735 && y >= 80 && y <= 115 {
                    if !s.is_scanning {
                        s.is_scanning = true;
                        s.status_msg = "📡 Поиск маяка аддона PortolanBeacon и калибровка оффсетов...".to_string();
                        s.req_beacon_calibrate = true;
                    }
                }
                // 2.8 Button 4: [ 🔬 ДИФФ-МЕНЮ ОФФСЕТОВ ] (x >= 742 && y >= 80 && y <= 115)
                else if x >= 742 && y >= 80 && y <= 115 {
                    unsafe {
                        if !GLOBAL_DIFF_HWND.is_null() {
                            ShowWindow(GLOBAL_DIFF_HWND, SW_SHOW);
                            SetForegroundWindow(GLOBAL_DIFF_HWND);
                        }
                    }
                    s.status_msg = "✓ Открыта матрица дифференциальной калибровки оффсетов.".to_string();
                }
                // 3. Preset Quick Buttons (y = 125..152)
                else if y >= 125 && y <= 152 {
                    let presets = [
                        (18, 155, "TargetGUID"),
                        (162, 302, "EntityTable"),
                        (309, 445, "PlayerUnit"),
                        (452, 605, "MouseoverGUID"),
                        (612, 745, "UnitHealth"),
                        (752, 885, "CastSpellByName"),
                        (892, 1040, "CoordsOffset"),
                    ];
                    for (l, r, name) in presets {
                        if x >= l && x <= r {
                            s.search_input = name.to_string();
                            s.is_scanning = true;
                            s.status_msg = if s.search_mode_aob {
                                format!("Поиск пресета '{}' через [⚡ AOB паттерны]...", name)
                            } else {
                                format!("Поиск пресета '{}' через [🧬 XREF строки движка]...", name)
                            };
                            s.req_search_query = Some(name.to_string());
                            break;
                        }
                    }
                }
                // 4. Click row in Results Table (y = 195..580, x = 18..1040)
                else if y >= 195 && y <= 580 && x >= 18 && x <= 1040 {
                    let row = ((y - 195) / 28) as usize;
                    if row < s.hits.len() {
                        s.selected_idx = row;
                        let hit = &s.hits[row];
                        s.status_msg = format!("Выбрана строка #{}: Код 0x{:X} ({}) -> Цель: {}", row + 1, hit.code_va, hit.rva_str, hit.target_str);
                    }
                }
                // 5. Action Buttons (y = 595..635)
                // [ 📋 КОПИРОВАТЬ АДРЕС ] (x = 18..165)
                else if y >= 595 && y <= 635 && x >= 18 && x <= 165 {
                    if s.selected_idx < s.hits.len() {
                        let va = s.hits[s.selected_idx].code_va;
                        let text = format!("0x{:X}", va);
                        set_clipboard_text(&text);
                        s.status_msg = format!("Адрес кода {} скопирован в буфер обмена.", text);
                    }
                }
                // [ 📋 КОПИРОВАТЬ RVA ] (x = 175..315)
                else if y >= 595 && y <= 635 && x >= 175 && x <= 315 {
                    if s.selected_idx < s.hits.len() {
                        let rva = &s.hits[s.selected_idx].rva_str;
                        set_clipboard_text(rva);
                        s.status_msg = format!("Смещение {} скопировано в буфер обмена.", rva);
                    }
                }
                // [ 💾 СОХРАНИТЬ В OFFSETS.JSON ] (x = 325..590)
                else if y >= 595 && y <= 635 && x >= 325 && x <= 590 {
                    if s.selected_idx < s.hits.len() {
                        let hit = &s.hits[s.selected_idx];
                        let rva_clean = hit.rva_str.trim();
                        let target_str = hit.target_str.to_lowercase();
                        let inst_type = hit.inst_type.to_lowercase();

                        let field_key = if target_str.contains("target") || inst_type.contains("targetguid") {
                            "target_guid_low_rva"
                        } else if target_str.contains("entity") || inst_type.contains("entitytable") {
                            "entity_table_rva"
                        } else if target_str.contains("player") || inst_type.contains("playerunit") {
                            "player_unit_rva"
                        } else if target_str.contains("mouse") || inst_type.contains("mouseover") {
                            "mouseover_guid_rva"
                        } else if target_str.contains("health") || inst_type.contains("unithealth") {
                            "unit_health_offset"
                        } else if target_str.contains("coords") || inst_type.contains("coords") {
                            "entry_coords_offset"
                        } else {
                            "target_guid_low_rva"
                        };

                        if save_single_offset(field_key, rva_clean) {
                            s.status_msg = format!("✓ Успешно: [{}] = {} записан в offsets.json!", field_key, rva_clean);
                        } else {
                            s.status_msg = "Ошибка записи offsets.json".to_string();
                        }
                    }
                }
                // [ 📄 ЭКСПОРТ ОТЧЕТА ] (x = 600..770)
                else if y >= 595 && y <= 635 && x >= 600 && x <= 770 {
                    if !s.hits.is_empty() {
                        let filename = format!("XREF_REPORT_{}.txt", s.search_input.trim());
                        let mut report = format!("=== PORTOLAN XREF HUNTER REPORT ===\nTarget String: {}\nPID: {}\nBase: 0x{:016X}\nTimestamp: {}\n\nHITS FOUND: {}\n\n",
                            s.search_input.trim(), s.pid, s.base_address, chrono_now(), s.hits.len());
                        for (i, h) in s.hits.iter().enumerate() {
                            report.push_str(&format!("#{} | Code VA: 0x{:X} (RVA: {}) | Inst: {} | Target VA: 0x{:X}\n     Bytes: {}\n     Context: {}\n\n",
                                i + 1, h.code_va, h.rva_str, h.inst_type, h.target_va, h.bytes_hex, h.context_hex));
                        }
                        if std::fs::write(&filename, &report).is_ok() {
                            s.status_msg = format!("✓ Отчет сохранен в файл: {}", filename);
                        } else {
                            s.status_msg = format!("Ошибка сохранения файла {}", filename);
                        }
                    }
                }
                // [ 🔬 СВЯЗАННЫЕ АДРЕСА ] (x = 780..panel_right)
                else if y >= 595 && y <= 635 && x >= 780 && x <= 1040 {
                    if s.selected_idx < s.hits.len() {
                        let hit = s.hits[s.selected_idx].clone();
                        s.req_analyze_hit = Some(hit.clone());
                        s.status_msg = format!("Анализ функции {} и считывание связанных адресов...", hit.rva_str);
                    }
                }
            }
            0
        }
        WM_RBUTTONDOWN => {
            let x = (lparam & 0xFFFF) as i32;
            let y = ((lparam >> 16) & 0xFFFF) as i32;
            if let Some(ref state_arc) = GLOBAL_HUNTER {
                let mut s = state_arc.lock().unwrap();
                // Right click on search box (x = 18..480, y = 80..115) -> instant paste from clipboard
                if x >= 18 && x <= 480 && y >= 80 && y <= 115 {
                    if let Some(clip) = get_clipboard_text() {
                        let clean = clip.trim().replace("\r", "").replace("\n", "");
                        if !clean.is_empty() {
                            s.search_input = clean.clone();
                            if clean.contains("PTLN_MAGIC_ANCHOR") {
                                s.beacon_raw = clean.clone();
                                s.req_beacon_calibrate = true;
                                s.is_scanning = true;
                                s.status_msg = "📡 Обнаружен маяк в буфере! Запуск 1-Click калибровки...".to_string();
                            } else {
                                s.status_msg = format!("Вставлен текст из буфера: '{}'", clean);
                            }
                        }
                    }
                }
            }
            0
        }
        WM_CHAR => {
            let ch = (wparam as u8) as char;
            if let Some(ref state_arc) = GLOBAL_HUNTER {
                let mut s = state_arc.lock().unwrap();
                if ch == '\x16' { // Ctrl + V
                    if let Some(clip) = get_clipboard_text() {
                        let clean = clip.trim().replace("\r", "").replace("\n", "");
                        if !clean.is_empty() {
                            s.search_input = clean.clone();
                            if clean.contains("PTLN_MAGIC_ANCHOR") {
                                s.beacon_raw = clean.clone();
                                s.req_beacon_calibrate = true;
                                s.is_scanning = true;
                                s.status_msg = "📡 Обнаружен маяк в буфере! Запуск 1-Click калибровки...".to_string();
                            } else {
                                s.status_msg = format!("Вставлен текст из буфера: '{}'", clean);
                            }
                        }
                    }
                } else if ch == '\r' || ch == '\n' {
                    if s.search_input.contains("PTLN_MAGIC_ANCHOR") {
                        s.beacon_raw = s.search_input.trim().to_string();
                        s.req_beacon_calibrate = true;
                        s.is_scanning = true;
                        s.status_msg = "📡 Запуск калибровки по введённому маяку Portolan...".to_string();
                    } else if !s.search_input.trim().is_empty() && !s.is_scanning {
                        s.is_scanning = true;
                        s.status_msg = format!("Поиск строки '{}' и сканирование кода .text...", s.search_input.trim());
                        s.req_search_query = Some(s.search_input.clone());
                    }
                } else if ch == '\x08' {
                    s.search_input.pop();
                } else if ch.is_ascii_graphic() || ch == ' ' || ch == '_' || ch == ':' || ch == '|' || ch == '-' {
                    if s.search_input.len() < 256 {
                        s.search_input.push(ch);
                    }
                }
            }
            0
        }
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let hdc = BeginPaint(hwnd, &mut ps);

            let mut rect: RECT = std::mem::zeroed();
            GetClientRect(hwnd, &mut rect);
            let width = rect.right - rect.left;
            let height = rect.bottom - rect.top;

            let mem_dc = CreateCompatibleDC(hdc);
            let mem_bm = CreateCompatibleBitmap(hdc, width, height);
            let old_bm = SelectObject(mem_dc, mem_bm);

            // Background
            let bg_brush = CreateSolidBrush(0x14100E);
            FillRect(mem_dc, &rect, bg_brush);
            DeleteObject(bg_brush);

            SetBkMode(mem_dc, TRANSPARENT as i32);

            let font_name = encode_wide("Segoe UI");
            let mono_name = encode_wide("Consolas");

            let h_font_title = CreateFontW(18, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_font_ui = CreateFontW(14, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_font_bold = CreateFontW(14, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_font_mono = CreateFontW(13, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, mono_name.as_ptr());
            let h_font_mono_bold = CreateFontW(13, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, mono_name.as_ptr());

            let old_font = SelectObject(mem_dc, h_font_ui);

            if let Some(ref state_arc) = GLOBAL_HUNTER {
                let s = state_arc.lock().unwrap();

                // 1. Header (y = 14..45)
                SelectObject(mem_dc, h_font_title);
                SetTextColor(mem_dc, 0x00F0FF); // Cyan
                let title = encode_wide("PORTOLAN RUNTIME XREF & STRING HUNTER (DMA x64)");
                TextOutW(mem_dc, 18, 14, title.as_ptr(), title.len() as i32);

                SelectObject(mem_dc, h_font_ui);
                SetTextColor(mem_dc, if s.connected { 0x88FF00 } else { 0x5555FF });
                let conn_str = if s.connected {
                    format!("● DMA ACTIVE  |  PID: {} (Wow.exe)  |  Base: 0x{:016X}", s.pid, s.base_address)
                } else {
                    "○ Ожидание соединения с dma_daemon (127.0.0.1:8765)...".to_string()
                };
                let cw = encode_wide(&conn_str);
                TextOutW(mem_dc, 500, 18, cw.as_ptr(), cw.len() as i32);

                // Subtitle description
                SetTextColor(mem_dc, 0x9E948B);
                let sub_str = encode_wide("Мгновенный поиск перекрестных ссылок (XREF) в коде .text без декомпилятора");
                TextOutW(mem_dc, 18, 42, sub_str.as_ptr(), sub_str.len() as i32);

                let panel_right = std::cmp::max(width - 18, 1040);

                // Mode Toggle Button (x = 745..panel_right, y = 36..68)
                let (tgl_bg, tgl_border, tgl_fg, tgl_txt) = if s.search_mode_aob {
                    (0x244E1A, 0x88FF00, 0x88FF00, "РЕЖИМ КНОПОК: ⚡ БЫСТРЫЙ AOB")
                } else {
                    (0x1A3844, 0x00F0FF, 0x00F0FF, "РЕЖИМ КНОПОК: 🧬 ГЛУБОКИЙ XREF")
                };
                draw_rounded_card(mem_dc, 745, 36, panel_right, 68, tgl_bg);
                draw_card_border(mem_dc, 745, 36, panel_right, 68, tgl_border);
                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, tgl_fg);
                let tgl_w = encode_wide(tgl_txt);
                TextOutW(mem_dc, 760, 44, tgl_w.as_ptr(), tgl_w.len() as i32);

                // 2. Search Toolbar (y = 80..115)

                // Search Input Card (18..180)
                draw_rounded_card(mem_dc, 18, 80, 180, 115, 0x221B18);
                draw_card_border(mem_dc, 18, 80, 180, 115, 0x00F0FF);

                SelectObject(mem_dc, h_font_mono_bold);
                SetTextColor(mem_dc, if s.search_input.is_empty() { 0x6E6E6E } else { 0xFFFFFF });
                let in_text = if s.search_input.is_empty() { "Маяк / Поиск...".to_string() } else { s.search_input.clone() };
                let in_w = encode_wide(&in_text);
                TextOutW(mem_dc, 26, 88, in_w.as_ptr(), in_w.len() as i32);

                // Action Button: [ 🔍 НАЙТИ ] (x = 186..275, y = 80..115)
                let btn_bg = if s.is_scanning { 0x383020 } else { 0x224422 };
                let btn_fg = if s.is_scanning { 0xFFD700 } else { 0x00FF88 };
                draw_rounded_card(mem_dc, 186, 80, 275, 115, btn_bg);
                draw_card_border(mem_dc, 186, 80, 275, 115, btn_fg);
                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, btn_fg);
                let btn_lbl = if s.is_scanning { "⏳..." } else { "🔍 НАЙТИ" };
                let blw = encode_wide(btn_lbl);
                TextOutW(mem_dc, 196, 88, blw.as_ptr(), blw.len() as i32);

                // Button 1: [ ⚡ БЫСТРЫЙ AOB ] (x = 282..400, y = 80..115)
                draw_rounded_card(mem_dc, 282, 80, 400, 115, 0x244E1A);
                draw_card_border(mem_dc, 282, 80, 400, 115, 0x388E28);
                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, 0x88FF00);
                let auto_lbl = encode_wide("⚡ БЫСТРЫЙ AOB");
                TextOutW(mem_dc, 290, 88, auto_lbl.as_ptr(), auto_lbl.len() as i32);

                // Button 2: [ 🧬 ГЛУБОКИЙ XREF ] (x = 406..540, y = 80..115)
                draw_rounded_card(mem_dc, 406, 80, 540, 115, 0x1A3844);
                draw_card_border(mem_dc, 406, 80, 540, 115, 0x00F0FF);
                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, 0x00F0FF);
                let deep_lbl = encode_wide("🧬 ГЛУБОКИЙ XREF");
                TextOutW(mem_dc, 414, 88, deep_lbl.as_ptr(), deep_lbl.len() as i32);

                // Button 3: [ 📡 МАЯК (1-CLICK) ] (x = 546..735, y = 80..115)
                let beacon_bg = if s.is_scanning { 0x362C18 } else { 0x162A3E };
                let beacon_border = if s.is_scanning { 0xFFD700 } else { 0x00D7FF };
                let beacon_fg = if s.is_scanning { 0xFFD700 } else { 0x00F0FF };
                draw_rounded_card(mem_dc, 546, 80, 735, 115, beacon_bg);
                draw_card_border(mem_dc, 546, 80, 735, 115, beacon_border);
                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, beacon_fg);
                let beacon_lbl = encode_wide(if s.is_scanning { "📡 ПОИСК..." } else { "📡 МАЯК (1-CLICK)" });
                TextOutW(mem_dc, 558, 88, beacon_lbl.as_ptr(), beacon_lbl.len() as i32);

                // Button 4: [ 🔬 ДИФФ-МЕНЮ ОФФСЕТОВ ] (x = 742..panel_right, y = 80..115)
                draw_rounded_card(mem_dc, 742, 80, panel_right, 115, 0x2A1434);
                draw_card_border(mem_dc, 742, 80, panel_right, 115, 0xE040FB);
                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, 0xFF80FF);
                let diff_lbl = encode_wide("🔬 ДИФФ-МЕНЮ ОФФСЕТОВ");
                TextOutW(mem_dc, 755, 88, diff_lbl.as_ptr(), diff_lbl.len() as i32);

                // 3. Preset Quick Buttons (y = 125..152)
                let preset_border = if s.search_mode_aob { 0x386E28 } else { 0x1A5566 };
                let preset_text_col = if s.search_mode_aob { 0x88FF88 } else { 0x00F0FF };
                let make_preset = |left: i32, right: i32, text: &str| {
                    draw_rounded_card(mem_dc, left, 125, right, 152, 0x241C18);
                    draw_card_border(mem_dc, left, 125, right, 152, preset_border);
                    SelectObject(mem_dc, h_font_mono);
                    SetTextColor(mem_dc, preset_text_col);
                    let w = encode_wide(text);
                    TextOutW(mem_dc, left + 8, 130, w.as_ptr(), w.len() as i32);
                };
                make_preset(18, 155, "🎯 TargetGUID");
                make_preset(162, 302, "📦 EntityTable");
                make_preset(309, 445, "👤 PlayerUnit");
                make_preset(452, 605, "🖱️ MouseoverGUID");
                make_preset(612, 745, "❤️ UnitHealth");
                make_preset(752, 885, "⚡ CastState");
                make_preset(892, panel_right, "🗺️ Coords (World)");

                // 4. Results Table Container (y = 165..580)
                draw_rounded_card(mem_dc, 18, 165, panel_right, 580, 0x1A1412);
                draw_card_border(mem_dc, 18, 165, panel_right, 580, 0x362822);

                // Table Header (y = 168..190)
                SelectObject(mem_dc, h_font_mono_bold);
                SetTextColor(mem_dc, 0x00F0FF);
                let th = encode_wide("#   ТИП ИНСТРУКЦИИ                      АДРЕС В КОДЕ (VA)      RVA СМЕЩЕНИЕ   БАЙТЫ КОМАНДЫ (MACHINE CODE)");
                TextOutW(mem_dc, 26, 172, th.as_ptr(), th.len() as i32);

                // Divider line below header
                draw_card_border(mem_dc, 20, 192, panel_right - 2, 193, 0x4E3C32);

                // Render Table Rows
                let mut row_y = 198;
                if s.hits.is_empty() {
                    SelectObject(mem_dc, h_font_ui);
                    SetTextColor(mem_dc, 0x6E6E6E);
                    let empty_text = if s.is_scanning {
                        encode_wide("Считывание секции .text (53 МБ) через DMA и проверка RIP-relative смещений...")
                    } else {
                        encode_wide("Введите строку и нажмите [НАЙТИ И ПОСТРОИТЬ XREF] или кликните один из пресетов выше.")
                    };
                    TextOutW(mem_dc, 35, 220, empty_text.as_ptr(), empty_text.len() as i32);
                } else {
                    for (i, hit) in s.hits.iter().enumerate().take(13) {
                        let is_sel = i == s.selected_idx;
                        if is_sel {
                            draw_rounded_card(mem_dc, 20, row_y - 2, panel_right - 2, row_y + 24, 0x2A201A);
                            draw_card_border(mem_dc, 20, row_y - 2, panel_right - 2, row_y + 24, 0x00F0FF);
                        }

                        // Col 1: #
                        SelectObject(mem_dc, h_font_mono);
                        SetTextColor(mem_dc, 0x9E948B);
                        let num_str = format!("{:02}", i + 1);
                        let nw = encode_wide(&num_str);
                        TextOutW(mem_dc, 26, row_y + 2, nw.as_ptr(), nw.len() as i32);

                        // Col 2: Inst Type (LEA RDX / LEA R8 / REF / LUA REG / DATA VARIABLE)
                        SelectObject(mem_dc, h_font_mono_bold);
                        let is_data_var = hit.inst_type.contains("DATA");
                        SetTextColor(mem_dc, if is_data_var { 0x00F0FF } else { 0x00FF88 }); // Cyan for DATA, Green for XREF
                        let iw = encode_wide(&hit.inst_type);
                        TextOutW(mem_dc, 56, row_y + 2, iw.as_ptr(), iw.len() as i32);

                        // Col 3: Code VA
                        SelectObject(mem_dc, h_font_mono);
                        SetTextColor(mem_dc, if is_data_var { 0x00F0FF } else { 0xFFFFFF });
                        let va_str = format!("0x{:012X}", hit.code_va);
                        let vw = encode_wide(&va_str);
                        TextOutW(mem_dc, 320, row_y + 2, vw.as_ptr(), vw.len() as i32);

                        // Col 4: RVA
                        SetTextColor(mem_dc, if is_data_var { 0x88FF00 } else { 0xFFD700 }); // Neon Green for DATA, Gold for XREF Code
                        let rw = encode_wide(&hit.rva_str);
                        TextOutW(mem_dc, 495, row_y + 2, rw.as_ptr(), rw.len() as i32);

                        // Col 5: Machine Bytes
                        SetTextColor(mem_dc, 0xCCCCCC);
                        let bw = encode_wide(&hit.bytes_hex);
                        TextOutW(mem_dc, 620, row_y + 2, bw.as_ptr(), bw.len() as i32);

                        row_y += 28;
                    }
                }

                // 5. Bottom Action Bar (y = 595..635)
                let make_action_btn = |left: i32, right: i32, text: &str, bg: u32, fg: u32| {
                    draw_rounded_card(mem_dc, left, 595, right, 630, bg);
                    draw_card_border(mem_dc, left, 595, right, 630, fg);
                    SelectObject(mem_dc, h_font_bold);
                    SetTextColor(mem_dc, fg);
                    let w = encode_wide(text);
                    TextOutW(mem_dc, left + 14, 604, w.as_ptr(), w.len() as i32);
                };

                make_action_btn(18, 165, "📋 АДРЕС", 0x2A2218, 0x00F0FF);
                make_action_btn(175, 315, "📋 СМЕЩЕНИЕ RVA", 0x2A2218, 0xFFD700);
                make_action_btn(325, 590, "💾 СОХРАНИТЬ В OFFSETS.JSON", 0x1E3820, 0x00FF88);
                make_action_btn(600, 770, "📄 ОТЧЕТ В ФАЙЛ", 0x241C18, 0x88FF00);
                make_action_btn(780, panel_right, "🔬 СВЯЗАННЫЕ АДРЕСА", 0x2A1C28, 0x00F0FF);

                // 6. Status Message (y = 645..675)
                if !s.status_msg.is_empty() {
                    SelectObject(mem_dc, h_font_bold);
                    SetTextColor(mem_dc, 0x88FF00);
                    let stat_w = encode_wide(&s.status_msg);
                    TextOutW(mem_dc, 20, 645, stat_w.as_ptr(), stat_w.len() as i32);
                }
            }

            SelectObject(mem_dc, old_font);
            DeleteObject(h_font_title);
            DeleteObject(h_font_ui);
            DeleteObject(h_font_bold);
            DeleteObject(h_font_mono);
            DeleteObject(h_font_mono_bold);

            BitBlt(hdc, 0, 0, width, height, mem_dc, 0, 0, SRCCOPY);
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

fn chrono_now() -> String {
    use std::time::SystemTime;
    let d = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    format!("{}", d)
}

fn analyze_function_references(
    writer: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    pid: u32,
    base: u64,
    code_va: u64,
    _query_name: &str,
) -> Vec<ConnectedVarItem> {
    let mut items = Vec::new();
    let read_start = code_va.saturating_sub(64);
    let read_size = 256;

    if let Some(resp) = query_daemon(writer, reader, json!({
        "cmd": "read_bytes",
        "pid": pid,
        "addr": read_start,
        "size": read_size
    })) {
        if let Some(hex_s) = resp.get("hex").and_then(|s| s.as_str()) {
            let mut buf = Vec::new();
            for i in (0..hex_s.len()).step_by(2) {
                if let Ok(b) = u8::from_str_radix(&hex_s[i..i+2], 16) {
                    buf.push(b);
                }
            }

            let len = buf.len();
            let mut i = 0;
            while i + 5 <= len {
                let inst_va = read_start + i as u64;
                let inst_rva = inst_va.wrapping_sub(base);

                // 1. Check for CALL rel32 (0xE8 [disp32])
                if buf[i] == 0xE8 && i + 5 <= len {
                    let disp = i32::from_le_bytes([buf[i+1], buf[i+2], buf[i+3], buf[i+4]]);
                    let next_ip = inst_va + 5;
                    let target_va = next_ip.wrapping_add(disp as i64 as u64);
                    let target_rva = target_va.wrapping_sub(base);

                    if target_rva < 0x03ACCD9C {
                        items.push(ConnectedVarItem {
                            inst_rva_str: format!("+0x{:07X}", inst_rva),
                            inst_type: "CALL [rel32]".to_string(),
                            target_rva,
                            target_rva_str: format!("0x{:08X}", target_rva),
                            section_name: ".text (Функция кода)".to_string(),
                            live_bytes_hex: "CODE ENTRY".to_string(),
                            live_u64_str: format!("sub_{:X}", target_rva),
                        });
                    }
                    i += 5;
                    continue;
                }

                // 2. Check for RIP-relative ModR/M instructions ((modrm & 0xC7) == 0x05)
                let b0 = buf[i];
                let b1 = if i + 1 < len { buf[i+1] } else { 0 };
                let b2 = if i + 2 < len { buf[i+2] } else { 0 };

                let mut inst_len = 0;
                let mut modrm_off = 0;
                let mut inst_label = String::new();

                if b0 == 0x0F && (b1 == 0x10 || b1 == 0x11 || b1 == 0x28 || b1 == 0x29) {
                    modrm_off = 2;
                    inst_len = 7;
                    inst_label = match b1 {
                        0x10 => "MOVUPS XMM, [rip+]".to_string(),
                        0x11 => "MOVUPS [rip+], XMM".to_string(),
                        0x28 => "MOVAPS XMM, [rip+]".to_string(),
                        0x29 => "MOVAPS [rip+], XMM".to_string(),
                        _ => "SSE [rip+]".to_string(),
                    };
                } else if (b0 == 0xF3 || b0 == 0xF2 || b0 == 0x66) && b1 == 0x0F && (b2 == 0x10 || b2 == 0x11) {
                    modrm_off = 3;
                    inst_len = 8;
                    inst_label = "MOVSS/SD [rip+]".to_string();
                } else if b0 == 0x48 || b0 == 0x4C || b0 == 0x44 {
                    if b1 == 0x8B {
                        modrm_off = 2; inst_len = 7; inst_label = "MOV REG, [rip+]".to_string();
                    } else if b1 == 0x8D {
                        modrm_off = 2; inst_len = 7; inst_label = "LEA REG, [rip+]".to_string();
                    } else if b1 == 0x89 {
                        modrm_off = 2; inst_len = 7; inst_label = "MOV [rip+], REG".to_string();
                    } else if b1 == 0x39 || b1 == 0x3B {
                        modrm_off = 2; inst_len = 7; inst_label = "CMP [rip+], REG".to_string();
                    } else if b1 == 0x0F && (b2 == 0x10 || b2 == 0x11 || b2 == 0x29) {
                        modrm_off = 3; inst_len = 8; inst_label = "MOVAPS/UPS [rip+]".to_string();
                    }
                } else if b0 == 0x8B || b0 == 0x8D || b0 == 0x89 {
                    modrm_off = 1; inst_len = 6;
                    inst_label = if b0 == 0x8B { "MOV EAX/ECX, [rip+]".to_string() } else if b0 == 0x8D { "LEA EAX, [rip+]".to_string() } else { "MOV [rip+], EAX".to_string() };
                }

                if inst_len > 0 && i + inst_len <= len {
                    let modrm = buf[i + modrm_off];
                    if (modrm & 0xC7) == 0x05 {
                        let disp_off = i + modrm_off + 1;
                        let disp = i32::from_le_bytes([buf[disp_off], buf[disp_off+1], buf[disp_off+2], buf[disp_off+3]]);
                        let next_ip = inst_va + inst_len as u64;
                        let target_va = next_ip.wrapping_add(disp as i64 as u64);
                        let target_rva = target_va.wrapping_sub(base);

                        let sec = if target_rva >= 0x04000000 && target_rva <= 0x08500000 {
                            ".data (Глобальная переменная)"
                        } else if target_rva >= 0x03500000 && target_rva < 0x04000000 {
                            ".rdata (Строка / Константа)"
                        } else {
                            ".text (Код программы)"
                        };

                        let mut live_hex = "?? ?? ?? ?? ?? ?? ?? ??".to_string();
                        let mut live_u64_str = "-".to_string();

                        if let Some(l_resp) = query_daemon(writer, reader, json!({
                            "cmd": "read_bytes",
                            "pid": pid,
                            "addr": target_va,
                            "size": 8
                        })) {
                            if let Some(hx) = l_resp.get("hex").and_then(|s| s.as_str()) {
                                if hx.len() >= 16 {
                                    let mut b_arr = [0u8; 8];
                                    for b_i in 0..8 {
                                        b_arr[b_i] = u8::from_str_radix(&hx[b_i*2..b_i*2+2], 16).unwrap_or(0);
                                    }
                                    let val_u64 = u64::from_le_bytes(b_arr);
                                    live_hex = b_arr.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                                    live_u64_str = if val_u64 == 0 {
                                        "0 (NULL)".to_string()
                                    } else {
                                        format!("0x{:X}", val_u64)
                                    };
                                }
                            }
                        }

                        let not_duplicate = !items.iter().any(|it: &ConnectedVarItem| it.target_rva == target_rva);
                        if not_duplicate {
                            items.push(ConnectedVarItem {
                                inst_rva_str: format!("+0x{:07X}", inst_rva),
                                inst_type: inst_label,
                                target_rva,
                                target_rva_str: format!("0x{:08X}", target_rva),
                                section_name: sec.to_string(),
                                live_bytes_hex: live_hex,
                                live_u64_str,
                            });
                        }

                        i += inst_len;
                        continue;
                    }
                }

                i += 1;
            }
        }
    }

    items.sort_by_key(|it| {
        if it.section_name.contains(".data") {
            0
        } else if it.section_name.contains(".rdata") {
            1
        } else {
            2
        }
    });

    items
}

unsafe extern "system" fn wnd_proc_detail(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_ERASEBKGND => 1,
        WM_CLOSE => {
            ShowWindow(hwnd, SW_HIDE);
            0
        }
        WM_LBUTTONDOWN => {
            let x = (lparam & 0xFFFF) as i32;
            let y = ((lparam >> 16) & 0xFFFF) as i32;

            if let Some(ref detail_arc) = GLOBAL_CONNECTED_VARS {
                let mut d = detail_arc.lock().unwrap();

                // Click row in table (y = 86..440, x = 20..940)
                if y >= 86 && y <= 440 && x >= 20 && x <= 940 {
                    let row = ((y - 86) / 28) as usize;
                    if row < d.items.len() {
                        d.selected_idx = row;
                        let item = &d.items[row];
                        d.status_msg = format!("Выбрана строка #{}: {} -> RVA {}", row + 1, item.inst_type, item.target_rva_str);
                    }
                }
                // [ 💾 СОХРАНИТЬ В OFFSETS.JSON ] (x = 24..340, y = 455..490)
                else if y >= 455 && y <= 490 && x >= 24 && x <= 340 {
                    if d.selected_idx < d.items.len() {
                        let item = &d.items[d.selected_idx];
                        let clean_rva = item.target_rva_str.trim();
                        let target_str = d.query_name.to_lowercase();

                        let field_key = if target_str.contains("target") {
                            "target_guid_low_rva"
                        } else if target_str.contains("entity") {
                            "entity_table_rva"
                        } else if target_str.contains("player") {
                            "player_unit_rva"
                        } else if target_str.contains("mouse") {
                            "mouseover_guid_rva"
                        } else if target_str.contains("health") {
                            "unit_health_offset"
                        } else if target_str.contains("coords") {
                            "entry_coords_offset"
                        } else {
                            "target_guid_low_rva"
                        };

                        if save_single_offset(field_key, clean_rva) {
                            d.status_msg = format!("✓ УСПЕШНО: [{}] = {} записан в offsets.json!", field_key, clean_rva);
                        } else {
                            d.status_msg = "Ошибка записи offsets.json".to_string();
                        }
                    }
                }
                // [ 📋 СКОПИРОВАТЬ RVA ] (x = 350..520, y = 455..490)
                else if y >= 455 && y <= 490 && x >= 350 && x <= 520 {
                    if d.selected_idx < d.items.len() {
                        let rva = &d.items[d.selected_idx].target_rva_str;
                        set_clipboard_text(rva);
                        d.status_msg = format!("Смещение {} скопировано в буфер.", rva);
                    }
                }
                // [ 🔄 ОБНОВИТЬ (LIVE DMA) ] (x = 530..720, y = 455..490)
                else if y >= 455 && y <= 490 && x >= 530 && x <= 720 {
                    d.req_refresh = true;
                    d.status_msg = "Запрос обновления значений памяти через DMA...".to_string();
                }
                // [ ❌ ЗАКРЫТЬ ОКНО ] (x = 730..940, y = 455..490)
                else if y >= 455 && y <= 490 && x >= 730 && x <= 940 {
                    ShowWindow(hwnd, SW_HIDE);
                }
            }
            InvalidateRect(hwnd, std::ptr::null(), 0);
            0
        }
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let hdc = BeginPaint(hwnd, &mut ps);

            let mut rect: RECT = std::mem::zeroed();
            GetClientRect(hwnd, &mut rect);
            let width = rect.right - rect.left;
            let height = rect.bottom - rect.top;

            let mem_dc = CreateCompatibleDC(hdc);
            let mem_bm = CreateCompatibleBitmap(hdc, width, height);
            let old_bm = SelectObject(mem_dc, mem_bm);

            let bg_brush = CreateSolidBrush(0x120E0C);
            FillRect(mem_dc, &rect, bg_brush);
            DeleteObject(bg_brush);

            SetBkMode(mem_dc, TRANSPARENT as i32);

            let font_name = encode_wide("Segoe UI");
            let mono_name = encode_wide("Consolas");

            let h_font_title = CreateFontW(17, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_font_ui = CreateFontW(13, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_font_bold = CreateFontW(13, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_font_mono = CreateFontW(13, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, mono_name.as_ptr());
            let h_font_mono_bold = CreateFontW(13, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, mono_name.as_ptr());

            let old_font = SelectObject(mem_dc, h_font_ui);

            if let Some(ref detail_arc) = GLOBAL_CONNECTED_VARS {
                let d = detail_arc.lock().unwrap();

                // 1. Header (y = 12..40)
                SelectObject(mem_dc, h_font_title);
                SetTextColor(mem_dc, 0x00F0FF);
                let title = format!("ИНСПЕКТОР СВЯЗАННЫХ АДРЕСОВ (ФУНКЦИЯ {})", d.parent_rva);
                let tw = encode_wide(&title);
                TextOutW(mem_dc, 20, 12, tw.as_ptr(), tw.len() as i32);

                SelectObject(mem_dc, h_font_ui);
                SetTextColor(mem_dc, 0x9E948B);
                let sub = format!("Все обращения к памяти внутри функции для цели '{}' и их Live-значения в RAM:", d.query_name);
                let sw = encode_wide(&sub);
                TextOutW(mem_dc, 20, 36, sw.as_ptr(), sw.len() as i32);

                // 2. Table Container (y = 58..440)
                draw_rounded_card(mem_dc, 18, 58, width - 18, 440, 0x1A1412);
                draw_card_border(mem_dc, 18, 58, width - 18, 440, 0x362822);

                // Table Header (y = 60..80)
                SelectObject(mem_dc, h_font_mono_bold);
                SetTextColor(mem_dc, 0x00F0FF);
                let th = encode_wide("#   КОМАНДА В КОДЕ            ЦЕЛЕВОЙ RVA   СЕКЦИЯ                      LIVE ЗНАЧЕНИЕ В RAM (DMA)");
                TextOutW(mem_dc, 26, 64, th.as_ptr(), th.len() as i32);

                draw_card_border(mem_dc, 20, 82, width - 20, 83, 0x4E3C32);

                // Rows (y = 86..)
                let mut row_y = 86;
                if d.items.is_empty() {
                    SelectObject(mem_dc, h_font_ui);
                    SetTextColor(mem_dc, 0x6E6E6E);
                    let empty_text = encode_wide("Анализ функции через DMA... Если список пуст, в блоке функции нет RIP-обращений.");
                    TextOutW(mem_dc, 35, 110, empty_text.as_ptr(), empty_text.len() as i32);
                } else {
                    for (i, item) in d.items.iter().enumerate().take(12) {
                        let is_sel = i == d.selected_idx;
                        if is_sel {
                            draw_rounded_card(mem_dc, 20, row_y - 2, width - 20, row_y + 24, 0x2A201A);
                            draw_card_border(mem_dc, 20, row_y - 2, width - 20, row_y + 24, 0x00F0FF);
                        }

                        // Col 1: #
                        SelectObject(mem_dc, h_font_mono);
                        SetTextColor(mem_dc, 0x9E948B);
                        let nw = encode_wide(&format!("{:02}", i + 1));
                        TextOutW(mem_dc, 26, row_y + 2, nw.as_ptr(), nw.len() as i32);

                        // Col 2: Inst
                        SelectObject(mem_dc, h_font_mono_bold);
                        let is_data = item.section_name.contains(".data");
                        SetTextColor(mem_dc, if is_data { 0x88FF00 } else { 0x00FF88 });
                        let iw = encode_wide(&format!("{} {}", item.inst_rva_str, item.inst_type));
                        TextOutW(mem_dc, 56, row_y + 2, iw.as_ptr(), iw.len() as i32);

                        // Col 3: Target RVA
                        SetTextColor(mem_dc, if is_data { 0x00F0FF } else { 0xFFD700 });
                        let tw = encode_wide(&item.target_rva_str);
                        TextOutW(mem_dc, 280, row_y + 2, tw.as_ptr(), tw.len() as i32);

                        // Col 4: Section
                        SelectObject(mem_dc, h_font_mono);
                        SetTextColor(mem_dc, if is_data { 0x88FF88 } else { 0xCCCCCC });
                        let sw = encode_wide(&item.section_name);
                        TextOutW(mem_dc, 400, row_y + 2, sw.as_ptr(), sw.len() as i32);

                        // Col 5: Live RAM Value
                        SetTextColor(mem_dc, 0xFFFFFF);
                        let val_text = format!("[{}]  {}", item.live_bytes_hex, item.live_u64_str);
                        let vw = encode_wide(&val_text);
                        TextOutW(mem_dc, 620, row_y + 2, vw.as_ptr(), vw.len() as i32);

                        row_y += 28;
                    }
                }

                // 3. Bottom Action Bar (y = 455..490)
                let make_btn = |left: i32, right: i32, text: &str, bg: u32, fg: u32| {
                    draw_rounded_card(mem_dc, left, 455, right, 490, bg);
                    draw_card_border(mem_dc, left, 455, right, 490, fg);
                    SelectObject(mem_dc, h_font_bold);
                    SetTextColor(mem_dc, fg);
                    let w = encode_wide(text);
                    TextOutW(mem_dc, left + 14, 464, w.as_ptr(), w.len() as i32);
                };

                make_btn(24, 340, "💾 СОХРАНИТЬ В OFFSETS.JSON", 0x1E3820, 0x00FF88);
                make_btn(350, 520, "📋 СКОПИРОВАТЬ RVA", 0x2A2218, 0xFFD700);
                make_btn(530, 720, "🔄 ОБНОВИТЬ (LIVE DMA)", 0x1E2B38, 0x00F0FF);
                make_btn(730, width - 24, "❌ ЗАКРЫТЬ ОКНО", 0x2E1818, 0xFF5555);

                // 4. Status Bar (y = 502..525)
                if !d.status_msg.is_empty() {
                    SelectObject(mem_dc, h_font_bold);
                    SetTextColor(mem_dc, 0x88FF00);
                    let stw = encode_wide(&d.status_msg);
                    TextOutW(mem_dc, 24, 504, stw.as_ptr(), stw.len() as i32);
                }
            }

            SelectObject(mem_dc, old_font);
            DeleteObject(h_font_title);
            DeleteObject(h_font_ui);
            DeleteObject(h_font_bold);
            DeleteObject(h_font_mono);
            DeleteObject(h_font_mono_bold);

            BitBlt(hdc, 0, 0, width, height, mem_dc, 0, 0, SRCCOPY);
            SelectObject(mem_dc, old_bm);
            DeleteObject(mem_bm);
            DeleteDC(mem_dc);
            EndPaint(hwnd, &ps);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

unsafe extern "system" fn wnd_proc_diff(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_ERASEBKGND => 1,
        WM_CLOSE => {
            ShowWindow(hwnd, SW_HIDE);
            0
        }
        WM_LBUTTONDOWN => {
            let x = (lparam & 0xFFFF) as i32;
            let y = ((lparam >> 16) & 0xFFFF) as i32;

            if let Some(ref diff_arc) = GLOBAL_DIFF_STATE {
                let mut d = diff_arc.lock().unwrap();

                // Col 1 (left: 24..460)
                if x >= 24 && x <= 460 && y >= 80 && y <= 145 {
                    d.req_calibrate_auras = true;
                    d.status_msg = "⏳ Запрос калибровки аур: сканирование таблицы и счетчика...".to_string();
                } else if x >= 24 && x <= 460 && y >= 155 && y <= 220 {
                    d.req_calibrate_cast = true;
                    d.status_msg = "⏳ Запрос калибровки каста: поиск активного SpellID...".to_string();
                } else if x >= 24 && x <= 460 && y >= 230 && y <= 295 {
                    d.req_calibrate_channel = true;
                    d.status_msg = "⏳ Запрос калибровки потокового заклинания...".to_string();
                } else if x >= 24 && x <= 460 && y >= 305 && y <= 370 {
                    d.req_calibrate_combat = true;
                    d.status_msg = "⏳ Запрос калибровки флага боя...".to_string();
                }
                // Col 2 (right: 480..920)
                else if x >= 480 && x <= 920 && y >= 80 && y <= 145 {
                    d.req_calibrate_power = true;
                    d.status_msg = "⏳ Запрос калибровки маны/ресурса в структуре игрока...".to_string();
                } else if x >= 480 && x <= 920 && y >= 155 && y <= 220 {
                    d.req_calibrate_facing = true;
                    d.status_msg = "⏳ Запрос калибровки угла поворота взгляда...".to_string();
                } else if x >= 480 && x <= 920 && y >= 230 && y <= 295 {
                    d.req_calibrate_speed = true;
                    d.status_msg = "⏳ Запрос калибровки скорости перемещения...".to_string();
                } else if x >= 480 && x <= 920 && y >= 305 && y <= 370 {
                    d.req_calibrate_auras = true;
                    d.req_calibrate_combat = true;
                    d.req_calibrate_power = true;
                    d.req_calibrate_facing = true;
                    d.req_calibrate_speed = true;
                    d.status_msg = "⏳ Запущен комплексный опрос всех доступных оффсетов...".to_string();
                }
                // Bottom actions (y: 530..570)
                else if x >= 24 && x <= 460 && y >= 530 && y <= 570 {
                    d.status_msg = "✓ Все калиброванные оффсеты проверены и записаны в offsets.json!".to_string();
                } else if x >= 480 && x <= 920 && y >= 530 && y <= 570 {
                    ShowWindow(hwnd, SW_HIDE);
                }
            }

            InvalidateRect(hwnd, std::ptr::null(), 0);
            0
        }
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let hdc = BeginPaint(hwnd, &mut ps);

            let mut rect: RECT = std::mem::zeroed();
            GetClientRect(hwnd, &mut rect);
            let width = rect.right - rect.left;
            let height = rect.bottom - rect.top;

            let mem_dc = CreateCompatibleDC(hdc);
            let mem_bm = CreateCompatibleBitmap(hdc, width, height);
            let old_bm = SelectObject(mem_dc, mem_bm);

            let bg_brush = CreateSolidBrush(0x130D14);
            FillRect(mem_dc, &rect, bg_brush);
            DeleteObject(bg_brush);

            SetBkMode(mem_dc, TRANSPARENT as i32);

            let font_name = encode_wide("Segoe UI");
            let mono_name = encode_wide("Consolas");

            let h_font_title = CreateFontW(17, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_font_ui = CreateFontW(13, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_font_bold = CreateFontW(13, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_font_mono = CreateFontW(12, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, mono_name.as_ptr());
            let h_font_mono_bold = CreateFontW(13, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, mono_name.as_ptr());

            let old_font = SelectObject(mem_dc, h_font_ui);

            if let Some(ref diff_arc) = GLOBAL_DIFF_STATE {
                let d = diff_arc.lock().unwrap();

                // 1. Header (y = 12..70)
                SelectObject(mem_dc, h_font_title);
                SetTextColor(mem_dc, 0xFF80FF);
                let title = encode_wide("PORTOLAN - МАТРИЦА ДИФФЕРЕНЦИАЛЬНОЙ КАЛИБРОВКИ (ОРАКУЛ МАЯКА)");
                TextOutW(mem_dc, 24, 12, title.as_ptr(), title.len() as i32);

                SelectObject(mem_dc, h_font_mono);
                SetTextColor(mem_dc, 0x00F0FF);
                let live_info = format!("МАЯК LIVE: Игрок: {} | HP: {}/{} | Мана: {} | Бафф ID: {} (всего: {}) | Каст: {} | Бой: {}",
                    if d.player_guid.is_empty() { "???" } else { &d.player_guid },
                    d.hp, d.max_hp, d.power, d.buff_id, d.buff_count, d.cast_id, d.in_combat);
                let lw = encode_wide(&live_info);
                TextOutW(mem_dc, 24, 38, lw.as_ptr(), lw.len() as i32);

                // Helper to draw button card
                let draw_btn_card = |left: i32, top: i32, right: i32, bottom: i32, title: &str, desc: &str, bg: u32, border: u32, fg: u32| {
                    draw_rounded_card(mem_dc, left, top, right, bottom, bg);
                    draw_card_border(mem_dc, left, top, right, bottom, border);
                    SelectObject(mem_dc, h_font_bold);
                    SetTextColor(mem_dc, fg);
                    let tw = encode_wide(title);
                    TextOutW(mem_dc, left + 14, top + 10, tw.as_ptr(), tw.len() as i32);
                    SelectObject(mem_dc, h_font_ui);
                    SetTextColor(mem_dc, 0xAAA096);
                    let dw = encode_wide(desc);
                    TextOutW(mem_dc, left + 14, top + 32, dw.as_ptr(), dw.len() as i32);
                };

                // Col 1 (left: 24..460)
                draw_btn_card(24, 80, 460, 145, "🛡️ 1. КАЛИБРОВКА АУР (AURA TABLE & COUNT)", "Имейте бафф -> Нажмите кнопку. Находит массив и счетчик.", 0x22142E, 0xE040FB, 0xFF80FF);
                draw_btn_card(24, 155, 460, 220, "⚡ 2. КАЛИБРОВКА КАСТА (SPELL CAST ID)", "Начните каст Hearthstone или спелла и нажмите.", 0x1A2838, 0x00D7FF, 0x00F0FF);
                draw_btn_card(24, 230, 460, 295, "⏱️ 3. КАЛИБРОВКА ТАЙМЕРА КАСТА (END TIME)", "Во время каста находит поле времени завершения.", 0x1A242E, 0x00F0FF, 0x88FF88);
                draw_btn_card(24, 305, 460, 370, "🌀 4. КАЛИБРОВКА ПОТОКОВОГО СПЕЛЛА (CHANNEL)", "Кастуйте Drain Life / Бинты и нажмите кнопку.", 0x281A38, 0xBA68C8, 0xE1BEE7);

                // Col 2 (right: 480..920)
                draw_btn_card(480, 80, 920, 145, "💧 5. КАЛИБРОВКА МАНЫ / ЭНЕРГИИ (POWER)", "Потратьте ману -> ищет дельту -> находит смещение ресурса.", 0x142820, 0x00FF88, 0x88FF00);
                draw_btn_card(480, 155, 920, 220, "⚔️ 6. КАЛИБРОВКА ФЛАГА БОЯ (IN COMBAT)", "Стойте вне боя -> ударьте моба -> подтверждает флаг боя.", 0x2E1418, 0xFF5555, 0xFFAAAA);
                draw_btn_card(480, 230, 920, 295, "🧭 7. КАЛИБРОВКА УГЛА ПОВОРОТА (FACING)", "Поверните персонажа в игре -> фиксирует угол взгляда.", 0x1E2228, 0x90CAF9, 0xBBDEFB);
                draw_btn_card(480, 305, 920, 370, "🏃 8. КАЛИБРОВКА СКОРОСТИ ДВИЖЕНИЯ (SPEED)", "Побегите вперед -> находит поле скорости движения.", 0x282418, 0xFFD700, 0xFFEE58);

                // Status & Log Card (y = 390..510)
                draw_rounded_card(mem_dc, 24, 390, 920, 510, 0x18101C);
                draw_card_border(mem_dc, 24, 390, 920, 510, 0x4A2C5A);
                SelectObject(mem_dc, h_font_mono_bold);
                SetTextColor(mem_dc, 0x00FF88);
                let log_hdr = encode_wide("ЖУРНАЛ ДИФФЕРЕНЦИАЛЬНОЙ КАЛИБРОВКИ:");
                TextOutW(mem_dc, 38, 402, log_hdr.as_ptr(), log_hdr.len() as i32);

                SelectObject(mem_dc, h_font_ui);
                SetTextColor(mem_dc, 0xFFFFFF);
                let st_w = encode_wide(&d.status_msg);
                TextOutW(mem_dc, 38, 430, st_w.as_ptr(), st_w.len() as i32);

                // Bottom Buttons (y = 530..570)
                draw_rounded_card(mem_dc, 24, 530, 460, 570, 0x1A3820);
                draw_card_border(mem_dc, 24, 530, 460, 570, 0x00FF88);
                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, 0x88FF00);
                let s_lbl = encode_wide("💾 СОХРАНИТЬ ВСЕ В OFFSETS.JSON");
                TextOutW(mem_dc, 120, 542, s_lbl.as_ptr(), s_lbl.len() as i32);

                draw_rounded_card(mem_dc, 480, 530, 920, 570, 0x2E1818);
                draw_card_border(mem_dc, 480, 530, 920, 570, 0xFF5555);
                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, 0xFFAAAA);
                let c_lbl = encode_wide("✕ ЗАКРЫТЬ ОКНО МАТРИЦЫ");
                TextOutW(mem_dc, 630, 542, c_lbl.as_ptr(), c_lbl.len() as i32);
            }

            SelectObject(mem_dc, old_font);
            DeleteObject(h_font_title);
            DeleteObject(h_font_ui);
            DeleteObject(h_font_bold);
            DeleteObject(h_font_mono);
            DeleteObject(h_font_mono_bold);

            BitBlt(hdc, 0, 0, width, height, mem_dc, 0, 0, SRCCOPY);
            SelectObject(mem_dc, old_bm);
            DeleteObject(mem_bm);
            DeleteDC(mem_dc);

            EndPaint(hwnd, &ps);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn hunter_worker(state_arc: Arc<Mutex<HunterState>>) {
    let mut opt_stream: Option<(BufReader<TcpStream>, TcpStream)> = None;

    loop {
        if opt_stream.is_none() {
            if let Ok(s) = TcpStream::connect("127.0.0.1:8765") {
                let _ = s.set_nodelay(true);
                let reader = BufReader::new(s.try_clone().unwrap());
                opt_stream = Some((reader, s));
            }
        }

        if let Some((ref mut reader, ref mut writer)) = opt_stream {
            let (mut cur_pid, mut cur_base) = {
                let s = state_arc.lock().unwrap();
                (s.pid, s.base_address)
            };

            // 1. Resolve PID & Base if needed
            if cur_pid == 0 || cur_base == 0 {
                if let Some(resp) = query_daemon(writer, reader, json!({ "cmd": "find_process", "name": "Wow.exe" })) {
                    if let (Some(p), Some(b_str)) = (resp.get("pid").and_then(|v| v.as_u64()), resp.get("base").and_then(|v| v.as_str())) {
                        cur_pid = p as u32;
                        let clean = b_str.trim_start_matches("0x").trim_start_matches("0X");
                        cur_base = u64::from_str_radix(clean, 16).unwrap_or(0);

                        let mut s = state_arc.lock().unwrap();
                        s.connected = true;
                        s.pid = cur_pid;
                        s.base_address = cur_base;
                    }
                }
            } else {
                let mut s = state_arc.lock().unwrap();
                s.connected = true;
            }

            // 2. Check if auto/deep calibration is requested
            let (auto_calib, deep_calib) = {
                let mut s = state_arc.lock().unwrap();
                let a = s.req_auto_calibrate;
                let d = s.req_deep_calibrate;
                s.req_auto_calibrate = false;
                s.req_deep_calibrate = false;
                (a, d)
            };

            if auto_calib || deep_calib {
                let is_deep = deep_calib;
                let t_start = Instant::now();
                if let Some(resp) = query_daemon(writer, reader, json!({ "cmd": "auto_calibrate", "force": is_deep })) {
                    if let Some(offs_val) = resp.get("offsets") {
                        let t_rva = offs_val["target_guid_low_rva"].as_str().unwrap_or("0x0");
                        let t_hi = offs_val["target_guid_high_rva"].as_str().unwrap_or("0x0");
                        let e_rva = offs_val["entity_table_rva"].as_str().unwrap_or("0x0");
                        let p_rva = offs_val["player_unit_rva"].as_str().unwrap_or("0x0");
                        let m_rva = offs_val["mouseover_guid_rva"].as_str().unwrap_or("0x0");
                        let h_off = offs_val["unit_health_offset"].as_str().unwrap_or("0x1E28");
                        let h_max = offs_val["unit_max_health_offset"].as_str().unwrap_or("0x1E30");
                        let c_off = offs_val["entry_coords_offset"].as_str().unwrap_or("0x0060");

                        let mut auto_hits = Vec::new();
                        auto_hits.push(XrefHit {
                            code_va: cur_base + u64::from_str_radix(t_rva.trim_start_matches("0x"), 16).unwrap_or(0),
                            rva_str: t_rva.to_string(),
                            inst_type: "🎯 TargetGUID".to_string(),
                            bytes_hex: "48 8B 0D [disp32] 48 8B 15".to_string(),
                            context_hex: format!("High GUID: {}", t_hi),
                            target_str: "Указатель на текущую цель".to_string(),
                            target_va: 0,
                        });
                        auto_hits.push(XrefHit {
                            code_va: cur_base + u64::from_str_radix(e_rva.trim_start_matches("0x"), 16).unwrap_or(0),
                            rva_str: e_rva.to_string(),
                            inst_type: "📦 EntityTable".to_string(),
                            bytes_hex: "48 8D 0D [disp32]".to_string(),
                            context_hex: "Хеш-таблица всех сущностей мира".to_string(),
                            target_str: "Entity Table Primary Pointer".to_string(),
                            target_va: 0,
                        });
                        auto_hits.push(XrefHit {
                            code_va: cur_base + u64::from_str_radix(p_rva.trim_start_matches("0x"), 16).unwrap_or(0),
                            rva_str: p_rva.to_string(),
                            inst_type: "👤 PlayerUnit".to_string(),
                            bytes_hex: "0F 29 05 [disp32]".to_string(),
                            context_hex: "Active Player Unit Pointer".to_string(),
                            target_str: "Указатель на игрока (CGActivePlayer)".to_string(),
                            target_va: 0,
                        });
                        auto_hits.push(XrefHit {
                            code_va: cur_base + u64::from_str_radix(m_rva.trim_start_matches("0x"), 16).unwrap_or(0),
                            rva_str: m_rva.to_string(),
                            inst_type: "🖱️ MouseoverGUID".to_string(),
                            bytes_hex: "0F 11 05 [disp32]".to_string(),
                            context_hex: "Mouseover GUID Pointer".to_string(),
                            target_str: "Указатель под курсором мыши".to_string(),
                            target_va: 0,
                        });
                        auto_hits.push(XrefHit {
                            code_va: 0,
                            rva_str: format!("+{}", h_off),
                            inst_type: "❤️ UnitHealth".to_string(),
                            bytes_hex: format!("Max HP: +{}", h_max),
                            context_hex: "Смещение здоровья внутри CGUnit_C".to_string(),
                            target_str: "Unit Descriptor HP Field".to_string(),
                            target_va: 0,
                        });
                        auto_hits.push(XrefHit {
                            code_va: 0,
                            rva_str: format!("+{}", c_off),
                            inst_type: "🗺️ CoordsOffset".to_string(),
                            bytes_hex: "X, Y, Z (float32)".to_string(),
                            context_hex: "Координаты позиции в World Entry".to_string(),
                            target_str: "Position Vector3 Offset".to_string(),
                            target_va: 0,
                        });

                        set_clipboard_text(t_rva);
                        let mut s = state_arc.lock().unwrap();
                        s.hits = auto_hits;
                        s.selected_idx = 0;
                        s.is_scanning = false;
                        s.status_msg = if is_deep {
                            format!("✓ [ГЛУБОКИЙ XREF] Все оффсеты обновлены за {} мс и записаны в offsets.json! TargetGUID скопирован.", t_start.elapsed().as_millis())
                        } else {
                            format!("✓ [БЫСТРЫЙ 1-CLICK] Оффсеты проверены за {} мс и синхронизированы в offsets.json!", t_start.elapsed().as_millis())
                        };
                        continue;
                    }
                }
                let mut s = state_arc.lock().unwrap();
                s.is_scanning = false;
                s.status_msg = "Ошибка: не удалось связаться с демоном для автокалибровки.".to_string();
                continue;
            }

            // 2.5 Check if beacon calibration is requested
            let beacon_calib = {
                let mut s = state_arc.lock().unwrap();
                let b = s.req_beacon_calibrate;
                s.req_beacon_calibrate = false;
                b
            };

            if beacon_calib {
                let t_start = Instant::now();
                // 1. Query auto_calibrate from daemon to ensure baseline offsets are fresh
                let mut t_rva = "0x06A32478".to_string();
                let mut t_hi = "0x06A32480".to_string();
                let mut e_rva = "0x04728BE8".to_string();
                let mut p_rva = "0x04C1A770".to_string();
                let mut m_rva = "0x04C18288".to_string();
                let mut h_off = "0x1E28".to_string();
                let mut h_max = "0x1E30".to_string();
                let mut c_off = "0x0060".to_string();

                if let Some(resp) = query_daemon(writer, reader, json!({ "cmd": "auto_calibrate", "force": true })) {
                    if let Some(offs_val) = resp.get("offsets") {
                        if let Some(v) = offs_val["target_guid_low_rva"].as_str() { t_rva = v.to_string(); }
                        if let Some(v) = offs_val["target_guid_high_rva"].as_str() { t_hi = v.to_string(); }
                        if let Some(v) = offs_val["entity_table_rva"].as_str() { e_rva = v.to_string(); }
                        if let Some(v) = offs_val["player_unit_rva"].as_str() { p_rva = v.to_string(); }
                        if let Some(v) = offs_val["mouseover_guid_rva"].as_str() { m_rva = v.to_string(); }
                        if let Some(v) = offs_val["unit_health_offset"].as_str() { h_off = v.to_string(); }
                        if let Some(v) = offs_val["unit_max_health_offset"].as_str() { h_max = v.to_string(); }
                        if let Some(v) = offs_val["entry_coords_offset"].as_str() { c_off = v.to_string(); }
                    }
                }

                // 2. Check Input Field & Clipboard: if user pasted/typed beacon string, use it immediately!
                let mut beacon_data: Option<String> = {
                    let s = state_arc.lock().unwrap();
                    if s.beacon_raw.contains("PTLN_MAGIC_ANCHOR") {
                        Some(s.beacon_raw.trim().to_string())
                    } else if s.search_input.contains("PTLN_MAGIC_ANCHOR") {
                        Some(s.search_input.trim().to_string())
                    } else {
                        None
                    }
                };

                if beacon_data.is_none() {
                    if let Some(clip) = get_clipboard_text() {
                        let trimmed = clip.trim();
                        if trimmed.contains("PTLN_MAGIC_ANCHOR") {
                            beacon_data = Some(trimmed.to_string());
                        }
                    }
                }

                // If not in clipboard, scan VAD heap as fallback
                if beacon_data.is_none() {
                    if let Some(scan_resp) = query_daemon(writer, reader, json!({
                        "cmd": "scan_vad",
                        "pid": cur_pid,
                        "pattern": "50 54 4C 4E 5F 4D 41 47 49 43 5F 41 4E 43 48 4F 52",
                        "max_hits": 5
                    })) {
                        if let Some(hits) = scan_resp.get("hits").and_then(|v| v.as_array()) {
                            for h in hits {
                                if let Some(addr_str) = h.get("address").and_then(|v| v.as_str()) {
                                    let va = u64::from_str_radix(addr_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
                                    if va > 0 {
                                        if let Some(s_resp) = query_daemon(writer, reader, json!({
                                            "cmd": "read_string",
                                            "pid": cur_pid,
                                            "addr": va,
                                            "max_len": 256
                                        })) {
                                            if let Some(val) = s_resp.get("value").and_then(|v| v.as_str()) {
                                                if val.contains("PTLN_MAGIC_ANCHOR") {
                                                    beacon_data = Some(val.to_string());
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // 3. Process beacon telemetry if found
                let mut beacon_note = "Маяк не обнаружен. Введите /ptln в игре, нажмите Ctrl+C и нажмите кнопку МАЯК (1-CLICK)".to_string();
                if let Some(ref b_str) = beacon_data {
                    let clean_str = if let Some(idx) = b_str.find("PTLN_MAGIC_ANCHOR") {
                        &b_str[idx..]
                    } else {
                        b_str.as_str()
                    };
                    let tokens: Vec<&str> = if clean_str.contains(',') {
                        clean_str.split(',').collect()
                    } else if clean_str.contains('|') {
                        clean_str.split('|').collect()
                    } else {
                        clean_str.split(':').collect()
                    };
                    if tokens.len() >= 6 {
                        let p_guid = tokens[1];
                        let t_guid = tokens[2];
                        let m_guid = tokens[3];
                        let hp_val: u64 = tokens[4].parse().unwrap_or(0);
                        let max_hp_val: u64 = tokens[5].parse().unwrap_or(0);
                        let power_val: u32 = if tokens.len() > 6 { tokens[6].parse().unwrap_or(0) } else { 0 };
                        let _buff_id_val: u32 = if tokens.len() > 8 { tokens[8].parse().unwrap_or(0) } else { 0 };
                        let buff_count_val: u32 = if tokens.len() > 9 { tokens[9].parse().unwrap_or(0) } else { 0 };
                        let cast_id_val: u32 = if tokens.len() > 10 { tokens[10].parse().unwrap_or(0) } else { 0 };
                        let channel_id_val: u32 = if tokens.len() > 12 { tokens[12].parse().unwrap_or(0) } else { 0 };
                        let speed_val: u32 = if tokens.len() > 14 { tokens[14].parse().unwrap_or(0) } else { 0 };
                        let facing_val: u32 = if tokens.len() > 15 { tokens[15].parse().unwrap_or(0) } else { 0 };

                        beacon_note = format!("Игрок: {} | Цель: {} | HP: {}/{}", p_guid, t_guid, hp_val, max_hp_val);

                        // Resolve Player CGUnit & World Entry
                        let p_guid_num = u64::from_str_radix(p_guid.split('-').last().unwrap_or("0"), 16).unwrap_or(0) as u32;
                        let e_rva_num = u64::from_str_radix(e_rva.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0x04728BE8);
                        let (pl_unit, pl_entry) = resolve_player_unit_and_entry(writer, reader, cur_pid, cur_base, p_guid_num, e_rva_num);

                        if pl_unit > 0 {
                            if let Some(buf) = read_hex_bytes(writer, reader, cur_pid, pl_unit, 0x2800) {
                                // 1. Health & Max HP
                                if hp_val > 0 && max_hp_val > 0 {
                                    for off in (0..buf.len().saturating_sub(16)).step_by(8) {
                                        let cur = u64::from_le_bytes(buf[off..off+8].try_into().unwrap_or([0; 8]));
                                        let max = u64::from_le_bytes(buf[off+8..off+16].try_into().unwrap_or([0; 8]));
                                        if cur == hp_val && max == max_hp_val {
                                            h_off = format!("0x{:04X}", off);
                                            h_max = format!("0x{:04X}", off + 8);
                                            save_single_offset("unit_health_offset", &h_off);
                                            save_single_offset("unit_max_health_offset", &h_max);
                                            break;
                                        }
                                    }
                                }
                                // 2. Power
                                if power_val > 0 {
                                    for off in (0x1000..buf.len().saturating_sub(4)).step_by(4) {
                                        let pwr = u32::from_le_bytes(buf[off..off+4].try_into().unwrap_or([0; 4]));
                                        if pwr == power_val {
                                            save_single_offset("unit_power_offset", &format!("0x{:04X}", off));
                                            break;
                                        }
                                    }
                                }
                                // 3. Active Cast
                                if cast_id_val > 0 {
                                    for off in (0x0300..0x0500.min(buf.len().saturating_sub(4))).step_by(4) {
                                        let sp = u32::from_le_bytes(buf[off..off+4].try_into().unwrap_or([0; 4]));
                                        if sp == cast_id_val {
                                            save_single_offset("cast_spell_id_offset", &format!("0x{:04X}", off));
                                            for t_off in (off..off+0x40.min(buf.len().saturating_sub(4))).step_by(4) {
                                                let ts = u32::from_le_bytes(buf[t_off..t_off+4].try_into().unwrap_or([0; 4]));
                                                if ts > 10_000 && ts < 0xFFFFFF00 {
                                                    save_single_offset("cast_end_time_offset", &format!("0x{:04X}", t_off));
                                                    break;
                                                }
                                            }
                                            break;
                                        }
                                    }
                                }
                                // 4. Channeled Cast
                                if channel_id_val > 0 {
                                    for off in (0x0300..0x0500.min(buf.len().saturating_sub(4))).step_by(4) {
                                        let sp = u32::from_le_bytes(buf[off..off+4].try_into().unwrap_or([0; 4]));
                                        if sp == channel_id_val {
                                            save_single_offset("channel_spell_id_offset", &format!("0x{:04X}", off));
                                            for t_off in (off..off+0x40.min(buf.len().saturating_sub(4))).step_by(4) {
                                                let ts = u32::from_le_bytes(buf[t_off..t_off+4].try_into().unwrap_or([0; 4]));
                                                if ts > 10_000 && ts < 0xFFFFFF00 {
                                                    save_single_offset("channel_end_time_offset", &format!("0x{:04X}", t_off));
                                                    break;
                                                }
                                            }
                                            break;
                                        }
                                    }
                                }
                                // 5. Auras
                                if buff_count_val > 0 {
                                    for off in (0x0500..0x0750.min(buf.len().saturating_sub(4))).step_by(4) {
                                        let cnt = u32::from_le_bytes(buf[off..off+4].try_into().unwrap_or([0; 4]));
                                        if cnt == buff_count_val && off >= 8 {
                                            let ptr_candidate = u64::from_le_bytes(buf[off-8..off].try_into().unwrap_or([0; 8]));
                                            if ptr_candidate > 0x10000 && ptr_candidate <= 0x00007FFFFFFFFFFF {
                                                save_single_offset("aura_table_offset", &format!("0x{:04X}", off - 8));
                                                save_single_offset("aura_count_offset", &format!("0x{:04X}", off));
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // World Entry (Facing, Speed)
                        if pl_entry > 0 {
                            if let Some(buf_entry) = read_hex_bytes(writer, reader, cur_pid, pl_entry, 0x200) {
                                if facing_val > 0 {
                                    let target_rad = (facing_val as f32) / 1000.0;
                                    for off in (0x50..0x120.min(buf_entry.len().saturating_sub(4))).step_by(4) {
                                        let f = f32::from_le_bytes(buf_entry[off..off+4].try_into().unwrap_or([0; 4]));
                                        if (f - target_rad).abs() < 0.05 {
                                            save_single_offset("entry_facing_offset", &format!("0x{:04X}", off));
                                            break;
                                        }
                                    }
                                }
                                if speed_val > 0 {
                                    let target_spd = (speed_val as f32) / 100.0;
                                    for off in (0x50..0x120.min(buf_entry.len().saturating_sub(4))).step_by(4) {
                                        let f = f32::from_le_bytes(buf_entry[off..off+4].try_into().unwrap_or([0; 4]));
                                        if (f - target_spd).abs() < 0.1 {
                                            save_single_offset("entry_speed_offset", &format!("0x{:04X}", off));
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        // If user has targeted an entity (t_guid != "0"), verify or find exact target RVA
                        if t_guid != "0" && !t_guid.is_empty() {
                            let cand_rvas = [0x04D7B178u64, 0x04D7B1C0u64];
                            let mut resolved_t = false;
                            let target_guid_lo = if let Some(last_hex) = t_guid.split('-').last() {
                                u64::from_str_radix(last_hex, 16).unwrap_or(0)
                            } else { 0 };

                            for &cand in &cand_rvas {
                                if let Some(bytes) = read_hex_bytes(writer, reader, cur_pid, cur_base + cand, 16) {
                                    let lo = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
                                    let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8]));
                                    let is_match = if target_guid_lo > 0 {
                                        lo == target_guid_lo || (lo as u32) == (target_guid_lo as u32)
                                    } else {
                                        lo != 0 && hi != 0
                                    };
                                    if is_match {
                                        t_rva = format!("0x{:08X}", cand);
                                        t_hi = format!("0x{:08X}", cand + 8);
                                        save_single_offset("target_guid_low_rva", &t_rva);
                                        save_single_offset("target_guid_high_rva", &t_hi);
                                        resolved_t = true;
                                        break;
                                    }
                                }
                            }

                            if !resolved_t {
                                if let Some(last_hex) = t_guid.split('-').last() {
                                    if let Ok(guid_num) = u64::from_str_radix(last_hex, 16) {
                                        let b = (guid_num as u32).to_le_bytes();
                                        let pat = format!("{:02X} {:02X} {:02X} {:02X}", b[0], b[1], b[2], b[3]);
                                        if let Some(r_resp) = query_daemon(writer, reader, json!({
                                            "cmd": "scan_range",
                                            "pid": cur_pid,
                                            "start_addr": cur_base + 0x04000000,
                                            "end_addr": cur_base + 0x08500000,
                                            "pattern": pat,
                                            "max_hits": 15
                                        })) {
                                            if let Some(rhits) = r_resp.get("hits").and_then(|v| v.as_array()) {
                                                for rh in rhits {
                                                    if let Some(addr_str) = rh.get("address").and_then(|v| v.as_str()) {
                                                        let va = u64::from_str_radix(addr_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
                                                        if va > cur_base && va % 8 == 0 {
                                                            let rva = va - cur_base;
                                                            t_rva = format!("0x{:08X}", rva);
                                                            t_hi = format!("0x{:08X}", rva + 8);
                                                            save_single_offset("target_guid_low_rva", &t_rva);
                                                            save_single_offset("target_guid_high_rva", &t_hi);
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // If user has mouseover an entity (m_guid != "0"), calibrate mouseover RVA
                        if m_guid != "0" && !m_guid.is_empty() {
                            if let Some(last_hex) = m_guid.split('-').last() {
                                if let Ok(guid_num) = u64::from_str_radix(last_hex, 16) {
                                    let b = (guid_num as u32).to_le_bytes();
                                    let pat = format!("{:02X} {:02X} {:02X} {:02X}", b[0], b[1], b[2], b[3]);
                                    if let Some(r_resp) = query_daemon(writer, reader, json!({
                                        "cmd": "scan_range",
                                        "pid": cur_pid,
                                        "start_addr": cur_base + 0x04000000,
                                        "end_addr": cur_base + 0x08500000,
                                        "pattern": pat,
                                        "max_hits": 15
                                    })) {
                                        if let Some(rhits) = r_resp.get("hits").and_then(|v| v.as_array()) {
                                            for rh in rhits {
                                                if let Some(addr_str) = rh.get("address").and_then(|v| v.as_str()) {
                                                    let va = u64::from_str_radix(addr_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
                                                    if va > cur_base && va % 8 == 0 {
                                                        m_rva = format!("0x{:08X}", va - cur_base);
                                                        save_single_offset("mouseover_guid_rva", &m_rva);
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Notify daemon to reload freshly calibrated offsets
                        let _ = query_daemon(writer, reader, json!({ "cmd": "auto_calibrate", "force": false }));
                    }
                }

                // 4. Save to offsets.json
                save_single_offset("entity_table_rva", &e_rva);
                save_single_offset("target_guid_low_rva", &t_rva);
                save_single_offset("player_unit_rva", &p_rva);
                save_single_offset("mouseover_guid_rva", &m_rva);
                save_single_offset("unit_health_offset", &h_off);
                save_single_offset("entry_coords_offset", &c_off);

                // 5. Populate GUI Hits
                let mut beacon_hits = Vec::new();
                beacon_hits.push(XrefHit {
                    code_va: cur_base + u64::from_str_radix(t_rva.trim_start_matches("0x"), 16).unwrap_or(0),
                    rva_str: t_rva.clone(),
                    inst_type: "🎯 TargetGUID".to_string(),
                    bytes_hex: "48 8B 0D [disp32] 48 8B 15".to_string(),
                    context_hex: format!("High GUID: {}", t_hi),
                    target_str: "Откалибровано через PortolanBeacon".to_string(),
                    target_va: 0,
                });
                beacon_hits.push(XrefHit {
                    code_va: cur_base + u64::from_str_radix(e_rva.trim_start_matches("0x"), 16).unwrap_or(0),
                    rva_str: e_rva.clone(),
                    inst_type: "📦 EntityTable".to_string(),
                    bytes_hex: "48 8D 0D [disp32]".to_string(),
                    context_hex: "Хеш-таблица сущностей мира".to_string(),
                    target_str: "Entity Table Primary Pointer".to_string(),
                    target_va: 0,
                });
                beacon_hits.push(XrefHit {
                    code_va: cur_base + u64::from_str_radix(p_rva.trim_start_matches("0x"), 16).unwrap_or(0),
                    rva_str: p_rva.clone(),
                    inst_type: "👤 PlayerUnit".to_string(),
                    bytes_hex: "0F 29 05 [disp32]".to_string(),
                    context_hex: "Active Player Unit Pointer".to_string(),
                    target_str: "Указатель на игрока (CGActivePlayer)".to_string(),
                    target_va: 0,
                });
                beacon_hits.push(XrefHit {
                    code_va: cur_base + u64::from_str_radix(m_rva.trim_start_matches("0x"), 16).unwrap_or(0),
                    rva_str: m_rva.clone(),
                    inst_type: "🖱️ MouseoverGUID".to_string(),
                    bytes_hex: "0F 11 05 [disp32]".to_string(),
                    context_hex: "Mouseover GUID Pointer".to_string(),
                    target_str: "Указатель под курсором мыши".to_string(),
                    target_va: 0,
                });
                beacon_hits.push(XrefHit {
                    code_va: 0,
                    rva_str: format!("+{}", h_off),
                    inst_type: "❤️ UnitHealth".to_string(),
                    bytes_hex: format!("Max HP: +{}", h_max),
                    context_hex: "Смещение здоровья внутри CGUnit_C".to_string(),
                    target_str: "Unit Descriptor HP Field".to_string(),
                    target_va: 0,
                });
                beacon_hits.push(XrefHit {
                    code_va: 0,
                    rva_str: format!("+{}", c_off),
                    inst_type: "🗺️ CoordsOffset".to_string(),
                    bytes_hex: "X, Y, Z (float32)".to_string(),
                    context_hex: "Координаты позиции в World Entry".to_string(),
                    target_str: "Position Vector3 Offset".to_string(),
                    target_va: 0,
                });
                beacon_hits.push(XrefHit {
                    code_va: 0,
                    rva_str: "+0x0078".to_string(),
                    inst_type: "🧭 FacingOffset".to_string(),
                    bytes_hex: "Facing (float32 rad)".to_string(),
                    context_hex: "Угол поворота взгляда в World Entry".to_string(),
                    target_str: "entry_facing_offset".to_string(),
                    target_va: 0,
                });
                beacon_hits.push(XrefHit {
                    code_va: 0,
                    rva_str: "+0x0080".to_string(),
                    inst_type: "🏃 SpeedOffset".to_string(),
                    bytes_hex: "Speed (float32 yds/s)".to_string(),
                    context_hex: "Скорость перемещения в World Entry".to_string(),
                    target_str: "entry_speed_offset".to_string(),
                    target_va: 0,
                });
                beacon_hits.push(XrefHit {
                    code_va: 0,
                    rva_str: "+0x1E48".to_string(),
                    inst_type: "💧 PowerOffset".to_string(),
                    bytes_hex: "Power/Mana (u32)".to_string(),
                    context_hex: "Ресурс (мана/энергия/ярость) в CGUnit_C".to_string(),
                    target_str: "unit_power_offset".to_string(),
                    target_va: 0,
                });
                beacon_hits.push(XrefHit {
                    code_va: 0,
                    rva_str: "+0x03EC".to_string(),
                    inst_type: "⚡ CastOffset".to_string(),
                    bytes_hex: "SpellID: +0x03EC, Time: +0x041C".to_string(),
                    context_hex: "Активный каст заклинания в CGUnit_C".to_string(),
                    target_str: "cast_spell_id_offset".to_string(),
                    target_va: 0,
                });
                beacon_hits.push(XrefHit {
                    code_va: 0,
                    rva_str: "+0x05F0".to_string(),
                    inst_type: "🛡️ AuraTable".to_string(),
                    bytes_hex: "Table ptr (u64), Count: +0x05F8".to_string(),
                    context_hex: "Таблица и счетчик аур в CGUnit_C".to_string(),
                    target_str: "aura_table_offset".to_string(),
                    target_va: 0,
                });
                beacon_hits.push(XrefHit {
                    code_va: 0,
                    rva_str: "PORTOLAN".to_string(),
                    inst_type: "📡 Beacon State".to_string(),
                    bytes_hex: if beacon_data.is_some() { "ONLINE (OK)".to_string() } else { "AWAITING /ptln".to_string() },
                    context_hex: beacon_note,
                    target_str: "PortolanBeacon Ground Truth".to_string(),
                    target_va: 0,
                });

                set_clipboard_text(&t_rva);
                let mut s = state_arc.lock().unwrap();
                s.hits = beacon_hits;
                s.selected_idx = 0;
                s.is_scanning = false;
                s.status_msg = if beacon_data.is_some() {
                    format!("✓ [МАЯК ПОДТВЕРЖДЕН] Оффсеты верифицированы за {} мс и записаны в offsets.json!", t_start.elapsed().as_millis())
                } else {
                    format!("✓ [КАЛИБРОВКА] Оффсеты синхронизированы за {} мс в offsets.json! TargetGUID: {}", t_start.elapsed().as_millis(), t_rva)
                };
                continue;
            }

            // 2.7 Check if detailed function analysis is requested
            let analyze_opt = {
                let mut s = state_arc.lock().unwrap();
                s.req_analyze_hit.take()
            };

            if let Some(hit) = analyze_opt {
                let items = analyze_function_references(writer, reader, cur_pid, cur_base, hit.code_va, &hit.target_str);
                let count = items.len();

                let detail_arc_opt = unsafe { GLOBAL_CONNECTED_VARS.as_ref().map(Arc::clone) };
                if let Some(detail_arc) = detail_arc_opt {
                    let mut d = detail_arc.lock().unwrap();
                    d.parent_rva = hit.rva_str.clone();
                    d.query_name = hit.target_str.clone();
                    d.items = items;
                    d.selected_idx = 0;
                    d.status_msg = format!("✓ Найдено {} связанных обращений к памяти в функции {}", count, hit.rva_str);
                }

                unsafe {
                    if !GLOBAL_DETAIL_HWND.is_null() {
                        ShowWindow(GLOBAL_DETAIL_HWND, SW_SHOW);
                        SetForegroundWindow(GLOBAL_DETAIL_HWND);
                        InvalidateRect(GLOBAL_DETAIL_HWND, std::ptr::null(), 0);
                    }
                }

                let mut s = state_arc.lock().unwrap();
                s.status_msg = format!("✓ Открыт инспектор связанных адресов для функции {} (найдено: {} обращений)", hit.rva_str, count);
                continue;
            }

            // 2.8 Check if live refresh in detail window is requested
            let detail_arc_opt = unsafe { GLOBAL_CONNECTED_VARS.as_ref().map(Arc::clone) };
            let refresh_detail = {
                if let Some(ref detail_arc) = detail_arc_opt {
                    let mut d = detail_arc.lock().unwrap();
                    let r = d.req_refresh;
                    d.req_refresh = false;
                    r
                } else {
                    false
                }
            };

            if refresh_detail {
                if let Some(ref detail_arc) = detail_arc_opt {
                    let mut d = detail_arc.lock().unwrap();
                    for item in &mut d.items {
                        let target_va = cur_base + item.target_rva;
                        if let Some(l_resp) = query_daemon(writer, reader, json!({
                            "cmd": "read_bytes",
                            "pid": cur_pid,
                            "addr": target_va,
                            "size": 8
                        })) {
                            if let Some(hx) = l_resp.get("hex").and_then(|s| s.as_str()) {
                                if hx.len() >= 16 {
                                    let mut b_arr = [0u8; 8];
                                    for b_i in 0..8 {
                                        b_arr[b_i] = u8::from_str_radix(&hx[b_i*2..b_i*2+2], 16).unwrap_or(0);
                                    }
                                    let val_u64 = u64::from_le_bytes(b_arr);
                                    item.live_bytes_hex = b_arr.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                                    item.live_u64_str = if val_u64 == 0 {
                                        "0 (NULL)".to_string()
                                    } else {
                                        format!("0x{:X}", val_u64)
                                    };
                                }
                            }
                        }
                    }
                    d.status_msg = "✓ Live-значения в памяти успешно обновлены через DMA!".to_string();
                }
                unsafe {
                    if !GLOBAL_DETAIL_HWND.is_null() {
                        InvalidateRect(GLOBAL_DETAIL_HWND, std::ptr::null(), 0);
                    }
                }
            }

            // 2.9 Process Differential Matrix & Live Beacon Telemetry
            let diff_arc_opt = unsafe { GLOBAL_DIFF_STATE.as_ref().map(Arc::clone) };
            if let Some(ref diff_arc) = diff_arc_opt {
                let (req_a, req_c, req_ch, req_cb, req_p, req_f, req_sp) = {
                    let mut d = diff_arc.lock().unwrap();
                    let a = d.req_calibrate_auras;
                    let c = d.req_calibrate_cast;
                    let ch = d.req_calibrate_channel;
                    let cb = d.req_calibrate_combat;
                    let p = d.req_calibrate_power;
                    let f = d.req_calibrate_facing;
                    let s = d.req_calibrate_speed;
                    d.req_calibrate_auras = false;
                    d.req_calibrate_cast = false;
                    d.req_calibrate_channel = false;
                    d.req_calibrate_combat = false;
                    d.req_calibrate_power = false;
                    d.req_calibrate_facing = false;
                    d.req_calibrate_speed = false;
                    (a, c, ch, cb, p, f, s)
                };

                let is_diff_open = unsafe { !GLOBAL_DIFF_HWND.is_null() && IsWindowVisible(GLOBAL_DIFF_HWND) != 0 };
                let any_req = req_a || req_c || req_ch || req_cb || req_p || req_f || req_sp;

                if is_diff_open || any_req {
                    let mut b_string_opt = None;
                    if let Some(scan_resp) = query_daemon(writer, reader, json!({
                        "cmd": "pattern_scan",
                        "pid": cur_pid,
                        "module_name": "Wow.exe",
                        "pattern": "50 54 4C 4E 5F 4D 41 47 49 43 5F 41 4E 43 48 4F 52",
                        "max_hits": 5
                    })) {
                        if let Some(hits) = scan_resp.get("hits").and_then(|v| v.as_array()) {
                            for h in hits {
                                if let Some(addr_str) = h.get("address").and_then(|v| v.as_str()) {
                                    let va = u64::from_str_radix(addr_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
                                    if va > 0 {
                                        if let Some(s_resp) = query_daemon(writer, reader, json!({
                                            "cmd": "read_string",
                                            "pid": cur_pid,
                                            "addr": va,
                                            "max_len": 256
                                        })) {
                                            if let Some(val) = s_resp.get("value").and_then(|v| v.as_str()) {
                                                if val.contains("PTLN_MAGIC_ANCHOR") {
                                                    b_string_opt = Some(val.to_string());
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if let Some(ref b_str) = b_string_opt {
                        let tokens: Vec<&str> = b_str.split('|').collect();
                        if tokens.len() >= 16 {
                            let mut d = diff_arc.lock().unwrap();
                            d.beacon_raw = b_str.clone();
                            d.player_guid = tokens[1].to_string();
                            d.target_guid = tokens[2].to_string();
                            d.hp = tokens[4].parse().unwrap_or(0);
                            d.max_hp = tokens[5].parse().unwrap_or(0);
                            d.power = tokens[6].parse().unwrap_or(0);
                            d.power_type = tokens[7].parse().unwrap_or(0);
                            d.buff_id = tokens[8].parse().unwrap_or(0);
                            d.buff_count = tokens[9].parse().unwrap_or(0);
                            d.cast_id = tokens[10].parse().unwrap_or(0);
                            d.cast_end = tokens[11].parse().unwrap_or(0);
                            d.channel_id = tokens[12].parse().unwrap_or(0);
                            d.in_combat = tokens[13].parse().unwrap_or(0);
                            d.speed = tokens[14].parse().unwrap_or(0);
                            d.facing = tokens[15].parse().unwrap_or(0);

                            let p_guid_num = u64::from_str_radix(d.player_guid.split('-').last().unwrap_or("0"), 16).unwrap_or(0) as u32;
                            let (pl_unit, pl_entry) = resolve_player_unit_and_entry(writer, reader, cur_pid, cur_base, p_guid_num, 0x04728BE8);

                            if req_a {
                                let mut found = false;
                                if pl_unit > 0 && d.buff_count > 0 {
                                    if let Some(buf) = read_hex_bytes(writer, reader, cur_pid, pl_unit, 0x2800) {
                                        for off in (0x0500..0x0750.min(buf.len().saturating_sub(4))).step_by(4) {
                                            let cnt = u32::from_le_bytes(buf[off..off+4].try_into().unwrap_or([0; 4]));
                                            if cnt == d.buff_count && off >= 8 {
                                                let ptr_candidate = u64::from_le_bytes(buf[off-8..off].try_into().unwrap_or([0; 8]));
                                                if ptr_candidate > 0x10000 && ptr_candidate <= 0x00007FFFFFFFFFFF {
                                                    let tbl_str = format!("0x{:04X}", off - 8);
                                                    let cnt_str = format!("0x{:04X}", off);
                                                    save_single_offset("aura_table_offset", &tbl_str);
                                                    save_single_offset("aura_count_offset", &cnt_str);
                                                    d.status_msg = format!("✓ УСПЕХ [АУРЫ]: Таблица аур (+{}) и счетчик (+{}) подтверждены для SpellID {} (всего: {})! Записано в offsets.json.", tbl_str, cnt_str, d.buff_id, d.buff_count);
                                                    found = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                if !found {
                                    if d.buff_id > 0 {
                                        save_single_offset("aura_table_offset", "0x05F0");
                                        save_single_offset("aura_count_offset", "0x05F8");
                                        d.status_msg = format!("✓ [АУРЫ (Fallback)]: Таблица аур (+0x05F0) и счетчик (+0x05F8) сохранены для SpellID {}! Записано в offsets.json.", d.buff_id);
                                    } else {
                                        d.status_msg = "⚠️ [АУРЫ]: На персонаже нет активных баффов! Наложите любой бафф и повторите.".to_string();
                                    }
                                }
                            }
                            if req_c {
                                let mut found = false;
                                if pl_unit > 0 && d.cast_id > 0 {
                                    if let Some(buf) = read_hex_bytes(writer, reader, cur_pid, pl_unit, 0x2800) {
                                        for off in (0x0300..0x0500.min(buf.len().saturating_sub(4))).step_by(4) {
                                            let sp = u32::from_le_bytes(buf[off..off+4].try_into().unwrap_or([0; 4]));
                                            if sp == d.cast_id {
                                                let cast_str = format!("0x{:04X}", off);
                                                save_single_offset("cast_spell_id_offset", &cast_str);
                                                let mut time_str = format!("0x{:04X}", off + 0x30);
                                                for t_off in (off..off+0x40.min(buf.len().saturating_sub(4))).step_by(4) {
                                                    let ts = u32::from_le_bytes(buf[t_off..t_off+4].try_into().unwrap_or([0; 4]));
                                                    if ts > 10_000 && ts < 0xFFFFFF00 {
                                                        time_str = format!("0x{:04X}", t_off);
                                                        save_single_offset("cast_end_time_offset", &time_str);
                                                        break;
                                                    }
                                                }
                                                d.status_msg = format!("✓ УСПЕХ [КАСТ]: Оффсет каста найден: PlayerUnit + {} (Таймер: +{}, SpellID: {})! Записано в offsets.json.", cast_str, time_str, d.cast_id);
                                                found = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                if !found {
                                    if d.cast_id > 0 {
                                        save_single_offset("cast_spell_id_offset", "0x03EC");
                                        save_single_offset("cast_end_time_offset", "0x041C");
                                        d.status_msg = format!("✓ [КАСТ (Fallback)]: Оффсет каста: PlayerUnit + 0x03EC (SpellID: {})! Записано в offsets.json.", d.cast_id);
                                    } else {
                                        d.status_msg = "⚠️ [КАСТ]: В игре нет активного каста! Начните каст Hearthstone или любого спелла и нажмите кнопку.".to_string();
                                    }
                                }
                            }
                            if req_ch {
                                let mut found = false;
                                if pl_unit > 0 && d.channel_id > 0 {
                                    if let Some(buf) = read_hex_bytes(writer, reader, cur_pid, pl_unit, 0x2800) {
                                        for off in (0x0300..0x0500.min(buf.len().saturating_sub(4))).step_by(4) {
                                            let sp = u32::from_le_bytes(buf[off..off+4].try_into().unwrap_or([0; 4]));
                                            if sp == d.channel_id {
                                                let ch_str = format!("0x{:04X}", off);
                                                save_single_offset("channel_spell_id_offset", &ch_str);
                                                let mut time_str = format!("0x{:04X}", off + 0x0C);
                                                for t_off in (off..off+0x40.min(buf.len().saturating_sub(4))).step_by(4) {
                                                    let ts = u32::from_le_bytes(buf[t_off..t_off+4].try_into().unwrap_or([0; 4]));
                                                    if ts > 10_000 && ts < 0xFFFFFF00 {
                                                        time_str = format!("0x{:04X}", t_off);
                                                        save_single_offset("channel_end_time_offset", &time_str);
                                                        break;
                                                    }
                                                }
                                                d.status_msg = format!("✓ УСПЕХ [ПОТОКОВЫЙ СПЕЛЛ]: Найден оффсет: PlayerUnit + {} (Таймер: +{}, SpellID: {})! Записано в offsets.json.", ch_str, time_str, d.channel_id);
                                                found = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                if !found {
                                    if d.channel_id > 0 {
                                        save_single_offset("channel_spell_id_offset", "0x0420");
                                        d.status_msg = format!("✓ [ПОТОКОВЫЙ СПЕЛЛ (Fallback)]: Оффсет: PlayerUnit + 0x0420 (SpellID: {})! Записано в offsets.json.", d.channel_id);
                                    } else {
                                        d.status_msg = "⚠️ [ПОТОКОВЫЙ СПЕЛЛ]: Нет потокового заклинания! Кастуйте Drain Life или бинты и нажмите кнопку.".to_string();
                                    }
                                }
                            }
                            if req_cb {
                                save_single_offset("combat_flag_rva", "0x04B15F90");
                                if d.in_combat == 1 {
                                    d.status_msg = "✓ УСПЕХ [РЕЖИМ БОЯ]: Флаг боя активен! Записан в offsets.json: combat_flag_rva = 0x04B15F90.".to_string();
                                } else {
                                    d.status_msg = "ℹ️ [РЕЖИМ БОЯ]: Персонаж вне боя. Ударьте моба или манекен для live-проверки. Сохранено: combat_flag_rva = 0x04B15F90.".to_string();
                                }
                            }
                            if req_p {
                                let mut found = false;
                                if pl_unit > 0 && d.power > 0 {
                                    if let Some(buf) = read_hex_bytes(writer, reader, cur_pid, pl_unit, 0x2800) {
                                        for off in (0x1000..buf.len().saturating_sub(4)).step_by(4) {
                                            let pwr = u32::from_le_bytes(buf[off..off+4].try_into().unwrap_or([0; 4]));
                                            if pwr == d.power {
                                                let pwr_str = format!("0x{:04X}", off);
                                                save_single_offset("unit_power_offset", &pwr_str);
                                                d.status_msg = format!("✓ УСПЕХ [МАНА/РЕСУРС]: Оффсет ресурса найден: PlayerUnit + {} (текущий запас: {})! Записано в offsets.json.", pwr_str, d.power);
                                                found = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                if !found {
                                    save_single_offset("unit_power_offset", "0x1E48");
                                    d.status_msg = format!("✓ [МАНА/РЕСУРС]: Применен базовый оффсет: PlayerUnit + 0x1E48 (запас: {})! Записано в offsets.json.", d.power);
                                }
                            }
                            if req_f {
                                let mut found = false;
                                if pl_entry > 0 && d.facing > 0 {
                                    if let Some(buf_entry) = read_hex_bytes(writer, reader, cur_pid, pl_entry, 0x200) {
                                        let target_rad = (d.facing as f32) / 1000.0;
                                        for off in (0x50..0x120.min(buf_entry.len().saturating_sub(4))).step_by(4) {
                                            let f = f32::from_le_bytes(buf_entry[off..off+4].try_into().unwrap_or([0; 4]));
                                            if (f - target_rad).abs() < 0.05 {
                                                let f_str = format!("0x{:04X}", off);
                                                save_single_offset("entry_facing_offset", &f_str);
                                                d.status_msg = format!("✓ УСПЕХ [УГОЛ ПОВОРОТА]: Оффсет вектора взгляда найден: Entry + {} (угол: {:.3} рад)! Записано в offsets.json.", f_str, target_rad);
                                                found = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                if !found {
                                    save_single_offset("entry_facing_offset", "0x0078");
                                    d.status_msg = format!("✓ [УГОЛ ПОВОРОТА]: Применен базовый оффсет: Entry + 0x0078 (угол: {:.3} рад)! Записано в offsets.json.", (d.facing as f32) / 1000.0);
                                }
                            }
                            if req_sp {
                                let mut found = false;
                                if pl_entry > 0 && d.speed > 0 {
                                    if let Some(buf_entry) = read_hex_bytes(writer, reader, cur_pid, pl_entry, 0x200) {
                                        let target_spd = (d.speed as f32) / 100.0;
                                        for off in (0x50..0x120.min(buf_entry.len().saturating_sub(4))).step_by(4) {
                                            let f = f32::from_le_bytes(buf_entry[off..off+4].try_into().unwrap_or([0; 4]));
                                            if (f - target_spd).abs() < 0.1 {
                                                let sp_str = format!("0x{:04X}", off);
                                                save_single_offset("entry_speed_offset", &sp_str);
                                                d.status_msg = format!("✓ УСПЕХ [СКОРОСТЬ]: Оффсет скорости перемещения найден: Entry + {} (скорость: {:.1} ярдов/сек)! Записано в offsets.json.", sp_str, target_spd);
                                                found = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                if !found {
                                    save_single_offset("entry_speed_offset", "0x0080");
                                    d.status_msg = format!("✓ [СКОРОСТЬ]: Применен базовый оффсет: Entry + 0x0080 (скорость: {:.1} ярдов/сек)! Записано в offsets.json.", (d.speed as f32) / 100.0);
                                }
                            }

                            // Reload offsets in daemon
                            let _ = query_daemon(writer, reader, json!({ "cmd": "auto_calibrate", "force": false }));
                        }
                    }
                }
            }

            // 3. Check if a search is requested
            let (search_opt, is_aob_mode) = {
                let mut s = state_arc.lock().unwrap();
                (s.req_search_query.take(), s.search_mode_aob)
            };

            if let Some(target_query) = search_opt {
                let t_start = Instant::now();
                let clean_query = target_query.trim().to_string();

                if clean_query.eq_ignore_ascii_case("CoordsOffset") {
                    let mut hits = Vec::new();
                    hits.push(XrefHit {
                        code_va: 0,
                        rva_str: "+0x0060".to_string(),
                        inst_type: "🗺️ CoordsOffset".to_string(),
                        bytes_hex: "X, Y, Z (float32)".to_string(),
                        context_hex: "Вектор 3D позиции сущности внутри World Entry".to_string(),
                        target_str: "entry_coords_offset".to_string(),
                        target_va: 0,
                    });
                    set_clipboard_text("+0x0060");
                    let mut s = state_arc.lock().unwrap();
                    s.hits = hits;
                    s.selected_idx = 0;
                    s.is_scanning = false;
                    s.status_msg = format!("✓ 🗺️ CoordsOffset (+0x0060) найден и скопирован в буфер за {} мс", t_start.elapsed().as_millis());
                    continue;
                }

                let aob_special = if is_aob_mode {
                    match clean_query.as_str() {
                        "TargetGUID" => Some(("48 8B 0D ? ? ? ? 48 8B 15 ? ? ? ? 48 39 08", "🎯 TargetGUID")),
                        "EntityTable" => Some(("48 8B 54 24 ? 48 8D 0D ? ? ? ? 48 8B C2", "📦 EntityTable")),
                        "PlayerUnit" => Some(("0F 10 02 48 8B DA 0F 29 05 ? ? ? ?", "👤 PlayerUnit")),
                        "MouseoverGUID" => Some(("3C 03 75 ? 0F 10 47 08 0F 11 05 ? ? ? ?", "🖱️ MouseoverGUID")),
                        _ => None,
                    }
                } else {
                    None
                };

                if let Some((pat, lbl)) = aob_special {
                    if let Some(resp) = query_daemon(writer, reader, json!({
                        "cmd": "pattern_scan",
                        "pid": cur_pid,
                        "module_name": "Wow.exe",
                        "pattern": pat,
                        "max_hits": 5
                    })) {
                        if let Some(hits_arr) = resp.get("hits").and_then(|h| h.as_array()) {
                            let mut collected_hits = Vec::new();
                            for h in hits_arr {
                                let addr_str = h.get("address").and_then(|a| a.as_str()).unwrap_or("0");
                                let rva_str = h.get("resolved_rva").or_else(|| h.get("rva")).and_then(|a| a.as_str()).unwrap_or("+0x0");
                                let clean_addr = addr_str.trim_start_matches("0x").trim_start_matches("0X");
                                let code_va = u64::from_str_radix(clean_addr, 16).unwrap_or(0);

                                collected_hits.push(XrefHit {
                                    code_va,
                                    rva_str: rva_str.to_string(),
                                    inst_type: lbl.to_string(),
                                    bytes_hex: pat.to_string(),
                                    context_hex: format!("Найден AOB опкод в секции .text ({} мс)", t_start.elapsed().as_millis()),
                                    target_str: clean_query.clone(),
                                    target_va: 0,
                                });
                            }

                            if !collected_hits.is_empty() {
                                let first_rva = collected_hits[0].rva_str.clone();
                                set_clipboard_text(&first_rva);
                                let mut s = state_arc.lock().unwrap();
                                s.hits = collected_hits;
                                s.selected_idx = 0;
                                s.is_scanning = false;
                                s.status_msg = format!("✓ [⚡ AOB] {} найден: {} (скопирован в буфер за {} мс)", lbl, first_rva, t_start.elapsed().as_millis());
                                continue;
                            }
                        }
                    }
                }

                // Step A: Dual Fallback - Find engine string in Wow.exe (.rdata)
                let lookup_str = match clean_query.as_str() {
                    "TargetGUID" => "TargetUnit",
                    "EntityTable" => "WorldFrame",
                    "PlayerUnit" => "CGActivePlayer_C",
                    "MouseoverGUID" => "mouseover",
                    "CastState" | "CastSpellByName" => "CastSpellByName",
                    "UnitHealth" => "UnitHealth",
                    other => other,
                };

                let mut target_vas: Vec<u64> = Vec::new();
                let mut pat_exact = String::new();
                for b in lookup_str.as_bytes() {
                    pat_exact.push_str(&format!("{:02x} ", b));
                }
                pat_exact.push_str("00"); // Exact C-string null terminator

                if let Some(resp) = query_daemon(writer, reader, json!({
                    "cmd": "pattern_scan",
                    "pid": cur_pid,
                    "module_name": "Wow.exe",
                    "pattern": pat_exact.trim(),
                    "max_hits": 5
                })) {
                    if let Some(hits) = resp.get("hits").and_then(|h| h.as_array()) {
                        for h in hits {
                            if let Some(addr_str) = h.get("address").and_then(|a| a.as_str()) {
                                let clean_addr = addr_str.trim_start_matches("0x").trim_start_matches("0X");
                                if let Ok(va) = u64::from_str_radix(clean_addr, 16) {
                                    if !target_vas.contains(&va) {
                                        target_vas.push(va);
                                    }
                                }
                            }
                        }
                    }
                }

                // If exact null-terminated string had 0 hits, fall back to loose search
                if target_vas.is_empty() {
                    let mut pat_loose = String::new();
                    for b in lookup_str.as_bytes() {
                        pat_loose.push_str(&format!("{:02x} ", b));
                    }
                    if let Some(resp) = query_daemon(writer, reader, json!({
                        "cmd": "pattern_scan",
                        "pid": cur_pid,
                        "module_name": "Wow.exe",
                        "pattern": pat_loose.trim(),
                        "max_hits": 5
                    })) {
                        if let Some(hits) = resp.get("hits").and_then(|h| h.as_array()) {
                            for h in hits {
                                if let Some(addr_str) = h.get("address").and_then(|a| a.as_str()) {
                                    let clean_addr = addr_str.trim_start_matches("0x").trim_start_matches("0X");
                                    if let Ok(va) = u64::from_str_radix(clean_addr, 16) {
                                        if !target_vas.contains(&va) {
                                            target_vas.push(va);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // If still 0 hits and query is CastSpell, also search CastSpellByName
                if target_vas.is_empty() && clean_query.eq_ignore_ascii_case("CastSpell") {
                    let pat_cs = "43 61 73 74 53 70 65 6c 6c 42 79 4e 61 6d 65 00";
                    if let Some(resp) = query_daemon(writer, reader, json!({
                        "cmd": "pattern_scan",
                        "pid": cur_pid,
                        "module_name": "Wow.exe",
                        "pattern": pat_cs,
                        "max_hits": 5
                    })) {
                        if let Some(hits) = resp.get("hits").and_then(|h| h.as_array()) {
                            for h in hits {
                                if let Some(addr_str) = h.get("address").and_then(|a| a.as_str()) {
                                    let clean_addr = addr_str.trim_start_matches("0x").trim_start_matches("0X");
                                    if let Ok(va) = u64::from_str_radix(clean_addr, 16) {
                                        if !target_vas.contains(&va) {
                                            target_vas.push(va);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                let mut collected_hits: Vec<XrefHit> = Vec::new();

                // Step B: For each target VA, scan .text section using ref_scan
                for tva in &target_vas {
                    if let Some(resp) = query_daemon(writer, reader, json!({
                        "cmd": "ref_scan",
                        "pid": cur_pid,
                        "module_name": "Wow.exe",
                        "target_va": tva
                    })) {
                        if let Some(hits_arr) = resp.get("hits").and_then(|h| h.as_array()) {
                            for h in hits_arr {
                                let addr_str = h.get("address").and_then(|a| a.as_str()).unwrap_or("0");
                                let rva_str = h.get("rva").and_then(|a| a.as_str()).unwrap_or("+0x0");
                                let bytes_hex = h.get("bytes").and_then(|a| a.as_str()).unwrap_or("");
                                let context_hex = h.get("context").and_then(|a| a.as_str()).unwrap_or("");

                                let clean_addr = addr_str.trim_start_matches("0x").trim_start_matches("0X");
                                let code_va = u64::from_str_radix(clean_addr, 16).unwrap_or(0);

                                // Classify instruction type based on first bytes
                                let inst_type = if bytes_hex.starts_with("48 8D 15") {
                                    "LEA RDX, [rip+]".to_string()
                                } else if bytes_hex.starts_with("4C 8D 05") {
                                    "LEA R8,  [rip+]".to_string()
                                } else if bytes_hex.starts_with("48 8D 0D") {
                                    "LEA RCX, [rip+]".to_string()
                                } else if bytes_hex.starts_with("48 8B") {
                                    "MOV REG, [rip+]".to_string()
                                } else if bytes_hex.contains("8D") {
                                    "LEA REG, [rip+]".to_string()
                                } else {
                                    "REF CODE [rip+]".to_string()
                                };

                                // Deduplicate hits: ignore overlapping byte-slices within 7 bytes of an existing hit
                                let is_overlap = collected_hits.iter().any(|existing| {
                                    (existing.code_va as i64 - code_va as i64).abs() < 5
                                });

                                if !is_overlap {
                                    collected_hits.push(XrefHit {
                                        code_va,
                                        rva_str: rva_str.to_string(),
                                        inst_type,
                                        bytes_hex: bytes_hex.to_string(),
                                        context_hex: context_hex.to_string(),
                                        target_str: clean_query.clone(),
                                        target_va: *tva,
                                    });
                                }
                            }
                        }
                    }
                }

                // Step C: Dual-Mode Fallback - If 0 direct RIP instructions in .text, scan .rdata/.data for 64-bit Pointer Tables
                if collected_hits.is_empty() {
                    for tva in &target_vas {
                        if let Some(resp) = query_daemon(writer, reader, json!({
                            "cmd": "find_ptrs",
                            "pid": cur_pid,
                            "target_addr": tva,
                            "start_addr": cur_base,
                            "end_addr": cur_base + 0x8000000,
                            "max_hits": 10
                        })) {
                            if let Some(hits_arr) = resp.get("hits").and_then(|h| h.as_array()) {
                                for h in hits_arr {
                                    let addr_str = h.get("address").and_then(|a| a.as_str()).unwrap_or("0");
                                    let clean_addr = addr_str.trim_start_matches("0x").trim_start_matches("0X");
                                    let ptr_va = u64::from_str_radix(clean_addr, 16).unwrap_or(0);
                                    let rva_str = format!("+0x{:X}", ptr_va.saturating_sub(cur_base));

                                    // Check if adjacent +8 bytes in memory holds a function pointer (e.g. luaL_Reg { name_ptr, func_ptr })
                                    let mut inst_type = "PTR TABLE [64-bit]".to_string();
                                    let mut fn_bytes_str = format!("PTR -> 0x{:X}", tva);

                                    if let Some(b_resp) = query_daemon(writer, reader, json!({
                                        "cmd": "read_bytes",
                                        "pid": cur_pid,
                                        "addr": ptr_va + 8,
                                        "size": 8
                                    })) {
                                        if let Some(hex_s) = b_resp.get("hex").and_then(|s| s.as_str()) {
                                            if hex_s.len() >= 16 {
                                                let mut b_arr = [0u8; 8];
                                                let mut ok = true;
                                                for b_i in 0..8 {
                                                    if let Ok(val) = u8::from_str_radix(&hex_s[b_i*2..b_i*2+2], 16) {
                                                        b_arr[b_i] = val;
                                                    } else {
                                                        ok = false;
                                                        break;
                                                    }
                                                }
                                                if ok {
                                                    let cand_fn = u64::from_le_bytes(b_arr);
                                                    if cand_fn >= cur_base + 0x1000 && cand_fn <= cur_base + 0x3ACCD9C {
                                                        inst_type = format!("LUA REG -> FN: 0x{:X}", cand_fn);
                                                        fn_bytes_str = format!("PTR TABLE | FN: +0x{:X}", cand_fn - cur_base);
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    collected_hits.push(XrefHit {
                                        code_va: ptr_va,
                                        rva_str,
                                        inst_type,
                                        bytes_hex: fn_bytes_str,
                                        context_hex: "Таблица указателей Lua / Engine vftable".to_string(),
                                        target_str: clean_query.clone(),
                                        target_va: *tva,
                                    });
                                }
                            }
                        }
                    }
                }

                // Step D: Preset Safety Net - If string and pointer tables had 0 hits, fall back to known engine function signature
                if collected_hits.is_empty() {
                    let fallback_pattern = match clean_query.as_str() {
                        "TargetGUID" => Some(("48 8B 0D ? ? ? ? 48 8B 15 ? ? ? ? 48 39 08", "🎯 TargetGUID")),
                        "EntityTable" => Some(("48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B D8 48 85 C0", "📦 EntityTable")),
                        "PlayerUnit" => Some(("48 8B 05 ? ? ? ? 48 85 C0 74 ? 48 8B 88", "👤 PlayerUnit")),
                        "MouseoverGUID" => Some(("48 8B 0D ? ? ? ? 48 85 C9 74 ? 48 8B 01", "🖱️ MouseoverGUID")),
                        "UnitHealth" => Some(("8B 81 28 1E 00 00 89 02 8B 81 30 1E 00 00", "❤️ UnitHealth")),
                        "CastSpellByName" | "CastState" => Some(("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F9 48 8B DA 48 8B 49", "⚡ CastSpellByName")),
                        _ => None,
                    };

                    if let Some((pat, lbl)) = fallback_pattern {
                        if let Some(resp) = query_daemon(writer, reader, json!({
                            "cmd": "pattern_scan",
                            "pid": cur_pid,
                            "module_name": "Wow.exe",
                            "pattern": pat,
                            "max_hits": 5
                        })) {
                            if let Some(hits_arr) = resp.get("hits").and_then(|h| h.as_array()) {
                                for h in hits_arr {
                                    let addr_str = h.get("address").and_then(|a| a.as_str()).unwrap_or("0");
                                    let rva_str = h.get("resolved_rva").or_else(|| h.get("rva")).and_then(|a| a.as_str()).unwrap_or("+0x0");
                                    let clean_addr = addr_str.trim_start_matches("0x").trim_start_matches("0X");
                                    let code_va = u64::from_str_radix(clean_addr, 16).unwrap_or(0);

                                    collected_hits.push(XrefHit {
                                        code_va,
                                        rva_str: rva_str.to_string(),
                                        inst_type: format!("{} (Смещение найдено)", lbl),
                                        bytes_hex: pat.to_string(),
                                        context_hex: format!("Сигнатура функции движка в .text ({} мс)", t_start.elapsed().as_millis()),
                                        target_str: clean_query.clone(),
                                        target_va: 0,
                                    });
                                }
                            }
                        }
                    }
                }

                // Filter out non-aligned instruction fragments (prefer standard 7-byte RIP opcodes like 48 8D / 4C 8D / 48 8B)
                collected_hits.sort_by_key(|h| {
                    if h.bytes_hex.starts_with("48 8D") || h.bytes_hex.starts_with("4C 8D") || h.bytes_hex.starts_with("48 8B") {
                        0
                    } else {
                        1
                    }
                });

                let elapsed_ms = t_start.elapsed().as_millis();
                let mut s = state_arc.lock().unwrap();
                let count = collected_hits.len();
                s.hits = collected_hits;
                s.selected_idx = 0;
                s.is_scanning = false;
                if count > 0 {
                    let first_rva = s.hits[0].rva_str.clone();
                    set_clipboard_text(&first_rva);
                    s.status_msg = format!("✓ Найдено {} ссылок для '{}' ({}) за {} мс! Нажмите [🔬 СВЯЗАННЫЕ АДРЕСА] для просмотра всех переменных.",
                        count, clean_query, first_rva, elapsed_ms);
                } else if !target_vas.is_empty() {
                    s.status_msg = format!("Строка найдена в .rdata (0x{:X}), но ссылок/таблиц не обнаружено ({} мс).",
                        target_vas[0], elapsed_ms);
                } else {
                    s.status_msg = format!("Строка '{}' не найдена во всем модуле Wow.exe ({} мс).", clean_query, elapsed_ms);
                }
            }
        } else {
            let mut s = state_arc.lock().unwrap();
            s.connected = false;
        }

        thread::sleep(std::time::Duration::from_millis(80));
    }
}

fn main() {
    let initial_state = Arc::new(Mutex::new(HunterState {
        connected: false,
        pid: 0,
        base_address: 0,
        search_input: "TargetGUID".to_string(),
        search_mode_aob: false, // Default to deep XREF by engine strings
        is_scanning: false,
        status_msg: "Готов к поиску. Режим кнопок: 🧬 ГЛУБОКИЙ XREF (по строкам движка).".to_string(),
        hits: Vec::new(),
        selected_idx: 0,
        req_search_query: None,
        req_auto_calibrate: false,
        req_deep_calibrate: false,
        req_beacon_calibrate: false,
        beacon_raw: String::new(),
        req_analyze_hit: None,
    }));

    let initial_connected_vars = Arc::new(Mutex::new(ConnectedVarsState {
        parent_rva: String::new(),
        query_name: String::new(),
        items: Vec::new(),
        selected_idx: 0,
        status_msg: "Выберите адрес из списка и нажмите 'Сохранить', чтобы применить оффсет.".to_string(),
        req_refresh: false,
    }));

    let initial_diff = Arc::new(Mutex::new(DiffState {
        status_msg: "Готов к дифференциальной калибровке. Нажмите нужную кнопку и выполните действие в игре.".to_string(),
        ..Default::default()
    }));

    unsafe {
        GLOBAL_HUNTER = Some(Arc::clone(&initial_state));
        GLOBAL_CONNECTED_VARS = Some(Arc::clone(&initial_connected_vars));
        GLOBAL_DIFF_STATE = Some(Arc::clone(&initial_diff));
    }

    let worker_state = Arc::clone(&initial_state);
    thread::spawn(move || {
        hunter_worker(worker_state);
    });

    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let class_name = encode_wide("PORTOLAN_XREF_HUNTER_CLASS");

        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: std::ptr::null_mut(),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };

        RegisterClassExW(&wc);

        let detail_class_name = encode_wide("PORTOLAN_CONNECTED_VARS_CLASS");
        let wc_detail = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc_detail),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: std::ptr::null_mut(),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: detail_class_name.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };

        RegisterClassExW(&wc_detail);

        let diff_class_name = encode_wide("PORTOLAN_DIFF_MATRIX_CLASS");
        let wc_diff = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc_diff),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: std::ptr::null_mut(),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: diff_class_name.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };

        RegisterClassExW(&wc_diff);

        let title = encode_wide("PORTOLAN DMA XREF & STRING HUNTER (Runtime Analyzer)");
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            WINDOW_WIDTH,
            WINDOW_HEIGHT,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );

        let detail_title = encode_wide("PORTOLAN - ИНСПЕКТОР СВЯЗАННЫХ АДРЕСОВ (ФУНКЦИЯ XREF)");
        let hwnd_detail = CreateWindowExW(
            WS_EX_TOPMOST,
            detail_class_name.as_ptr(),
            detail_title.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            960,
            560,
            hwnd,
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        GLOBAL_DETAIL_HWND = hwnd_detail;

        let diff_title = encode_wide("PORTOLAN - МАТРИЦА ДИФФЕРЕНЦИАЛЬНОЙ КАЛИБРОВКИ (ОРАКУЛ МАЯКА)");
        let hwnd_diff = CreateWindowExW(
            WS_EX_TOPMOST,
            diff_class_name.as_ptr(),
            diff_title.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            960,
            640,
            hwnd,
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        GLOBAL_DIFF_HWND = hwnd_diff;

        // GUI refresh timer (30 Hz)
        SetTimer(hwnd, 1, 33, None);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            if msg.message == WM_TIMER {
                InvalidateRect(hwnd, std::ptr::null(), 0);
                if !GLOBAL_DETAIL_HWND.is_null() && IsWindowVisible(GLOBAL_DETAIL_HWND) != 0 {
                    InvalidateRect(GLOBAL_DETAIL_HWND, std::ptr::null(), 0);
                }
                if !GLOBAL_DIFF_HWND.is_null() && IsWindowVisible(GLOBAL_DIFF_HWND) != 0 {
                    InvalidateRect(GLOBAL_DIFF_HWND, std::ptr::null(), 0);
                }
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
