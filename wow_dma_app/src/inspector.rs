// language: Rust, file: src/inspector.rs, target: Windows 11, MSVC x64
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use serde_json::{json, Value};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{ReleaseCapture, SetCapture};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const WINDOW_WIDTH: i32 = 1180;
const WINDOW_HEIGHT: i32 = 720;
const BYTES_TO_READ: usize = 384; // 24 rows of 16 bytes

struct InspectorState {
    connected: bool,
    pid: u32,
    base_address: u64,
    current_address: u64,
    anchor_address: u64, // Base anchor for calculating relative offsets (+0x0000, +0x1E28, etc.)
    origin_name: String,
    
    // Quick anchor addresses
    player_unit: u64,
    target_unit: u64,
    mouseover_unit: u64,
    entity_table: u64,

    // Memory buffer
    buffer: Vec<u8>,
    selected_offset: usize, // 0..BYTES_TO_READ
    
    // Matched search highlight
    match_addr: Option<u64>,
    match_len: usize,
    
    // Column positions and drag state
    col_addr_x: i32,
    col_hex_x: i32,
    col_ascii_x: i32,
    dragging_col: usize, // 0 = none, 1 = addr, 2 = hex, 3 = ascii

    // UI state
    is_live: bool,
    address_input: String,
    search_input: String,
    active_input_box: usize, // 0 = none, 1 = address, 2 = search
    status_msg: String,
    status_flash: u32,
    
    // Commands queued to worker
    req_jump_address: Option<u64>,
    req_search_val: Option<(String, bool)>, // (query, is_global)
}

static mut GLOBAL_STATE: Option<Arc<Mutex<InspectorState>>> = None;

fn encode_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

const CF_UNICODETEXT: u32 = 13;

fn get_clipboard_text() -> Option<String> {
    unsafe {
        use windows_sys::Win32::System::DataExchange::*;
        use windows_sys::Win32::System::Memory::*;

        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return None;
        }
        let handle = GetClipboardData(CF_UNICODETEXT as u32);
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
                SetClipboardData(CF_UNICODETEXT as u32, h_mem);
            }
        }
        CloseClipboard();
        true
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

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            SetTimer(hwnd, 1, 50, None); // 20 FPS redraw
            0
        }
        WM_ERASEBKGND => 1,
        WM_GETMINMAXINFO => {
            let mmi = lparam as *mut MINMAXINFO;
            if !mmi.is_null() {
                (*mmi).ptMinTrackSize.x = 980;
                (*mmi).ptMinTrackSize.y = 650;
            }
            0
        }
        WM_TIMER => {
            if let Some(ref state_arc) = GLOBAL_STATE {
                let mut state = state_arc.lock().unwrap();
                if state.status_flash > 0 {
                    state.status_flash -= 1;
                }
            }
            InvalidateRect(hwnd, std::ptr::null(), 0);
            0
        }
        WM_MOUSEWHEEL => {
            let delta = ((wparam >> 16) as i16) as i32;
            if let Some(ref state_arc) = GLOBAL_STATE {
                let mut state = state_arc.lock().unwrap();
                let step = if delta > 0 {
                    state.current_address.saturating_sub(0x20)
                } else {
                    state.current_address.saturating_add(0x20)
                };
                state.current_address = step;
                state.address_input = format!("0x{:X}", state.current_address);
                state.req_jump_address = Some(step);
            }
            0
        }
        WM_LBUTTONDOWN => {
            let x = (lparam & 0xFFFF) as i32;
            let y = ((lparam >> 16) & 0xFFFF) as i32;

            if let Some(ref state_arc) = GLOBAL_STATE {
                let mut s = state_arc.lock().unwrap();

                // 1. Quick Jump Buttons (y = 52..82)
                // [ ИГРОК ] (x = 18..110)
                if y >= 52 && y <= 82 && x >= 18 && x <= 110 {
                    if s.player_unit != 0 {
                        s.current_address = s.player_unit;
                        s.anchor_address = s.player_unit;
                        s.address_input = format!("0x{:X}", s.current_address);
                        s.origin_name = "PlayerUnit (Игрок)".to_string();
                        s.req_jump_address = Some(s.current_address);
                    }
                }
                // [ ЦЕЛЬ ] (x = 118..200)
                else if y >= 52 && y <= 82 && x >= 118 && x <= 200 {
                    if s.target_unit != 0 {
                        s.current_address = s.target_unit;
                        s.anchor_address = s.target_unit;
                        s.address_input = format!("0x{:X}", s.current_address);
                        s.origin_name = "TargetUnit (Цель)".to_string();
                        s.req_jump_address = Some(s.current_address);
                    }
                }
                // [ КУРСОР ] (x = 208..290)
                else if y >= 52 && y <= 82 && x >= 208 && x <= 290 {
                    if s.mouseover_unit != 0 {
                        s.current_address = s.mouseover_unit;
                        s.anchor_address = s.mouseover_unit;
                        s.address_input = format!("0x{:X}", s.current_address);
                        s.origin_name = "MouseoverUnit (Под курсором)".to_string();
                        s.req_jump_address = Some(s.current_address);
                    }
                }
                // [ ENTITY TABLE ] (x = 298..410)
                else if y >= 52 && y <= 82 && x >= 298 && x <= 410 {
                    if s.entity_table != 0 {
                        s.current_address = s.entity_table;
                        s.anchor_address = s.entity_table;
                        s.address_input = format!("0x{:X}", s.current_address);
                        s.origin_name = "EntityTable Root".to_string();
                        s.req_jump_address = Some(s.current_address);
                    }
                }
                // [ WOW BASE ] (x = 418..510)
                else if y >= 52 && y <= 82 && x >= 418 && x <= 510 {
                    if s.base_address != 0 {
                        s.current_address = s.base_address;
                        s.anchor_address = s.base_address;
                        s.address_input = format!("0x{:X}", s.current_address);
                        s.origin_name = "Wow.exe Base Module".to_string();
                        s.req_jump_address = Some(s.current_address);
                    }
                }

                // 2. Step Buttons (y = 52..82)
                // [ -0x100 ] (x = 525..585)
                else if y >= 52 && y <= 82 && x >= 525 && x <= 585 {
                    s.current_address = s.current_address.saturating_sub(0x100);
                    s.address_input = format!("0x{:X}", s.current_address);
                    s.req_jump_address = Some(s.current_address);
                }
                // [ -0x20 ] (x = 590..645)
                else if y >= 52 && y <= 82 && x >= 590 && x <= 645 {
                    s.current_address = s.current_address.saturating_sub(0x20);
                    s.address_input = format!("0x{:X}", s.current_address);
                    s.req_jump_address = Some(s.current_address);
                }
                // [ +0x20 ] (x = 650..705)
                else if y >= 52 && y <= 82 && x >= 650 && x <= 705 {
                    s.current_address = s.current_address.saturating_add(0x20);
                    s.address_input = format!("0x{:X}", s.current_address);
                    s.req_jump_address = Some(s.current_address);
                }
                // [ +0x100 ] (x = 710..770)
                else if y >= 52 && y <= 82 && x >= 710 && x <= 770 {
                    s.current_address = s.current_address.saturating_add(0x100);
                    s.address_input = format!("0x{:X}", s.current_address);
                    s.req_jump_address = Some(s.current_address);
                }

                // 3. Live toggle (x = 810..940, y = 52..82)
                else if y >= 52 && y <= 82 && x >= 810 && x <= 940 {
                    s.is_live = !s.is_live;
                }
                // [ ⚓ ПОСТАВИТЬ ЯКОРЬ ] (x = 950..1120, y = 52..82)
                else if y >= 52 && y <= 82 && x >= 950 && x <= 1120 {
                    let sel_addr = s.current_address.wrapping_add(s.selected_offset as u64);
                    s.anchor_address = sel_addr;
                    s.origin_name = format!("Ручной якорь (0x{:X})", sel_addr);
                    s.status_msg = format!("⚓ Якорь отсчета установлен на адрес: 0x{:X}", sel_addr);
                }

                // 4. Address input click (x = 18..260, y = 92..122)
                else if y >= 92 && y <= 122 && x >= 18 && x <= 260 {
                    s.active_input_box = 1;
                }
                // [ ПЕРЕЙТИ ] button (x = 265..350, y = 92..122)
                else if y >= 92 && y <= 122 && x >= 265 && x <= 350 {
                    s.active_input_box = 0;
                    let clean = s.address_input.trim_start_matches("0x").trim_start_matches("0X").trim();
                    if let Ok(addr) = u64::from_str_radix(clean, 16) {
                        s.current_address = addr;
                        s.anchor_address = addr;
                        s.req_jump_address = Some(addr);
                        s.origin_name = "Пользовательский адрес".to_string();
                    }
                }

                // 5. Search input click (x = 510..760, y = 92..122)
                else if y >= 92 && y <= 122 && x >= 510 && x <= 760 {
                    s.active_input_box = 2;
                }
                // [ ВПЕРЕД ] button (x = 768..868, y = 92..122) - Local search +64 KB
                else if y >= 92 && y <= 122 && x >= 768 && x <= 868 {
                    s.active_input_box = 0;
                    if !s.search_input.trim().is_empty() {
                        s.req_search_val = Some((s.search_input.clone(), false));
                    }
                }
                // [ ГЛОБАЛЬНО ] button (x = 876..1020, y = 92..122) - Global module search
                else if y >= 92 && y <= 122 && x >= 876 && x <= 1020 {
                    s.active_input_box = 0;
                    if !s.search_input.trim().is_empty() {
                        s.req_search_val = Some((s.search_input.clone(), true));
                    }
                }

                // Column Dividers Drag Initiation (y = 130..152)
                else if y >= 130 && y <= 152 {
                    if (x - s.col_addr_x).abs() <= 6 {
                        s.dragging_col = 1;
                        unsafe { SetCapture(hwnd); }
                    } else if (x - s.col_hex_x).abs() <= 6 {
                        s.dragging_col = 2;
                        unsafe { SetCapture(hwnd); }
                    } else if (x - s.col_ascii_x).abs() <= 6 {
                        s.dragging_col = 3;
                        unsafe { SetCapture(hwnd); }
                    }
                }

                // 6. Click in Hex Grid to select byte/row (x = 18..670, y = 153..495)
                else if y >= 153 && y <= 495 && x >= 18 && x <= 670 {
                    let row = ((y - 153) / 15) as usize;
                    if row < 22 {
                        let col_step = std::cmp::max(16, (s.col_ascii_x - s.col_hex_x - 14) / 16);
                        let col = if x >= s.col_hex_x && x < s.col_ascii_x {
                            let rel_x = x - s.col_hex_x - 4;
                            (rel_x / col_step).clamp(0, 15) as usize
                        } else if x >= s.col_ascii_x {
                            let rel_x = x - s.col_ascii_x - 4;
                            (rel_x / 7).clamp(0, 15) as usize
                        } else {
                            0
                        };
                        s.selected_offset = row * 16 + col;
                    }
                }
                // 7. Click in Type Inspector to copy values directly (x = 680..1160, y = 132..495)
                else if x >= 680 && y >= 132 && y <= 495 {
                    let sel_idx = s.selected_offset;
                    let sel_addr = s.current_address.wrapping_add(sel_idx as u64);
                    let off_str = if s.anchor_address != 0 {
                        if sel_addr >= s.anchor_address {
                            format!("+0x{:04X}", sel_addr - s.anchor_address)
                        } else {
                            format!("-0x{:04X}", s.anchor_address - sel_addr)
                        }
                    } else {
                        format!("+0x{:04X}", sel_idx)
                    };

                    let get_bytes = |len: usize| -> Vec<u8> {
                        let mut b = Vec::new();
                        for i in 0..len {
                            if sel_idx + i < s.buffer.len() {
                                b.push(s.buffer[sel_idx + i]);
                            } else {
                                b.push(0);
                            }
                        }
                        b
                    };
                    let b4 = get_bytes(4);
                    let b8 = get_bytes(8);
                    let u32_val = u32::from_le_bytes(b4.as_slice().try_into().unwrap_or([0; 4]));
                    let u64_val = u64::from_le_bytes(b8.as_slice().try_into().unwrap_or([0; 8]));
                    let f32_val = f32::from_le_bytes(b4.as_slice().try_into().unwrap_or([0; 4]));

                    // Check if clicked button [КОПИР. ОФФСЕТ] (x = 830..940, y = 136..160)
                    if x >= 830 && x <= 940 && y >= 136 && y <= 160 {
                        set_clipboard_text(&off_str);
                        s.status_msg = format!("Смещение {} скопировано в буфер обмена.", off_str);
                    }
                    // Check if clicked button [КОПИР. АДРЕС] (x = 948..1060, y = 136..160)
                    else if x >= 948 && x <= 1060 && y >= 136 && y <= 160 {
                        let addr_str = format!("0x{:X}", sel_addr);
                        set_clipboard_text(&addr_str);
                        s.status_msg = format!("Адрес {} скопирован в буфер обмена.", addr_str);
                    }
                    // Clicked on row: UInt32 (y = 285..315)
                    else if y >= 285 && y < 315 {
                        let v_str = format!("{}", u32_val);
                        set_clipboard_text(&v_str);
                        s.status_msg = format!("UInt32: {} скопировано в буфер обмена.", v_str);
                    }
                    // Clicked on row: UInt64 (y = 335..365)
                    else if y >= 335 && y < 365 {
                        let v_str = format!("0x{:016X}", u64_val);
                        set_clipboard_text(&v_str);
                        s.status_msg = format!("UInt64: {} скопировано в буфер обмена.", v_str);
                    }
                    // Clicked on row: Float32 (y = 385..415)
                    else if y >= 385 && y < 415 {
                        let v_str = format!("{:.4}", f32_val);
                        set_clipboard_text(&v_str);
                        s.status_msg = format!("Float32: {} скопировано в буфер обмена.", v_str);
                    }
                    // Clicked anywhere on header (y = 160..190)
                    else if y >= 160 && y <= 190 {
                        let combo = format!("{} (0x{:X})", off_str, sel_addr);
                        set_clipboard_text(&combo);
                        s.status_msg = format!("Скопировано в буфер: {}", combo);
                    }
                } else {
                    s.active_input_box = 0;
                }
            }
            0
        }
        WM_RBUTTONDOWN => {
            let x = (lparam & 0xFFFF) as i32;
            let y = ((lparam >> 16) & 0xFFFF) as i32;
            if let Some(ref state_arc) = GLOBAL_STATE {
                let mut s = state_arc.lock().unwrap();
                // If right-clicked on Search Box (x = 540..760, y = 92..122) -> Instant Paste
                if y >= 92 && y <= 122 && x >= 540 && x <= 760 {
                    if let Some(clip) = get_clipboard_text() {
                        let clean = clip.trim().replace("\r", "").replace("\n", "");
                        if !clean.is_empty() {
                            s.search_input = clean.clone();
                            s.active_input_box = 2;
                            s.status_msg = format!("Вставлена строка из буфера: {}", clean);
                        }
                    }
                }
                // If right-clicked on Address Box (x = 18..260, y = 92..122) -> Instant Paste
                else if y >= 92 && y <= 122 && x >= 18 && x <= 260 {
                    if let Some(clip) = get_clipboard_text() {
                        let clean = clip.trim().replace("\r", "").replace("\n", "");
                        if !clean.is_empty() {
                            s.address_input = clean.clone();
                            s.active_input_box = 1;
                            s.status_msg = format!("Вставлен адрес из буфера: {}", clean);
                        }
                    }
                }
                // If right-clicked in Hex Grid -> select and copy clicked byte address
                else if y >= 153 && y <= 495 && x >= 18 && x <= 670 {
                    let row = ((y - 153) / 15) as usize;
                    if row < 22 {
                        let col_step = std::cmp::max(16, (s.col_ascii_x - s.col_hex_x - 14) / 16);
                        let col = if x >= s.col_hex_x && x < s.col_ascii_x {
                            let rel_x = x - s.col_hex_x - 4;
                            (rel_x / col_step).clamp(0, 15) as usize
                        } else if x >= s.col_ascii_x {
                            let rel_x = x - s.col_ascii_x - 4;
                            (rel_x / 7).clamp(0, 15) as usize
                        } else {
                            0
                        };
                        s.selected_offset = row * 16 + col;
                        let sel_addr = s.current_address.wrapping_add(s.selected_offset as u64);
                        let copy_str = format!("0x{:X}", sel_addr);
                        set_clipboard_text(&copy_str);
                        s.status_msg = format!("Скопирован адрес 0x{:X} в буфер обмена.", sel_addr);
                    }
                }
            }
            0
        }
        WM_CHAR => {
            let ch = (wparam as u8) as char;
            if let Some(ref state_arc) = GLOBAL_STATE {
                let mut s = state_arc.lock().unwrap();

                // Global Ctrl + C (copy selected address & offset)
                if ch == '\x03' {
                    let sel_idx = s.selected_offset;
                    let sel_addr = s.current_address.wrapping_add(sel_idx as u64);
                    let off_str = if s.anchor_address != 0 {
                        if sel_addr >= s.anchor_address {
                            format!("+0x{:04X}", sel_addr - s.anchor_address)
                        } else {
                            format!("-0x{:04X}", s.anchor_address - sel_addr)
                        }
                    } else {
                        format!("+0x{:04X}", sel_idx)
                    };
                    let copy_text = format!("0x{:X}", sel_addr);
                    set_clipboard_text(&copy_text);
                    s.status_msg = format!("Скопирован адрес 0x{:X} (смещение {}) в буфер обмена.", sel_addr, off_str);
                }

                if s.active_input_box == 1 {
                    // Address input
                    if ch == '\x16' { // Ctrl + V
                        if let Some(clip) = get_clipboard_text() {
                            let clean = clip.trim().replace("\r", "").replace("\n", "");
                            if !clean.is_empty() {
                                s.address_input = clean.clone();
                                s.status_msg = format!("Вставлен адрес из буфера: {}", clean);
                            }
                        }
                    } else if ch == '\r' || ch == '\n' {
                        s.active_input_box = 0;
                        let clean = s.address_input.trim_start_matches("0x").trim_start_matches("0X").trim();
                        if let Ok(addr) = u64::from_str_radix(clean, 16) {
                            s.current_address = addr;
                            s.req_jump_address = Some(addr);
                        }
                    } else if ch == '\x08' {
                        s.address_input.pop();
                    } else if ch.is_ascii_hexdigit() || ch == 'x' || ch == 'X' {
                        if s.address_input.len() < 20 {
                            s.address_input.push(ch);
                        }
                    }
                } else if s.active_input_box == 2 {
                    // Search input
                    if ch == '\x16' { // Ctrl + V
                        if let Some(clip) = get_clipboard_text() {
                            let clean = clip.trim().replace("\r", "").replace("\n", "");
                            if !clean.is_empty() {
                                s.search_input = clean.clone();
                                s.status_msg = format!("Вставлена строка из буфера: {}", clean);
                            }
                        }
                    } else if ch == '\r' || ch == '\n' {
                        s.active_input_box = 0;
                        if !s.search_input.trim().is_empty() {
                            s.req_search_val = Some((s.search_input.clone(), false));
                        }
                    } else if ch == '\x08' {
                        s.search_input.pop();
                    } else if ch.is_ascii_graphic() || ch == ' ' {
                        if s.search_input.len() < 30 {
                            s.search_input.push(ch);
                        }
                    }
                }
            }
            0
        }
        WM_MOUSEMOVE => {
            let x = (lparam & 0xFFFF) as i16 as i32;
            if let Some(ref state_arc) = GLOBAL_STATE {
                let mut s = state_arc.lock().unwrap();
                if s.dragging_col != 0 {
                    match s.dragging_col {
                        1 => {
                            s.col_addr_x = x.clamp(50, s.col_hex_x - 50);
                        }
                        2 => {
                            s.col_hex_x = x.clamp(s.col_addr_x + 50, s.col_ascii_x - 120);
                        }
                        3 => {
                            s.col_ascii_x = x.clamp(s.col_hex_x + 120, 660);
                        }
                        _ => {}
                    }
                    unsafe {
                        InvalidateRect(hwnd, std::ptr::null(), 0);
                    }
                }
            }
            0
        }
        WM_LBUTTONUP => {
            if let Some(ref state_arc) = GLOBAL_STATE {
                let mut s = state_arc.lock().unwrap();
                if s.dragging_col != 0 {
                    s.dragging_col = 0;
                    unsafe {
                        ReleaseCapture();
                    }
                }
            }
            0
        }
        WM_SETCURSOR => {
            let mut pt: POINT = std::mem::zeroed();
            unsafe {
                GetCursorPos(&mut pt);
                ScreenToClient(hwnd, &mut pt);
            }
            if pt.y >= 130 && pt.y <= 495 {
                if let Some(ref state_arc) = GLOBAL_STATE {
                    let s = state_arc.lock().unwrap();
                    if (pt.x - s.col_addr_x).abs() <= 5 || (pt.x - s.col_hex_x).abs() <= 5 || (pt.x - s.col_ascii_x).abs() <= 5 {
                        unsafe {
                            SetCursor(LoadCursorW(std::ptr::null_mut(), IDC_SIZEWE));
                            return 1;
                        }
                    }
                }
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
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

            let h_font_title = CreateFontW(17, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_font_ui = CreateFontW(14, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_font_bold = CreateFontW(14, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_font_mono = CreateFontW(13, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, mono_name.as_ptr());
            let h_font_mono_bold = CreateFontW(13, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, mono_name.as_ptr());

            let old_font = SelectObject(mem_dc, h_font_ui);

            if let Some(ref state_arc) = GLOBAL_STATE {
                let s = state_arc.lock().unwrap();

                // 1. Header (y = 12..45)
                SelectObject(mem_dc, h_font_title);
                SetTextColor(mem_dc, 0x00F0FF); // Cyan
                let title = encode_wide("PORTOLAN DMA LIVE MEMORY INSPECTOR");
                TextOutW(mem_dc, 18, 12, title.as_ptr(), title.len() as i32);

                SelectObject(mem_dc, h_font_ui);
                SetTextColor(mem_dc, if s.connected { 0x88FF00 } else { 0x5555FF });
                let conn_str = if s.connected {
                    format!("● 127.0.0.1:8765   |   PID: {} (Wow.exe)   |   Base: 0x{:016X}", s.pid, s.base_address)
                } else {
                    "○ Ожидание соединения с dma_daemon (127.0.0.1:8765)...".to_string()
                };
                let cw = encode_wide(&conn_str);
                TextOutW(mem_dc, 350, 15, cw.as_ptr(), cw.len() as i32);

                // 2. Navigation & Anchor Toolbar (y = 52..82)
                let make_btn = |left: i32, right: i32, text: &str, is_active: bool, bg_color: u32, text_color: u32| {
                    draw_rounded_card(mem_dc, left, 52, right, 82, bg_color);
                    if is_active {
                        draw_card_border(mem_dc, left, 52, right, 82, 0x00F0FF);
                    }
                    SelectObject(mem_dc, h_font_bold);
                    SetTextColor(mem_dc, text_color);
                    let w = encode_wide(text);
                    TextOutW(mem_dc, left + 8, 58, w.as_ptr(), w.len() as i32);
                };

                make_btn(18, 110, "ИГРОК", s.current_address == s.player_unit && s.player_unit != 0, 0x2A2218, 0xFFD700);
                make_btn(118, 200, "ЦЕЛЬ", s.current_address == s.target_unit && s.target_unit != 0, 0x2A2218, 0x88FF00);
                make_btn(208, 290, "КУРСОР", s.current_address == s.mouseover_unit && s.mouseover_unit != 0, 0x2A2218, 0x00F0FF);
                make_btn(298, 410, "ENTITY TABLE", s.current_address == s.entity_table && s.entity_table != 0, 0x221D1A, 0xCCCCCC);
                make_btn(418, 510, "WOW BASE", s.current_address == s.base_address && s.base_address != 0, 0x221D1A, 0xCCCCCC);

                // Steps
                make_btn(525, 585, "-0x100", false, 0x241C18, 0x9E948B);
                make_btn(590, 645, "-0x20", false, 0x241C18, 0x9E948B);
                make_btn(650, 705, "+0x20", false, 0x241C18, 0x9E948B);
                make_btn(710, 770, "+0x100", false, 0x241C18, 0x9E948B);

                // Live toggle button
                let (live_text, live_bg, live_fg) = if s.is_live {
                    ("● LIVE 10 Hz", 0x1E3820, 0x88FF00)
                } else {
                    ("⏸ ПАУЗА", 0x38201E, 0x5555FF)
                };
                make_btn(800, 930, live_text, false, live_bg, live_fg);
                make_btn(940, 1120, "⚓ ПОСТАВИТЬ ЯКОРЬ", false, 0x2E2818, 0xFFD700);

                // 3. Address and Search Bar (y = 92..122)
                // Address Box
                draw_rounded_card(mem_dc, 18, 92, 260, 122, if s.active_input_box == 1 { 0x382A20 } else { 0x221B18 });
                draw_card_border(mem_dc, 18, 92, 260, 122, if s.active_input_box == 1 { 0x00F0FF } else { 0x44362E });
                SelectObject(mem_dc, h_font_mono_bold);
                SetTextColor(mem_dc, 0xFFFFFF);
                let cur_addr_w = encode_wide(&s.address_input);
                TextOutW(mem_dc, 26, 98, cur_addr_w.as_ptr(), cur_addr_w.len() as i32);

                // Go Button
                draw_rounded_card(mem_dc, 265, 92, 350, 122, 0x352A22);
                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, 0x00F0FF);
                let go_w = encode_wide("ПЕРЕЙТИ");
                TextOutW(mem_dc, 276, 98, go_w.as_ptr(), go_w.len() as i32);

                // Origin Label
                SelectObject(mem_dc, h_font_ui);
                SetTextColor(mem_dc, 0x9E948B);
                let origin_str = if s.anchor_address != 0 {
                    format!("Метка: {}  [База: 0x{:X}]", s.origin_name, s.anchor_address)
                } else {
                    format!("Метка: {}", s.origin_name)
                };
                let origin_w = encode_wide(&origin_str);
                TextOutW(mem_dc, 360, 98, origin_w.as_ptr(), origin_w.len() as i32);

                // Search Box
                draw_rounded_card(mem_dc, 540, 92, 760, 122, if s.active_input_box == 2 { 0x382A20 } else { 0x221B18 });
                draw_card_border(mem_dc, 540, 92, 760, 122, if s.active_input_box == 2 { 0x00F0FF } else { 0x44362E });
                SelectObject(mem_dc, h_font_mono);
                SetTextColor(mem_dc, if s.search_input.is_empty() { 0x6E6E6E } else { 0xFFFFFF });
                let st = if s.search_input.is_empty() { "Поиск: число, hex или строка...".to_string() } else { s.search_input.clone() };
                let st_w = encode_wide(&st);
                TextOutW(mem_dc, 548, 98, st_w.as_ptr(), st_w.len() as i32);

                // Local Search Button [ВПЕРЕД]
                draw_rounded_card(mem_dc, 768, 92, 868, 122, 0x352A22);
                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, 0xFFD700);
                let s_btn_w = encode_wide("ВПЕРЕД");
                TextOutW(mem_dc, 786, 98, s_btn_w.as_ptr(), s_btn_w.len() as i32);

                // Global Search Button [ГЛОБАЛЬНО]
                draw_rounded_card(mem_dc, 876, 92, 1020, 122, 0x223822);
                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, 0x88FF00);
                let g_btn_w = encode_wide("ГЛОБАЛЬНО");
                TextOutW(mem_dc, 894, 98, g_btn_w.as_ptr(), g_btn_w.len() as i32);

                // 4. Memory Hex Dump Grid (y = 132..495)
                draw_rounded_card(mem_dc, 18, 132, 670, 495, 0x1A1412);
                draw_card_border(mem_dc, 18, 132, 670, 495, 0x362822);

                // Grid Header (Dynamic column headers + visual drag dividers)
                SelectObject(mem_dc, h_font_mono_bold);
                SetTextColor(mem_dc, 0x00F0FF);
                let off_hdr = encode_wide("OFFSET");
                TextOutW(mem_dc, 26, 136, off_hdr.as_ptr(), off_hdr.len() as i32);

                // Divider 1 (Address)
                draw_card_border(mem_dc, s.col_addr_x - 3, 134, s.col_addr_x - 2, 150, 0x55443A);
                let addr_hdr = encode_wide("ADDRESS");
                TextOutW(mem_dc, s.col_addr_x + 4, 136, addr_hdr.as_ptr(), addr_hdr.len() as i32);

                // Divider 2 (Hex)
                draw_card_border(mem_dc, s.col_hex_x - 3, 134, s.col_hex_x - 2, 150, 0x55443A);
                let hex_hdr = encode_wide("00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F");
                TextOutW(mem_dc, s.col_hex_x + 4, 136, hex_hdr.as_ptr(), hex_hdr.len() as i32);

                // Divider 3 (ASCII)
                draw_card_border(mem_dc, s.col_ascii_x - 3, 134, s.col_ascii_x - 2, 150, 0x55443A);
                let asc_hdr = encode_wide("ASCII");
                TextOutW(mem_dc, s.col_ascii_x + 4, 136, asc_hdr.as_ptr(), asc_hdr.len() as i32);

                // Grid rows
                let mut row_y = 153;
                let sel_row = s.selected_offset / 16;
                let _sel_col = s.selected_offset % 16;
                let col_step = std::cmp::max(16, (s.col_ascii_x - s.col_hex_x - 14) / 16);

                for r in 0..22 {
                    let base_off = r * 16;
                    let row_addr = s.current_address.wrapping_add(base_off as u64);

                    if r == sel_row {
                        draw_rounded_card(mem_dc, 20, row_y - 1, 668, row_y + 14, 0x2A201A);
                    }

                    // 1. Offset relative to Anchor Base
                    SelectObject(mem_dc, h_font_mono);
                    SetTextColor(mem_dc, 0x7E7770);
                    let off_str = if s.anchor_address != 0 {
                        if row_addr >= s.anchor_address {
                            format!("+0x{:04X}", row_addr - s.anchor_address)
                        } else {
                            format!("-0x{:04X}", s.anchor_address - row_addr)
                        }
                    } else {
                        format!("+0x{:04X}", base_off)
                    };
                    let off_w = encode_wide(&off_str);
                    TextOutW(mem_dc, 26, row_y, off_w.as_ptr(), off_w.len() as i32);

                    // 2. Absolute Address
                    SetTextColor(mem_dc, 0x9E948B);
                    let addr_str = format!("0x{:012X}", row_addr);
                    let addr_w = encode_wide(&addr_str);
                    TextOutW(mem_dc, s.col_addr_x + 4, row_y, addr_w.as_ptr(), addr_w.len() as i32);

                    // 3. Hex Bytes and ASCII Column (byte-by-byte with match highlight)
                    for c in 0..16 {
                        let idx = base_off + c;
                        let byte_addr = row_addr.wrapping_add(c as u64);
                        let b = if idx < s.buffer.len() { s.buffer[idx] } else { 0 };

                        let is_match = if let Some(ma) = s.match_addr {
                            byte_addr >= ma && byte_addr < ma.wrapping_add(s.match_len as u64)
                        } else {
                            false
                        };
                        let is_sel = idx == s.selected_offset;

                        let byte_x = s.col_hex_x + 4 + (c as i32) * col_step;
                        let ascii_x = s.col_ascii_x + 4 + (c as i32) * 7;

                        // Visual highlight background & borders
                        if is_match {
                            // Glowing Emerald Card + Neon Border for matched value
                            draw_rounded_card(mem_dc, byte_x - 2, row_y - 1, byte_x + 19, row_y + 14, 0x1E4A35);
                            draw_card_border(mem_dc, byte_x - 2, row_y - 1, byte_x + 19, row_y + 14, 0x00FF88);
                            draw_rounded_card(mem_dc, ascii_x - 1, row_y - 1, ascii_x + 8, row_y + 14, 0x1E4A35);
                        } else if is_sel {
                            // Cyan border for user-selected byte
                            draw_card_border(mem_dc, byte_x - 2, row_y - 1, byte_x + 19, row_y + 14, 0x00F0FF);
                            draw_card_border(mem_dc, ascii_x - 1, row_y - 1, ascii_x + 8, row_y + 14, 0x00F0FF);
                        }

                        // Text colors: dim zeroes, bright match, cyan selection, silver normal
                        let (hex_color, asc_color) = if is_match {
                            (0x00FF88, 0x00FF88) // Neon Green / Gold
                        } else if is_sel {
                            (0x00F0FF, 0x00F0FF) // Cyan
                        } else if b == 0 {
                            (0x554E48, 0x554E48) // Dim gray for zero bytes
                        } else {
                            (0xD4C4B5, if b >= 32 && b <= 126 { 0x00F0FF } else { 0x66605A }) // Silver & Cyan ASCII
                        };

                        // Render Hex Byte
                        SelectObject(mem_dc, if is_match || is_sel { h_font_mono_bold } else { h_font_mono });
                        SetTextColor(mem_dc, hex_color);
                        let b_str = format!("{:02X}", b);
                        let bw = encode_wide(&b_str);
                        TextOutW(mem_dc, byte_x, row_y, bw.as_ptr(), bw.len() as i32);

                        // Render ASCII Char
                        let asc_char = if b >= 32 && b <= 126 { b as char } else { '.' };
                        let mut asc_str = String::new();
                        asc_str.push(asc_char);
                        let aw = encode_wide(&asc_str);
                        SetTextColor(mem_dc, asc_color);
                        TextOutW(mem_dc, ascii_x, row_y, aw.as_ptr(), aw.len() as i32);
                    }

                    row_y += 15;
                }

                let panel_right = std::cmp::max(width - 18, 962);
                let bottom_y = std::cmp::max(height - 18, 670);

                // 5. Type Inspector Side Card (x = 680..panel_right, y = 132..495)
                draw_rounded_card(mem_dc, 680, 132, panel_right, 495, 0x1E1714);
                draw_card_border(mem_dc, 680, 132, panel_right, 495, 0x362822);

                SelectObject(mem_dc, h_font_title);
                SetTextColor(mem_dc, 0xFFD700); // Gold
                let insp_title = encode_wide("ИНСПЕКТОР ТИПОВ");
                TextOutW(mem_dc, 695, 140, insp_title.as_ptr(), insp_title.len() as i32);

                // Quick Copy Buttons
                draw_rounded_card(mem_dc, 830, 136, 940, 158, 0x2A201A);
                draw_card_border(mem_dc, 830, 136, 940, 158, 0x44362E);
                SelectObject(mem_dc, h_font_ui);
                SetTextColor(mem_dc, 0x00F0FF);
                let btn_off_w = encode_wide("КОПИР. ОФФСЕТ");
                TextOutW(mem_dc, 836, 140, btn_off_w.as_ptr(), btn_off_w.len() as i32);

                draw_rounded_card(mem_dc, 948, 136, 1060, 158, 0x2A201A);
                draw_card_border(mem_dc, 948, 136, 1060, 158, 0x44362E);
                SetTextColor(mem_dc, 0x88FF00);
                let btn_addr_w = encode_wide("КОПИР. АДРЕС");
                TextOutW(mem_dc, 956, 140, btn_addr_w.as_ptr(), btn_addr_w.len() as i32);

                let sel_idx = s.selected_offset;
                let sel_addr = s.current_address.wrapping_add(sel_idx as u64);

                let is_sel_match = if let Some(ma) = s.match_addr {
                    sel_addr >= ma && sel_addr < ma.wrapping_add(s.match_len as u64)
                } else {
                    false
                };

                let rel_offset = if s.anchor_address != 0 && sel_addr >= s.anchor_address {
                    (sel_addr - s.anchor_address) as usize
                } else {
                    sel_idx
                };

                let off_label = if s.anchor_address != 0 {
                    if sel_addr >= s.anchor_address {
                        format!("+0x{:04X}", sel_addr - s.anchor_address)
                    } else {
                        format!("-0x{:04X}", s.anchor_address - sel_addr)
                    }
                } else {
                    format!("+0x{:04X}", sel_idx)
                };

                SelectObject(mem_dc, h_font_ui);
                SetTextColor(mem_dc, if is_sel_match { 0x00FF88 } else { 0x9E948B });
                let sel_str = if is_sel_match {
                    format!("Смещение: {}  |  0x{:012X}  ★ НАЙДЕНО", off_label, sel_addr)
                } else {
                    format!("Смещение: {}  |  0x{:012X}", off_label, sel_addr)
                };
                let sw = encode_wide(&sel_str);
                TextOutW(mem_dc, 695, 164, sw.as_ptr(), sw.len() as i32);

                // Decode types from selected byte
                let get_bytes = |len: usize| -> Vec<u8> {
                    let mut b = Vec::new();
                    for i in 0..len {
                        if sel_idx + i < s.buffer.len() {
                            b.push(s.buffer[sel_idx + i]);
                        } else {
                            b.push(0);
                        }
                    }
                    b
                };

                let b1 = get_bytes(1);
                let b2 = get_bytes(2);
                let b4 = get_bytes(4);
                let b8 = get_bytes(8);

                let u8_val = b1[0];
                let i8_val = b1[0] as i8;
                let u16_val = u16::from_le_bytes(b2.as_slice().try_into().unwrap_or([0; 2]));
                let i16_val = i16::from_le_bytes(b2.as_slice().try_into().unwrap_or([0; 2]));
                let u32_val = u32::from_le_bytes(b4.as_slice().try_into().unwrap_or([0; 4]));
                let i32_val = i32::from_le_bytes(b4.as_slice().try_into().unwrap_or([0; 4]));
                let u64_val = u64::from_le_bytes(b8.as_slice().try_into().unwrap_or([0; 8]));
                let i64_val = i64::from_le_bytes(b8.as_slice().try_into().unwrap_or([0; 8]));
                let f32_val = f32::from_le_bytes(b4.as_slice().try_into().unwrap_or([0; 4]));
                let f64_val = f64::from_le_bytes(b8.as_slice().try_into().unwrap_or([0; 8]));

                let mut insp_y = 195;
                let draw_type_field = |dc: HDC, y: i32, label: &str, val_str: &str, color: u32| {
                    SelectObject(dc, h_font_bold);
                    SetTextColor(dc, 0x9E948B);
                    let lw = encode_wide(label);
                    TextOutW(dc, 695, y, lw.as_ptr(), lw.len() as i32);

                    SelectObject(dc, h_font_mono_bold);
                    SetTextColor(dc, color);
                    let vw = encode_wide(val_str);
                    TextOutW(dc, 765, y, vw.as_ptr(), vw.len() as i32);
                };

                draw_type_field(mem_dc, insp_y, "UInt8:", &format!("{} (0x{:02X})", u8_val, u8_val), 0xD4C4B5);
                insp_y += 24;
                draw_type_field(mem_dc, insp_y, "Int8:", &format!("{}", i8_val), 0xD4C4B5);
                insp_y += 24;
                draw_type_field(mem_dc, insp_y, "UInt16:", &format!("{} (0x{:04X})", u16_val, u16_val), 0xD4C4B5);
                insp_y += 24;
                draw_type_field(mem_dc, insp_y, "Int16:", &format!("{}", i16_val), 0xD4C4B5);
                insp_y += 24;
                draw_type_field(mem_dc, insp_y, "UInt32:", &format!("{} (0x{:08X})", u32_val, u32_val), 0x00F0FF);
                insp_y += 24;
                draw_type_field(mem_dc, insp_y, "Int32:", &format!("{}", i32_val), 0x00F0FF);
                insp_y += 24;
                draw_type_field(mem_dc, insp_y, "UInt64:", &format!("{} (0x{:016X})", u64_val, u64_val), 0x88FF00);
                insp_y += 24;
                draw_type_field(mem_dc, insp_y, "Int64:", &format!("{}", i64_val), 0x88FF00);
                insp_y += 24;
                let f_str = if f32_val.is_finite() { format!("{:.4}", f32_val) } else { "NaN".to_string() };
                draw_type_field(mem_dc, insp_y, "Float32:", &f_str, 0xFF9900);
                insp_y += 24;
                let f64_str = if f64_val.is_finite() { format!("{:.4}", f64_val) } else { "NaN".to_string() };
                draw_type_field(mem_dc, insp_y, "Float64:", &f64_str, 0xFF9900);
                insp_y += 28;

                // Meaning heuristic
                SelectObject(mem_dc, h_font_ui);
                SetTextColor(mem_dc, if is_sel_match { 0x00FF88 } else { 0xFFD700 });
                let hint = if is_sel_match {
                    "★ НАЙДЕННОЕ СОВПАДЕНИЕ ПОИСКА"
                } else if rel_offset == 0x1E28 {
                    "★ Смещение 0x1E28: Текущее здоровье (Health)"
                } else if rel_offset == 0x1E30 {
                    "★ Смещение 0x1E30: Максимальное здоровье (MaxHealth)"
                } else if rel_offset == 0x1BC0 {
                    "★ Смещение 0x1BC0: Мана / Энергия / Ярость (Power)"
                } else if rel_offset >= 0x60 && rel_offset <= 0x68 {
                    "★ Смещение 0x60: Координаты позиции X, Y, Z (Float32)"
                } else if rel_offset >= 0x10 && rel_offset <= 0x18 {
                    "★ Смещение 0x18: Уникальный GUID объекта"
                } else if u64_val > 0x0000010000000000 && u64_val < 0x00007FFFFFFFFFFF {
                    "→ Указатель на адрес кучи / модуль (Pointer)"
                } else if u32_val >= 50 && u32_val <= 100000 {
                    "• Возможное значение HP / Mana / SpellID"
                } else {
                    ""
                };
                if !hint.is_empty() {
                    let hw = encode_wide(hint);
                    TextOutW(mem_dc, 695, insp_y, hw.as_ptr(), hw.len() as i32);
                }

                SelectObject(mem_dc, h_font_ui);
                SetTextColor(mem_dc, 0x6E6E6E);
                let copy_tip = encode_wide("• Разделители колонок в шапке можно двигать мышкой  |  ПКМ вставляет  |  Ctrl+C: адрес");
                TextOutW(mem_dc, 695, insp_y + 20, copy_tip.as_ptr(), copy_tip.len() as i32);

                // 6. Bottom Status / Guide Card (y = 510..bottom_y)
                draw_rounded_card(mem_dc, 18, 510, panel_right, bottom_y, 0x181311);
                draw_card_border(mem_dc, 18, 510, panel_right, bottom_y, 0x362822);

                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, 0x00F0FF);
                let guide_title = encode_wide("КАК НАХОДИТЬ АДРЕСА В ПАМЯТИ (РУКОВОДСТВО ПО ПОИСКУ):");
                TextOutW(mem_dc, 30, 520, guide_title.as_ptr(), guide_title.len() as i32);

                SelectObject(mem_dc, h_font_ui);
                SetTextColor(mem_dc, 0x9E948B);
                let g1 = encode_wide("1. [ИГРОК] / [ЦЕЛЬ] — переход к объекту. Кнопка [⚓ ПОСТАВИТЬ ЯКОРЬ] делает выбранный байт точкой отсчета (+0x0000).");
                let g2 = encode_wide("2. Смещение +0x1E28 содержит текущее HP (64-bit int), а +0x1E30 — максимальное HP.");
                let g3 = encode_wide("3. Для поиска строк/чисел в окрестности жмите [ВПЕРЕД] (+64 КБ). Для поиска во всем клиенте — [ГЛОБАЛЬНО].");
                let g4 = encode_wide("4. Разделители OFFSET/ADDRESS/HEX/ASCII можно свободно перетаскивать мышью для изменения ширины.");
                TextOutW(mem_dc, 30, 542, g1.as_ptr(), g1.len() as i32);
                TextOutW(mem_dc, 30, 562, g2.as_ptr(), g2.len() as i32);
                TextOutW(mem_dc, 30, 582, g3.as_ptr(), g3.len() as i32);
                TextOutW(mem_dc, 30, 602, g4.as_ptr(), g4.len() as i32);

                if !s.status_msg.is_empty() {
                    SelectObject(mem_dc, h_font_bold);
                    SetTextColor(mem_dc, 0x88FF00);
                    let stat_w = encode_wide(&s.status_msg);
                    TextOutW(mem_dc, 30, std::cmp::min(630, bottom_y - 25), stat_w.as_ptr(), stat_w.len() as i32);
                }
            }

            // Restore fonts
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

fn worker_loop(state_arc: Arc<Mutex<InspectorState>>) {
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
            // 1. Get process info if needed
            let (pid, base, cur_addr, is_live, req_jump, req_search) = {
                let mut s = state_arc.lock().unwrap();
                let jump = s.req_jump_address.take();
                let search = s.req_search_val.take();
                (s.pid, s.base_address, s.current_address, s.is_live, jump, search)
            };

            let mut cur_pid = pid;
            let mut cur_base = base;

            // 1. Refresh process info & detect PID switch (e.g. game restart)
            if let Some(resp) = query_daemon(writer, reader, json!({ "cmd": "find_process", "name": "Wow.exe" })) {
                if let (Some(p), Some(b_str)) = (resp.get("pid").and_then(|v| v.as_u64()), resp.get("base").and_then(|v| v.as_str())) {
                    let new_pid = p as u32;
                    let clean = b_str.trim_start_matches("0x").trim_start_matches("0X");
                    let new_base = u64::from_str_radix(clean, 16).unwrap_or(0);

                    if new_pid != cur_pid || new_base != cur_base {
                        cur_pid = new_pid;
                        cur_base = new_base;

                        let mut s = state_arc.lock().unwrap();
                        s.connected = true;
                        s.pid = cur_pid;
                        s.base_address = cur_base;
                        if s.current_address == 0 {
                            s.current_address = cur_base;
                            s.address_input = format!("0x{:X}", cur_base);
                        }
                    }
                }
            }

            // 2. Refresh target anchors periodically
            if cur_pid != 0 {
                if let Some(_resp) = query_daemon(writer, reader, json!({ "cmd": "get_target", "include_mouseover": true })) {
                    // Update anchors if daemon returns target / player info
                    let mut s = state_arc.lock().unwrap();
                    s.connected = true;
                }
            }

            // Resolve player unit address
            if cur_pid != 0 && cur_base != 0 {
                let r1 = query_daemon(writer, reader, json!({ "cmd": "read_type", "pid": cur_pid, "addr": cur_base + 0x04C1A770, "type_name": "u64" }));
                let p_lo = r1.and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                if p_lo != 0 {
                    let r2 = query_daemon(writer, reader, json!({ "cmd": "read_type", "pid": cur_pid, "addr": cur_base + 0x04728BE8, "type_name": "u64" }));
                    let et = r2.and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                    if et != 0 {
                        let r3 = query_daemon(writer, reader, json!({ "cmd": "read_type", "pid": cur_pid, "addr": et + 8, "type_name": "u64" }));
                        let arr = r3.and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                        if arr != 0 {
                            for i in 0..600 {
                                let re = query_daemon(writer, reader, json!({ "cmd": "read_type", "pid": cur_pid, "addr": arr + i * 16 + 8, "type_name": "u64" }));
                                let entry = re.and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                                if entry == 0 { continue; }
                                let rg = query_daemon(writer, reader, json!({ "cmd": "read_type", "pid": cur_pid, "addr": entry + 0x18, "type_name": "u64" }));
                                let glo = rg.and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                                if (glo & 0xFFFFFFFF) == (p_lo & 0xFFFFFFFF) {
                                    let rp = query_daemon(writer, reader, json!({ "cmd": "read_type", "pid": cur_pid, "addr": entry + 0x28, "type_name": "u64" }));
                                    let mut ptr = rp.and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                                    if ptr == 0 || ptr == 1 || ptr > 0x7FFFFFFFFFFF {
                                        let rp2 = query_daemon(writer, reader, json!({ "cmd": "read_type", "pid": cur_pid, "addr": entry + 0xD8, "type_name": "u64" }));
                                        ptr = rp2.and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                                    }
                                    let mut s = state_arc.lock().unwrap();
                                    s.player_unit = if ptr != 0 && ptr <= 0x7FFFFFFFFFFF { ptr } else { entry };
                                    s.entity_table = et;
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // Resolve Target Unit address
            if cur_pid != 0 && cur_base != 0 {
                let rt = query_daemon(writer, reader, json!({ "cmd": "read_type", "pid": cur_pid, "addr": cur_base + 0x06A32478, "type_name": "u64" }));
                let t_lo = rt.and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                if t_lo != 0 {
                    let et = { state_arc.lock().unwrap().entity_table };
                    if et != 0 {
                        let r3 = query_daemon(writer, reader, json!({ "cmd": "read_type", "pid": cur_pid, "addr": et + 8, "type_name": "u64" }));
                        let arr = r3.and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                        if arr != 0 {
                            for i in 0..800 {
                                let re = query_daemon(writer, reader, json!({ "cmd": "read_type", "pid": cur_pid, "addr": arr + i * 16 + 8, "type_name": "u64" }));
                                let entry = re.and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                                if entry == 0 { continue; }
                                let rg = query_daemon(writer, reader, json!({ "cmd": "read_type", "pid": cur_pid, "addr": entry + 0x18, "type_name": "u64" }));
                                let glo = rg.and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                                if (glo & 0x00FFFFFF) == (t_lo & 0x00FFFFFF) {
                                    let rp = query_daemon(writer, reader, json!({ "cmd": "read_type", "pid": cur_pid, "addr": entry + 0x28, "type_name": "u64" }));
                                    let mut ptr = rp.and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                                    if ptr == 0 || ptr == 1 || ptr > 0x7FFFFFFFFFFF {
                                        let rp2 = query_daemon(writer, reader, json!({ "cmd": "read_type", "pid": cur_pid, "addr": entry + 0xD8, "type_name": "u64" }));
                                        ptr = rp2.and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                                    }
                                    let mut s = state_arc.lock().unwrap();
                                    s.target_unit = if ptr != 0 && ptr <= 0x7FFFFFFFFFFF { ptr } else { entry };
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // Handle Value Search (Supports: Decimal Integer, Hex Bytes, or ASCII Strings)
            if let Some((target_val_str, is_global)) = req_search {
                let search_addr = { state_arc.lock().unwrap().current_address };
                let mut found_addr = None;

                let trimmed = target_val_str.trim();
                let mut target_pat_bytes: Option<Vec<u8>> = None;

                if trimmed.starts_with("str:") || trimmed.starts_with("s:") {
                    let text = trimmed.trim_start_matches("str:").trim_start_matches("s:");
                    target_pat_bytes = Some(text.as_bytes().to_vec());
                } else if let Ok(val_u32) = trimmed.parse::<u32>() {
                    target_pat_bytes = Some(val_u32.to_le_bytes().to_vec());
                } else {
                    let clean_hex = trimmed.trim_start_matches("0x").trim_start_matches("0X").trim();
                    if clean_hex.len() >= 2 && clean_hex.len() % 2 == 0 && clean_hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        let mut b = Vec::new();
                        let chars: Vec<char> = clean_hex.chars().collect();
                        for i in (0..chars.len()).step_by(2) {
                            let s: String = [chars[i], chars[i + 1]].iter().collect();
                            if let Ok(byte) = u8::from_str_radix(&s, 16) {
                                b.push(byte);
                            }
                        }
                        target_pat_bytes = Some(b);
                    } else if !trimmed.is_empty() {
                        // Any other text (e.g. "ClntObjMgr", "Demon", "CGUnit") -> treat as ASCII string
                        target_pat_bytes = Some(trimmed.as_bytes().to_vec());
                    }
                }

                let mut pat_hex = String::new();
                let match_len = if let Some(ref target_pat) = target_pat_bytes {
                    for b in target_pat { pat_hex.push_str(&format!("{:02x} ", b)); }
                    target_pat.len()
                } else {
                    0
                };
                let pat_hex = pat_hex.trim().to_string();

                if match_len > 0 {
                    if is_global {
                        // Global search across the entire Wow.exe module (.text + .rdata + .data)
                        if let Some(resp) = query_daemon(writer, reader, json!({
                            "cmd": "pattern_scan",
                            "pid": cur_pid,
                            "module_name": "Wow.exe",
                            "pattern": pat_hex,
                            "max_hits": 5
                        })) {
                            if let Some(hits) = resp.get("hits").and_then(|h| h.as_array()) {
                                if !hits.is_empty() {
                                    let str_va_str = hits[0].get("address").and_then(|a| a.as_str()).unwrap_or("");
                                    let clean_va = str_va_str.trim_start_matches("0x").trim_start_matches("0X");
                                    found_addr = u64::from_str_radix(clean_va, 16).ok();
                                }
                            }
                        }
                    } else {
                        // Local search: scan forward 64 KB from search_addr
                        let chunk_size = 4096;
                        let scan_limit = 65536;
                        let no_space_pat = pat_hex.replace(" ", "");
                        for off in (0..scan_limit).step_by(chunk_size) {
                            let va = search_addr + off as u64;
                            if let Some(resp) = query_daemon(writer, reader, json!({ "cmd": "read_bytes", "pid": cur_pid, "addr": va, "size": chunk_size })) {
                                if let Some(hex_str) = resp.get("hex").and_then(|h| h.as_str()) {
                                    if let Some(pos) = hex_str.to_lowercase().find(&no_space_pat.to_lowercase()) {
                                        found_addr = Some(va + (pos / 2) as u64);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                let mut s = state_arc.lock().unwrap();
                if let Some(fa) = found_addr {
                    s.current_address = fa;
                    s.address_input = format!("0x{:X}", fa);
                    s.selected_offset = 0;
                    s.match_addr = Some(fa);
                    s.match_len = match_len;
                    if s.anchor_address == 0 {
                        s.anchor_address = fa;
                    }
                    if is_global {
                        s.status_msg = format!("Значение найдено ГЛОБАЛЬНО в Wow.exe: 0x{:X} (RVA: +0x{:X})", fa, fa.saturating_sub(cur_base));
                    } else {
                        s.status_msg = format!("Значение найдено локально по адресу: 0x{:X} (+0x{:X})", fa, fa.saturating_sub(search_addr));
                    }
                } else {
                    s.match_addr = None;
                    if is_global {
                        s.status_msg = format!("Значение '{}' не найдено во всем модуле Wow.exe.", target_val_str);
                    } else {
                        s.status_msg = format!("Значение '{}' не найдено в окрестности 64 КБ. Нажмите [ГЛОБАЛЬНО] для поиска по всему Wow.exe.", target_val_str);
                    }
                }
            }

            // Read Memory Buffer at current_address
            let read_target = req_jump.unwrap_or(cur_addr);
            if cur_pid != 0 && read_target != 0 && (is_live || req_jump.is_some()) {
                if let Some(resp) = query_daemon(writer, reader, json!({ "cmd": "read_bytes", "pid": cur_pid, "addr": read_target, "size": BYTES_TO_READ })) {
                    if let Some(hex) = resp.get("hex").and_then(|h| h.as_str()) {
                        let mut bytes = Vec::with_capacity(BYTES_TO_READ);
                        let chars: Vec<char> = hex.chars().collect();
                        for i in (0..chars.len()).step_by(2) {
                            if i + 1 < chars.len() {
                                let s: String = [chars[i], chars[i + 1]].iter().collect();
                                if let Ok(b) = u8::from_str_radix(&s, 16) {
                                    bytes.push(b);
                                }
                            }
                        }

                        let mut s = state_arc.lock().unwrap();
                        s.buffer = bytes;
                        if req_jump.is_some() {
                            s.current_address = read_target;
                            s.address_input = format!("0x{:X}", read_target);
                        }
                    }
                }
            }
        } else {
            let mut s = state_arc.lock().unwrap();
            s.connected = false;
        }

        thread::sleep(Duration::from_millis(100)); // 10 Hz refresh
    }
}

fn main() {
    let initial_state = Arc::new(Mutex::new(InspectorState {
        connected: false,
        pid: 0,
        base_address: 0,
        current_address: 0,
        anchor_address: 0,
        origin_name: "Не выбрано".to_string(),
        player_unit: 0,
        target_unit: 0,
        mouseover_unit: 0,
        entity_table: 0,
        buffer: vec![0u8; BYTES_TO_READ],
        selected_offset: 0,
        match_addr: None,
        match_len: 0,
        col_addr_x: 80,
        col_hex_x: 200,
        col_ascii_x: 550,
        dragging_col: 0,
        is_live: true,
        address_input: "0x0".to_string(),
        search_input: String::new(),
        active_input_box: 0,
        status_msg: String::new(),
        status_flash: 0,
        req_jump_address: None,
        req_search_val: None,
    }));

    unsafe {
        GLOBAL_STATE = Some(Arc::clone(&initial_state));
    }

    // Spawn background worker thread
    let worker_state = Arc::clone(&initial_state);
    thread::spawn(move || {
        worker_loop(worker_state);
    });

    // Create Win32 UI Window
    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let class_name = encode_wide("DmaInspectorWindowClass");

        let wnd_class = WNDCLASSW {
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
        };

        RegisterClassW(&wnd_class);

        let window_title = encode_wide("PORTOLAN DMA Live Memory Inspector & Hex Browser");
        let _hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            window_title.as_ptr(),
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

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
