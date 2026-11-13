// language: Rust, file: src/gui.rs, target: Windows 11, MSVC x64
// #![windows_subsystem = "windows"]

mod rotation;
pub mod editor;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rotation::{ConditionType, MouseTrigger, RotationConfig, RotationRule, RotationStore};
use serde_json::{json, Value};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

#[derive(Clone, Default)]
pub struct GuiAura {
    pub name: String,
    pub spell_id: u32,
    pub stacks: u8,
    pub rem_ms: u32,
}

pub struct GuiState {
    pub hud_x: i32,
    pub hud_y: i32,
    pub is_dragging: bool,
    pub drag_anchor_x: i32,
    pub drag_anchor_y: i32,
    pub is_fullscreen: bool,
    pub is_hud_visible: bool,
    pub has_target: bool,
    pub player_guid: String,
    pub target_guid: String,
    pub target_name: String,
    pub target_type: String,
    pub target_badge: String,
    pub target_distance: f32,
    pub is_target_alive: bool,
    pub auras: Vec<GuiAura>,
    pub use_mouseover: bool,
    pub is_mouseover: bool,
    pub connected: bool,
    pub makcu_connected: bool,
    pub trigger_jump: bool,
    pub trigger_rotation_tick: bool,
    pub jump_flash: u8,
    pub rotation_store: RotationStore,
    pub rotation_config: RotationConfig,
    pub last_rotation_cast: Option<String>,
    pub sync_rotation: bool,
    pub is_casting: bool,
    pub is_channeling: bool,
    pub cast_rem_ms: u32,
    pub channel_rem_ms: u32,
    pub cast_spell_id: u32,
    pub cast_spell_name: String,
    pub channel_spell_id: u32,
    pub channel_spell_name: String,
}

static mut GLOBAL_STATE: Option<Arc<Mutex<GuiState>>> = None;

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            SetTimer(hwnd, 1, 33, None); // 30 FPS redraw
            0
        }
        WM_ERASEBKGND => 1,
        WM_TIMER => {
            if let Some(ref state_arc) = GLOBAL_STATE {
                let mut state = state_arc.lock().unwrap();
                if state.jump_flash > 0 {
                    state.jump_flash -= 1;
                }
            }
            InvalidateRect(hwnd, std::ptr::null(), 0);
            0
        }
        WM_LBUTTONDOWN => {
            let x = (lparam & 0xFFFF) as i32;
            let y = ((lparam >> 16) & 0xFFFF) as i32;

            if let Some(ref state_arc) = GLOBAL_STATE {
                let mut state = state_arc.lock().unwrap();

                // If HUD is hidden, clicking the top-left pill restores it
                if !state.is_hud_visible {
                    if x >= 18 && x <= 230 && y >= 14 && y <= 45 {
                        state.is_hud_visible = true;
                    }
                    return 0;
                }

                let ox = state.hud_x;
                let oy = state.hud_y;

                // Minimize/Hide Button [ — ]: Rect(ox + 486..ox + 522, oy + 12..oy + 42)
                if x >= ox + 486 && x <= ox + 522 && y >= oy + 12 && y <= oy + 42 {
                    state.is_hud_visible = false;
                    return 0;
                }
                // 1. Mouseover Checkbox area: Rect(ox + 18, oy + 296, ox + 522, oy + 344)
                else if x >= ox + 18 && x <= ox + 522 && y >= oy + 296 && y <= oy + 344 {
                    state.use_mouseover = !state.use_mouseover;
                }
                // 1.5. Button [ ⚙ РОТАЦИИ ]: Rect(ox + 380..ox + 518, oy + 354..oy + 398)
                else if x >= ox + 380 && x <= ox + 518 && y >= oy + 354 && y <= oy + 398 {
                    drop(state);
                    editor::open_rotation_editor(hwnd, Arc::clone(state_arc));
                    return 0;
                }
                // Header drag area (click on HUD title area to drag across the fuser screen)
                else if x >= ox && x <= ox + 480 && y >= oy && y <= oy + 48 {
                    state.is_dragging = true;
                    state.drag_anchor_x = x - ox;
                    state.drag_anchor_y = y - oy;
                    unsafe {
                        windows_sys::Win32::UI::Input::KeyboardAndMouse::SetCapture(hwnd);
                    }
                }
            }
            0
        }
        WM_MOUSEMOVE => {
            let x = (lparam & 0xFFFF) as i32;
            let y = ((lparam >> 16) & 0xFFFF) as i32;
            if let Some(ref state_arc) = GLOBAL_STATE {
                let mut state = state_arc.lock().unwrap();
                if state.is_dragging {
                    state.hud_x = x - state.drag_anchor_x;
                    state.hud_y = y - state.drag_anchor_y;
                }
            }
            0
        }
        WM_LBUTTONUP => {
            if let Some(ref state_arc) = GLOBAL_STATE {
                let mut state = state_arc.lock().unwrap();
                if state.is_dragging {
                    state.is_dragging = false;
                    unsafe {
                        windows_sys::Win32::UI::Input::KeyboardAndMouse::ReleaseCapture();
                    }
                }
            }
            0
        }
        WM_HOTKEY => {
            if let Some(ref state_arc) = GLOBAL_STATE {
                let mut state = state_arc.lock().unwrap();
                state.is_hud_visible = !state.is_hud_visible;
            }
            0
        }
        WM_KEYDOWN => {
            if let Some(ref state_arc) = GLOBAL_STATE {
                let mut state = state_arc.lock().unwrap();
                match wparam as i32 {
                    0x2D | 0x79 | 0x7B => { // Insert (0x2D), F10 (0x79), F12 (0x7B): Toggle HUD visibility
                        state.is_hud_visible = !state.is_hud_visible;
                    }
                    0x7A => { // F11 key: Toggle Fullscreen (Fuser Mode) / Windowed Mode
                        state.is_fullscreen = !state.is_fullscreen;
                        let fs = state.is_fullscreen;
                        drop(state);
                        unsafe {
                            if fs {
                                let sw = GetSystemMetrics(SM_CXSCREEN);
                                let sh = GetSystemMetrics(SM_CYSCREEN);
                                SetWindowLongPtrW(hwnd, GWL_STYLE, (WS_POPUP | WS_VISIBLE) as isize);
                                SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, sw, sh, SWP_FRAMECHANGED | SWP_SHOWWINDOW);
                            } else {
                                SetWindowLongPtrW(hwnd, GWL_STYLE, (WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE) as isize);
                                SetWindowPos(hwnd, HWND_TOPMOST, 100, 80, 560, 540, SWP_FRAMECHANGED | SWP_SHOWWINDOW);
                            }
                        }
                    }
                    0x4D => { // 'M' key toggles Mouseover
                        state.use_mouseover = !state.use_mouseover;
                    }
                    0x1B => { // Escape
                        PostQuitMessage(0);
                    }
                    _ => {}
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

            // Double Buffering
            let mem_dc = CreateCompatibleDC(hdc);
            let mem_bm = CreateCompatibleBitmap(hdc, width, height);
            let old_bm = SelectObject(mem_dc, mem_bm);

            // Fonts: Segoe UI
            let font_name = encode_wide("Segoe UI");
            let h_font_title = CreateFontW(
                22, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr()
            );
            let h_font_regular = CreateFontW(
                15, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr()
            );
            let h_font_bold = CreateFontW(
                16, 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr()
            );
            let h_font_small = CreateFontW(
                13, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr()
            );
            let old_font = SelectObject(mem_dc, h_font_regular);

            // Background: 100% Pure Black (0x000000) for HDMI/DP Hardware Fuser Chroma Keying
            let bg_brush = CreateSolidBrush(0x000000);
            FillRect(mem_dc, &rect, bg_brush);
            DeleteObject(bg_brush);

            SetBkMode(mem_dc, 1); // TRANSPARENT

            if let Some(ref state_arc) = GLOBAL_STATE {
                let s = state_arc.lock().unwrap();

                if !s.is_hud_visible {
                    // Minimalist pill in top-left corner
                    draw_rounded_card(mem_dc, 18, 14, 215, 42, 0x1A1412);
                    draw_card_border(mem_dc, 18, 14, 215, 42, 0x00F0FF);
                    SelectObject(mem_dc, h_font_bold);
                    SetTextColor(mem_dc, 0x00F0FF);
                    let pill_txt = encode_wide("👁 РАДАР (Insert)");
                    TextOutW(mem_dc, 28, 20, pill_txt.as_ptr(), pill_txt.len() as i32);
                } else {
                    let ox = s.hud_x;
                    let oy = s.hud_y;

                    // 1. Title Header
                    SelectObject(mem_dc, h_font_title);
                    SetTextColor(mem_dc, 0xFFF000); // Cyan
                    let title = encode_wide("WoW DMA RADAR (RUST)");
                    TextOutW(mem_dc, ox + 20, oy + 14, title.as_ptr(), title.len() as i32);

                    // Minimize / Hide Button [ — ] at ox + 486..ox + 522, oy + 14..oy + 42
                    draw_rounded_card(mem_dc, ox + 486, oy + 14, ox + 522, oy + 42, 0x261E1A);
                    draw_card_border(mem_dc, ox + 486, oy + 14, ox + 522, oy + 42, 0x00F0FF);
                    SelectObject(mem_dc, h_font_bold);
                    SetTextColor(mem_dc, 0x00F0FF);
                    let hide_txt = encode_wide("—");
                    TextOutW(mem_dc, ox + 498, oy + 18, hide_txt.as_ptr(), hide_txt.len() as i32);

                    // Online Badges: MAKCU V4 Hardware + DMA Bridge
                    SelectObject(mem_dc, h_font_bold);

                    if s.makcu_connected {
                        SetTextColor(mem_dc, 0x88FF00); // Green
                        let a_badge = encode_wide("[● MAKCU]");
                        TextOutW(mem_dc, ox + 295, oy + 17, a_badge.as_ptr(), a_badge.len() as i32);
                    } else {
                        SetTextColor(mem_dc, 0x3A45FF); // Red
                        let a_badge = encode_wide("[-] MAKCU");
                        TextOutW(mem_dc, ox + 295, oy + 17, a_badge.as_ptr(), a_badge.len() as i32);
                    }

                    if s.connected {
                        SetTextColor(mem_dc, 0x88FF00); // Green
                        let badge = encode_wide("[+] DMA");
                        TextOutW(mem_dc, ox + 400, oy + 17, badge.as_ptr(), badge.len() as i32);
                    } else {
                        SetTextColor(mem_dc, 0x3A45FF); // Red
                        let badge = encode_wide("[-] DMA");
                        TextOutW(mem_dc, ox + 400, oy + 17, badge.as_ptr(), badge.len() as i32);
                    }

                // 2. Target Card Box
                draw_rounded_card(mem_dc, ox + 18, oy + 50, ox + 522, oy + 160, 0x231C1A);
                draw_card_border(mem_dc, ox + 18, oy + 50, ox + 522, oy + 160, if s.has_target { 0x00F0FF } else { 0x3E3028 });
                SelectObject(mem_dc, h_font_regular);
                SetTextColor(mem_dc, 0x9E948B);
                let card_title = encode_wide("ТЕКУЩАЯ ЦЕЛЬ");
                TextOutW(mem_dc, ox + 30, oy + 58, card_title.as_ptr(), card_title.len() as i32);

                if s.has_target {
                    SelectObject(mem_dc, h_font_bold);
                    SetTextColor(mem_dc, if s.is_target_alive { 0x88FF00 } else { 0x555555 }); // Green or Grey for dead
                    let t_text = encode_wide(&format!(">> {}{}", s.target_name, if !s.is_target_alive { " [ТРУП]" } else { "" }));
                    TextOutW(mem_dc, ox + 30, oy + 78, t_text.as_ptr(), t_text.len() as i32);

                    SelectObject(mem_dc, h_font_regular);
                    SetTextColor(mem_dc, 0x00F0FF); // Cyan
                    let dist_str = if s.target_distance > 0.0 {
                        format!("   |   Дистанция: {:.1} ярдов", s.target_distance)
                    } else {
                        String::new()
                    };
                    let type_txt = encode_wide(&format!("{}  [Тип: {}]{}", s.target_badge, s.target_type, dist_str));
                    TextOutW(mem_dc, ox + 30, oy + 105, type_txt.as_ptr(), type_txt.len() as i32);

                    SetTextColor(mem_dc, 0x9E948B);
                    let sub = encode_wide(&format!("GUID: {}   |   Игрок: {}", s.target_guid, s.player_guid));
                    TextOutW(mem_dc, ox + 30, oy + 130, sub.as_ptr(), sub.len() as i32);
                } else {
                    SelectObject(mem_dc, h_font_regular);
                    SetTextColor(mem_dc, 0x6E6E6E);
                    let t_text = encode_wide("НЕТ ЦЕЛИ (нажмите Tab / выберите моба)");
                    TextOutW(mem_dc, ox + 30, oy + 80, t_text.as_ptr(), t_text.len() as i32);

                    let sub = encode_wide(&format!("GUID: -   |   Игрок: {}", s.player_guid));
                    TextOutW(mem_dc, ox + 30, oy + 114, sub.as_ptr(), sub.len() as i32);
                }

                // 3. Dynamic Auras On Target Card Box
                draw_rounded_card(mem_dc, ox + 18, oy + 168, ox + 522, oy + 288, 0x1E1A16);
                draw_card_border(mem_dc, ox + 18, oy + 168, ox + 522, oy + 288, 0x3E3028);
                SelectObject(mem_dc, h_font_regular);
                SetTextColor(mem_dc, 0x9E948B);
                let aura_title = encode_wide("АКТИВНЫЕ АУРЫ И ТАЙМЕРЫ ЦЕЛИ (ДИНАМИЧЕСКИЙ ТРЕКИНГ)");
                TextOutW(mem_dc, ox + 30, oy + 176, aura_title.as_ptr(), aura_title.len() as i32);

                if !s.auras.is_empty() {
                    let mut start_y = oy + 201;
                    for a in s.auras.iter().take(3) {
                        SelectObject(mem_dc, h_font_bold);
                        SetTextColor(mem_dc, 0x00F0FF); // Cyan
                        let a_name = if a.stacks > 1 {
                            format!("{} x{}", a.name, a.stacks)
                        } else {
                            a.name.clone()
                        };
                        let name_w = encode_wide(&a_name);
                        TextOutW(mem_dc, ox + 32, start_y, name_w.as_ptr(), name_w.len() as i32);

                        // Progress timer badge
                        let rem_sec = (a.rem_ms as f32) / 1000.0;
                        let (rem_str, t_color) = if a.rem_ms == 0 {
                            ("Постоянно".to_string(), 0x00F0FF) // Cyan
                        } else if rem_sec <= 3.0 {
                            (format!("{:.1} сек [ОБНОВИТЬ!]", rem_sec), 0x3A45FF) // Red
                        } else if rem_sec >= 60.0 {
                            let mins = a.rem_ms / 60000;
                            let secs = (a.rem_ms % 60000) / 1000;
                            (format!("{:02}:{:02} мин", mins, secs), 0x88FF00) // Green
                        } else {
                            (format!("{:.1} сек", rem_sec), 0x88FF00) // Green
                        };
                        SelectObject(mem_dc, h_font_regular);
                        SetTextColor(mem_dc, t_color);
                        let rem_w = encode_wide(&rem_str);
                        TextOutW(mem_dc, ox + 230, start_y + 1, rem_w.as_ptr(), rem_w.len() as i32);

                        SetTextColor(mem_dc, 0x7E7770);
                        let id_w = encode_wide(&format!("ID: {}", a.spell_id));
                        TextOutW(mem_dc, ox + 420, start_y + 1, id_w.as_ptr(), id_w.len() as i32);

                        start_y += 26;
                    }
                } else if s.has_target {
                    SelectObject(mem_dc, h_font_regular);
                    SetTextColor(mem_dc, 0x6E6E6E);
                    let empty_txt = encode_wide("Нет активных аур на цели");
                    TextOutW(mem_dc, ox + 32, oy + 221, empty_txt.as_ptr(), empty_txt.len() as i32);
                } else {
                    SelectObject(mem_dc, h_font_regular);
                    SetTextColor(mem_dc, 0x5E5E5E);
                    let empty_txt = encode_wide("Выберите цель для отслеживания аур");
                    TextOutW(mem_dc, ox + 32, oy + 221, empty_txt.as_ptr(), empty_txt.len() as i32);
                }

                // 4. Mouseover Checkbox Card
                let mo_bg = if s.use_mouseover { 0x2A2218 } else { 0x1E1A16 };
                draw_rounded_card(mem_dc, ox + 18, oy + 296, ox + 522, oy + 344, mo_bg);
                draw_card_border(mem_dc, ox + 18, oy + 296, ox + 522, oy + 344, if s.use_mouseover { 0x00F0FF } else { 0x3E3028 });

                SelectObject(mem_dc, h_font_bold);
                let (mo_box, mo_color) = if s.use_mouseover {
                    ("[X] Считывать цель по mouseover (наведению курсора)", 0x00F0FF) // Cyan
                } else {
                    ("[  ] Считывать цель по mouseover (наведению курсора)", 0x9E948B) // Gray
                };
                SetTextColor(mem_dc, mo_color);
                let mo_txt = encode_wide(mo_box);
                TextOutW(mem_dc, ox + 30, oy + 305, mo_txt.as_ptr(), mo_txt.len() as i32);

                SelectObject(mem_dc, h_font_regular);
                SetTextColor(mem_dc, 0x7E7770);
                let mo_sub = encode_wide("Кликните мышью или нажмите 'M' для переключения");
                TextOutW(mem_dc, ox + 30, oy + 324, mo_sub.as_ptr(), mo_sub.len() as i32);

                // 5. Active Rotations Summary Card (y = 352..402)
                draw_rounded_card(mem_dc, ox + 18, oy + 352, ox + 522, oy + 402, 0x211A17);
                draw_card_border(mem_dc, ox + 18, oy + 352, ox + 522, oy + 402, 0x3E3028);
                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, 0xFFD700); // Gold
                let rot_title = encode_wide("РОТАЦИИ: АКТИВНЫ ПО ХОТКЕЯМ");
                TextOutW(mem_dc, ox + 30, oy + 362, rot_title.as_ptr(), rot_title.len() as i32);

                SelectObject(mem_dc, h_font_small);
                SetTextColor(mem_dc, 0x9E948B);
                let hotkeys_summary: Vec<String> = s.rotation_store.profiles.iter()
                    .filter(|p| p.trigger != MouseTrigger::Disabled)
                    .map(|p| {
                        let trig_name = match p.trigger {
                            MouseTrigger::Mouse4 => "M4",
                            MouseTrigger::Mouse5 => "M5",
                            MouseTrigger::Middle => "Middle",
                            MouseTrigger::Right => "ПКМ",
                            MouseTrigger::Disabled => "Откл",
                        };
                        format!("{}: {}", trig_name, p.name)
                    })
                    .collect();
                let trig_str = if hotkeys_summary.is_empty() {
                    "Все хоткеи отключены (настройте в редакторе)".to_string()
                } else {
                    hotkeys_summary.join("   •   ")
                };
                let ts_w = encode_wide(&trig_str);
                TextOutW(mem_dc, ox + 30, oy + 382, ts_w.as_ptr(), ts_w.len() as i32);

                // Button [ ⚙ РОТАЦИИ ]
                draw_rounded_card(mem_dc, ox + 388, oy + 358, ox + 514, oy + 394, 0x382C24);
                draw_card_border(mem_dc, ox + 388, oy + 358, ox + 514, oy + 394, 0x00F0FF);
                SelectObject(mem_dc, h_font_bold);
                SetTextColor(mem_dc, 0x00F0FF);
                let btn_rot_w = encode_wide("⚙ РОТАЦИИ");
                TextOutW(mem_dc, ox + 404, oy + 368, btn_rot_w.as_ptr(), btn_rot_w.len() as i32);

                // 6. Dedicated Player Cast Bar & State Indicator Card (y = 410..480)
                let cast_bg = if s.is_channeling {
                    0x2E251A
                } else if s.is_casting {
                    0x2A2016
                } else {
                    0x1E1A16
                };
                draw_rounded_card(mem_dc, ox + 18, oy + 410, ox + 522, oy + 480, cast_bg);
                draw_card_border(mem_dc, ox + 18, oy + 410, ox + 522, oy + 480, if s.is_casting || s.is_channeling { 0x00D7FF } else { 0x3E3028 });

                SelectObject(mem_dc, h_font_regular);
                SetTextColor(mem_dc, 0x9E948B);
                let cast_title = encode_wide("ИНДИКАТОР КАСТА ИГРОКА (DMA ТЕЛЕМЕТРИЯ)");
                TextOutW(mem_dc, ox + 30, oy + 418, cast_title.as_ptr(), cast_title.len() as i32);

                SelectObject(mem_dc, h_font_bold);
                if s.is_channeling {
                    SetTextColor(mem_dc, 0x00F0FF);
                    let badge = encode_wide("[● ПОТОКОВОЕ]");
                    TextOutW(mem_dc, ox + 400, oy + 418, badge.as_ptr(), badge.len() as i32);

                    let sp_name = if !s.channel_spell_name.is_empty() {
                        s.channel_spell_name.clone()
                    } else if s.channel_spell_id != 0 {
                        format!("Заклинание #{}", s.channel_spell_id)
                    } else {
                        "Потоковое заклинание".to_string()
                    };
                    let sec = (s.channel_rem_ms as f32) / 1000.0;
                    let txt = encode_wide(&format!(">> {}   [Осталось: {:.2} сек]", sp_name, sec));
                    TextOutW(mem_dc, ox + 30, oy + 438, txt.as_ptr(), txt.len() as i32);

                    let bar_w = ((sec / 5.0).clamp(0.05, 1.0) * 476.0) as i32;
                    let bar_brush = CreateSolidBrush(0x00F0FF);
                    let bar_rect = RECT { left: ox + 30, top: oy + 460, right: ox + 30 + bar_w, bottom: oy + 470 };
                    FillRect(mem_dc, &bar_rect, bar_brush);
                    DeleteObject(bar_brush);
                } else if s.is_casting {
                    SetTextColor(mem_dc, 0x00D7FF);
                    let badge = encode_wide("[● КАСТУЕТ]");
                    TextOutW(mem_dc, ox + 410, oy + 418, badge.as_ptr(), badge.len() as i32);

                    let sp_name = if !s.cast_spell_name.is_empty() {
                        s.cast_spell_name.clone()
                    } else if s.cast_spell_id != 0 {
                        format!("Заклинание #{}", s.cast_spell_id)
                    } else {
                        "Применение заклинания".to_string()
                    };
                    let sec = (s.cast_rem_ms as f32) / 1000.0;
                    let txt = encode_wide(&format!(">> {}   [Осталось: {:.2} сек]", sp_name, sec));
                    TextOutW(mem_dc, ox + 30, oy + 438, txt.as_ptr(), txt.len() as i32);

                    let bar_w = ((sec / 3.0).clamp(0.05, 1.0) * 476.0) as i32;
                    let bar_brush = CreateSolidBrush(0x00D7FF);
                    let bar_rect = RECT { left: ox + 30, top: oy + 460, right: ox + 30 + bar_w, bottom: oy + 470 };
                    FillRect(mem_dc, &bar_rect, bar_brush);
                    DeleteObject(bar_brush);
                } else {
                    SetTextColor(mem_dc, 0x6E6E6E);
                    let badge = encode_wide("[○ ПОКОЙ]");
                    TextOutW(mem_dc, ox + 430, oy + 418, badge.as_ptr(), badge.len() as i32);

                    SelectObject(mem_dc, h_font_regular);
                    let txt = encode_wide("Персонаж готов к заклинанию (нет активного каста)");
                    TextOutW(mem_dc, ox + 30, oy + 438, txt.as_ptr(), txt.len() as i32);

                    let trough_brush = CreateSolidBrush(0x161210);
                    let bar_rect = RECT { left: ox + 30, top: oy + 460, right: ox + 506, bottom: oy + 470 };
                    FillRect(mem_dc, &bar_rect, trough_brush);
                    DeleteObject(trough_brush);
                }

                // Footer (y = 488)
                SelectObject(mem_dc, h_font_regular);
                SetTextColor(mem_dc, 0x5E5E5E);
                let foot = encode_wide("Fuser: 100% Черный | F11: Окно | Insert/Кнопка: Скрыть | Тяни за шапку");
                TextOutW(mem_dc, ox + 20, oy + 488, foot.as_ptr(), foot.len() as i32);
                }
            }

            // Restore font & cleanup
            SelectObject(mem_dc, old_font);
            DeleteObject(h_font_title);
            DeleteObject(h_font_regular);
            DeleteObject(h_font_bold);
            DeleteObject(h_font_small);

            // Blit buffer to screen
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

fn draw_rounded_card(hdc: HDC, left: i32, top: i32, right: i32, bottom: i32, color_bgr: u32) {
    let r = RECT { left, top, right, bottom };
    unsafe {
        let br = CreateSolidBrush(color_bgr);
        FillRect(hdc, &r, br);
        DeleteObject(br);
    }
}

fn draw_card_border(hdc: HDC, left: i32, top: i32, right: i32, bottom: i32, color_bgr: u32) {
    let r = RECT { left, top, right, bottom };
    unsafe {
        let br = CreateSolidBrush(color_bgr);
        FrameRect(hdc, &r, br);
        DeleteObject(br);
    }
}

fn encode_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() {
    let rotation_store = RotationStore::load_or_default();
    let rotation_config = rotation_store.active_config();

    let state = Arc::new(Mutex::new(GuiState {
        hud_x: 25,
        hud_y: 25,
        is_dragging: false,
        drag_anchor_x: 0,
        drag_anchor_y: 0,
        is_fullscreen: true,
        is_hud_visible: true,
        has_target: false,
        player_guid: "0x0".into(),
        target_guid: "0x0".into(),
        target_name: "НЕТ ЦЕЛИ".into(),
        target_type: "Нет цели".into(),
        target_badge: "[-]".into(),
        target_distance: 0.0,
        is_target_alive: true,
        auras: Vec::new(),
        use_mouseover: false,
        is_mouseover: false,
        connected: false,
        makcu_connected: false,
        trigger_jump: false,
        trigger_rotation_tick: false,
        jump_flash: 0,
        rotation_store,
        rotation_config,
        last_rotation_cast: None,
        sync_rotation: true,
        is_casting: false,
        is_channeling: false,
        cast_rem_ms: 0,
        channel_rem_ms: 0,
        cast_spell_id: 0,
        cast_spell_name: String::new(),
        channel_spell_id: 0,
        channel_spell_name: String::new(),
    }));

    unsafe {
        GLOBAL_STATE = Some(Arc::clone(&state));
    }

    // High-speed poller thread (wire-speed TCP socket polling)
    let state_worker = Arc::clone(&state);
    thread::spawn(move || {
        let mut opt_stream: Option<(BufReader<TcpStream>, TcpStream)> = None;

        loop {
            let (use_mo, do_tick, sync_store) = {
                let mut s = state_worker.lock().unwrap();
                let tick = s.trigger_rotation_tick;
                let sync = s.sync_rotation;
                s.trigger_rotation_tick = false;
                s.sync_rotation = false;
                let st = if sync { Some(s.rotation_store.clone()) } else { None };
                (s.use_mouseover, tick, st)
            };

            // Connect or reuse socket
            if opt_stream.is_none() {
                if let Ok(s) = TcpStream::connect("127.0.0.1:8765") {
                    let _ = s.set_nodelay(true);
                    let reader = BufReader::new(s.try_clone().unwrap());
                    opt_stream = Some((reader, s));
                }
            }

            let mut success = false;
            if let Some((ref mut reader, ref mut writer)) = opt_stream {
                // If configuration changed, sync to daemon
                if let Some(ref st) = sync_store {
                    let sync_cmd = json!({ "cmd": "set_rotation_store", "store": st });
                    let payload = format!("{}\n", sync_cmd);
                    if writer.write_all(payload.as_bytes()).is_ok() && writer.flush().is_ok() {
                        let mut line = String::new();
                        let _ = reader.read_line(&mut line);
                    }
                }

                // If manual rotation tick requested, send it
                if do_tick {
                    let tick_cmd = json!({ "cmd": "tick_rotation" });
                    let payload = format!("{}\n", tick_cmd);
                    if writer.write_all(payload.as_bytes()).is_ok() && writer.flush().is_ok() {
                        let mut line = String::new();
                        let _ = reader.read_line(&mut line);
                    }
                }

                let cmd = json!({ "cmd": "get_target", "include_mouseover": use_mo });
                let payload = format!("{}\n", cmd);
                if writer.write_all(payload.as_bytes()).is_ok() && writer.flush().is_ok() {
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_ok() {
                        if let Ok(resp) = serde_json::from_str::<Value>(&line) {
                            success = true;
                            let mut s = state_worker.lock().unwrap();
                            s.connected = true;
                            s.has_target = resp["has_target"].as_bool().unwrap_or(false);
                            s.is_mouseover = resp["is_mouseover"].as_bool().unwrap_or(false);
                            s.player_guid = resp["player_guid"].as_str().unwrap_or("0x0").to_string();
                            s.target_guid = resp["target_guid"].as_str().unwrap_or("0x0").to_string();
                            s.target_name = resp["target_name"].as_str().unwrap_or("НЕТ ЦЕЛИ").to_string();
                            s.target_type = resp["target_type"].as_str().unwrap_or("Существо").to_string();
                            s.target_badge = resp["target_badge"].as_str().unwrap_or("[-]").to_string();
                            s.target_distance = resp["target_distance"].as_f64().unwrap_or(0.0) as f32;
                            s.is_target_alive = resp["is_target_alive"].as_bool().unwrap_or(true);
                            s.makcu_connected = resp["makcu_connected"].as_bool().unwrap_or(false);

                            if let Some(cast_s) = resp["last_rotation_cast"].as_str() {
                                s.last_rotation_cast = Some(cast_s.to_string());
                            }
                            s.is_casting = resp["is_casting"].as_bool().unwrap_or(false);
                            s.is_channeling = resp["is_channeling"].as_bool().unwrap_or(false);
                            s.cast_rem_ms = resp["cast_rem_ms"].as_u64().unwrap_or(0) as u32;
                            s.channel_rem_ms = resp["channel_rem_ms"].as_u64().unwrap_or(0) as u32;
                            s.cast_spell_id = resp["cast_spell_id"].as_u64().unwrap_or(0) as u32;
                            s.channel_spell_id = resp["channel_spell_id"].as_u64().unwrap_or(0) as u32;
                            s.cast_spell_name = resp["cast_spell_name"].as_str().unwrap_or("").to_string();
                            s.channel_spell_name = resp["channel_spell_name"].as_str().unwrap_or("").to_string();

                            // Parse dynamic auras
                            if let Some(arr) = resp["auras"].as_array() {
                                let mut parsed_auras = Vec::new();
                                for item in arr {
                                    parsed_auras.push(GuiAura {
                                        name: item["name"].as_str().unwrap_or("Аура").to_string(),
                                        spell_id: item["spell_id"].as_u64().unwrap_or(0) as u32,
                                        stacks: item["stacks"].as_u64().unwrap_or(1) as u8,
                                        rem_ms: item["rem_ms"].as_u64().unwrap_or(0) as u32,
                                    });
                                }
                                s.auras = parsed_auras;
                            } else {
                                s.auras.clear();
                            }
                        }
                    }
                }
            }

            if !success {
                opt_stream = None;
                let mut s = state_worker.lock().unwrap();
                s.connected = false;
                s.makcu_connected = false;
                thread::sleep(Duration::from_millis(100));
            } else {
                thread::sleep(Duration::from_millis(10)); // 100 Hz wire-speed polling
            }
        }
    });

    // Native Win32 Window Registration & Creation
    unsafe {
        let hinstance = GetModuleHandleW(std::ptr::null());
        let class_name = encode_wide("WoW_DMA_Radar_Win32");

        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: std::ptr::null_mut(),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
        };

        RegisterClassW(&wc);

        let screen_w = GetSystemMetrics(SM_CXSCREEN);
        let screen_h = GetSystemMetrics(SM_CYSCREEN);

        let window_title = encode_wide("WoW DMA Radar Overlay (Fuser Mode)");
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST, // Stays over game
            class_name.as_ptr(),
            window_title.as_ptr(),
            WS_POPUP | WS_VISIBLE, // Borderless Fullscreen for Hardware Fuser
            0, 0,
            screen_w, screen_h,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinstance,
            std::ptr::null(),
        );

        if hwnd.is_null() {
            let err = GetLastError();
            eprintln!("[-] CreateWindowExW failed with error code: {}", err);
            return;
        }

        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);

        // Global hotkeys (work even when other windows are focused)
        windows_sys::Win32::UI::Input::KeyboardAndMouse::RegisterHotKey(hwnd, 1, 0, 0x2D); // VK_INSERT
        windows_sys::Win32::UI::Input::KeyboardAndMouse::RegisterHotKey(hwnd, 2, 0, 0x79); // VK_F10

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
