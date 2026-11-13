// language: Rust, file: src/editor.rs, target: Windows 11, MSVC x64
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::GuiState;
use super::rotation::{
    suggest_spell_range, AuraCondition, AuraPresence, AuraTarget, ConditionLogic, ConditionType,
    HpTarget, MouseTrigger, RotationConfig, RotationRule, RotationStore,
};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetKeyState, ReleaseCapture, SetCapture};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

pub struct EditorState {
    pub is_open: bool,
    pub hwnd: HWND,
    pub selected_idx: usize,
    pub editing_profile_name: bool,
    pub profile_name_buf: String,
    pub editing_spell_idx: Option<usize>,
    pub spell_name_buf: String,
    pub listening_key_idx: Option<usize>,
    pub status_msg: String,
    pub status_time: Option<Instant>,
    pub cursor_blink: bool,

    // Drag & Drop reordering
    pub dragging_rule_idx: Option<usize>,
    pub drag_mouse_y: i32,
    pub drag_target_idx: Option<usize>,

    // Spell condition configuration right panel
    pub configuring_rule_idx: Option<usize>,
    pub draft_conditions: Vec<AuraCondition>,
    pub editing_cond_idx: Option<usize>,
    pub aura_name_buf: String,
    pub cond_active_tab: usize, // 0 = Auras, 1 = Health (HP %), 2 = Kick (Interrupt), 3 = Range
    pub draft_check_hp: bool,
    pub draft_hp_target: HpTarget,
    pub draft_min_hp: u32,
    pub draft_max_hp: u32,
    pub draft_check_interrupt: bool,
    pub draft_interrupt_pct: u32,

    // General rotation settings panel
    pub show_rotation_settings: bool,

    // Non-blocking inline trigger dropdown
    pub open_trigger_dropdown_for_idx: Option<usize>,
}

static mut EDITOR_STATE: Option<Arc<Mutex<EditorState>>> = None;
static mut SHARED_GUI_STATE: Option<Arc<Mutex<GuiState>>> = None;

fn encode_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
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

fn vk_to_key_combo(vk: u32) -> Option<String> {
    // If vk is just a lone modifier key, wait for the actual target key
    if vk == 0x10 || vk == 0x11 || vk == 0x12 || vk == 0x5B || vk == 0x5C || vk == 0x14 {
        return None;
    }

    let shift = unsafe { (GetKeyState(0x10) as u16 & 0x8000) != 0 };
    let ctrl = unsafe { (GetKeyState(0x11) as u16 & 0x8000) != 0 };
    let alt = unsafe { (GetKeyState(0x12) as u16 & 0x8000) != 0 };

    let base_str: String = match vk {
        0x30 => "0".into(),
        0x31 => "1".into(),
        0x32 => "2".into(),
        0x33 => "3".into(),
        0x34 => "4".into(),
        0x35 => "5".into(),
        0x36 => "6".into(),
        0x37 => "7".into(),
        0x38 => "8".into(),
        0x39 => "9".into(),
        0x41..=0x5A => {
            let ch = ((vk - 0x41) as u8 + b'a') as char;
            ch.to_string()
        }
        0x70..=0x7B => format!("f{}", vk - 0x70 + 1),
        0x60..=0x69 => format!("num{}", vk - 0x60),
        0x6A => "num*".into(),
        0x6B => "num+".into(),
        0x6D => "num-".into(),
        0x6E => "num.".into(),
        0x6F => "num/".into(),
        0x20 => "space".into(),
        0x09 => "tab".into(),
        0x0D => "enter".into(),
        0x08 => "backspace".into(),
        0x2D => "insert".into(),
        0x2E => "delete".into(),
        0x24 => "home".into(),
        0x23 => "end".into(),
        0x21 => "pageup".into(),
        0x22 => "pagedown".into(),
        0x26 => "up".into(),
        0x28 => "down".into(),
        0x25 => "left".into(),
        0x27 => "right".into(),
        0xC0 => "`".into(),
        0xBD => "-".into(),
        0xBB => "=".into(),
        0xDB => "[".into(),
        0xDD => "]".into(),
        0xDC => "\\".into(),
        0xBA => ";".into(),
        0xDE => "'".into(),
        0xBC => ",".into(),
        0xBE => ".".into(),
        0xBF => "/".into(),
        _ => return None,
    };

    let mut combo = String::new();
    if ctrl { combo.push_str("Ctrl+"); }
    if alt { combo.push_str("Alt+"); }
    if shift { combo.push_str("Shift+"); }
    combo.push_str(&base_str);
    Some(combo)
}

pub struct SettingsDraft {
    pub profile_idx: usize,
    pub profile_name: String,
    pub wait_cast: bool,
    pub check_gcd: bool,
    pub reset_on_target_change: bool,
    pub protect_channeling: bool,
    pub auto_target: bool,
    pub auto_attack: bool,
    pub auto_attack_key: String,
    pub min_delay_ms: u32,
    pub max_delay_ms: u32,
    pub min_press_ms: u32,
    pub max_press_ms: u32,
    pub humanize: bool,
    pub listening_attack_key: bool,
}

static mut SETTINGS_HWND: HWND = std::ptr::null_mut();
static mut SETTINGS_DRAFT: Option<Arc<Mutex<SettingsDraft>>> = None;

pub unsafe fn open_rotation_settings_window(parent_hwnd: HWND, draft: SettingsDraft) {
    if !SETTINGS_HWND.is_null() && IsWindow(SETTINGS_HWND) != 0 {
        if let Some(ref draft_arc) = SETTINGS_DRAFT {
            *draft_arc.lock().unwrap() = draft;
        }
        ShowWindow(SETTINGS_HWND, SW_SHOW);
        SetForegroundWindow(SETTINGS_HWND);
        InvalidateRect(SETTINGS_HWND, std::ptr::null(), 0);
        return;
    }

    SETTINGS_DRAFT = Some(Arc::new(Mutex::new(draft)));

    let hinstance = GetModuleHandleW(std::ptr::null());
    let class_name = encode_wide("WoW_DMA_RotationSettings");

    let wc = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(settings_wnd_proc),
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

    let mut parent_rc: RECT = std::mem::zeroed();
    GetWindowRect(parent_hwnd, &mut parent_rc);
    let win_w = 620;
    let win_h = 620;
    let mut center_x = parent_rc.left + (parent_rc.right - parent_rc.left - win_w) / 2;
    let mut center_y = parent_rc.top + (parent_rc.bottom - parent_rc.top - win_h) / 2 + 25;
    if center_x < 50 { center_x = 50; }
    if center_y < 50 { center_y = 50; }

    let title_w = encode_wide("Настройки ротации");
    let hwnd = CreateWindowExW(
        WS_EX_TOPMOST,
        class_name.as_ptr(),
        title_w.as_ptr(),
        WS_POPUP | WS_VISIBLE,
        center_x,
        center_y,
        win_w,
        win_h,
        parent_hwnd,
        std::ptr::null_mut(),
        hinstance,
        std::ptr::null(),
    );
    SETTINGS_HWND = hwnd;
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
}

pub unsafe extern "system" fn settings_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_NCHITTEST => {
            let def = DefWindowProcW(hwnd, msg, wparam, lparam);
            if def == HTCLIENT as LRESULT {
                let mut pt = POINT {
                    x: (lparam as i32 & 0xFFFF) as i16 as i32,
                    y: ((lparam as i32 >> 16) & 0xFFFF) as i16 as i32,
                };
                ScreenToClient(hwnd, &mut pt);
                if pt.y >= 0 && pt.y <= 45 && pt.x < 560 {
                    return HTCAPTION as LRESULT;
                }
            }
            def
        }
        WM_LBUTTONDOWN => {
            let x = (lparam as i32 & 0xFFFF) as i16 as i32;
            let y = ((lparam as i32 >> 16) & 0xFFFF) as i16 as i32;

            // Close button [ ✕ ]: x = 570..610, y = 8..40
            if x >= 570 && x <= 610 && y >= 8 && y <= 40 {
                DestroyWindow(hwnd);
                return 0;
            }

            if let Some(ref draft_arc) = SETTINGS_DRAFT {
                let mut draft = draft_arc.lock().unwrap();

                if draft.listening_attack_key && (x < 440 || x > 596 || y < 376 || y > 428) {
                    draft.listening_attack_key = false;
                }

                // Checkbox 1: wait_cast (y = 86..138)
                if x >= 24 && x <= 596 && y >= 86 && y <= 138 {
                    draft.wait_cast = !draft.wait_cast;
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                // Checkbox 2: check_gcd (y = 144..196)
                if x >= 24 && x <= 596 && y >= 144 && y <= 196 {
                    draft.check_gcd = !draft.check_gcd;
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                // Checkbox 3: reset_on_target_change (y = 202..254)
                if x >= 24 && x <= 596 && y >= 202 && y <= 254 {
                    draft.reset_on_target_change = !draft.reset_on_target_change;
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                // Checkbox 4: protect_channeling (y = 260..312)
                if x >= 24 && x <= 596 && y >= 260 && y <= 312 {
                    draft.protect_channeling = !draft.protect_channeling;
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                // Checkbox 5: auto_target (y = 318..370)
                if x >= 24 && x <= 596 && y >= 318 && y <= 370 {
                    draft.auto_target = !draft.auto_target;
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                // Checkbox 6: auto_attack (y = 376..428)
                if y >= 376 && y <= 428 {
                    if x >= 450 && x <= 596 {
                        draft.listening_attack_key = !draft.listening_attack_key;
                    } else if x >= 24 && x < 450 {
                        draft.auto_attack = !draft.auto_attack;
                    }
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                // Delay presets pill: x = 24..300, y = 438..482
                if x >= 24 && x <= 300 && y >= 438 && y <= 482 {
                    let (n_min, n_max) = match (draft.min_delay_ms, draft.max_delay_ms) {
                        (140, 230) => (200, 320),
                        (200, 320) => (240, 380),
                        (240, 380) => (300, 480),
                        _ => (140, 230),
                    };
                    draft.min_delay_ms = n_min;
                    draft.max_delay_ms = n_max;
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                // Key Hold duration presets pill: x = 310..596, y = 438..482
                if x >= 310 && x <= 596 && y >= 438 && y <= 482 {
                    let (h_min, h_max) = match (draft.min_press_ms, draft.max_press_ms) {
                        (50, 100) => (80, 150),
                        (80, 150) => (110, 190),
                        (110, 190) => (140, 240),
                        _ => (50, 100),
                    };
                    draft.min_press_ms = h_min;
                    draft.max_press_ms = h_max;
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                // Humanize toggle pill: x = 24..596, y = 490..534
                if x >= 24 && x <= 596 && y >= 490 && y <= 534 {
                    draft.humanize = !draft.humanize;
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                // Button [ Отмена ]: x = 320..448, y = 550..594
                if x >= 320 && x <= 448 && y >= 550 && y <= 594 {
                    DestroyWindow(hwnd);
                    return 0;
                }

                // Button [ Применить ]: x = 464..596, y = 550..594
                if x >= 464 && x <= 596 && y >= 550 && y <= 594 {
                    if let Some(ref gui_arc) = SHARED_GUI_STATE {
                        let mut gui = gui_arc.lock().unwrap();
                        let sel = draft.profile_idx;
                        if sel < gui.rotation_store.profiles.len() {
                            let prof = &mut gui.rotation_store.profiles[sel];
                            prof.wait_cast = draft.wait_cast;
                            prof.check_gcd = draft.check_gcd;
                            prof.reset_on_target_change = draft.reset_on_target_change;
                            prof.protect_channeling = draft.protect_channeling;
                            prof.auto_target = draft.auto_target;
                            prof.auto_attack = draft.auto_attack;
                            prof.auto_attack_key = draft.auto_attack_key.clone();
                            prof.min_delay_ms = draft.min_delay_ms;
                            prof.max_delay_ms = draft.max_delay_ms;
                            prof.min_press_ms = draft.min_press_ms;
                            prof.max_press_ms = draft.max_press_ms;
                            prof.humanize = draft.humanize;
                            let _ = gui.rotation_store.save();
                            gui.sync_rotation = true;
                        }
                    }
                    DestroyWindow(hwnd);
                    return 0;
                }
            }
            0
        }
        WM_KEYDOWN => {
            let vk = wparam as u32;
            if let Some(ref draft_arc) = SETTINGS_DRAFT {
                let mut draft = draft_arc.lock().unwrap();
                if draft.listening_attack_key {
                    if vk == 0x1B {
                        draft.listening_attack_key = false;
                    } else if let Some(combo) = vk_to_key_combo(vk) {
                        draft.auto_attack_key = combo;
                        draft.listening_attack_key = false;
                    }
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                } else if vk == 0x1B {
                    DestroyWindow(hwnd);
                    return 0;
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
            let mem_bmp = CreateCompatibleBitmap(hdc, width, height);
            let old_bmp = SelectObject(mem_dc, mem_bmp);

            let bg_br = CreateSolidBrush(0x0E1014);
            FillRect(mem_dc, &rect, bg_br);
            DeleteObject(bg_br);

            draw_card_border(mem_dc, 0, 0, width, height, 0x389E28);
            draw_card_border(mem_dc, 1, 1, width - 1, height - 1, 0x2A6E20);

            let font_name = encode_wide("Segoe UI");
            let h_title = CreateFontW(19, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_sub = CreateFontW(15, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_bold = CreateFontW(13, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_small = CreateFontW(11, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());

            SetBkMode(mem_dc, TRANSPARENT as i32);

            SelectObject(mem_dc, h_title);
            SetTextColor(mem_dc, 0x88FF00);
            let t_w = encode_wide("Настройки ротации");
            TextOutW(mem_dc, 24, 14, t_w.as_ptr(), t_w.len() as i32);

            SelectObject(mem_dc, h_bold);
            SetTextColor(mem_dc, 0x8E847B);
            let close_w = encode_wide("✕");
            TextOutW(mem_dc, 584, 16, close_w.as_ptr(), close_w.len() as i32);

            if let Some(ref draft_arc) = SETTINGS_DRAFT {
                let draft = draft_arc.lock().unwrap();

                SelectObject(mem_dc, h_sub);
                SetTextColor(mem_dc, 0xFFD700);
                let p_w = encode_wide(&draft.profile_name);
                TextOutW(mem_dc, 24, 52, p_w.as_ptr(), p_w.len() as i32);

                let draw_checkbox_row = |top: i32, is_checked: bool, title: &str, subtitle: &str| {
                    let bot = top + 52;
                    let (card_bg, card_border) = if is_checked { (0x201814, 0x362820) } else { (0x1A1412, 0x2A201A) };
                    draw_rounded_card(mem_dc, 24, top, 596, bot, card_bg);
                    draw_card_border(mem_dc, 24, top, 596, bot, card_border);

                    let (box_bg, box_border) = if is_checked { (0x284E20, 0x389E28) } else { (0x221B17, 0x44362E) };
                    draw_rounded_card(mem_dc, 36, top + 16, 56, top + 36, box_bg);
                    draw_card_border(mem_dc, 36, top + 16, 56, top + 36, box_border);

                    if is_checked {
                        SelectObject(mem_dc, h_bold);
                        SetTextColor(mem_dc, 0x88FF00);
                        let tick_w = encode_wide("✓");
                        TextOutW(mem_dc, 41, top + 18, tick_w.as_ptr(), tick_w.len() as i32);
                    }

                    SelectObject(mem_dc, h_bold);
                    SetTextColor(mem_dc, if is_checked { 0x88FF00 } else { 0xE0D8D0 });
                    let tw = encode_wide(title);
                    TextOutW(mem_dc, 68, top + 10, tw.as_ptr(), tw.len() as i32);

                    SelectObject(mem_dc, h_small);
                    SetTextColor(mem_dc, 0x8E847B);
                    let subw = encode_wide(subtitle);
                    TextOutW(mem_dc, 68, top + 30, subw.as_ptr(), subw.len() as i32);
                };

                draw_checkbox_row(86, draft.wait_cast, "Ждать окончания каста", "Кастуемые заклинания не прерываются спамом клавиши ротации");
                draw_checkbox_row(144, draft.check_gcd, "Учитывать глобальный кулдаун (ГКД)", "Блокировать отправку команд во время активного ГКД (~ 1.0 - 1.5 сек)");
                draw_checkbox_row(202, draft.reset_on_target_change, "Сброс условий при смене цели", "Сбрасывать симуляцию дебаффов при переключении на новую цель");
                draw_checkbox_row(260, draft.protect_channeling, "Защита потоковых заклинаний (Channeling)", "Не прерывать потоковые заклинания (Вытягивание жизни, Пытка разума и др.)");
                draw_checkbox_row(318, draft.auto_target, "Авто-таргет (Tab при отсутствии цели)", "Выбирать ближайшую цель через Tab при зажатом триггере ротации");
                draw_checkbox_row(376, draft.auto_attack, "Авто-атака (/startattack)", "Автоматически включать атаку ближнего или дальнего боя при начале ротации");

                let (kb_txt, kb_bg, kb_col) = if draft.listening_attack_key {
                    ("Нажмите любую клавишу...".to_string(), 0x381818, 0xFF8844)
                } else {
                    (format!("Бинд: [{}]", draft.auto_attack_key.to_uppercase()), 0x2A201A, 0x00F0FF)
                };
                draw_rounded_card(mem_dc, 450, 386, 586, 418, kb_bg);
                draw_card_border(mem_dc, 450, 386, 586, 418, 0x4A382A);
                SelectObject(mem_dc, h_bold);
                SetTextColor(mem_dc, kb_col);
                let ak_w = encode_wide(&kb_txt);
                TextOutW(mem_dc, 462, 394, ak_w.as_ptr(), ak_w.len() as i32);

                // Delay presets (Interval between clicks)
                draw_rounded_card(mem_dc, 24, 438, 300, 482, 0x201814);
                draw_card_border(mem_dc, 24, 438, 300, 482, 0x362820);
                let delay_str = match (draft.min_delay_ms, draft.max_delay_ms) {
                    (140, 230) => "Интервал: 140-230мс [Быстрый] ⟳".to_string(),
                    (200, 320) => "Интервал: 200-320мс [Баланс] ⟳".to_string(),
                    (240, 380) => "Интервал: 240-380мс [Живой] ⟳".to_string(),
                    (300, 480) => "Интервал: 300-480мс [Плавный] ⟳".to_string(),
                    (mi, ma) => format!("Интервал: {}-{}мс ⟳", mi, ma),
                };
                SelectObject(mem_dc, h_bold);
                SetTextColor(mem_dc, 0x00F0FF);
                let del_w = encode_wide(&delay_str);
                TextOutW(mem_dc, 36, 452, del_w.as_ptr(), del_w.len() as i32);

                // Key Hold duration presets (Time key is kept down)
                draw_rounded_card(mem_dc, 310, 438, 596, 482, 0x201814);
                draw_card_border(mem_dc, 310, 438, 596, 482, 0x362820);
                let hold_str = match (draft.min_press_ms, draft.max_press_ms) {
                    (50, 100) => "Удержание: 50-100мс [Тап] ⟳".to_string(),
                    (80, 150) => "Удержание: 80-150мс [Норма] ⟳".to_string(),
                    (110, 190) => "Удержание: 110-190мс [Четкий] ⟳".to_string(),
                    (140, 240) => "Удержание: 140-240мс [Глубокий] ⟳".to_string(),
                    (mi, ma) => format!("Удержание: {}-{}мс ⟳", mi, ma),
                };
                SelectObject(mem_dc, h_bold);
                SetTextColor(mem_dc, 0xFFCC00);
                let hld_w = encode_wide(&hold_str);
                TextOutW(mem_dc, 324, 452, hld_w.as_ptr(), hld_w.len() as i32);

                // Humanize toggle (Gaussian jitter + micro-pauses for both interval & hold)
                draw_rounded_card(mem_dc, 24, 490, 596, 534, 0x201814);
                draw_card_border(mem_dc, 24, 490, 596, 534, 0x362820);
                let (hum_txt, hum_col) = if draft.humanize {
                    ("Рандомизация удержания и пауз (Гаусс + микро-задержки): ВКЛ", 0x88FF00)
                } else {
                    ("Рандомизация: ВЫКЛ (Аппаратный робот, жесткий тайминг)", 0x777777)
                };
                SelectObject(mem_dc, h_bold);
                SetTextColor(mem_dc, hum_col);
                let hum_w = encode_wide(hum_txt);
                TextOutW(mem_dc, 36, 504, hum_w.as_ptr(), hum_w.len() as i32);

                // Bottom Buttons
                draw_rounded_card(mem_dc, 320, 550, 448, 594, 0x261E1A);
                draw_card_border(mem_dc, 320, 550, 448, 594, 0x3E3028);
                SelectObject(mem_dc, h_bold);
                SetTextColor(mem_dc, 0x9E948B);
                let can_w = encode_wide("Отмена");
                TextOutW(mem_dc, 356, 564, can_w.as_ptr(), can_w.len() as i32);

                draw_rounded_card(mem_dc, 464, 550, 596, 594, 0x2A5E1A);
                draw_card_border(mem_dc, 464, 550, 596, 594, 0x389E28);
                SelectObject(mem_dc, h_bold);
                SetTextColor(mem_dc, 0x88FF00);
                let app_w = encode_wide("Применить");
                TextOutW(mem_dc, 496, 564, app_w.as_ptr(), app_w.len() as i32);
            }

            BitBlt(hdc, 0, 0, width, height, mem_dc, 0, 0, SRCCOPY);

            DeleteObject(h_title);
            DeleteObject(h_sub);
            DeleteObject(h_bold);
            DeleteObject(h_small);
            SelectObject(mem_dc, old_bmp);
            DeleteObject(mem_bmp);
            DeleteDC(mem_dc);
            EndPaint(hwnd, &ps);
            0
        }
        WM_DESTROY => {
            SETTINGS_HWND = std::ptr::null_mut();
            SETTINGS_DRAFT = None;
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub unsafe extern "system" fn editor_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            SetTimer(hwnd, 1, 35, None); // ~30 FPS refresh
            0
        }
        WM_TIMER => {
            if let Some(ref ed_arc) = EDITOR_STATE {
                let mut ed = ed_arc.lock().unwrap();
                ed.cursor_blink = !ed.cursor_blink;
                if let Some(st) = ed.status_time {
                    if st.elapsed() > Duration::from_secs(3) {
                        ed.status_msg.clear();
                        ed.status_time = None;
                    }
                }
            }
            InvalidateRect(hwnd, std::ptr::null(), 0);
            0
        }
        WM_KEYDOWN => {
            let vk = wparam as u32;

            if let Some(ref ed_arc) = EDITOR_STATE {
                let mut ed = ed_arc.lock().unwrap();

                // 1. Listening for keybind assignment
                if let Some(rule_idx) = ed.listening_key_idx {
                    if vk == 0x1B { // Escape cancels
                        ed.listening_key_idx = None;
                    } else if let Some(key_str) = vk_to_key_combo(vk) {
                        if let Some(ref gui_arc) = SHARED_GUI_STATE {
                            let mut gui = gui_arc.lock().unwrap();
                            let sel = ed.selected_idx;
                            if sel < gui.rotation_store.profiles.len() {
                                let profile = &mut gui.rotation_store.profiles[sel];
                                if rule_idx < profile.rules.len() {
                                    profile.rules[rule_idx].key = key_str;
                                    let _ = gui.rotation_store.save();
                                    gui.sync_rotation = true;
                                }
                            }
                        }
                        ed.listening_key_idx = None;
                    }
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                // 2. Editing aura name buffer
                if let Some(c_idx) = ed.editing_cond_idx {
                    if vk == 0x0D { // Enter commits
                        if c_idx < ed.draft_conditions.len() {
                            ed.draft_conditions[c_idx].aura_name = ed.aura_name_buf.trim().to_string();
                        }
                        ed.editing_cond_idx = None;
                    } else if vk == 0x1B { // Escape cancels
                        ed.editing_cond_idx = None;
                    }
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                // 3. Editing profile name
                if ed.editing_profile_name {
                    if vk == 0x0D { // Enter commits
                        if let Some(ref gui_arc) = SHARED_GUI_STATE {
                            let mut gui = gui_arc.lock().unwrap();
                            let sel = ed.selected_idx;
                            if sel < gui.rotation_store.profiles.len() && !ed.profile_name_buf.trim().is_empty() {
                                gui.rotation_store.profiles[sel].name = ed.profile_name_buf.trim().to_string();
                                let _ = gui.rotation_store.save();
                                gui.sync_rotation = true;
                            }
                        }
                        ed.editing_profile_name = false;
                    } else if vk == 0x1B {
                        ed.editing_profile_name = false;
                    }
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                // 4. Editing spell name
                if let Some(rule_idx) = ed.editing_spell_idx {
                    if vk == 0x0D {
                        if let Some(ref gui_arc) = SHARED_GUI_STATE {
                            let mut gui = gui_arc.lock().unwrap();
                            let sel = ed.selected_idx;
                            if sel < gui.rotation_store.profiles.len() {
                                let profile = &mut gui.rotation_store.profiles[sel];
                                if rule_idx < profile.rules.len() && !ed.spell_name_buf.trim().is_empty() {
                                    profile.rules[rule_idx].name = ed.spell_name_buf.trim().to_string();
                                    let _ = gui.rotation_store.save();
                                    gui.sync_rotation = true;
                                }
                            }
                        }
                        ed.editing_spell_idx = None;
                    } else if vk == 0x1B {
                        ed.editing_spell_idx = None;
                    }
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                if vk == 0x1B {
                    if ed.configuring_rule_idx.is_some() {
                        ed.configuring_rule_idx = None;
                        InvalidateRect(hwnd, std::ptr::null(), 0);
                        return 0;
                    }
                    DestroyWindow(hwnd);
                    return 0;
                }
            }
            0
        }
        WM_CHAR => {
            let ch = wparam as u16;

            if let Some(ref ed_arc) = EDITOR_STATE {
                let mut ed = ed_arc.lock().unwrap();

                if ed.editing_cond_idx.is_some() {
                    if ch == 8 {
                        ed.aura_name_buf.pop();
                    } else if ch >= 32 && ch != 127 {
                        if let Some(c) = char::from_u32(ch as u32) {
                            if ed.aura_name_buf.chars().count() < 36 {
                                ed.aura_name_buf.push(c);
                            }
                        }
                    }
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                if ed.editing_profile_name {
                    if ch == 8 {
                        ed.profile_name_buf.pop();
                    } else if ch >= 32 && ch != 127 {
                        if let Some(c) = char::from_u32(ch as u32) {
                            if ed.profile_name_buf.chars().count() < 30 {
                                ed.profile_name_buf.push(c);
                            }
                        }
                    }
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }

                if ed.editing_spell_idx.is_some() {
                    if ch == 8 {
                        ed.spell_name_buf.pop();
                    } else if ch >= 32 && ch != 127 {
                        if let Some(c) = char::from_u32(ch as u32) {
                            if ed.spell_name_buf.chars().count() < 36 {
                                ed.spell_name_buf.push(c);
                            }
                        }
                    }
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                    return 0;
                }
            }
            0
        }
        WM_MOUSEMOVE => {
            let y = ((lparam >> 16) & 0xFFFF) as i32;

            if let Some(ref ed_arc) = EDITOR_STATE {
                let mut ed = ed_arc.lock().unwrap();
                if ed.dragging_rule_idx.is_some() {
                    ed.drag_mouse_y = y;

                    if let Some(ref gui_arc) = SHARED_GUI_STATE {
                        let gui = gui_arc.lock().unwrap();
                        let sel = ed.selected_idx;
                        if sel < gui.rotation_store.profiles.len() {
                            let rules_len = gui.rotation_store.profiles[sel].rules.len();
                            if rules_len > 0 {
                                let row_start_y = 104;
                                let row_h = 62;
                                let tgt = ((y - row_start_y + (row_h / 2)) / row_h)
                                    .clamp(0, (rules_len - 1) as i32) as usize;
                                ed.drag_target_idx = Some(tgt);
                            }
                        }
                    }
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                }
            }
            0
        }
        WM_LBUTTONUP => {
            if let Some(ref ed_arc) = EDITOR_STATE {
                let mut ed = ed_arc.lock().unwrap();
                if let Some(src_idx) = ed.dragging_rule_idx.take() {
                    ReleaseCapture();

                    if let Some(dst_idx) = ed.drag_target_idx.take() {
                        if src_idx != dst_idx {
                            if let Some(ref gui_arc) = SHARED_GUI_STATE {
                                let mut gui = gui_arc.lock().unwrap();
                                let sel = ed.selected_idx;
                                if sel < gui.rotation_store.profiles.len() {
                                    let profile = &mut gui.rotation_store.profiles[sel];
                                    if src_idx < profile.rules.len() && dst_idx < profile.rules.len() {
                                        let item = profile.rules.remove(src_idx);
                                        profile.rules.insert(dst_idx, item);

                                        if ed.configuring_rule_idx == Some(src_idx) {
                                            ed.configuring_rule_idx = Some(dst_idx);
                                        }

                                        let _ = gui.rotation_store.save();
                                        gui.sync_rotation = true;
                                        ed.status_msg = "Порядок заклинаний обновлен!".into();
                                        ed.status_time = Some(Instant::now());
                                    }
                                }
                            }
                        }
                    }
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                }
            }
            0
        }
        WM_LBUTTONDOWN => {
            let x = (lparam & 0xFFFF) as i32;
            let y = ((lparam >> 16) & 0xFFFF) as i32;

            if let (Some(ref ed_arc), Some(ref gui_arc)) = (EDITOR_STATE.as_ref(), SHARED_GUI_STATE.as_ref()) {
                let mut ed = ed_arc.lock().unwrap();
                let mut gui = gui_arc.lock().unwrap();

                // Commit any in-flight text edits if clicking elsewhere
                if ed.editing_profile_name {
                    let sel = ed.selected_idx;
                    if sel < gui.rotation_store.profiles.len() && !ed.profile_name_buf.trim().is_empty() {
                        gui.rotation_store.profiles[sel].name = ed.profile_name_buf.trim().to_string();
                        let _ = gui.rotation_store.save();
                        gui.sync_rotation = true;
                    }
                    ed.editing_profile_name = false;
                }
                if let Some(rule_idx) = ed.editing_spell_idx {
                    let sel = ed.selected_idx;
                    if sel < gui.rotation_store.profiles.len() {
                        let profile = &mut gui.rotation_store.profiles[sel];
                        if rule_idx < profile.rules.len() && !ed.spell_name_buf.trim().is_empty() {
                            profile.rules[rule_idx].name = ed.spell_name_buf.trim().to_string();
                            let _ = gui.rotation_store.save();
                            gui.sync_rotation = true;
                        }
                    }
                    ed.editing_spell_idx = None;
                }
                ed.listening_key_idx = None;

                // If an inline trigger dropdown is open, process click or close it
                if let Some(drop_p_idx) = ed.open_trigger_dropdown_for_idx {
                    let card_start_y = 48;
                    let card_h = 82;
                    let c_top = card_start_y + (drop_p_idx as i32) * (card_h + 8);
                    let menu_x1 = 26;
                    let menu_x2 = 248;
                    let menu_y1 = c_top + 76;
                    let menu_y2 = menu_y1 + 130;

                    if x >= menu_x1 && x <= menu_x2 && y >= menu_y1 && y <= menu_y2 {
                        let item_idx = ((y - menu_y1) / 26).clamp(0, 4);
                        let new_trigger = match item_idx {
                            0 => MouseTrigger::Mouse4,
                            1 => MouseTrigger::Mouse5,
                            2 => MouseTrigger::Middle,
                            3 => MouseTrigger::Right,
                            _ => MouseTrigger::Disabled,
                        };
                        gui.rotation_store.profiles[drop_p_idx].trigger = new_trigger;
                        let _ = gui.rotation_store.save();
                        gui.sync_rotation = true;
                        ed.open_trigger_dropdown_for_idx = None;
                        InvalidateRect(hwnd, std::ptr::null(), 0);
                        return 0;
                    } else {
                        ed.open_trigger_dropdown_for_idx = None;
                        InvalidateRect(hwnd, std::ptr::null(), 0);
                    }
                }

                // ==========================================
                // 1. LEFT PANEL: Profile List (x = 16..260)
                // ==========================================
                if x >= 16 && x <= 260 {
                    // Button [ + Создать ]: x = 160..255, y = 14..40
                    if x >= 160 && x <= 255 && y >= 14 && y <= 40 {
                        let count = gui.rotation_store.profiles.len();
                        let new_profile = RotationConfig {
                            name: format!("Ротация #{}", count + 1),
                            active: true,
                            trigger: MouseTrigger::Mouse4,
                            min_delay_ms: 110,
                            max_delay_ms: 160,
                            min_press_ms: 30,
                            max_press_ms: 70,
                            humanize: true,
                            wait_cast: true,
                            check_gcd: true,
                            reset_on_target_change: true,
                            protect_channeling: true,
                            auto_target: false,
                            auto_attack: false,
                            auto_attack_key: "t".to_string(),
                            rules: vec![
                                RotationRule {
                                    enabled: true,
                                    name: "Стрела Тьмы".into(),
                                    spell_id: Some(686),
                                    key: "1".into(),
                                    condition: ConditionType::AlwaysFiller,
                                    threshold_ms: 0,
                                    aura_target: AuraTarget::None,
                                    aura_presence: AuraPresence::Absent,
                                    aura_name: String::new(),
                                    ..Default::default()
                                },
                            ],
                        };
                        gui.rotation_store.profiles.push(new_profile);
                        let new_idx = gui.rotation_store.profiles.len() - 1;
                        ed.selected_idx = new_idx;
                        gui.sync_rotation = true;
                        let _ = gui.rotation_store.save();
                        ed.status_msg = "Новая ротация создана!".to_string();
                        ed.status_time = Some(Instant::now());
                        InvalidateRect(hwnd, std::ptr::null(), 0);
                        return 0;
                    }

                    // Profile Cards: y starts at 48, height 82px per card
                    let card_start_y = 48;
                    let card_h = 82;
                    let profiles_count = gui.rotation_store.profiles.len();

                    for p_idx in 0..profiles_count {
                        let c_top = card_start_y + (p_idx as i32) * (card_h + 8);
                        let c_bottom = c_top + card_h;

                        if y >= c_top && y <= c_bottom {
                            // Check delete button [ ✕ ]: x = 232..254, y = c_top + 6..c_top + 24
                            if x >= 232 && x <= 254 && y >= c_top + 6 && y <= c_top + 24 {
                                if profiles_count > 1 {
                                    gui.rotation_store.profiles.remove(p_idx);
                                    if ed.selected_idx >= gui.rotation_store.profiles.len() {
                                        ed.selected_idx = gui.rotation_store.profiles.len().saturating_sub(1);
                                    }
                                    gui.sync_rotation = true;
                                    let _ = gui.rotation_store.save();
                                    ed.status_msg = "Ротация удалена".to_string();
                                    ed.status_time = Some(Instant::now());
                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                    return 0;
                                }
                            }

                            // Check Trigger Dropdown Button: x = 30..248, y = c_top + 46..c_top + 76
                            if x >= 30 && x <= 248 && y >= c_top + 46 && y <= c_top + 76 {
                                if ed.open_trigger_dropdown_for_idx == Some(p_idx) {
                                    ed.open_trigger_dropdown_for_idx = None;
                                } else {
                                    ed.open_trigger_dropdown_for_idx = Some(p_idx);
                                }
                                InvalidateRect(hwnd, std::ptr::null(), 0);
                                return 0;
                            }

                            // Clicking anywhere else on card:
                            // Select this profile for editing
                            ed.selected_idx = p_idx;
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                            return 0;
                        }
                    }
                }

                // ==========================================
                // 2. MIDDLE PANEL: Spell Queue (x = 274..800)
                // ==========================================
                else if x >= 274 && x <= 800 {
                    let sel = ed.selected_idx;
                    if sel < gui.rotation_store.profiles.len() {
                        // Profile Name Edit: x = 274..640, y = 14..50
                        if x >= 274 && x <= 640 && y >= 14 && y <= 50 {
                            ed.editing_profile_name = true;
                            ed.profile_name_buf = gui.rotation_store.profiles[sel].name.clone();
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                            return 0;
                        }

                        // Button [ Настройка ротации ]: x = 648..796, y = 14..48
                        if x >= 648 && x <= 796 && y >= 14 && y <= 48 {
                            let p = &gui.rotation_store.profiles[sel];
                            let draft = SettingsDraft {
                                profile_idx: sel,
                                profile_name: p.name.clone(),
                                wait_cast: p.wait_cast,
                                check_gcd: p.check_gcd,
                                reset_on_target_change: p.reset_on_target_change,
                                protect_channeling: p.protect_channeling,
                                auto_target: p.auto_target,
                                auto_attack: p.auto_attack,
                                auto_attack_key: p.auto_attack_key.clone(),
                                min_delay_ms: p.min_delay_ms,
                                max_delay_ms: p.max_delay_ms,
                                min_press_ms: p.min_press_ms,
                                max_press_ms: p.max_press_ms,
                                humanize: p.humanize,
                                listening_attack_key: false,
                            };
                            drop(gui);
                            drop(ed);
                            open_rotation_settings_window(hwnd, draft);
                            return 0;
                        }

                        // Button [ + Добавить заклинание ]: x = 274..796, y = 56..94
                        if y >= 56 && y <= 94 {
                            let (sug_chk, sug_min, sug_max) = suggest_spell_range("Новое заклинание");
                            let new_rule = RotationRule {
                                enabled: true,
                                name: "Новое заклинание".into(),
                                spell_id: None,
                                key: "1".into(),
                                condition: ConditionType::AlwaysFiller,
                                threshold_ms: 0,
                                aura_target: AuraTarget::Target,
                                aura_presence: AuraPresence::Absent,
                                aura_name: String::new(),
                                conditions: Vec::new(),
                                check_hp: false,
                                hp_target: HpTarget::Target,
                                min_hp: 0,
                                max_hp: 100,
                                check_interrupt: false,
                                interrupt_pct: 70,
                                check_range: sug_chk,
                                min_range: sug_min,
                                max_range: sug_max,
                            };
                            gui.rotation_store.profiles[sel].rules.push(new_rule);
                            let new_rule_idx = gui.rotation_store.profiles[sel].rules.len() - 1;
                            ed.configuring_rule_idx = Some(new_rule_idx);
                            let rule = &gui.rotation_store.profiles[sel].rules[new_rule_idx];
                            ed.draft_conditions = rule.get_conditions();
                            ed.draft_check_hp = rule.check_hp;
                            ed.draft_hp_target = rule.hp_target;
                            ed.draft_min_hp = rule.min_hp;
                            ed.draft_max_hp = rule.max_hp;
                            ed.draft_check_interrupt = rule.check_interrupt;
                            ed.draft_interrupt_pct = rule.interrupt_pct;
                            ed.editing_cond_idx = None;
                            ed.aura_name_buf.clear();
                            ed.cond_active_tab = 0;

                            let _ = gui.rotation_store.save();
                            gui.sync_rotation = true;
                            InvalidateRect(hwnd, std::ptr::null(), 0);
                            return 0;
                        }

                        // Spell Rows: y starts at 104, row height 60px
                        let row_start_y = 104;
                        let row_h = 60;
                        let rules_len = gui.rotation_store.profiles[sel].rules.len();

                        for r_idx in 0..rules_len {
                            let r_top = row_start_y + (r_idx as i32) * (row_h + 6);
                            let r_bot = r_top + row_h;

                            if y >= r_top && y <= r_bot {
                                // 1. Check Delete button [ ✕ ]: x = 756..790, y = r_top + 14..r_top + 46
                                if x >= 756 && x <= 790 && y >= r_top + 14 && y <= r_top + 46 {
                                    if rules_len > 1 {
                                        gui.rotation_store.profiles[sel].rules.remove(r_idx);
                                        if ed.configuring_rule_idx == Some(r_idx) {
                                            ed.configuring_rule_idx = None;
                                        } else if let Some(c_idx) = ed.configuring_rule_idx {
                                            if c_idx > r_idx {
                                                ed.configuring_rule_idx = Some(c_idx - 1);
                                            }
                                        }
                                        let _ = gui.rotation_store.save();
                                        gui.sync_rotation = true;
                                    }
                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                    return 0;
                                }

                                // 2. Check [ Настройки ]: x = 650..748, y = r_top + 14..r_top + 46
                                if x >= 650 && x <= 748 && y >= r_top + 14 && y <= r_top + 46 {
                                    ed.configuring_rule_idx = Some(r_idx);
                                    let rule = &gui.rotation_store.profiles[sel].rules[r_idx];
                                    ed.draft_conditions = rule.get_conditions();
                                    ed.draft_check_hp = rule.check_hp;
                                    ed.draft_hp_target = rule.hp_target;
                                    ed.draft_min_hp = rule.min_hp;
                                    ed.draft_max_hp = rule.max_hp;
                                    ed.draft_check_interrupt = rule.check_interrupt;
                                    ed.draft_interrupt_pct = rule.interrupt_pct;
                                    ed.editing_cond_idx = None;
                                    ed.aura_name_buf.clear();
                                    ed.cond_active_tab = 0;
                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                    return 0;
                                }

                                // 3. Check Keybind pill: x = 566..642, y = r_top + 14..r_top + 46
                                if x >= 566 && x <= 642 && y >= r_top + 14 && y <= r_top + 46 {
                                    ed.listening_key_idx = Some(r_idx);
                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                    return 0;
                                }

                                // 4. Check Spell Name click to rename: x = 370..558, y = r_top + 8..r_top + 30
                                if x >= 370 && x <= 558 && y >= r_top + 8 && y <= r_top + 30 {
                                    ed.editing_spell_idx = Some(r_idx);
                                    ed.spell_name_buf = gui.rotation_store.profiles[sel].rules[r_idx].name.clone();
                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                    return 0;
                                }

                                // 5. Drag Handle and general row click -> Start Drag & Drop
                                ed.dragging_rule_idx = Some(r_idx);
                                ed.drag_mouse_y = y;
                                ed.drag_target_idx = Some(r_idx);
                                SetCapture(hwnd);
                                InvalidateRect(hwnd, std::ptr::null(), 0);
                                return 0;
                            }
                        }
                    }
                }

                // ==============================================================
                // 3. RIGHT PANEL: Condition Settings (x = 812..1330)
                // ==============================================================
                else if x >= 812 && x <= 1330 {
                    let sel = ed.selected_idx;
                    if sel < gui.rotation_store.profiles.len() {
                        if let Some(r_idx) = ed.configuring_rule_idx {
                            if r_idx < gui.rotation_store.profiles[sel].rules.len() {
                                // 1. Close [ ✕ ] button: x = 1285..1320, y = 14..44
                                if x >= 1285 && x <= 1320 && y >= 14 && y <= 44 {
                                    ed.configuring_rule_idx = None;
                                    ed.editing_cond_idx = None;
                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                    return 0;
                                }

                                // 2. Tabs (y = 56..90):
                                // Tab 0: [ Ауры ]: x = 826..942
                                if x >= 826 && x <= 942 && y >= 56 && y <= 90 {
                                    ed.cond_active_tab = 0;
                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                    return 0;
                                }
                                // Tab 1: [ Здоровье (HP %) ]: x = 948..1064
                                if x >= 948 && x <= 1064 && y >= 56 && y <= 90 {
                                    ed.cond_active_tab = 1;
                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                    return 0;
                                }
                                // Tab 2: [ Кик (Прерывание) ]: x = 1070..1186
                                if x >= 1070 && x <= 1186 && y >= 56 && y <= 90 {
                                    ed.cond_active_tab = 2;
                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                    return 0;
                                }
                                // Tab 3: [ Дистанция (Range) ]: x = 1192..1312
                                if x >= 1192 && x <= 1312 && y >= 56 && y <= 90 {
                                    ed.cond_active_tab = 3;
                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                    return 0;
                                }

                                // Bottom Buttons:
                                let mut client_rc: RECT = std::mem::zeroed();
                                GetClientRect(hwnd, &mut client_rc);
                                let client_h = client_rc.bottom - client_rc.top;
                                let btn_y1 = client_h - 64;
                                let btn_y2 = client_h - 12;

                                // [ Отмена ]: x = 930..1095
                                if x >= 930 && x <= 1095 && y >= btn_y1 && y <= btn_y2 {
                                    ed.configuring_rule_idx = None;
                                    ed.editing_cond_idx = None;
                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                    return 0;
                                }

                                // [ Применить ]: x = 1100..1315
                                if x >= 1100 && x <= 1315 && y >= btn_y1 && y <= btn_y2 {
                                    if let Some(c_idx) = ed.editing_cond_idx {
                                        if c_idx < ed.draft_conditions.len() {
                                            ed.draft_conditions[c_idx].aura_name = ed.aura_name_buf.trim().to_string();
                                        }
                                        ed.editing_cond_idx = None;
                                    }
                                    let rule = &mut gui.rotation_store.profiles[sel].rules[r_idx];
                                    rule.conditions = ed.draft_conditions.clone();
                                    rule.sync_legacy_fields();
                                    rule.check_hp = ed.draft_check_hp;
                                    rule.hp_target = ed.draft_hp_target;
                                    rule.min_hp = ed.draft_min_hp;
                                    rule.max_hp = ed.draft_max_hp;
                                    rule.check_interrupt = ed.draft_check_interrupt;
                                    rule.interrupt_pct = ed.draft_interrupt_pct;
                                    let _ = gui.rotation_store.save();
                                    gui.sync_rotation = true;
                                    ed.status_msg = "Условия применены!".to_string();
                                    ed.status_time = Some(Instant::now());
                                    ed.configuring_rule_idx = None;
                                    ed.editing_cond_idx = None;
                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                    return 0;
                                }

                                if ed.cond_active_tab == 0 {
                                    // Button [ + Добавить ауру ]: x = 1150..1310, y = 96..126
                                    if x >= 1150 && x <= 1310 && y >= 96 && y <= 126 {
                                        if ed.draft_conditions.len() < 5 {
                                            ed.draft_conditions.push(AuraCondition::default());
                                            InvalidateRect(hwnd, std::ptr::null(), 0);
                                            return 0;
                                        }
                                    }

                                    // Condition cards
                                    let conds_len = ed.draft_conditions.len();
                                    for i in 0..conds_len {
                                        let cy1 = 132 + (i as i32) * 118;
                                        let cy2 = cy1 + 112;

                                        if y >= cy1 && y <= cy2 {
                                            // Card Delete Button [ ✕ ]: x = 1282..1306, y = cy1 + 6..cy1 + 32
                                            if x >= 1282 && x <= 1306 && y >= cy1 + 6 && y <= cy1 + 32 {
                                                if conds_len > 1 {
                                                    ed.draft_conditions.remove(i);
                                                    if ed.editing_cond_idx == Some(i) {
                                                        ed.editing_cond_idx = None;
                                                    } else if let Some(edit_i) = ed.editing_cond_idx {
                                                        if edit_i > i {
                                                            ed.editing_cond_idx = Some(edit_i - 1);
                                                        }
                                                    }
                                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                                    return 0;
                                                }
                                            }

                                            // If i > 0, Logic Operator Buttons:
                                            // [ И (AND) ]: x = 834..906, y = cy1 + 8..cy1 + 36
                                            // [ ИЛИ (OR) ]: x = 912..984, y = cy1 + 8..cy1 + 36
                                            if i > 0 {
                                                if x >= 834 && x <= 906 && y >= cy1 + 8 && y <= cy1 + 36 {
                                                    ed.draft_conditions[i].logic = ConditionLogic::And;
                                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                                    return 0;
                                                }
                                                if x >= 912 && x <= 984 && y >= cy1 + 8 && y <= cy1 + 36 {
                                                    ed.draft_conditions[i].logic = ConditionLogic::Or;
                                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                                    return 0;
                                                }
                                            }

                                            // Target buttons:
                                            let (t_x1, t_x2, p_x1, p_x2, n_x1, n_x2) = if i == 0 {
                                                (874, 960, 968, 1064, 1072, 1195)
                                            } else {
                                                (1026, 1106, 1114, 1198, 1206, 1276)
                                            };

                                            // [ Цель ]
                                            if x >= t_x1 && x <= t_x2 && y >= cy1 + 8 && y <= cy1 + 36 {
                                                ed.draft_conditions[i].aura_target = AuraTarget::Target;
                                                InvalidateRect(hwnd, std::ptr::null(), 0);
                                                return 0;
                                            }
                                            // [ На себе ]
                                            if x >= p_x1 && x <= p_x2 && y >= cy1 + 8 && y <= cy1 + 36 {
                                                ed.draft_conditions[i].aura_target = AuraTarget::Player;
                                                InvalidateRect(hwnd, std::ptr::null(), 0);
                                                return 0;
                                            }
                                            // [ Без условий ]
                                            if x >= n_x1 && x <= n_x2 && y >= cy1 + 8 && y <= cy1 + 36 {
                                                ed.draft_conditions[i].aura_target = AuraTarget::None;
                                                InvalidateRect(hwnd, std::ptr::null(), 0);
                                                return 0;
                                            }

                                            if ed.draft_conditions[i].aura_target != AuraTarget::None {
                                                // Row 2: Input Box: x = 880..1220, y = cy1 + 42..cy1 + 72
                                                if x >= 880 && x <= 1220 && y >= cy1 + 42 && y <= cy1 + 72 {
                                                    if let Some(prev_i) = ed.editing_cond_idx {
                                                        if prev_i < ed.draft_conditions.len() {
                                                            ed.draft_conditions[prev_i].aura_name = ed.aura_name_buf.trim().to_string();
                                                        }
                                                    }
                                                    ed.editing_cond_idx = Some(i);
                                                    let curr_a = ed.draft_conditions[i].aura_name.clone();
                                                    ed.aura_name_buf = if curr_a.is_empty() {
                                                        gui.rotation_store.profiles[sel].rules[r_idx].name.clone()
                                                    } else {
                                                        curr_a
                                                    };
                                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                                    return 0;
                                                }

                                                // Row 2: Button [ Сброс ]: x = 1228..1304, y = cy1 + 42..cy1 + 72
                                                if x >= 1228 && x <= 1304 && y >= cy1 + 42 && y <= cy1 + 72 {
                                                    ed.draft_conditions[i].aura_name.clear();
                                                    if ed.editing_cond_idx == Some(i) {
                                                        ed.aura_name_buf.clear();
                                                    }
                                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                                    return 0;
                                                }

                                                // Row 3: Presence buttons: y = cy1 + 78..cy1 + 106
                                                // [ Отсутствует ]: x = 834..970
                                                if x >= 834 && x <= 970 && y >= cy1 + 78 && y <= cy1 + 106 {
                                                    ed.draft_conditions[i].aura_presence = AuraPresence::Absent;
                                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                                    return 0;
                                                }
                                                // [ Присутствует ]: x = 978..1114
                                                if x >= 978 && x <= 1114 && y >= cy1 + 78 && y <= cy1 + 106 {
                                                    ed.draft_conditions[i].aura_presence = AuraPresence::Present;
                                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                                    return 0;
                                                }

                                                // Row 3: Threshold pill / steppers: x = 1205..1304, y = cy1 + 78..cy1 + 106
                                                if x >= 1205 && x <= 1304 && y >= cy1 + 78 && y <= cy1 + 106 {
                                                    let cur_th = ed.draft_conditions[i].threshold_ms;
                                                    let next_th = match cur_th {
                                                        0 => 1500,
                                                        1500 => 2000,
                                                        2000 => 3000,
                                                        3000 => 4000,
                                                        4000 => 5000,
                                                        _ => 0,
                                                    };
                                                    ed.draft_conditions[i].threshold_ms = next_th;
                                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                                    return 0;
                                                }
                                            }
                                        }
                                    }
                                } else if ed.cond_active_tab == 1 {
                                    // Tab 1: Health (HP %) Check
                                    // 1. Checkbox: [✓] Контроль уровня здоровья (y = 106..142)
                                    if x >= 830 && x <= 1280 && y >= 106 && y <= 142 {
                                        ed.draft_check_hp = !ed.draft_check_hp;
                                        InvalidateRect(hwnd, std::ptr::null(), 0);
                                        return 0;
                                    }

                                    if ed.draft_check_hp {
                                        // 2. Target selector (y = 152..184)
                                        // [ Цель ]: x = 990..1090
                                        if x >= 990 && x <= 1090 && y >= 152 && y <= 184 {
                                            ed.draft_hp_target = HpTarget::Target;
                                            InvalidateRect(hwnd, std::ptr::null(), 0);
                                            return 0;
                                        }
                                        // [ На себе ]: x = 1100..1280
                                        if x >= 1100 && x <= 1280 && y >= 152 && y <= 184 {
                                            ed.draft_hp_target = HpTarget::Player;
                                            InvalidateRect(hwnd, std::ptr::null(), 0);
                                            return 0;
                                        }

                                        // 3. Min HP Steppers (y = 198..230)
                                        // [-]: x = 836..872
                                        if x >= 836 && x <= 872 && y >= 198 && y <= 230 {
                                            ed.draft_min_hp = ed.draft_min_hp.saturating_sub(5);
                                            InvalidateRect(hwnd, std::ptr::null(), 0);
                                            return 0;
                                        }
                                        // [+]: x = 996..1032
                                        if x >= 996 && x <= 1032 && y >= 198 && y <= 230 {
                                            ed.draft_min_hp = (ed.draft_min_hp + 5).min(ed.draft_max_hp).min(100);
                                            InvalidateRect(hwnd, std::ptr::null(), 0);
                                            return 0;
                                        }

                                        // 4. Max HP Steppers (y = 198..230)
                                        // [-]: x = 1080..1116
                                        if x >= 1080 && x <= 1116 && y >= 198 && y <= 230 {
                                            ed.draft_max_hp = ed.draft_max_hp.saturating_sub(5).max(ed.draft_min_hp);
                                            InvalidateRect(hwnd, std::ptr::null(), 0);
                                            return 0;
                                        }
                                        // [+]: x = 1240..1276
                                        if x >= 1240 && x <= 1276 && y >= 198 && y <= 230 {
                                            ed.draft_max_hp = (ed.draft_max_hp + 5).min(100);
                                            InvalidateRect(hwnd, std::ptr::null(), 0);
                                            return 0;
                                        }

                                        // 5. Presets (y = 288..316):
                                        if y >= 288 && y <= 316 {
                                            let hp_presets: [(u32, u32, Option<HpTarget>, i32, i32); 6] = [
                                                (0, 20, Some(HpTarget::Target), 836, 910),
                                                (0, 30, Some(HpTarget::Target), 914, 988),
                                                (0, 35, Some(HpTarget::Target), 992, 1066),
                                                (0, 35, Some(HpTarget::Player), 1070, 1144),
                                                (20, 100, Some(HpTarget::Target), 1148, 1222),
                                                (0, 100, None, 1226, 1300),
                                            ];
                                            for &(min_v, max_v, tgt_opt, px1, px2) in &hp_presets {
                                                if x >= px1 && x <= px2 {
                                                    ed.draft_min_hp = min_v;
                                                    ed.draft_max_hp = max_v;
                                                    if let Some(t) = tgt_opt {
                                                        ed.draft_hp_target = t;
                                                    }
                                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                                    return 0;
                                                }
                                            }
                                        }
                                    }
                                } else if ed.cond_active_tab == 2 {
                                    // Tab 2: Auto-Kick / Interrupt Check
                                    // 1. Toggle Checkbox [✓] Только прерывать (y = 106..142)
                                    if x >= 830 && x <= 1280 && y >= 106 && y <= 142 {
                                        ed.draft_check_interrupt = !ed.draft_check_interrupt;
                                        InvalidateRect(hwnd, std::ptr::null(), 0);
                                        return 0;
                                    }

                                    if ed.draft_check_interrupt {
                                        // 2. Steppers (y = 198..230)
                                        // [-]: x = 836..874
                                        if x >= 836 && x <= 874 && y >= 198 && y <= 230 {
                                            ed.draft_interrupt_pct = ed.draft_interrupt_pct.saturating_sub(5).max(10);
                                            InvalidateRect(hwnd, std::ptr::null(), 0);
                                            return 0;
                                        }
                                        // [+]: x = 1232..1270
                                        if x >= 1232 && x <= 1270 && y >= 198 && y <= 230 {
                                            ed.draft_interrupt_pct = (ed.draft_interrupt_pct + 5).min(95);
                                            InvalidateRect(hwnd, std::ptr::null(), 0);
                                            return 0;
                                        }

                                        // 3. Presets (y = 288..316)
                                        if y >= 288 && y <= 316 {
                                            let kick_presets: [(u32, i32, i32); 5] = [
                                                (50, 836, 916),
                                                (65, 924, 1004),
                                                (75, 1012, 1092),
                                                (85, 1100, 1180),
                                                (90, 1188, 1268),
                                            ];
                                            for &(k_pct, px1, px2) in &kick_presets {
                                                if x >= px1 && x <= px2 {
                                                    ed.draft_interrupt_pct = k_pct;
                                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                                    return 0;
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    // Tab 3: Range Check
                                    // Range Check Toggle (y = 106..142)
                                    if x >= 830 && x <= 1280 && y >= 106 && y <= 142 {
                                        let cur = gui.rotation_store.profiles[sel].rules[r_idx].check_range;
                                        gui.rotation_store.profiles[sel].rules[r_idx].check_range = !cur;
                                        let _ = gui.rotation_store.save();
                                        gui.sync_rotation = true;
                                        InvalidateRect(hwnd, std::ptr::null(), 0);
                                        return 0;
                                    }

                                    if gui.rotation_store.profiles[sel].rules[r_idx].check_range {
                                        // [-] button: x = 836..875, y = 168..200
                                        if x >= 836 && x <= 875 && y >= 168 && y <= 200 {
                                            let cur_max = gui.rotation_store.profiles[sel].rules[r_idx].max_range;
                                            gui.rotation_store.profiles[sel].rules[r_idx].max_range = (cur_max - 1.0).max(5.0);
                                            let _ = gui.rotation_store.save();
                                            InvalidateRect(hwnd, std::ptr::null(), 0);
                                            return 0;
                                        }
                                        // [+] button: x = 1205..1245, y = 168..200
                                        if x >= 1205 && x <= 1245 && y >= 168 && y <= 200 {
                                            let cur_max = gui.rotation_store.profiles[sel].rules[r_idx].max_range;
                                            gui.rotation_store.profiles[sel].rules[r_idx].max_range = (cur_max + 1.0).min(50.0);
                                            let _ = gui.rotation_store.save();
                                            InvalidateRect(hwnd, std::ptr::null(), 0);
                                            return 0;
                                        }
                                        // Presets (y = 214..240): 5я, 20я, 30я, 36я, 40я
                                        if y >= 214 && y <= 240 {
                                            let presets = [(5.0, 836, 904), (20.0, 911, 979), (30.0, 986, 1054), (36.0, 1061, 1129), (40.0, 1136, 1204)];
                                            for &(pval, px1, px2) in &presets {
                                                if x >= px1 && x <= px2 {
                                                    gui.rotation_store.profiles[sel].rules[r_idx].max_range = pval;
                                                    let _ = gui.rotation_store.save();
                                                    InvalidateRect(hwnd, std::ptr::null(), 0);
                                                    return 0;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
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

            // Fonts
            let font_name = encode_wide("Segoe UI");
            let h_title = CreateFontW(19, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_bold = CreateFontW(15, 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_reg = CreateFontW(14, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_small = CreateFontW(12, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());
            let h_huge = CreateFontW(22, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, font_name.as_ptr());

            // Dark canvas (#121318)
            let bg_brush = CreateSolidBrush(0x181312);
            FillRect(mem_dc, &rect, bg_brush);
            DeleteObject(bg_brush);
            SetBkMode(mem_dc, 1);

            if let (Some(ref ed_arc), Some(ref gui_arc)) = (EDITOR_STATE.as_ref(), SHARED_GUI_STATE.as_ref()) {
                let ed = ed_arc.lock().unwrap();
                let gui = gui_arc.lock().unwrap();
                let store = &gui.rotation_store;

                // ==========================================
                // 1. LEFT PANEL: Profile List (x = 16..260)
                // ==========================================
                draw_rounded_card(mem_dc, 16, 12, 262, height - 12, 0x1A1513);
                draw_card_border(mem_dc, 16, 12, 262, height - 12, 0x2A221E);

                // Header
                SelectObject(mem_dc, h_bold);
                SetTextColor(mem_dc, 0xFFD700); // Gold
                let rot_title = encode_wide("РОТАЦИИ");
                TextOutW(mem_dc, 26, 20, rot_title.as_ptr(), rot_title.len() as i32);

                // Button [ + Создать ]
                draw_rounded_card(mem_dc, 160, 16, 254, 40, 0x2A5E1A);
                draw_card_border(mem_dc, 160, 16, 254, 40, 0x3AA02A);
                SelectObject(mem_dc, h_small);
                SetTextColor(mem_dc, 0x88FF00);
                let btn_create = encode_wide("+ Создать");
                TextOutW(mem_dc, 178, 21, btn_create.as_ptr(), btn_create.len() as i32);

                // Cards
                let card_start_y = 48;
                let card_h = 82;

                for (idx, p) in store.profiles.iter().enumerate() {
                    let c_top = card_start_y + (idx as i32) * (card_h + 8);
                    if c_top + card_h > height - 16 { break; }

                    let is_sel = idx == ed.selected_idx;

                    let bg_col = if is_sel {
                        0x261E1A
                    } else {
                        0x1C1715
                    };
                    draw_rounded_card(mem_dc, 22, c_top, 256, c_top + card_h, bg_col);

                    let border_col = if is_sel {
                        0x00F0FF // Cyan outline for selected
                    } else {
                        0x2A221E
                    };
                    draw_card_border(mem_dc, 22, c_top, 256, c_top + card_h, border_col);

                    // Name
                    SelectObject(mem_dc, h_bold);
                    let name_col = if is_sel { 0x00F0FF } else { 0xDDDDDD };
                    SetTextColor(mem_dc, name_col);
                    let name_disp = encode_wide(&p.name);
                    TextOutW(mem_dc, 30, c_top + 8, name_disp.as_ptr(), name_disp.len() as i32);

                    // Delete [ ✕ ] button in top right of card (if > 1 profile)
                    if store.profiles.len() > 1 {
                        SelectObject(mem_dc, h_bold);
                        SetTextColor(mem_dc, 0x4455FF); // Red
                        let x_w = encode_wide("✕");
                        TextOutW(mem_dc, 238, c_top + 7, x_w.as_ptr(), x_w.len() as i32);
                    }

                    // Subtext: count of spells
                    SelectObject(mem_dc, h_small);
                    SetTextColor(mem_dc, 0x8E847B);
                    let sub_str = format!("{} заклинаний", p.rules.len());
                    let sub_w = encode_wide(&sub_str);
                    TextOutW(mem_dc, 30, c_top + 28, sub_w.as_ptr(), sub_w.len() as i32);

                    // Full-width Hotkey Selector Button: x = 30..248, y = c_top + 48..c_top + 74
                    let (trig_label, trig_bg, trig_border, trig_text_col) = match p.trigger {
                        MouseTrigger::Mouse4 => ("Хоткей: Mouse 4 ▼", 0x22481A, 0x388A22, 0x88FF00),
                        MouseTrigger::Mouse5 => ("Хоткей: Mouse 5 ▼", 0x22481A, 0x388A22, 0x88FF00),
                        MouseTrigger::Middle => ("Хоткей: Middle ▼", 0x22481A, 0x388A22, 0x88FF00),
                        MouseTrigger::Right => ("Хоткей: ПКМ ▼", 0x22481A, 0x388A22, 0x88FF00),
                        MouseTrigger::Disabled => ("Хоткей: Отключен ▼", 0x28201C, 0x3E3028, 0x8E847B),
                    };
                    draw_rounded_card(mem_dc, 30, c_top + 48, 248, c_top + 74, trig_bg);
                    draw_card_border(mem_dc, 30, c_top + 48, 248, c_top + 74, trig_border);
                    SelectObject(mem_dc, h_small);
                    SetTextColor(mem_dc, trig_text_col);
                    let tabbr_w = encode_wide(trig_label);
                    TextOutW(mem_dc, 48, c_top + 53, tabbr_w.as_ptr(), tabbr_w.len() as i32);
                }

                // ==========================================
                // 2. MIDDLE PANEL: Spell Queue (x = 274..800)
                // ==========================================
                let sel = ed.selected_idx;
                if sel < store.profiles.len() {
                    let prof = &store.profiles[sel];

                    // Profile Name Field
                    draw_rounded_card(mem_dc, 274, 14, 638, 50, 0x241C18);
                    draw_card_border(mem_dc, 274, 14, 638, 50, 0x362820);
                    SelectObject(mem_dc, h_title);
                    SetTextColor(mem_dc, 0xFFD700);
                    let p_title = if ed.editing_profile_name {
                        let cur = if ed.cursor_blink { "|" } else { "" };
                        format!("{}{}", ed.profile_name_buf, cur)
                    } else {
                        format!("{}  ✎", prof.name)
                    };
                    let pt_w = encode_wide(&p_title);
                    TextOutW(mem_dc, 286, 21, pt_w.as_ptr(), pt_w.len() as i32);

                    // Button [ Настройка ротации ]
                    draw_rounded_card(mem_dc, 646, 14, 796, 50, 0x2A201A);
                    draw_card_border(mem_dc, 646, 14, 796, 50, 0x403026);
                    SelectObject(mem_dc, h_reg);
                    SetTextColor(mem_dc, 0x00F0FF);
                    let n_rot_w = encode_wide("Настройка ротации ⚙");
                    TextOutW(mem_dc, 656, 23, n_rot_w.as_ptr(), n_rot_w.len() as i32);

                    // Large Add Spell Bar
                    draw_rounded_card(mem_dc, 274, 56, 796, 96, 0x1A2818);
                    draw_card_border(mem_dc, 274, 56, 796, 96, 0x2A5E2A);
                    SelectObject(mem_dc, h_bold);
                    SetTextColor(mem_dc, 0x88FF00);
                    let add_w = encode_wide("[ + ] Добавить заклинание в ротацию");
                    TextOutW(mem_dc, 410, 66, add_w.as_ptr(), add_w.len() as i32);

                    // Spell Rows List
                    let row_start_y = 104;
                    let row_h = 60;

                    for (r_idx, rule) in prof.rules.iter().enumerate() {
                        let r_top = row_start_y + (r_idx as i32) * (row_h + 6);
                        if r_top + row_h > height - 14 { break; }

                        let is_dragging_this = ed.dragging_rule_idx == Some(r_idx);
                        let is_drop_target = ed.drag_target_idx == Some(r_idx);
                        let is_configured = ed.configuring_rule_idx == Some(r_idx);

                        let card_bg = if is_configured {
                            0x2E241E
                        } else if is_dragging_this {
                            0x181412
                        } else {
                            0x221B17
                        };
                        draw_rounded_card(mem_dc, 274, r_top, 796, r_top + row_h, card_bg);

                        let border_c = if is_configured {
                            0x88FF00 // Green highlight
                        } else if is_drop_target && ed.dragging_rule_idx.is_some() {
                            0x00F0FF // Cyan highlight for drop target
                        } else {
                            0x322620
                        };
                        draw_card_border(mem_dc, 274, r_top, 796, r_top + row_h, border_c);

                        // 1. Drag Handle and Priority Number: ::: #1
                        SelectObject(mem_dc, h_bold);
                        SetTextColor(mem_dc, 0x666666);
                        let dots_w = encode_wide(":::");
                        TextOutW(mem_dc, 284, r_top + 20, dots_w.as_ptr(), dots_w.len() as i32);

                        SetTextColor(mem_dc, 0x00F0FF);
                        let num_s = format!("#{}", r_idx + 1);
                        let num_w = encode_wide(&num_s);
                        TextOutW(mem_dc, 305, r_top + 20, num_w.as_ptr(), num_w.len() as i32);

                        // 2. Spell Icon Box Placeholder
                        draw_rounded_card(mem_dc, 332, r_top + 10, 368, r_top + 50, 0x362020);
                        draw_card_border(mem_dc, 332, r_top + 10, 368, r_top + 50, 0x553030);
                        SelectObject(mem_dc, h_bold);
                        SetTextColor(mem_dc, 0xFF8844);
                        let icon_letter = rule.name.chars().next().unwrap_or('?').to_string();
                        let il_w = encode_wide(&icon_letter);
                        TextOutW(mem_dc, 344, r_top + 18, il_w.as_ptr(), il_w.len() as i32);

                        // 3. Spell Name (Editable on click)
                        SelectObject(mem_dc, h_bold);
                        SetTextColor(mem_dc, 0xFFFFFF);
                        let name_text = if ed.editing_spell_idx == Some(r_idx) {
                            let cur = if ed.cursor_blink { "|" } else { "" };
                            format!("{}{}", ed.spell_name_buf, cur)
                        } else {
                            rule.name.clone()
                        };
                        let nt_w = encode_wide(&name_text);
                        TextOutW(mem_dc, 376, r_top + 10, nt_w.as_ptr(), nt_w.len() as i32);

                        // 4. Subtitle: Condition Summary
                        SelectObject(mem_dc, h_small);
                        SetTextColor(mem_dc, 0xA89B90);
                        let cond_sum = rule.condition_summary();
                        let cs_w = encode_wide(&cond_sum);
                        TextOutW(mem_dc, 376, r_top + 32, cs_w.as_ptr(), cs_w.len() as i32);

                        // 5. Keybind pill: [ Кл: 1 ]
                        let is_listening = ed.listening_key_idx == Some(r_idx);
                        let (kb_txt, kb_bg, kb_col) = if is_listening {
                            ("Нажмите...".to_string(), 0x381818, 0xFF8844)
                        } else {
                            (format!("[Кл: {}]", rule.key), 0x2A201A, 0x00F0FF)
                        };
                        draw_rounded_card(mem_dc, 566, r_top + 14, 642, r_top + 46, kb_bg);
                        draw_card_border(mem_dc, 566, r_top + 14, 642, r_top + 46, 0x403026);
                        SelectObject(mem_dc, h_small);
                        SetTextColor(mem_dc, kb_col);
                        let kb_w = encode_wide(&kb_txt);
                        TextOutW(mem_dc, 574, r_top + 21, kb_w.as_ptr(), kb_w.len() as i32);

                        // 6. Button [ Настройки ]
                        let cfg_btn_bg = if is_configured { 0x2A5E1A } else { 0x2A221C };
                        let cfg_btn_col = if is_configured { 0x88FF00 } else { 0x00F0FF };
                        draw_rounded_card(mem_dc, 650, r_top + 14, 748, r_top + 46, cfg_btn_bg);
                        draw_card_border(mem_dc, 650, r_top + 14, 748, r_top + 46, 0x3E3028);
                        SelectObject(mem_dc, h_small);
                        SetTextColor(mem_dc, cfg_btn_col);
                        let cfg_w = encode_wide("Настройки");
                        TextOutW(mem_dc, 668, r_top + 21, cfg_w.as_ptr(), cfg_w.len() as i32);

                        // 7. Button [ ✕ ] (Delete rule)
                        draw_rounded_card(mem_dc, 756, r_top + 14, 790, r_top + 46, 0x241618);
                        draw_card_border(mem_dc, 756, r_top + 14, 790, r_top + 46, 0x452024);
                        SelectObject(mem_dc, h_bold);
                        SetTextColor(mem_dc, 0x4455FF); // Red
                        let del_w = encode_wide("✕");
                        TextOutW(mem_dc, 768, r_top + 21, del_w.as_ptr(), del_w.len() as i32);
                    }
                }

                // ==============================================================
                // 3. RIGHT PANEL: Condition Settings (x = 812..1324)
                // ==============================================================
                draw_rounded_card(mem_dc, 812, 12, 1324, height - 12, 0x1A1513);
                draw_card_border(mem_dc, 812, 12, 1324, height - 12, 0x2A221E);

                let sel = ed.selected_idx;
                if sel < store.profiles.len() {
                    if let Some(r_idx) = ed.configuring_rule_idx {
                        if r_idx < store.profiles[sel].rules.len() {
                            let rule = &store.profiles[sel].rules[r_idx];

                            // Panel Title
                            SelectObject(mem_dc, h_title);
                            SetTextColor(mem_dc, 0x88FF00); // Green accent
                            let ct_w = encode_wide("Настройка условий действия");
                            TextOutW(mem_dc, 828, 20, ct_w.as_ptr(), ct_w.len() as i32);

                            // Close Button [ ✕ ]
                            SelectObject(mem_dc, h_bold);
                            SetTextColor(mem_dc, 0x5555FF); // Coral red
                            let close_w = encode_wide("✕");
                            TextOutW(mem_dc, 1298, 20, close_w.as_ptr(), close_w.len() as i32);

                            // Tab 0: [ Ауры ] (826..942)
                            let tab0_active = ed.cond_active_tab == 0;
                            draw_rounded_card(mem_dc, 826, 56, 942, 90, if tab0_active { 0x284E20 } else { 0x201814 });
                            draw_card_border(mem_dc, 826, 56, 942, 90, if tab0_active { 0x388E28 } else { 0x322822 });
                            SelectObject(mem_dc, h_small);
                            SetTextColor(mem_dc, if tab0_active { 0x88FF00 } else { 0x8E847B });
                            let tab0_w = encode_wide("Ауры (Дебаффы)");
                            TextOutW(mem_dc, 834, 66, tab0_w.as_ptr(), tab0_w.len() as i32);

                            // Tab 1: [ Здоровье (HP %) ] (948..1064)
                            let tab1_active = ed.cond_active_tab == 1;
                            draw_rounded_card(mem_dc, 948, 56, 1064, 90, if tab1_active { 0x284E20 } else { 0x201814 });
                            draw_card_border(mem_dc, 948, 56, 1064, 90, if tab1_active { 0x388E28 } else { 0x322822 });
                            SelectObject(mem_dc, h_small);
                            SetTextColor(mem_dc, if tab1_active { 0x88FF00 } else { 0x8E847B });
                            let tab1_w = encode_wide("Здоровье (HP)");
                            TextOutW(mem_dc, 958, 66, tab1_w.as_ptr(), tab1_w.len() as i32);

                            // Tab 2: [ Кик (Автокик) ] (1070..1186)
                            let tab2_active = ed.cond_active_tab == 2;
                            draw_rounded_card(mem_dc, 1070, 56, 1186, 90, if tab2_active { 0x284E20 } else { 0x201814 });
                            draw_card_border(mem_dc, 1070, 56, 1186, 90, if tab2_active { 0x388E28 } else { 0x322822 });
                            SelectObject(mem_dc, h_small);
                            SetTextColor(mem_dc, if tab2_active { 0x88FF00 } else { 0x8E847B });
                            let tab2_w = encode_wide("Кик (Автокик)");
                            TextOutW(mem_dc, 1080, 66, tab2_w.as_ptr(), tab2_w.len() as i32);

                            // Tab 3: [ Дистанция (Range) ] (1192..1312)
                            let tab3_active = ed.cond_active_tab == 3;
                            draw_rounded_card(mem_dc, 1192, 56, 1312, 90, if tab3_active { 0x284E20 } else { 0x201814 });
                            draw_card_border(mem_dc, 1192, 56, 1312, 90, if tab3_active { 0x388E28 } else { 0x322822 });
                            SelectObject(mem_dc, h_small);
                            SetTextColor(mem_dc, if tab3_active { 0x88FF00 } else { 0x8E847B });
                            let tab3_w = encode_wide("Дистанция");
                            TextOutW(mem_dc, 1216, 66, tab3_w.as_ptr(), tab3_w.len() as i32);

                            if ed.cond_active_tab == 0 {
                                // Section Label: Список условий (с логикой И / ИЛИ для каждой ауры):
                                SelectObject(mem_dc, h_bold);
                                SetTextColor(mem_dc, 0xFFD700);
                                let lbl_w = encode_wide("Список условий (с логикой И / ИЛИ для каждой ауры):");
                                TextOutW(mem_dc, 828, 104, lbl_w.as_ptr(), lbl_w.len() as i32);

                                // Button [ + Добавить ауру ]
                                draw_rounded_card(mem_dc, 1150, 96, 1312, 124, 0x261E1A);
                                draw_card_border(mem_dc, 1150, 96, 1312, 124, 0x3E3028);
                                SelectObject(mem_dc, h_small);
                                SetTextColor(mem_dc, 0xFFD700);
                                let add_a_w = encode_wide("+ Добавить ауру");
                                TextOutW(mem_dc, 1168, 102, add_a_w.as_ptr(), add_a_w.len() as i32);

                                // Render Condition Cards
                                let conds_len = ed.draft_conditions.len();
                                for (i, cond) in ed.draft_conditions.iter().enumerate() {
                                    let cy1 = 132 + (i as i32) * 118;
                                    let cy2 = cy1 + 112;

                                    if cy2 > height - 64 {
                                        break; // Safety boundary
                                    }

                                    // Card Body
                                    draw_rounded_card(mem_dc, 826, cy1, 1312, cy2, 0x221B17);
                                    draw_card_border(mem_dc, 826, cy1, 1312, cy2, 0x342820);

                                    // Card Delete Button [ x ]
                                    if conds_len > 1 {
                                        SelectObject(mem_dc, h_bold);
                                        SetTextColor(mem_dc, 0x8E847B);
                                        let del_w = encode_wide("✕");
                                        TextOutW(mem_dc, 1290, cy1 + 10, del_w.as_ptr(), del_w.len() as i32);
                                    }

                                    // Row 1: Badges & Targets
                                    if i == 0 {
                                        // Badge # 1
                                        SelectObject(mem_dc, h_bold);
                                        SetTextColor(mem_dc, 0x88FF00);
                                        let num_w = encode_wide("# 1");
                                        TextOutW(mem_dc, 838, cy1 + 12, num_w.as_ptr(), num_w.len() as i32);

                                        // [ Цель ]
                                        let is_t = cond.aura_target == AuraTarget::Target;
                                        draw_rounded_card(mem_dc, 874, cy1 + 8, 960, cy1 + 36, if is_t { 0x2A5E1A } else { 0x2E241E });
                                        draw_card_border(mem_dc, 874, cy1 + 8, 960, cy1 + 36, if is_t { 0x389E28 } else { 0x3E3028 });
                                        SelectObject(mem_dc, h_small);
                                        SetTextColor(mem_dc, if is_t { 0x88FF00 } else { 0x9E948B });
                                        let b_t = encode_wide("Цель");
                                        TextOutW(mem_dc, 902, cy1 + 15, b_t.as_ptr(), b_t.len() as i32);

                                        // [ На себе ]
                                        let is_p = cond.aura_target == AuraTarget::Player;
                                        draw_rounded_card(mem_dc, 968, cy1 + 8, 1064, cy1 + 36, if is_p { 0x2A5E1A } else { 0x2E241E });
                                        draw_card_border(mem_dc, 968, cy1 + 8, 1064, cy1 + 36, if is_p { 0x389E28 } else { 0x3E3028 });
                                        SetTextColor(mem_dc, if is_p { 0x88FF00 } else { 0x9E948B });
                                        let b_p = encode_wide("На себе");
                                        TextOutW(mem_dc, 995, cy1 + 15, b_p.as_ptr(), b_p.len() as i32);

                                        // [ Без условий ]
                                        let is_n = cond.aura_target == AuraTarget::None;
                                        draw_rounded_card(mem_dc, 1072, cy1 + 8, 1195, cy1 + 36, if is_n { 0x2A5E1A } else { 0x2E241E });
                                        draw_card_border(mem_dc, 1072, cy1 + 8, 1195, cy1 + 36, if is_n { 0x389E28 } else { 0x3E3028 });
                                        SetTextColor(mem_dc, if is_n { 0x88FF00 } else { 0x9E948B });
                                        let b_n = encode_wide("Без условий");
                                        TextOutW(mem_dc, 1098, cy1 + 15, b_n.as_ptr(), b_n.len() as i32);
                                    } else {
                                        // Logic Operator: [ И (AND) ] and [ ИЛИ (OR) ]
                                        let is_and = cond.logic == ConditionLogic::And;
                                        draw_rounded_card(mem_dc, 834, cy1 + 8, 906, cy1 + 36, if is_and { 0x2A5E1A } else { 0x221B17 });
                                        draw_card_border(mem_dc, 834, cy1 + 8, 906, cy1 + 36, if is_and { 0x389E28 } else { 0x322822 });
                                        SelectObject(mem_dc, h_small);
                                        SetTextColor(mem_dc, if is_and { 0x88FF00 } else { 0x777777 });
                                        let b_and = encode_wide("И (AND)");
                                        TextOutW(mem_dc, 846, cy1 + 15, b_and.as_ptr(), b_and.len() as i32);

                                        let is_or = cond.logic == ConditionLogic::Or;
                                        draw_rounded_card(mem_dc, 912, cy1 + 8, 984, cy1 + 36, if is_or { 0x2A5E1A } else { 0x221B17 });
                                        draw_card_border(mem_dc, 912, cy1 + 8, 984, cy1 + 36, if is_or { 0x389E28 } else { 0x322822 });
                                        SetTextColor(mem_dc, if is_or { 0x88FF00 } else { 0x777777 });
                                        let b_or = encode_wide("ИЛИ (OR)");
                                        TextOutW(mem_dc, 922, cy1 + 15, b_or.as_ptr(), b_or.len() as i32);

                                        // Badge # N
                                        SelectObject(mem_dc, h_bold);
                                        SetTextColor(mem_dc, 0x00F0FF);
                                        let num_str = format!("# {}", i + 1);
                                        let num_w = encode_wide(&num_str);
                                        TextOutW(mem_dc, 995, cy1 + 12, num_w.as_ptr(), num_w.len() as i32);

                                        // [ Цель ]
                                        let is_t = cond.aura_target == AuraTarget::Target;
                                        draw_rounded_card(mem_dc, 1026, cy1 + 8, 1106, cy1 + 36, if is_t { 0x2A5E1A } else { 0x2E241E });
                                        draw_card_border(mem_dc, 1026, cy1 + 8, 1106, cy1 + 36, if is_t { 0x389E28 } else { 0x3E3028 });
                                        SelectObject(mem_dc, h_small);
                                        SetTextColor(mem_dc, if is_t { 0x88FF00 } else { 0x9E948B });
                                        let b_t = encode_wide("Цель");
                                        TextOutW(mem_dc, 1052, cy1 + 15, b_t.as_ptr(), b_t.len() as i32);

                                        // [ На себе ]
                                        let is_p = cond.aura_target == AuraTarget::Player;
                                        draw_rounded_card(mem_dc, 1114, cy1 + 8, 1198, cy1 + 36, if is_p { 0x2A5E1A } else { 0x2E241E });
                                        draw_card_border(mem_dc, 1114, cy1 + 8, 1198, cy1 + 36, if is_p { 0x389E28 } else { 0x3E3028 });
                                        SetTextColor(mem_dc, if is_p { 0x88FF00 } else { 0x9E948B });
                                        let b_p = encode_wide("На себе");
                                        TextOutW(mem_dc, 1136, cy1 + 15, b_p.as_ptr(), b_p.len() as i32);

                                        // [ Без условий ]
                                        let is_n = cond.aura_target == AuraTarget::None;
                                        draw_rounded_card(mem_dc, 1206, cy1 + 8, 1276, cy1 + 36, if is_n { 0x2A5E1A } else { 0x2E241E });
                                        draw_card_border(mem_dc, 1206, cy1 + 8, 1276, cy1 + 36, if is_n { 0x389E28 } else { 0x3E3028 });
                                        SetTextColor(mem_dc, if is_n { 0x88FF00 } else { 0x9E948B });
                                        let b_n = encode_wide("Всегда");
                                        TextOutW(mem_dc, 1222, cy1 + 15, b_n.as_ptr(), b_n.len() as i32);
                                    }

                                    // Row 2: Input Box & Reset
                                    if cond.aura_target != AuraTarget::None {
                                        SelectObject(mem_dc, h_small);
                                        SetTextColor(mem_dc, 0x9E948B);
                                        let a_lbl = encode_wide("Аура:");
                                        TextOutW(mem_dc, 836, cy1 + 49, a_lbl.as_ptr(), a_lbl.len() as i32);

                                        let is_editing_this = ed.editing_cond_idx == Some(i);
                                        draw_rounded_card(mem_dc, 880, cy1 + 42, 1220, cy1 + 72, 0x181412);
                                        draw_card_border(mem_dc, 880, cy1 + 42, 1220, cy1 + 72, if is_editing_this { 0x00F0FF } else { 0x362820 });
                                        SelectObject(mem_dc, h_bold);
                                        SetTextColor(mem_dc, 0xFFFFFF);
                                        let a_display = if is_editing_this {
                                            let cur = if ed.cursor_blink { "|" } else { "" };
                                            format!("{}{}", ed.aura_name_buf, cur)
                                        } else if !cond.aura_name.trim().is_empty() {
                                            cond.aura_name.clone()
                                        } else {
                                            rule.name.clone()
                                        };
                                        let ad_w = encode_wide(&a_display);
                                        TextOutW(mem_dc, 890, cy1 + 49, ad_w.as_ptr(), ad_w.len() as i32);

                                        // Button [ Сброс ]
                                        draw_rounded_card(mem_dc, 1228, cy1 + 42, 1304, cy1 + 72, 0x2A201A);
                                        draw_card_border(mem_dc, 1228, cy1 + 42, 1304, cy1 + 72, 0x382A22);
                                        SelectObject(mem_dc, h_small);
                                        SetTextColor(mem_dc, 0x8E847B);
                                        let sbr_w = encode_wide("Сброс");
                                        TextOutW(mem_dc, 1248, cy1 + 49, sbr_w.as_ptr(), sbr_w.len() as i32);
                                    } else {
                                        SelectObject(mem_dc, h_small);
                                        SetTextColor(mem_dc, 0x88FF00);
                                        let bu_info = encode_wide("Аура не требуется — заклинание применяется по кулдауну / спам");
                                        TextOutW(mem_dc, 840, cy1 + 50, bu_info.as_ptr(), bu_info.len() as i32);
                                    }

                                    // Row 3: Presence & Threshold
                                    if cond.aura_target != AuraTarget::None {
                                        // [ Отсутствует ]
                                        let is_absent = cond.aura_presence == AuraPresence::Absent;
                                        draw_rounded_card(mem_dc, 834, cy1 + 78, 970, cy1 + 106, if is_absent { 0x2A5E1A } else { 0x2E241E });
                                        draw_card_border(mem_dc, 834, cy1 + 78, 970, cy1 + 106, if is_absent { 0x389E28 } else { 0x3E3028 });
                                        SelectObject(mem_dc, h_small);
                                        SetTextColor(mem_dc, if is_absent { 0x88FF00 } else { 0x9E948B });
                                        let abs_w = encode_wide("Отсутствует");
                                        TextOutW(mem_dc, 856, cy1 + 84, abs_w.as_ptr(), abs_w.len() as i32);

                                        // [ Присутствует ]
                                        let is_pres = cond.aura_presence == AuraPresence::Present;
                                        draw_rounded_card(mem_dc, 978, cy1 + 78, 1114, cy1 + 106, if is_pres { 0x2A5E1A } else { 0x2E241E });
                                        draw_card_border(mem_dc, 978, cy1 + 78, 1114, cy1 + 106, if is_pres { 0x389E28 } else { 0x3E3028 });
                                        SetTextColor(mem_dc, if is_pres { 0x88FF00 } else { 0x9E948B });
                                        let pres_w = encode_wide("Присутствует");
                                        TextOutW(mem_dc, 1004, cy1 + 84, pres_w.as_ptr(), pres_w.len() as i32);

                                        // Threshold pill
                                        SelectObject(mem_dc, h_small);
                                        SetTextColor(mem_dc, 0x9E948B);
                                        let th_lbl = encode_wide("Обновлять за:");
                                        TextOutW(mem_dc, 1124, cy1 + 84, th_lbl.as_ptr(), th_lbl.len() as i32);

                                        draw_rounded_card(mem_dc, 1210, cy1 + 78, 1304, cy1 + 106, 0x181412);
                                        draw_card_border(mem_dc, 1210, cy1 + 78, 1304, cy1 + 106, 0x32241C);
                                        SelectObject(mem_dc, h_bold);
                                        SetTextColor(mem_dc, 0x00F0FF);
                                        let sec_f = (cond.threshold_ms as f32) / 1000.0;
                                        let th_val_str = if cond.threshold_ms == 0 {
                                            "0 сек ⟳".to_string()
                                        } else {
                                            format!("{:.1} сек ⟳", sec_f)
                                        };
                                        let tv_w = encode_wide(&th_val_str);
                                        TextOutW(mem_dc, 1228, cy1 + 84, tv_w.as_ptr(), tv_w.len() as i32);
                                    }
                                }
                            } else if ed.cond_active_tab == 1 {
                                // Tab 1: Health (HP %) Tab
                                draw_rounded_card(mem_dc, 826, 100, 1312, 340, 0x221B17);
                                draw_card_border(mem_dc, 826, 100, 1312, 340, 0x342820);

                                // Checkbox [✓] / [ ]
                                let chk_bg = if ed.draft_check_hp { 0x2A5E1A } else { 0x2E241E };
                                draw_rounded_card(mem_dc, 836, 112, 860, 136, chk_bg);
                                draw_card_border(mem_dc, 836, 112, 860, 136, if ed.draft_check_hp { 0x389E28 } else { 0x3E3028 });
                                if ed.draft_check_hp {
                                    SelectObject(mem_dc, h_bold);
                                    SetTextColor(mem_dc, 0x88FF00);
                                    let v_mark = encode_wide("✓");
                                    TextOutW(mem_dc, 843, 115, v_mark.as_ptr(), v_mark.len() as i32);
                                }

                                SelectObject(mem_dc, h_bold);
                                SetTextColor(mem_dc, if ed.draft_check_hp { 0xFFD700 } else { 0x8E847B });
                                let hp_lbl = encode_wide("Контроль уровня здоровья (HP Check)");
                                TextOutW(mem_dc, 870, 115, hp_lbl.as_ptr(), hp_lbl.len() as i32);

                                if ed.draft_check_hp {
                                    // Row 1: Target selector
                                    SelectObject(mem_dc, h_small);
                                    SetTextColor(mem_dc, 0x9E948B);
                                    let who_lbl = encode_wide("Проверять здоровье у:");
                                    TextOutW(mem_dc, 836, 159, who_lbl.as_ptr(), who_lbl.len() as i32);

                                    // Button [ Цель ]
                                    let is_tgt = ed.draft_hp_target == HpTarget::Target;
                                    draw_rounded_card(mem_dc, 990, 152, 1090, 182, if is_tgt { 0x284E20 } else { 0x201814 });
                                    draw_card_border(mem_dc, 990, 152, 1090, 182, if is_tgt { 0x3AA02A } else { 0x322822 });
                                    SelectObject(mem_dc, h_bold);
                                    SetTextColor(mem_dc, if is_tgt { 0x88FF00 } else { 0x8E847B });
                                    let tgt_w = encode_wide("Цель");
                                    TextOutW(mem_dc, 1024, 158, tgt_w.as_ptr(), tgt_w.len() as i32);

                                    // Button [ На себе (Игрок) ]
                                    let is_pl = ed.draft_hp_target == HpTarget::Player;
                                    draw_rounded_card(mem_dc, 1100, 152, 1280, 182, if is_pl { 0x284E20 } else { 0x201814 });
                                    draw_card_border(mem_dc, 1100, 152, 1280, 182, if is_pl { 0x3AA02A } else { 0x322822 });
                                    SelectObject(mem_dc, h_bold);
                                    SetTextColor(mem_dc, if is_pl { 0x88FF00 } else { 0x8E847B });
                                    let pl_w = encode_wide("На себе (Игрок)");
                                    TextOutW(mem_dc, 1130, 158, pl_w.as_ptr(), pl_w.len() as i32);

                                    // Row 2: Min HP column
                                    SelectObject(mem_dc, h_small);
                                    SetTextColor(mem_dc, 0x9E948B);
                                    let min_lbl = encode_wide("Минимальное HP:");
                                    TextOutW(mem_dc, 836, 198, min_lbl.as_ptr(), min_lbl.len() as i32);

                                    // [-] button
                                    draw_rounded_card(mem_dc, 836, 218, 872, 248, 0x2A201A);
                                    draw_card_border(mem_dc, 836, 218, 872, 248, 0x382A22);
                                    SelectObject(mem_dc, h_bold);
                                    SetTextColor(mem_dc, 0x00F0FF);
                                    let minus_w = encode_wide("-");
                                    TextOutW(mem_dc, 850, 222, minus_w.as_ptr(), minus_w.len() as i32);

                                    // Value box (Min)
                                    draw_rounded_card(mem_dc, 878, 218, 990, 248, 0x181412);
                                    draw_card_border(mem_dc, 878, 218, 990, 248, 0x32241C);
                                    SelectObject(mem_dc, h_reg);
                                    SetTextColor(mem_dc, 0xFFFFFF);
                                    let min_val_str = format!("{} %", ed.draft_min_hp);
                                    let min_val_w = encode_wide(&min_val_str);
                                    TextOutW(mem_dc, 915, 225, min_val_w.as_ptr(), min_val_w.len() as i32);

                                    // [+] button
                                    draw_rounded_card(mem_dc, 996, 218, 1032, 248, 0x2A201A);
                                    draw_card_border(mem_dc, 996, 218, 1032, 248, 0x382A22);
                                    SelectObject(mem_dc, h_bold);
                                    SetTextColor(mem_dc, 0x00F0FF);
                                    let plus_w = encode_wide("+");
                                    TextOutW(mem_dc, 1010, 222, plus_w.as_ptr(), plus_w.len() as i32);

                                    // Row 2: Max HP column
                                    SelectObject(mem_dc, h_small);
                                    SetTextColor(mem_dc, 0x9E948B);
                                    let max_lbl = encode_wide("Максимальное HP:");
                                    TextOutW(mem_dc, 1080, 198, max_lbl.as_ptr(), max_lbl.len() as i32);

                                    // [-] button
                                    draw_rounded_card(mem_dc, 1080, 218, 1116, 248, 0x2A201A);
                                    draw_card_border(mem_dc, 1080, 218, 1116, 248, 0x382A22);
                                    SelectObject(mem_dc, h_bold);
                                    SetTextColor(mem_dc, 0x00F0FF);
                                    TextOutW(mem_dc, 1094, 222, minus_w.as_ptr(), minus_w.len() as i32);

                                    // Value box (Max)
                                    draw_rounded_card(mem_dc, 1122, 218, 1234, 248, 0x181412);
                                    draw_card_border(mem_dc, 1122, 218, 1234, 248, 0x32241C);
                                    SelectObject(mem_dc, h_reg);
                                    SetTextColor(mem_dc, 0xFFFFFF);
                                    let max_val_str = format!("{} %", ed.draft_max_hp);
                                    let max_val_w = encode_wide(&max_val_str);
                                    TextOutW(mem_dc, 1159, 225, max_val_w.as_ptr(), max_val_w.len() as i32);

                                    // [+] button
                                    draw_rounded_card(mem_dc, 1240, 218, 1276, 248, 0x2A201A);
                                    draw_card_border(mem_dc, 1240, 218, 1276, 248, 0x382A22);
                                    SelectObject(mem_dc, h_bold);
                                    SetTextColor(mem_dc, 0x00F0FF);
                                    TextOutW(mem_dc, 1254, 222, plus_w.as_ptr(), plus_w.len() as i32);

                                    // Row 3: Visual Health Range Bar
                                    draw_rounded_card(mem_dc, 836, 260, 1276, 276, 0x1A1412);
                                    draw_card_border(mem_dc, 836, 260, 1276, 276, 0x30241E);
                                    let bar_total_w = 440.0;
                                    let bar_x1 = 836 + ((ed.draft_min_hp as f32 / 100.0) * bar_total_w) as i32;
                                    let bar_x2 = 836 + ((ed.draft_max_hp as f32 / 100.0) * bar_total_w) as i32;
                                    if bar_x2 > bar_x1 {
                                        draw_rounded_card(mem_dc, bar_x1, 261, bar_x2, 275, 0x2A7020);
                                        draw_card_border(mem_dc, bar_x1, 261, bar_x2, 275, 0x389E28);
                                    }
                                    SelectObject(mem_dc, h_small);
                                    SetTextColor(mem_dc, 0x88FF00);
                                    let range_info = format!("Срабатывает: когда у [{}] от {}% до {}% здоровья", ed.draft_hp_target.as_str(), ed.draft_min_hp, ed.draft_max_hp);
                                    let ri_w = encode_wide(&range_info);
                                    TextOutW(mem_dc, 836, 280, ri_w.as_ptr(), ri_w.len() as i32);

                                    // Row 4: Presets
                                    let presets: [(u32, u32, Option<HpTarget>, &str); 6] = [
                                        (0, 20, Some(HpTarget::Target), "0-20% Казнь"),
                                        (0, 30, Some(HpTarget::Target), "0-30% Добив"),
                                        (0, 35, Some(HpTarget::Target), "0-35% Смерт"),
                                        (0, 35, Some(HpTarget::Player), "<35% Спас"),
                                        (20, 100, Some(HpTarget::Target), "20-100%"),
                                        (0, 100, None, "0-100% Все"),
                                    ];
                                    for (p_i, &(pr_min, pr_max, pr_tgt, pr_lbl)) in presets.iter().enumerate() {
                                        let px1 = 836 + (p_i as i32) * 74;
                                        let px2 = px1 + 68;
                                        let is_cur = ed.draft_min_hp == pr_min && ed.draft_max_hp == pr_max && (pr_tgt.is_none() || pr_tgt == Some(ed.draft_hp_target));
                                        let (pbg, pcol) = if is_cur { (0x284E20, 0x88FF00) } else { (0x221B17, 0x8E847B) };
                                        draw_rounded_card(mem_dc, px1, 304, px2, 326, pbg);
                                        draw_card_border(mem_dc, px1, 304, px2, 326, if is_cur { 0x3AA02A } else { 0x32241C });
                                        SelectObject(mem_dc, h_small);
                                        SetTextColor(mem_dc, pcol);
                                        let pr_w = encode_wide(pr_lbl);
                                        TextOutW(mem_dc, px1 + 4, 308, pr_w.as_ptr(), pr_w.len() as i32);
                                    }
                                } else {
                                    SelectObject(mem_dc, h_reg);
                                    SetTextColor(mem_dc, 0x6E645B);
                                    let off_msg = encode_wide("Проверка здоровья отключена (заклинание применяется независимо от % HP).");
                                    TextOutW(mem_dc, 840, 150, off_msg.as_ptr(), off_msg.len() as i32);
                                }
                            } else if ed.cond_active_tab == 2 {
                                // Tab 2: Auto-Kick / Interrupt Tab
                                draw_rounded_card(mem_dc, 826, 100, 1312, 340, 0x221B17);
                                draw_card_border(mem_dc, 826, 100, 1312, 340, 0x342820);

                                // Checkbox [✓] / [ ]
                                let chk_bg = if ed.draft_check_interrupt { 0x2A5E1A } else { 0x2E241E };
                                draw_rounded_card(mem_dc, 836, 112, 860, 136, chk_bg);
                                draw_card_border(mem_dc, 836, 112, 860, 136, if ed.draft_check_interrupt { 0x389E28 } else { 0x3E3028 });
                                if ed.draft_check_interrupt {
                                    SelectObject(mem_dc, h_bold);
                                    SetTextColor(mem_dc, 0x88FF00);
                                    let v_mark = encode_wide("✓");
                                    TextOutW(mem_dc, 843, 115, v_mark.as_ptr(), v_mark.len() as i32);
                                }

                                SelectObject(mem_dc, h_bold);
                                SetTextColor(mem_dc, if ed.draft_check_interrupt { 0xFFD700 } else { 0x8E847B });
                                let kick_lbl = encode_wide("Только прерывать (Auto-Kick / Interrupt)");
                                TextOutW(mem_dc, 870, 115, kick_lbl.as_ptr(), kick_lbl.len() as i32);

                                if ed.draft_check_interrupt {
                                    SelectObject(mem_dc, h_small);
                                    SetTextColor(mem_dc, 0x9E948B);
                                    let kick_sub = encode_wide("Заклинание срабатывает ТОЛЬКО когда цель читает заклинание или поддерживает поток");
                                    TextOutW(mem_dc, 836, 146, kick_sub.as_ptr(), kick_sub.len() as i32);

                                    // Row 2: Threshold stepper
                                    SelectObject(mem_dc, h_small);
                                    SetTextColor(mem_dc, 0x9E948B);
                                    let th_lbl = encode_wide("Порог срабатывания прерывания (прогресс каста):");
                                    TextOutW(mem_dc, 836, 174, th_lbl.as_ptr(), th_lbl.len() as i32);

                                    // [-] button
                                    draw_rounded_card(mem_dc, 836, 198, 874, 230, 0x2A201A);
                                    draw_card_border(mem_dc, 836, 198, 874, 230, 0x382A22);
                                    SelectObject(mem_dc, h_bold);
                                    SetTextColor(mem_dc, 0x00F0FF);
                                    let minus_w = encode_wide("-");
                                    TextOutW(mem_dc, 851, 202, minus_w.as_ptr(), minus_w.len() as i32);

                                    // Value box
                                    draw_rounded_card(mem_dc, 882, 198, 1224, 230, 0x181412);
                                    draw_card_border(mem_dc, 882, 198, 1224, 230, 0x32241C);
                                    SelectObject(mem_dc, h_reg);
                                    SetTextColor(mem_dc, 0xFFFFFF);
                                    let reaction_desc = if ed.draft_interrupt_pct <= 50 {
                                        "Ранний кик"
                                    } else if ed.draft_interrupt_pct <= 70 {
                                        "Оптимальный (Человеческая реакция)"
                                    } else if ed.draft_interrupt_pct <= 85 {
                                        "Поздний кик (Защита от фейков)"
                                    } else {
                                        "Фейк-чек (Конец каста)"
                                    };
                                    let th_str = format!("≥ {} % — {}", ed.draft_interrupt_pct, reaction_desc);
                                    let th_w = encode_wide(&th_str);
                                    TextOutW(mem_dc, 896, 205, th_w.as_ptr(), th_w.len() as i32);

                                    // [+] button
                                    draw_rounded_card(mem_dc, 1232, 198, 1270, 230, 0x2A201A);
                                    draw_card_border(mem_dc, 1232, 198, 1270, 230, 0x382A22);
                                    SelectObject(mem_dc, h_bold);
                                    SetTextColor(mem_dc, 0x00F0FF);
                                    let plus_w = encode_wide("+");
                                    TextOutW(mem_dc, 1247, 202, plus_w.as_ptr(), plus_w.len() as i32);

                                    // Row 3: Visual Cast Bar Simulation
                                    draw_rounded_card(mem_dc, 836, 244, 1270, 262, 0x161210);
                                    draw_card_border(mem_dc, 836, 244, 1270, 262, 0x30241E);
                                    let bar_w = 434.0;
                                    let kick_x = 836 + ((ed.draft_interrupt_pct as f32 / 100.0) * bar_w) as i32;
                                    if kick_x > 836 {
                                        draw_rounded_card(mem_dc, 836, 245, kick_x, 261, 0x2A5022);
                                    }
                                    draw_rounded_card(mem_dc, (kick_x - 2).max(836), 242, (kick_x + 2).min(1270), 264, 0x00D0FF);

                                    SelectObject(mem_dc, h_small);
                                    SetTextColor(mem_dc, 0x88FF00);
                                    let sim_txt = format!("Симуляция: каст прерывается при достижении {}% полосы каста", ed.draft_interrupt_pct);
                                    let sim_w = encode_wide(&sim_txt);
                                    TextOutW(mem_dc, 836, 268, sim_w.as_ptr(), sim_w.len() as i32);

                                    // Row 4: Presets
                                    let kick_presets: [(u32, &str); 5] = [
                                        (50, "50% Ранний"),
                                        (65, "65% Оптимал"),
                                        (75, "75% Стандарт"),
                                        (85, "85% Поздний"),
                                        (90, "90% Фейк-чек"),
                                    ];
                                    for (k_i, &(k_pct, k_lbl)) in kick_presets.iter().enumerate() {
                                        let kx1 = 836 + (k_i as i32) * 88;
                                        let kx2 = kx1 + 80;
                                        let is_cur = ed.draft_interrupt_pct == k_pct;
                                        let (kbg, kcol) = if is_cur { (0x284E20, 0x88FF00) } else { (0x221B17, 0x8E847B) };
                                        draw_rounded_card(mem_dc, kx1, 292, kx2, 318, kbg);
                                        draw_card_border(mem_dc, kx1, 292, kx2, 318, if is_cur { 0x3AA02A } else { 0x32241C });
                                        SelectObject(mem_dc, h_small);
                                        SetTextColor(mem_dc, kcol);
                                        let pr_w = encode_wide(k_lbl);
                                        TextOutW(mem_dc, kx1 + 6, 297, pr_w.as_ptr(), pr_w.len() as i32);
                                    }
                                } else {
                                    SelectObject(mem_dc, h_reg);
                                    SetTextColor(mem_dc, 0x6E645B);
                                    let off_msg = encode_wide("Авто-прерывание отключено. Заклинание применяется по общим условиям.");
                                    TextOutW(mem_dc, 840, 150, off_msg.as_ptr(), off_msg.len() as i32);
                                }
                            } else {
                                // Range Tab (ed.cond_active_tab == 3)
                                draw_rounded_card(mem_dc, 826, 100, 1312, 260, 0x221B17);
                                draw_card_border(mem_dc, 826, 100, 1312, 260, 0x342820);

                                // Checkbox [✓] / [ ]
                                let chk_bg = if rule.check_range { 0x2A5E1A } else { 0x2E241E };
                                draw_rounded_card(mem_dc, 836, 112, 860, 136, chk_bg);
                                draw_card_border(mem_dc, 836, 112, 860, 136, if rule.check_range { 0x389E28 } else { 0x3E3028 });
                                if rule.check_range {
                                    SelectObject(mem_dc, h_bold);
                                    SetTextColor(mem_dc, 0x88FF00);
                                    let v_mark = encode_wide("✓");
                                    TextOutW(mem_dc, 843, 115, v_mark.as_ptr(), v_mark.len() as i32);
                                }

                                SelectObject(mem_dc, h_bold);
                                SetTextColor(mem_dc, if rule.check_range { 0xFFD700 } else { 0x8E847B });
                                let rng_lbl = encode_wide("Контроль дистанции до цели (Range Check)");
                                TextOutW(mem_dc, 870, 115, rng_lbl.as_ptr(), rng_lbl.len() as i32);

                                if rule.check_range {
                                    SelectObject(mem_dc, h_small);
                                    SetTextColor(mem_dc, 0x9E948B);
                                    let max_lbl = encode_wide("Максимальная дистанция применения заклинания:");
                                    TextOutW(mem_dc, 836, 146, max_lbl.as_ptr(), max_lbl.len() as i32);

                                    // [-] button
                                    draw_rounded_card(mem_dc, 836, 168, 875, 198, 0x2A201A);
                                    draw_card_border(mem_dc, 836, 168, 875, 198, 0x382A22);
                                    SelectObject(mem_dc, h_bold);
                                    SetTextColor(mem_dc, 0x00F0FF);
                                    let minus_w = encode_wide("-");
                                    TextOutW(mem_dc, 852, 172, minus_w.as_ptr(), minus_w.len() as i32);

                                    // Value box
                                    draw_rounded_card(mem_dc, 885, 168, 1195, 198, 0x181412);
                                    draw_card_border(mem_dc, 885, 168, 1195, 198, 0x32241C);
                                    SelectObject(mem_dc, h_reg);
                                    SetTextColor(mem_dc, 0xFFFFFF);
                                    let max_val_str = format!("{:.0} ярдов ({})", rule.max_range, if rule.max_range <= 5.0 { "Ближний бой" } else if rule.max_range <= 30.0 { "Дальний бой" } else { "Увеличенная дальность / Таланты" });
                                    let max_val_w = encode_wide(&max_val_str);
                                    TextOutW(mem_dc, 895, 174, max_val_w.as_ptr(), max_val_w.len() as i32);

                                    // [+] button
                                    draw_rounded_card(mem_dc, 1205, 168, 1245, 198, 0x2A201A);
                                    draw_card_border(mem_dc, 1205, 168, 1245, 198, 0x382A22);
                                    SelectObject(mem_dc, h_bold);
                                    SetTextColor(mem_dc, 0x00F0FF);
                                    let plus_w = encode_wide("+");
                                    TextOutW(mem_dc, 1222, 172, plus_w.as_ptr(), plus_w.len() as i32);

                                    // Presets: [ 5я ] [ 20я ] [ 30я ] [ 36я ] [ 40я ]
                                    let presets = [(5.0, "5я"), (20.0, "20я"), (30.0, "30я"), (36.0, "36я"), (40.0, "40я")];
                                    for (p_i, &(pr_val, pr_lbl)) in presets.iter().enumerate() {
                                        let px1 = 836 + (p_i as i32) * 75;
                                        let px2 = px1 + 68;
                                        let is_cur = (rule.max_range - pr_val).abs() < 0.5;
                                        let (pbg, pcol) = if is_cur { (0x284E20, 0x88FF00) } else { (0x221B17, 0x8E847B) };
                                        draw_rounded_card(mem_dc, px1, 214, px2, 236, pbg);
                                        draw_card_border(mem_dc, px1, 214, px2, 236, if is_cur { 0x3AA02A } else { 0x32241C });
                                        SelectObject(mem_dc, h_small);
                                        SetTextColor(mem_dc, pcol);
                                        let pr_w = encode_wide(pr_lbl);
                                        TextOutW(mem_dc, px1 + 4, 218, pr_w.as_ptr(), pr_w.len() as i32);
                                    }
                                } else {
                                    SelectObject(mem_dc, h_reg);
                                    SetTextColor(mem_dc, 0x6E645B);
                                    let off_msg = encode_wide("Контроль дистанции отключен (заклинание применяется на любом расстоянии).");
                                    TextOutW(mem_dc, 840, 150, off_msg.as_ptr(), off_msg.len() as i32);
                                }
                            }

                            // Bottom Buttons
                            // [ Отмена ]
                            draw_rounded_card(mem_dc, 940, height - 58, 1090, height - 18, 0x261E1A);
                            draw_card_border(mem_dc, 940, height - 58, 1090, height - 18, 0x3E3028);
                            SelectObject(mem_dc, h_bold);
                            SetTextColor(mem_dc, 0x8E847B);
                            let cancel_w = encode_wide("Отмена");
                            TextOutW(mem_dc, 992, height - 44, cancel_w.as_ptr(), cancel_w.len() as i32);

                            // [ Применить ]
                            draw_rounded_card(mem_dc, 1105, height - 58, 1305, height - 18, 0x2A5E1A);
                            draw_card_border(mem_dc, 1105, height - 58, 1305, height - 18, 0x3AA02A);
                            SelectObject(mem_dc, h_bold);
                            SetTextColor(mem_dc, 0x88FF00);
                            let apply_w = encode_wide("Применить");
                            TextOutW(mem_dc, 1175, height - 44, apply_w.as_ptr(), apply_w.len() as i32);
                        }
                    } else {
                        // Placeholder when no spell is selected for configuring
                        SelectObject(mem_dc, h_bold);
                        SetTextColor(mem_dc, 0x6E645B);
                        let pl_w = encode_wide("Нажмите кнопку [ Настройки ]");
                        TextOutW(mem_dc, 950, 250, pl_w.as_ptr(), pl_w.len() as i32);

                        SelectObject(mem_dc, h_reg);
                        SetTextColor(mem_dc, 0x554E46);
                        let pl2_w = encode_wide("у заклинания для настройки аур и условий.");
                        TextOutW(mem_dc, 890, 280, pl2_w.as_ptr(), pl2_w.len() as i32);
                    }
                }

                // Overlay: Inline Non-blocking Trigger Dropdown (deadlock-free)
                if let Some(drop_p_idx) = ed.open_trigger_dropdown_for_idx {
                    if drop_p_idx < store.profiles.len() {
                        let card_start_y = 48;
                        let card_h = 82;
                        let c_top = card_start_y + (drop_p_idx as i32) * (card_h + 8);
                        let menu_x1 = 26;
                        let menu_x2 = 248;
                        let menu_y1 = c_top + 76;
                        let menu_y2 = menu_y1 + 130;

                        draw_rounded_card(mem_dc, menu_x1, menu_y1, menu_x2, menu_y2, 0x1A1412);
                        draw_card_border(mem_dc, menu_x1, menu_y1, menu_x2, menu_y2, 0x00F0FF);

                        let items = [
                            "Mouse 4 (Боковая 1)",
                            "Mouse 5 (Боковая 2)",
                            "Колёсико (Middle)",
                            "Правая кнопка (ПКМ)",
                            "Отключен (Вручную)",
                        ];

                        let curr_trig = store.profiles[drop_p_idx].trigger;
                        SelectObject(mem_dc, h_small);

                        for (i, label) in items.iter().enumerate() {
                            let it_top = menu_y1 + (i as i32) * 26;
                            let is_curr = match (i, curr_trig) {
                                (0, MouseTrigger::Mouse4) => true,
                                (1, MouseTrigger::Mouse5) => true,
                                (2, MouseTrigger::Middle) => true,
                                (3, MouseTrigger::Right) => true,
                                (4, MouseTrigger::Disabled) => true,
                                _ => false,
                            };

                            if is_curr {
                                draw_rounded_card(mem_dc, menu_x1 + 2, it_top + 2, menu_x2 - 2, it_top + 24, 0x2A5E1A);
                                SetTextColor(mem_dc, 0x88FF00);
                            } else {
                                SetTextColor(mem_dc, 0x00F0FF);
                            }

                            let txt_w = encode_wide(label);
                            TextOutW(mem_dc, menu_x1 + 8, it_top + 5, txt_w.as_ptr(), txt_w.len() as i32);
                        }
                    }
                }

                // Global Status Message Banner
                if !ed.status_msg.is_empty() {
                    draw_rounded_card(mem_dc, 350, height - 42, 750, height - 16, 0x243E18);
                    draw_card_border(mem_dc, 350, height - 42, 750, height - 16, 0x388E28);
                    SelectObject(mem_dc, h_bold);
                    SetTextColor(mem_dc, 0x88FF00);
                    let st_w = encode_wide(&ed.status_msg);
                    TextOutW(mem_dc, 370, height - 36, st_w.as_ptr(), st_w.len() as i32);
                }
            }

            // Blit buffer to screen
            BitBlt(hdc, 0, 0, width, height, mem_dc, 0, 0, SRCCOPY);

            // Cleanup GDI
            SelectObject(mem_dc, old_bm);
            DeleteObject(mem_bm);
            DeleteDC(mem_dc);

            DeleteObject(h_title);
            DeleteObject(h_bold);
            DeleteObject(h_reg);
            DeleteObject(h_small);
            DeleteObject(h_huge);

            EndPaint(hwnd, &ps);
            0
        }
        WM_DESTROY => {
            if let Some(ref ed_arc) = EDITOR_STATE {
                let mut ed = ed_arc.lock().unwrap();
                ed.is_open = false;
                ed.hwnd = std::ptr::null_mut();
                ed.dragging_rule_idx = None;
                ed.drag_target_idx = None;
                ed.configuring_rule_idx = None;
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub fn open_rotation_editor(_parent_hwnd: HWND, gui_state: Arc<Mutex<GuiState>>) {
    unsafe {
        // If window already exists and is valid, bring it to front
        if let Some(ref ed_arc) = EDITOR_STATE {
            let hwnd = {
                let ed = ed_arc.lock().unwrap();
                ed.hwnd
            };
            if !hwnd.is_null() && IsWindow(hwnd) != 0 {
                ShowWindow(hwnd, SW_SHOW);
                SetForegroundWindow(hwnd);
                return;
            }
        }
    }

    std::thread::spawn(move || {
        unsafe {
            SHARED_GUI_STATE = Some(Arc::clone(&gui_state));

            if EDITOR_STATE.is_none() {
                EDITOR_STATE = Some(Arc::new(Mutex::new(EditorState {
                    is_open: true,
                    hwnd: std::ptr::null_mut(),
                    selected_idx: 0,
                    editing_profile_name: false,
                    profile_name_buf: String::new(),
                    editing_spell_idx: None,
                    spell_name_buf: String::new(),
                    listening_key_idx: None,
                    status_msg: String::new(),
                    status_time: None,
                    cursor_blink: true,
                    dragging_rule_idx: None,
                    drag_mouse_y: 0,
                    drag_target_idx: None,
                    configuring_rule_idx: None,
                    draft_conditions: Vec::new(),
                    editing_cond_idx: None,
                    aura_name_buf: String::new(),
                    cond_active_tab: 0,
                    draft_check_hp: false,
                    draft_hp_target: HpTarget::Target,
                    draft_min_hp: 0,
                    draft_max_hp: 100,
                    draft_check_interrupt: false,
                    draft_interrupt_pct: 70,
                    show_rotation_settings: false,
                    open_trigger_dropdown_for_idx: None,
                })));
            }

            let hinstance = GetModuleHandleW(std::ptr::null());
            let class_name = encode_wide("WoW_DMA_RotationEditor");

            let wc = WNDCLASSW {
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(editor_wnd_proc),
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

            let window_title = encode_wide("FOREVER HELPER — Настройка ротаций");
            let hwnd = CreateWindowExW(
                WS_EX_TOPMOST,
                class_name.as_ptr(),
                window_title.as_ptr(),
                WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE,
                60, 60,
                1340, 740,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                hinstance,
                std::ptr::null(),
            );

            if hwnd.is_null() {
                return;
            }

            if let Some(ref ed_arc) = EDITOR_STATE {
                let mut ed = ed_arc.lock().unwrap();
                ed.hwnd = hwnd;
                ed.is_open = true;
            }

            ShowWindow(hwnd, SW_SHOW);
            UpdateWindow(hwnd);

            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            if let Some(ref ed_arc) = EDITOR_STATE {
                let mut ed = ed_arc.lock().unwrap();
                ed.is_open = false;
                ed.hwnd = std::ptr::null_mut();
            }
        }
    });
}
