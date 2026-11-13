// language: Rust, file: src/main.rs, target: Windows 11, MSVC x64
mod vmm;
mod makcu;
mod scanner;

use std::io::{stdout, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};
use colored::*;
use crossterm::{
    cursor,
    execute,
    terminal::{self, ClearType},
};
use serde_json::Value;

enum DmaBackend {
    Daemon(TcpStream),
    Direct {
        vmm: vmm::Vmm,
        makcu: makcu::Makcu,
        pid: u32,
        has_t_addr: u64,
        t_guid_addr: u64,
        p_addr: u64,
    },
}

fn main() {
    println!("{}", "=== WORLD OF WARCRAFT HIGH-PERFORMANCE DMA RADAR ===".cyan().bold());

    // Check if Rust DMA Daemon is already running on 127.0.0.1:8765
    let backend = match TcpStream::connect("127.0.0.1:8765") {
        Ok(stream) => {
            println!("{}", "[+] Connected to Native Rust DMA Daemon (127.0.0.1:8765)!".green().bold());
            println!("{}", "[*] Zero-collision shared DMA bridge active.".cyan());
            DmaBackend::Daemon(stream)
        }
        Err(_) => {
            println!("[*] Rust DMA Daemon not detected, initializing direct PCIe link...");
            let dll_path = Path::new(r"C:\Users\1111\Desktop\WOW DMA\memprocfs_bin\vmm.dll");
            let v = match vmm::Vmm::new(dll_path, &["-device", "fpga"]) {
                Ok(v) => {
                    println!("{}", "[+] FPGA PCIe DMA Hardware link established!".green().bold());
                    v
                }
                Err(e) => {
                    eprintln!("{}", format!("[-] DMA Initialization Error: {}", e).red().bold());
                    return;
                }
            };

            let pid = loop {
                if let Some(p) = v.get_pid("Wow.exe") {
                    println!("{}", format!("[+] Process Acquired: Wow.exe (PID: {})", p).green().bold());
                    break p;
                }
                std::thread::sleep(Duration::from_millis(500));
            };

            let mod_base = loop {
                if let Some(b) = v.get_module_base(pid, "Wow.exe") {
                    println!("{}", format!("[+] Module Base: 0x{:X}", b).green().bold());
                    break b;
                }
                std::thread::sleep(Duration::from_millis(500));
            };

            let m = makcu::Makcu::new("COM3");
            DmaBackend::Direct {
                vmm: v,
                makcu: m,
                pid,
                has_t_addr: mod_base + 0x04B15F90,
                t_guid_addr: mod_base + 0x04B15F98,
                p_addr: mod_base + 0x4C1B1C0,
            }
        }
    };

    let mut tracker = scanner::CombatTracker::new();
    let mut auto_cast = false;
    let mut last_action = "Готов к работе".to_string();

    let mut stdout = stdout();
    let _ = terminal::enable_raw_mode();
    let _ = execute!(stdout, cursor::Hide);

    let mut last_draw = Instant::now();
    let mut last_auto_trigger = Instant::now();
    let mut backend = backend;

    loop {
        let t_start = Instant::now();

        // Check keypresses
        if crossterm::event::poll(Duration::from_millis(1)).unwrap_or(false) {
            if let Ok(crossterm::event::Event::Key(key)) = crossterm::event::read() {
                match key.code {
                    crossterm::event::KeyCode::Char('q') | crossterm::event::KeyCode::Esc => break,
                    crossterm::event::KeyCode::Char('c') => {
                        auto_cast = !auto_cast;
                        last_action = format!("Авто-каст: {}", if auto_cast { "ВКЛЮЧЕН" } else { "ВЫКЛЮЧЕН" });
                    }
                    crossterm::event::KeyCode::Char('1') => {
                        tracker.record_cast("corruption");
                        match &mut backend {
                            DmaBackend::Daemon(s) => { let _ = writeln!(s, "{{\"cmd\":\"cast\",\"spell\":\"corruption\"}}"); }
                            DmaBackend::Direct { makcu, .. } => { makcu.cast_corruption(); }
                        }
                        last_action = "Каст Порчи [1]".into();
                    }
                    crossterm::event::KeyCode::Char('2') => {
                        tracker.record_cast("immolate");
                        match &mut backend {
                            DmaBackend::Daemon(s) => { let _ = writeln!(s, "{{\"cmd\":\"cast\",\"spell\":\"immolate\"}}"); }
                            DmaBackend::Direct { makcu, .. } => { makcu.cast_immolate(); }
                        }
                        last_action = "Каст Жертвенного огня [2]".into();
                    }
                    crossterm::event::KeyCode::Char('3') => {
                        match &mut backend {
                            DmaBackend::Daemon(s) => { let _ = writeln!(s, "{{\"cmd\":\"cast\",\"spell\":\"shadow_bolt\"}}"); }
                            DmaBackend::Direct { makcu, .. } => { makcu.cast_shadow_bolt(); }
                        }
                        last_action = "Каст Стрелы Тьмы [3]".into();
                    }
                    _ => {}
                }
            }
        }

        // Fetch state from Backend
        let (p_guid, has_t, t_guid) = match &mut backend {
            DmaBackend::Daemon(stream) => {
                let _ = writeln!(stream, "{{\"cmd\":\"get_target\"}}");
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    if let Ok(v) = serde_json::from_str::<Value>(&line) {
                        let has = v["has_target"].as_bool().unwrap_or(false);
                        let pg = v["player_guid"].as_str().and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok()).unwrap_or(0);
                        let tg = v["target_guid"].as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()).unwrap_or(0);
                        (pg, has, tg as u32)
                    } else {
                        (0, false, 0)
                    }
                } else {
                    (0, false, 0)
                }
            }
            DmaBackend::Direct { vmm, pid, has_t_addr, t_guid_addr, p_addr, .. } => {
                let p = vmm.read_val::<u32>(*pid, *p_addr).unwrap_or(0);
                let h = vmm.read_val::<u64>(*pid, *has_t_addr).unwrap_or(0) != 0;
                let t = if h { vmm.read_val::<u64>(*pid, *t_guid_addr).unwrap_or(0) as u32 } else { 0 };
                (p, h, t)
            }
        };

        let t_name = if has_t { format!("Цель [0x{:X}]", t_guid) } else { "НЕТ ЦЕЛИ".to_string() };
        let dma_latency = t_start.elapsed().as_micros() as f64 / 1000.0;

        tracker.player_guid = p_guid;
        tracker.has_target = has_t;
        tracker.current_target_guid = t_guid;
        tracker.current_target_name = t_name;

        // Auto-cast logic via MAKCU
        if auto_cast && has_t && last_auto_trigger.elapsed() >= Duration::from_millis(1500) {
            let (rec, _) = tracker.recommend_next_spell();
            match rec {
                "ПОРЧА" => {
                    match &mut backend {
                        DmaBackend::Daemon(s) => { let _ = writeln!(s, "{{\"cmd\":\"cast\",\"spell\":\"corruption\"}}"); }
                        DmaBackend::Direct { makcu, .. } => { makcu.cast_corruption(); }
                    }
                    tracker.record_cast("corruption");
                    last_auto_trigger = Instant::now();
                    last_action = "[AUTO] Нажата Порча (Mouse 4)".into();
                }
                "ЖЕРТВЕННЫЙ ОГОНЬ" => {
                    match &mut backend {
                        DmaBackend::Daemon(s) => { let _ = writeln!(s, "{{\"cmd\":\"cast\",\"spell\":\"immolate\"}}"); }
                        DmaBackend::Direct { makcu, .. } => { makcu.cast_immolate(); }
                    }
                    tracker.record_cast("immolate");
                    last_auto_trigger = Instant::now();
                    last_action = "[AUTO] Нажат Огонь (Mouse 5)".into();
                }
                "СТРЕЛА ТЬМЫ" => {
                    match &mut backend {
                        DmaBackend::Daemon(s) => { let _ = writeln!(s, "{{\"cmd\":\"cast\",\"spell\":\"shadow_bolt\"}}"); }
                        DmaBackend::Direct { makcu, .. } => { makcu.cast_shadow_bolt(); }
                    }
                    last_auto_trigger = Instant::now();
                    last_action = "[AUTO] Нажата Стрела Тьмы (Middle)".into();
                }
                _ => {}
            }
        }

        // Draw HUD at 30 FPS
        if last_draw.elapsed() >= Duration::from_millis(33) {
            last_draw = Instant::now();
            let _ = execute!(stdout, cursor::MoveTo(0, 0), terminal::Clear(ClearType::FromCursorDown));

            println!("{}", "┌─────────────────────────────────────────────────────────────┐".cyan());
            println!("{}", "│       WORLD OF WARCRAFT HIGH-PERFORMANCE DMA RADAR (RUST)   │".cyan().bold());
            println!("{}", "├─────────────────────────────────────────────────────────────┤".cyan());
            println!(
                "│ DMA Задержка: {:<6.2} ms  | Игрок: 0x{:<8X}                 │",
                dma_latency, tracker.player_guid
            );
            println!(
                "│ Мост: {:<20} | Авто-каст: {:<17} │",
                match backend { DmaBackend::Daemon(_) => "Rust TCP 127.0.0.1".green(), DmaBackend::Direct { .. } => "Direct FPGA".yellow() },
                if auto_cast { "ВКЛЮЧЕН [c]".green().bold() } else { "ВЫКЛЮЧЕН [c]".red() }
            );
            println!("{}", "├─────────────────────────────────────────────────────────────┤".cyan());

            if tracker.has_target {
                println!(
                    "│ Статус цели:   {:<45} │",
                    "ЗАХВАЧЕНА".green().bold()
                );
                println!(
                    "│ GUID цели:     0x{:<43X} │",
                    tracker.current_target_guid
                );
                println!(
                    "│ Имя цели:      {:<45} │",
                    tracker.current_target_name.yellow().bold()
                );
            } else {
                println!(
                    "│ Статус цели:   {:<45} │",
                    "НЕТ ЦЕЛИ".dimmed()
                );
                println!(
                    "│ GUID цели:     {:<45} │",
                    "-".dimmed()
                );
                println!(
                    "│ Имя цели:      {:<45} │",
                    "-".dimmed()
                );
            }

            println!("{}", "├─────────────────────────────────────────────────────────────┤".cyan());
            let (rec_spell, desc) = tracker.recommend_next_spell();
            println!("│ РЕКОМЕНДУЕМОЕ ДЕЙСТВИЕ:                                     │");
            let rec_styled = match rec_spell {
                "ПОРЧА" => format!(">> {:<43}", rec_spell).purple().bold(),
                "ЖЕРТВЕННЫЙ ОГОНЬ" => format!(">> {:<43}", rec_spell).red().bold(),
                "СТРЕЛА ТЬМЫ" => format!(">> {:<43}", rec_spell).blue().bold(),
                _ => format!(">> {:<43}", rec_spell).white(),
            };
            println!("│ {} │", rec_styled);
            println!("│ {:<59} │", desc.cyan());

            println!("{}", "├─────────────────────────────────────────────────────────────┤".cyan());
            println!("│ ТАЙМЕРЫ ДЕБАФФОВ НА ЦЕЛИ:                                   │");
            println!(
                "│ Порча (Corruption): {}     {:<15} │",
                tracker.render_bar("corruption"),
                tracker.get_debuff_display("corruption")
            );
            println!(
                "│ Жертвенный огонь  : {}     {:<15} │",
                tracker.render_bar("immolate"),
                tracker.get_debuff_display("immolate")
            );
            println!(
                "│ Проклятие агонии  : {}     {:<15} │",
                tracker.render_bar("agony"),
                tracker.get_debuff_display("agony")
            );

            println!("{}", "├─────────────────────────────────────────────────────────────┤".cyan());
            println!("│ Последнее действие: {:<40}│", last_action.yellow());
            println!("│ Управление: [1] Порча  [2] Огонь  [3] Стрела  [c] Авто  [q] Выход│");
            println!("{}", "└─────────────────────────────────────────────────────────────┘".cyan());
            let _ = stdout.flush();
        }

        std::thread::sleep(Duration::from_millis(5));
    }

    let _ = terminal::disable_raw_mode();
    let _ = execute!(stdout, cursor::Show);
    println!("\n[+] Radar cleanly terminated.");
}
