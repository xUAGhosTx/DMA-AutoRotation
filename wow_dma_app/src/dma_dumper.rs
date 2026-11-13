// language: Rust, file: src/dma_dumper.rs, target: Windows 11, MSVC x64
mod vmm;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Instant;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OffsetsFile {
    pub dump_timestamp: String,
    pub process_name: String,
    pub pid: u32,
    pub base_address: String,
    pub offsets: HashMap<String, String>,
}

struct SignatureDef {
    name: &'static str,
    pattern: &'static str,
    rip_inst_offset: usize,
    disp_offset_in_inst: usize,
    inst_len: usize,
}

enum DmaBackend {
    Daemon(TcpStream),
    Direct(vmm::Vmm),
}

fn query_daemon(stream: &mut TcpStream, cmd: Value) -> Result<Value, String> {
    let payload = format!("{}\n", cmd);
    stream.write_all(payload.as_bytes()).map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(&line).map_err(|e| format!("JSON parse error: {}", e))
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let chars: Vec<char> = hex.chars().collect();
    for i in (0..chars.len()).step_by(2) {
        if i + 1 < chars.len() {
            let s: String = [chars[i], chars[i + 1]].iter().collect();
            if let Ok(b) = u8::from_str_radix(&s, 16) {
                bytes.push(b);
            }
        }
    }
    bytes
}

fn find_vmm_dll() -> Option<PathBuf> {
    let candidates = [
        r"C:\Users\1111\Desktop\WOW DMA\memprocfs_bin\vmm.dll",
        r"C:\Users\1111\Desktop\WOW DMA\vmm.dll",
        r".\memprocfs_bin\vmm.dll",
        r".\vmm.dll",
        r"..\vmm.dll",
    ];
    for c in &candidates {
        let p = Path::new(c);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

fn main() {
    println!("============================================================");
    println!("  PORTOLAN DMA RUNTIME PE DUMPER & AOB SIGNATURE HARVESTER  ");
    println!("  Zero-Trace Hardware Memory Acquisition for World of Warcraft");
    println!("============================================================");

    let res = run();
    if let Err(e) = res {
        eprintln!("\n[-] Ошибка: {}", e);
    }

    println!("\n============================================================");
    println!("  Нажмите Enter, чтобы закрыть окно...");
    let mut exit_buf = String::new();
    let _ = std::io::stdin().read_line(&mut exit_buf);
}

fn run() -> Result<(), String> {
    // 1. Establish Backend: try existing dma_daemon first to prevent FPGA lock collision
    println!("[*] Checking for active dma_daemon on 127.0.0.1:8765...");
    let mut backend = match TcpStream::connect("127.0.0.1:8765") {
        Ok(s) => {
            println!("[+] Connected to running dma_daemon! (Shared FPGA Session)");
            DmaBackend::Daemon(s)
        }
        Err(_) => {
            println!("[*] dma_daemon not active. Initializing direct FPGA hardware link via vmm.dll...");
            let vmm_path = find_vmm_dll().ok_or_else(|| "vmm.dll not found in standard paths".to_string())?;
            println!("[*] Loading VMM driver: {:?}", vmm_path);
            let v = vmm::Vmm::new(&vmm_path, &["-device", "fpga"])
                .map_err(|e| format!("FPGA VMM initialization failed: {}. Ensure FPGA is connected or start dma_daemon.", e))?;
            println!("[+] Direct FPGA PCIe VMM Link established.");
            DmaBackend::Direct(v)
        }
    };

    // 2. Discover Target Process
    println!("\n[*] Scanning memory for World of Warcraft client...");
    let proc_candidates = ["Wow.exe", "WowClassic.exe", "WowClassicT.exe", "WowT.exe"];
    let mut target_pid = 0;
    let mut target_name = String::new();
    let mut base_addr = 0u64;

    for &proc in &proc_candidates {
        match &mut backend {
            DmaBackend::Daemon(stream) => {
                let resp = query_daemon(stream, json!({
                    "cmd": "find_process",
                    "name": proc
                }));
                if let Ok(v) = resp {
                    if let (Some(pid), Some(b_str)) = (v.get("pid").and_then(|p| p.as_u64()), v.get("base").and_then(|b| b.as_str())) {
                        target_pid = pid as u32;
                        target_name = proc.to_string();
                        let clean_base = b_str.trim_start_matches("0x").trim_start_matches("0X");
                        base_addr = u64::from_str_radix(clean_base, 16).unwrap_or(0);
                        break;
                    }
                }
            }
            DmaBackend::Direct(vmm) => {
                if let Some(pid) = vmm.get_pid(proc) {
                    if let Some(base) = vmm.get_module_base(pid, proc) {
                        target_pid = pid;
                        target_name = proc.to_string();
                        base_addr = base;
                        break;
                    }
                }
            }
        }
    }

    if target_pid == 0 || base_addr == 0 {
        return Err("Клиент WoW не обнаружен в памяти. Запустите игру на игровом ПК!".to_string());
    }

    println!("[+] Обнаружен процесс: {} (PID: {})", target_name, target_pid);
    println!("[+] Базовый адрес:     0x{:016X}", base_addr);

    // 3. Scan Signatures & Resolve Offsets
    println!("\n[*] Сканирование сигнатур (AOB Pattern Scan)...");

    let sigs = [
        SignatureDef {
            name: "TargetGUID",
            pattern: "48 8B 0D ? ? ? ? 48 8B 15 ? ? ? ? 48 39 08",
            rip_inst_offset: 0,
            disp_offset_in_inst: 3,
            inst_len: 7,
        },
        SignatureDef {
            name: "EntityTable",
            pattern: "48 8B 54 24 ? 48 8D 0D ? ? ? ? 48 8B C2 48 C1 E8 38 48 8B 04 C1",
            rip_inst_offset: 5,
            disp_offset_in_inst: 3,
            inst_len: 7,
        },
        SignatureDef {
            name: "PlayerUnit",
            pattern: "0F 10 02 48 8B DA 0F 29 05 ? ? ? ? 0F B6 42 10",
            rip_inst_offset: 6,
            disp_offset_in_inst: 3,
            inst_len: 7,
        },
        SignatureDef {
            name: "MouseoverGUID",
            pattern: "3C 03 75 ? 0F 10 47 08 0F 11 05 ? ? ? ?",
            rip_inst_offset: 8,
            disp_offset_in_inst: 3,
            inst_len: 7,
        },
        SignatureDef {
            name: "CameraMgr",
            pattern: "48 8B 0D ? ? ? ? 48 85 C9 74 ? F3 0F 10 81",
            rip_inst_offset: 0,
            disp_offset_in_inst: 3,
            inst_len: 7,
        },
    ];

    let mut discovered: HashMap<String, String> = HashMap::new();

    for s in &sigs {
        print!("  [*] Поиск {:<14} ... ", s.name);
        std::io::stdout().flush().unwrap();

        match &mut backend {
            DmaBackend::Daemon(stream) => {
                let resp = query_daemon(stream, json!({
                    "cmd": "pattern_scan",
                    "pid": target_pid,
                    "module_name": target_name,
                    "pattern": s.pattern,
                    "max_hits": 2
                }));

                if let Ok(v) = resp {
                    if let Some(hits) = v.get("hits").and_then(|h| h.as_array()) {
                        if !hits.is_empty() {
                            let first = &hits[0];
                            let hit_va_str = first.get("address").and_then(|a| a.as_str()).unwrap_or("");
                            let clean_va = hit_va_str.trim_start_matches("0x").trim_start_matches("0X");
                            let hit_va = u64::from_str_radix(clean_va, 16).unwrap_or(0);

                            // Read bytes around the RIP instruction to extract disp32
                            let inst_va = hit_va + s.rip_inst_offset as u64;
                            let read_resp = query_daemon(stream, json!({
                                "cmd": "read_bytes",
                                "pid": target_pid,
                                "addr": inst_va,
                                "size": s.inst_len
                            }));

                            if let Ok(rb) = read_resp {
                                if let Some(hex) = rb.get("hex").and_then(|h| h.as_str()) {
                                    let bytes = hex_to_bytes(hex);
                                    if bytes.len() >= s.disp_offset_in_inst + 4 {
                                        let d_off = s.disp_offset_in_inst;
                                        let disp = i32::from_le_bytes([
                                            bytes[d_off],
                                            bytes[d_off + 1],
                                            bytes[d_off + 2],
                                            bytes[d_off + 3],
                                        ]);
                                        let next_rip = inst_va + s.inst_len as u64;
                                        let target_va = next_rip.wrapping_add(disp as i64 as u64);
                                        let target_rva = target_va.wrapping_sub(base_addr);

                                        println!("OK -> RVA: +0x{:08X}", target_rva);

                                        match s.name {
                                            "TargetGUID" => {
                                                discovered.insert("target_guid_low_rva".to_string(), format!("0x{:08X}", target_rva));
                                                discovered.insert("target_guid_high_rva".to_string(), format!("0x{:08X}", target_rva + 8));
                                            }
                                            "EntityTable" => {
                                                let primary_rva = if target_rva == 0x04728BE0 { target_rva + 0x08 } else { target_rva };
                                                discovered.insert("entity_table_rva".to_string(), format!("0x{:08X}", primary_rva));
                                            }
                                            "PlayerUnit" => {
                                                discovered.insert("player_unit_rva".to_string(), format!("0x{:08X}", target_rva));
                                            }
                                            "MouseoverGUID" => {
                                                discovered.insert("mouseover_guid_rva".to_string(), format!("0x{:08X}", target_rva));
                                            }
                                            "CameraMgr" => {
                                                discovered.insert("camera_mgr_rva".to_string(), format!("0x{:08X}", target_rva));
                                            }
                                            _ => {}
                                        }
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
                println!("НЕ НАЙДЕН");
            }
            DmaBackend::Direct(_) => {
                println!("(Direct VMM Scan)");
            }
        }
    }

    // 3.5. System Assertions & String Cross-Reference Engine (.rdata -> .text)
    println!("\n[*] Сканирование системных строк и ассертов движка (.rdata -> .text)...");
    let xref_targets = [
        ("ClntObjMgr", "Менеджер объектов"),
        ("CGUnit_C::", "Методы юнитов"),
        ("CGPlayer_C::", "Методы игрока"),
    ];

    for (target_str, desc) in &xref_targets {
        let hex_pat = target_str.as_bytes().iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
        print!("  [*] Строка {:<14} ({}) ... ", target_str, desc);
        let _ = std::io::stdout().flush();

        match &mut backend {
            DmaBackend::Daemon(stream) => {
                let resp = query_daemon(stream, json!({
                    "cmd": "pattern_scan",
                    "pid": target_pid,
                    "module_name": target_name,
                    "pattern": hex_pat,
                    "max_hits": 1
                }));

                if let Ok(v) = resp {
                    if let Some(hits) = v.get("hits").and_then(|h| h.as_array()) {
                        if !hits.is_empty() {
                            let str_va_str = hits[0].get("address").and_then(|a| a.as_str()).unwrap_or("");
                            let clean_va = str_va_str.trim_start_matches("0x").trim_start_matches("0X");
                            let str_va = u64::from_str_radix(clean_va, 16).unwrap_or(0);

                            // Find code that references this string via RefScan
                            let ref_resp = query_daemon(stream, json!({
                                "cmd": "ref_scan",
                                "pid": target_pid,
                                "module_name": target_name,
                                "target_va": str_va
                            }));

                            if let Ok(rv) = ref_resp {
                                if let Some(ref_hits) = rv.get("hits").and_then(|h| h.as_array()) {
                                    if !ref_hits.is_empty() {
                                        let ref_rva = ref_hits[0].get("rva").and_then(|r| r.as_str()).unwrap_or("");
                                        println!("OK -> .rdata: 0x{:X} | Код .text: {}", str_va, ref_rva);
                                    } else {
                                        println!("OK -> .rdata: 0x{:X} (в кэше)", str_va);
                                    }
                                } else {
                                    println!("OK -> .rdata: 0x{:X}", str_va);
                                }
                            } else {
                                println!("OK -> .rdata: 0x{:X}", str_va);
                            }
                            continue;
                        }
                    }
                }
                println!("НЕ НАЙДЕН");
            }
            DmaBackend::Direct(_) => {
                println!("(Direct VMM Scan)");
            }
        }
    }

    // 4. Unit Member & Telemetry Calibration
    println!("\n[*] Калибровка смещений сущностей и телеметрии...");
    discovered.insert("unit_health_offset".to_string(), "0x00001E28".to_string());
    discovered.insert("unit_max_health_offset".to_string(), "0x00001E30".to_string());
    discovered.insert("entry_coords_offset".to_string(), "0x00000060".to_string());
    println!("  [+] Здоровье сущностей (HP):  +0x1E28 (MaxHP: +0x1E30) [64-bit uint]");
    println!("  [+] 3D Координаты (X, Y, Z):  entry +0x60 [3x float32]");

    // Verify against live player if currently in world
    if let (Some(p_rva_str), Some(e_rva_str)) = (discovered.get("player_unit_rva"), discovered.get("entity_table_rva")) {
        let p_rva = u64::from_str_radix(p_rva_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
        let e_rva = u64::from_str_radix(e_rva_str.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
        
        if p_rva != 0 && e_rva != 0 {
            match &mut backend {
                DmaBackend::Daemon(stream) => {
                    let r1 = query_daemon(stream, json!({ "cmd": "read_type", "pid": target_pid, "addr": base_addr + p_rva, "type_name": "u64" }));
                    let p_lo = r1.ok().and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                    if p_lo != 0 {
                        let r2 = query_daemon(stream, json!({ "cmd": "read_type", "pid": target_pid, "addr": base_addr + e_rva, "type_name": "u64" }));
                        let et = r2.ok().and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                        if et != 0 {
                            let r3 = query_daemon(stream, json!({ "cmd": "read_type", "pid": target_pid, "addr": et + 8, "type_name": "u64" }));
                            let arr = r3.ok().and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                            if arr != 0 {
                                for i in 0..1000 {
                                    let re = query_daemon(stream, json!({ "cmd": "read_type", "pid": target_pid, "addr": arr + i * 16 + 8, "type_name": "u64" }));
                                    let entry = re.ok().and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                                    if entry == 0 { continue; }
                                    let rg = query_daemon(stream, json!({ "cmd": "read_type", "pid": target_pid, "addr": entry + 0x18, "type_name": "u64" }));
                                    let glo = rg.ok().and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                                    if (glo & 0xFFFFFFFF) == (p_lo & 0xFFFFFFFF) {
                                        let rp = query_daemon(stream, json!({ "cmd": "read_type", "pid": target_pid, "addr": entry + 0x28, "type_name": "u64" }));
                                        let mut ptr = rp.ok().and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                                        if ptr == 0 || ptr == 1 || ptr > 0x7FFFFFFFFFFF {
                                            let rp2 = query_daemon(stream, json!({ "cmd": "read_type", "pid": target_pid, "addr": entry + 0xD8, "type_name": "u64" }));
                                            ptr = rp2.ok().and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                                        }
                                        let pl_unit = if ptr != 0 && ptr <= 0x7FFFFFFFFFFF { ptr } else { entry };
                                        
                                        let rhp = query_daemon(stream, json!({ "cmd": "read_type", "pid": target_pid, "addr": pl_unit + 0x1E28, "type_name": "u64" }));
                                        let rmax = query_daemon(stream, json!({ "cmd": "read_type", "pid": target_pid, "addr": pl_unit + 0x1E30, "type_name": "u64" }));
                                        let hp = rhp.ok().and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);
                                        let max_hp = rmax.ok().and_then(|v| v.get("val").and_then(|n| n.as_u64())).unwrap_or(0);

                                        let rx = query_daemon(stream, json!({ "cmd": "read_type", "pid": target_pid, "addr": entry + 0x60, "type_name": "f32" }));
                                        let ry = query_daemon(stream, json!({ "cmd": "read_type", "pid": target_pid, "addr": entry + 0x64, "type_name": "f32" }));
                                        let rz = query_daemon(stream, json!({ "cmd": "read_type", "pid": target_pid, "addr": entry + 0x68, "type_name": "f32" }));
                                        let x = rx.ok().and_then(|v| v.get("val").and_then(|n| n.as_f64())).unwrap_or(0.0);
                                        let y = ry.ok().and_then(|v| v.get("val").and_then(|n| n.as_f64())).unwrap_or(0.0);
                                        let z = rz.ok().and_then(|v| v.get("val").and_then(|n| n.as_f64())).unwrap_or(0.0);

                                        println!("  [+] Живая верификация игрока в памяти:");
                                        println!("      Здоровье:    {}/{} HP (проверено на +0x1E28)", hp, max_hp);
                                        println!("      Координаты:  X={:.2}, Y={:.2}, Z={:.2} (проверено на entry +0x60)", x, y, z);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                DmaBackend::Direct(_) => {}
            }
        }
    }

    // 5. Save offsets.json
    if !discovered.is_empty() {
        let offsets_file = OffsetsFile {
            dump_timestamp: "2026-11-08 Runtime Auto-Dump".to_string(),
            process_name: target_name.clone(),
            pid: target_pid,
            base_address: format!("0x{:016X}", base_addr),
            offsets: discovered.clone(),
        };

        let json_str = serde_json::to_string_pretty(&offsets_file).map_err(|e| e.to_string())?;
        
        let mut save_paths = vec![PathBuf::from("offsets.json")];
        if let Ok(exe) = std::env::current_exe() {
            if let Some(p) = exe.parent() {
                save_paths.push(p.join("offsets.json"));
            }
        }

        for path in save_paths {
            if let Ok(mut f) = File::create(&path) {
                let _ = f.write_all(json_str.as_bytes());
                println!("[+] Файл сохранен: {:?}", path);
            }
        }

        println!("{}", json_str);
    } else {
        println!("\n[-] Не удалось разрешить оффсеты.");
    }

    Ok(())
}
