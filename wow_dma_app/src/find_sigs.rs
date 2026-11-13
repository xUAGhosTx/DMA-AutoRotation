// language: Rust, file: src/find_sigs.rs, target: Windows 11, MSVC x64
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use serde_json::{json, Value};

fn send_cmd(cmd: Value) -> Result<Value, String> {
    let mut stream = TcpStream::connect("127.0.0.1:8765")
        .map_err(|e| format!("Connect error: {}", e))?;
    let payload = format!("{}\n", cmd);
    stream.write_all(payload.as_bytes()).map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(&line).map_err(|e| format!("Parse error: {}", e))
}

fn read_bytes(pid: u32, addr: u64, size: usize) -> Option<Vec<u8>> {
    let resp = send_cmd(json!({
        "cmd": "read_bytes",
        "pid": pid,
        "addr": addr,
        "size": size
    })).ok()?;

    let hex_arr = resp.get("bytes")?.as_array()?;
    let mut res = Vec::with_capacity(hex_arr.len());
    for v in hex_arr {
        let s = v.as_str()?;
        res.push(u8::from_str_radix(s, 16).ok()?);
    }
    Some(res)
}

struct TargetRef {
    name: &'static str,
    target_rva: u64,
}

fn main() {
    println!("=== WOW DMA CODE SIGNATURE ANALYZER ===");
    let pid = 15272;
    let base = 0x7FF7A73D0000u64;

    let targets = [
        TargetRef { name: "EntityTable", target_rva: 0x04728BF0 },
        TargetRef { name: "TargetGUID_Low", target_rva: 0x06A32478 },
        TargetRef { name: "PlayerUnit", target_rva: 0x04C1A770 },
        TargetRef { name: "MouseoverGUID", target_rva: 0x04C18288 },
        TargetRef { name: "CombatFlag", target_rva: 0x04B15F90 },
    ];

    println!("[*] Scanning .text section of Wow.exe (0x1000 .. 0x3000000)...");
    let chunk_size = 512 * 1024; // 512 KB
    let text_start = base + 0x1000;
    let text_end = base + 0x3000000;

    let mut curr = text_start;
    let mut hits: Vec<(&'static str, u64, u64, usize, usize, Vec<u8>)> = Vec::new();

    while curr < text_end {
        let to_read = std::cmp::min(chunk_size as u64, text_end - curr) as usize;
        if let Some(buf) = read_bytes(pid, curr, to_read) {
            let limit = buf.len().saturating_sub(16);
            for i in 0..limit {
                // Must not start with 0x00 or 0xCC
                let op = buf[i];
                if op == 0x00 || op == 0xCC { continue; }

                // Check common instruction lengths with 32-bit RIP relative displacements
                // 5 bytes: e8/e9/8b/8d...
                // 6 bytes: 8b 05 / 8d 05...
                // 7 bytes: 48 8b 05 / 48 8d 05 / 4c 8b ...
                // 8 bytes: 48 8b 84 ...
                for ilen in [5, 6, 7, 8] {
                    let disp_off = ilen - 4;
                    let disp = i32::from_le_bytes([
                        buf[i + disp_off],
                        buf[i + disp_off + 1],
                        buf[i + disp_off + 2],
                        buf[i + disp_off + 3],
                    ]);
                    if disp == 0 { continue; }

                    let next_ip = (curr + i as u64) + ilen as u64;
                    let resolved = next_ip.wrapping_add(disp as i64 as u64);
                    let resolved_rva = resolved.wrapping_sub(base);

                    for t in &targets {
                        if resolved_rva == t.target_rva {
                            let inst_va = curr + i as u64;
                            let inst_rva = inst_va - base;
                            let context_start = i.saturating_sub(8);
                            let context_end = std::cmp::min(buf.len(), i + ilen + 12);
                            let context_bytes = buf[context_start..context_end].to_vec();
                            hits.push((t.name, inst_rva, resolved_rva, i - context_start, ilen, context_bytes));
                        }
                    }
                }
            }
        }
        curr += (to_read - 16) as u64;
    }

    println!("[+] Found {} referencing instructions in .text:", hits.len());
    for (name, inst_rva, target_rva, inst_rel, ilen, ctx) in &hits {
        let hex_ctx = ctx.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
        println!("\n[*] Target: {} (RVA: +0x{:08X})", name, target_rva);
        println!("    At code RVA: +0x{:08X} (Instruction length: {})", inst_rva, ilen);
        println!("    Context bytes: {}", hex_ctx);

        // Build pattern mask
        // Mask the 4 displacement bytes as ??
        let mut pat_str = String::new();
        let disp_start = inst_rel + ilen - 4;
        let disp_end = disp_start + 4;
        for (idx, b) in ctx.iter().enumerate() {
            if idx >= disp_start && idx < disp_end {
                pat_str.push_str("?? ");
            } else {
                pat_str.push_str(&format!("{:02X} ", b));
            }
        }
        println!("    AOB Signature: {}", pat_str.trim());
    }
}

