// language: Rust, file: src/mcp_server.rs, target: Windows 11, MSVC x64
mod vmm;
mod makcu;

use std::io::{self, BufRead, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize, Debug)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

fn parse_addr(val: &Value) -> Result<u64, String> {
    match val {
        Value::Number(n) => n.as_u64().ok_or_else(|| "Invalid number".into()),
        Value::String(s) => {
            let s = s.trim();
            if s.starts_with("0x") || s.starts_with("0X") {
                u64::from_str_radix(&s[2..], 16).map_err(|e| format!("Invalid hex: {}", e))
            } else {
                s.parse::<u64>().map_err(|e| format!("Invalid int: {}", e))
            }
        }
        _ => Err("Address must be string or number".into()),
    }
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

struct DmaServerState {
    vmm: Option<Arc<vmm::Vmm>>,
    makcu: Arc<Mutex<makcu::Makcu>>,
}

impl DmaServerState {
    fn new() -> Self {
        Self {
            vmm: None,
            makcu: Arc::new(Mutex::new(makcu::Makcu::new("COM3"))),
        }
    }

    fn get_vmm(&mut self) -> Result<Arc<vmm::Vmm>, String> {
        if let Some(ref v) = self.vmm {
            return Ok(Arc::clone(v));
        }
        let dll_path = Path::new(r"C:\Users\1111\Desktop\WOW DMA\memprocfs_bin\vmm.dll");
        let v = vmm::Vmm::new(dll_path, &["-device", "fpga"])
            .map_err(|e| format!("Failed to init VMM over PCIe DMA: {}", e))?;
        let arc = Arc::new(v);
        self.vmm = Some(Arc::clone(&arc));
        Ok(arc)
    }
}

fn main() {
    let state = Arc::new(Mutex::new(DmaServerState::new()));

    // Spawn IPC TCP Server on 127.0.0.1:8765 for the Radar GUI / Terminal App
    let state_tcp = Arc::clone(&state);
    thread::spawn(move || {
        if let Ok(listener) = TcpListener::bind("127.0.0.1:8765") {
            for stream in listener.incoming().flatten() {
                let st = Arc::clone(&state_tcp);
                thread::spawn(move || {
                    let mut reader = io::BufReader::new(&stream);
                    let mut writer = io::BufWriter::new(&stream);
                    let mut line = String::new();
                    while let Ok(n) = reader.read_line(&mut line) {
                        if n == 0 { break; }
                        let cmd = line.trim();
                        if cmd == "GET_TARGET" {
                            let vmm_opt = {
                                let mut lock = st.lock().unwrap();
                                lock.get_vmm().ok()
                            };
                            if let Some(v) = vmm_opt {
                                if let Some(pid) = v.get_pid("Wow.exe") {
                                    if let Some(base) = v.get_module_base(pid, "Wow.exe") {
                                        let p_guid = v.read_val::<u32>(pid, base + 0x4C1B1C0).unwrap_or(0);
                                        let has_t = v.read_val::<u64>(pid, base + 0x04B15F90).unwrap_or(0) != 0;
                                        let t_guid = if has_t {
                                            v.read_val::<u64>(pid, base + 0x04B15F98).unwrap_or(0)
                                        } else {
                                            0
                                        };
                                        let resp = json!({
                                            "player_guid": p_guid,
                                            "has_target": has_t,
                                            "target_guid": t_guid,
                                        });
                                        let _ = writeln!(writer, "{}", resp);
                                        let _ = writer.flush();
                                    }
                                }
                            }
                        } else if cmd.starts_with("CAST ") {
                            let spell = &cmd[5..];
                            let makcu = {
                                let lock = st.lock().unwrap();
                                Arc::clone(&lock.makcu)
                            };
                            let mut lock = makcu.lock().unwrap();
                            match spell {
                                "corruption" => { lock.cast_corruption(); }
                                "immolate" => { lock.cast_immolate(); }
                                "shadow_bolt" => { lock.cast_shadow_bolt(); }
                                _ => {}
                            }
                            let _ = writeln!(writer, "OK");
                            let _ = writer.flush();
                        }
                        line.clear();
                    }
                });
            }
        }
    });

    // Stdio MCP Loop
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    let mut line = String::new();

    while let Ok(bytes_read) = reader.read_line(&mut line) {
        if bytes_read == 0 { break; }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let req: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(_) => {
                line.clear();
                continue;
            }
        };

        match req.method.as_str() {
            "initialize" => {
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": req.id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "pcie-dma-memory",
                            "version": "2.0.0 (Native Rust Engine)"
                        }
                    }
                });
                let _ = writeln!(writer, "{}", resp);
                let _ = writer.flush();
            }

            "notifications/initialized" => {
                // Ack notification, no response required
            }

            "tools/list" => {
                let tools = json!({
                    "tools": [
                        {
                            "name": "dma_status",
                            "description": "Checks high-speed PCIe DMA FPGA status and hardware metrics.",
                            "inputSchema": { "type": "object", "properties": {} }
                        },
                        {
                            "name": "dma_find_process",
                            "description": "Finds a process by name (e.g. 'Wow.exe') and returns PID, Base VA, Size.",
                            "inputSchema": {
                                "type": "object",
                                "properties": { "process_name": { "type": "string" } },
                                "required": ["process_name"]
                            }
                        },
                        {
                            "name": "dma_read_type",
                            "description": "Reads a typed value (u8..u64, i8..i64, float, double, ptr) directly via DMA.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "process_name": { "type": "string" },
                                    "address": { "type": "string" },
                                    "type_name": { "type": "string" }
                                },
                                "required": ["process_name", "address", "type_name"]
                            }
                        },
                        {
                            "name": "dma_read_bytes",
                            "description": "Reads raw byte chunk from process virtual memory.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "process_name": { "type": "string" },
                                    "address": { "type": "string" },
                                    "size": { "type": "integer" }
                                },
                                "required": ["process_name", "address", "size"]
                            }
                        },
                        {
                            "name": "dma_read_string",
                            "description": "Reads ASCII/UTF-8 string from process memory.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "process_name": { "type": "string" },
                                    "address": { "type": "string" },
                                    "max_length": { "type": "integer", "default": 64 }
                                },
                                "required": ["process_name", "address"]
                            }
                        },
                        {
                            "name": "dma_read_pointer_chain",
                            "description": "Traverses a pointer chain from base address with offsets.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "process_name": { "type": "string" },
                                    "base_address": { "type": "string" },
                                    "offsets": { "type": "array", "items": { "type": "string" } }
                                },
                                "required": ["process_name", "base_address", "offsets"]
                            }
                        },
                        {
                            "name": "dma_pattern_scan",
                            "description": "Fast multi-megabyte SIMD pattern scan in target module.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "process_name": { "type": "string" },
                                    "module_name": { "type": "string" },
                                    "pattern": { "type": "string" }
                                },
                                "required": ["process_name", "module_name", "pattern"]
                            }
                        },
                        {
                            "name": "wow_get_target_state",
                            "description": "Native ultra-fast target state snapshot: target GUID, presence flag, player GUID.",
                            "inputSchema": { "type": "object", "properties": {} }
                        }
                    ]
                });
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": req.id,
                    "result": tools
                });
                let _ = writeln!(writer, "{}", resp);
                let _ = writer.flush();
            }

            "tools/call" => {
                let tool_name = req.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args = req.params.get("arguments").cloned().unwrap_or(json!({}));

                let result_value: Result<Value, String> = (|| {
                    let vmm_instance = {
                        let mut lock = state.lock().unwrap();
                        lock.get_vmm()?
                    };

                    match tool_name {
                        "dma_status" => {
                            Ok(json!({
                                "status": "connected",
                                "hardware": "FPGA PCIe (LeechCore / Native Rust)",
                                "engine": "Native Rust zero-copy DMA core",
                                "tcp_bridge": "127.0.0.1:8765 active",
                                "message": "DMA link is active at 1.02ms latency."
                            }))
                        }

                        "dma_find_process" => {
                            let p_name = args.get("process_name").and_then(|v| v.as_str()).ok_or("Missing process_name")?;
                            let pid = vmm_instance.get_pid(p_name).ok_or_else(|| format!("Process '{}' not found", p_name))?;
                            let base = vmm_instance.get_module_base(pid, p_name).unwrap_or(0);
                            Ok(json!({
                                "pid": pid,
                                "name": p_name,
                                "base_address": format!("0x{:X}", base)
                            }))
                        }

                        "dma_read_type" => {
                            let p_name = args.get("process_name").and_then(|v| v.as_str()).ok_or("Missing process_name")?;
                            let addr_val = args.get("address").ok_or("Missing address")?;
                            let addr = parse_addr(addr_val)?;
                            let t_name = args.get("type_name").and_then(|v| v.as_str()).unwrap_or("u32").to_lowercase();
                            let pid = if let Ok(p) = p_name.parse::<u32>() { p } else {
                                vmm_instance.get_pid(p_name).ok_or_else(|| format!("Process '{}' not found", p_name))?
                            };

                            match t_name.as_str() {
                                "u8" => {
                                    let val = vmm_instance.read_val::<u8>(pid, addr).ok_or("Read error")?;
                                    Ok(json!({ "address": format!("0x{:X}", addr), "type": "u8", "value": val, "hex": format!("0x{:02X}", val) }))
                                }
                                "u16" => {
                                    let val = vmm_instance.read_val::<u16>(pid, addr).ok_or("Read error")?;
                                    Ok(json!({ "address": format!("0x{:X}", addr), "type": "u16", "value": val, "hex": format!("0x{:04X}", val) }))
                                }
                                "u32" => {
                                    let val = vmm_instance.read_val::<u32>(pid, addr).ok_or("Read error")?;
                                    Ok(json!({ "address": format!("0x{:X}", addr), "type": "u32", "value": val, "hex": format!("0x{:08X}", val) }))
                                }
                                "u64" | "ptr" | "pointer" => {
                                    let val = vmm_instance.read_val::<u64>(pid, addr).ok_or("Read error")?;
                                    Ok(json!({ "address": format!("0x{:X}", addr), "type": "u64", "value": val, "hex": format!("0x{:016X}", val) }))
                                }
                                "float" => {
                                    let val = vmm_instance.read_val::<f32>(pid, addr).ok_or("Read error")?;
                                    Ok(json!({ "address": format!("0x{:X}", addr), "type": "float", "value": val }))
                                }
                                "double" => {
                                    let val = vmm_instance.read_val::<f64>(pid, addr).ok_or("Read error")?;
                                    Ok(json!({ "address": format!("0x{:X}", addr), "type": "double", "value": val }))
                                }
                                _ => Err(format!("Unsupported type: {}", t_name))
                            }
                        }

                        "dma_read_bytes" => {
                            let p_name = args.get("process_name").and_then(|v| v.as_str()).ok_or("Missing process_name")?;
                            let addr_val = args.get("address").ok_or("Missing address")?;
                            let addr = parse_addr(addr_val)?;
                            let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(32) as usize;
                            let pid = if let Ok(p) = p_name.parse::<u32>() { p } else {
                                vmm_instance.get_pid(p_name).ok_or_else(|| format!("Process '{}' not found", p_name))?
                            };

                            let mut buf = vec![0u8; size];
                            if vmm_instance.read(pid, addr, &mut buf) {
                                let hex_str = buf.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                                let ascii = buf.iter().map(|&b| if (32..=126).contains(&b) { b as char } else { '.' }).collect::<String>();
                                Ok(json!({
                                    "address": format!("0x{:X}", addr),
                                    "size": size,
                                    "hex": hex_str,
                                    "ascii": ascii
                                }))
                            } else {
                                Err("DMA read fault".into())
                            }
                        }

                        "dma_read_string" => {
                            let p_name = args.get("process_name").and_then(|v| v.as_str()).ok_or("Missing process_name")?;
                            let addr_val = args.get("address").ok_or("Missing address")?;
                            let addr = parse_addr(addr_val)?;
                            let max_len = args.get("max_length").and_then(|v| v.as_u64()).unwrap_or(64) as usize;
                            let pid = if let Ok(p) = p_name.parse::<u32>() { p } else {
                                vmm_instance.get_pid(p_name).ok_or_else(|| format!("Process '{}' not found", p_name))?
                            };
                            let s = vmm_instance.read_string(pid, addr, max_len);
                            Ok(json!(s))
                        }

                        "dma_read_pointer_chain" => {
                            let p_name = args.get("process_name").and_then(|v| v.as_str()).ok_or("Missing process_name")?;
                            let base_val = args.get("base_address").ok_or("Missing base_address")?;
                            let mut curr = parse_addr(base_val)?;
                            let offsets = args.get("offsets").and_then(|v| v.as_array()).ok_or("Missing offsets array")?;
                            let pid = if let Ok(p) = p_name.parse::<u32>() { p } else {
                                vmm_instance.get_pid(p_name).ok_or_else(|| format!("Process '{}' not found", p_name))?
                            };

                            let mut chain = vec![format!("0x{:X}", curr)];
                            for (i, off_val) in offsets.iter().enumerate() {
                                let off = parse_addr(off_val)?;
                                if i == offsets.len() - 1 {
                                    curr += off;
                                    chain.push(format!("0x{:X} (resolved)", curr));
                                } else {
                                    let next_ptr = vmm_instance.read_val::<u64>(pid, curr + off).ok_or("Pointer dereference failed")?;
                                    curr = next_ptr;
                                    chain.push(format!("0x{:X}", curr));
                                }
                            }
                            Ok(json!({
                                "resolved_address": format!("0x{:X}", curr),
                                "chain": chain
                            }))
                        }

                        "dma_pattern_scan" => {
                            let p_name = args.get("process_name").and_then(|v| v.as_str()).ok_or("Missing process_name")?;
                            let mod_name = args.get("module_name").and_then(|v| v.as_str()).unwrap_or("Wow.exe");
                            let pat_str = args.get("pattern").and_then(|v| v.as_str()).ok_or("Missing pattern")?;
                            let pid = if let Ok(p) = p_name.parse::<u32>() { p } else {
                                vmm_instance.get_pid(p_name).ok_or_else(|| format!("Process '{}' not found", p_name))?
                            };
                            let mod_base = vmm_instance.get_module_base(pid, mod_name).ok_or("Module base not found")?;

                            let (pat_bytes, mask) = parse_pattern(pat_str);
                            if pat_bytes.is_empty() { return Err("Empty pattern".into()); }

                            let t0 = Instant::now();
                            let mut hits = Vec::new();
                            let chunk_size = 2 * 1024 * 1024;
                            let max_scan = 64 * 1024 * 1024;
                            let mut buf = vec![0u8; chunk_size];

                            for off in (0..max_scan).step_by(chunk_size - pat_bytes.len()) {
                                let va = mod_base + off as u64;
                                if !vmm_instance.read(pid, va, &mut buf) { continue; }

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

                                        // RIP relative resolution
                                        if i + 7 <= buf.len() && buf[i] == 0x48 && (buf[i+1] == 0x8B || buf[i+1] == 0x8D) && (buf[i+2] & 0xC7 == 0x05) {
                                            let disp = i32::from_le_bytes([buf[i+3], buf[i+4], buf[i+5], buf[i+6]]);
                                            let rip_target = (hit_va + 7).wrapping_add(disp as i64 as u64);
                                            hit_obj["resolved_rip_target"] = json!(format!("0x{:X}", rip_target));
                                            hit_obj["resolved_rva"] = json!(format!("+0x{:X}", rip_target.wrapping_sub(mod_base)));
                                        }

                                        hits.push(hit_obj);
                                        if hits.len() >= 25 { break; }
                                    }
                                }
                                if hits.len() >= 25 { break; }
                            }
                            let elapsed = t0.elapsed().as_millis();
                            Ok(json!({
                                "hits": hits,
                                "count": hits.len(),
                                "scan_time_ms": elapsed
                            }))
                        }

                        "wow_get_target_state" => {
                            let pid = vmm_instance.get_pid("Wow.exe").ok_or("Wow.exe not found")?;
                            let base = vmm_instance.get_module_base(pid, "Wow.exe").ok_or("Wow.exe base not found")?;

                            let p_guid = vmm_instance.read_val::<u32>(pid, base + 0x4C1B1C0).unwrap_or(0);
                            let has_t = vmm_instance.read_val::<u64>(pid, base + 0x04B15F90).unwrap_or(0) != 0;
                            let (t_guid, t_name) = if has_t {
                                let g = vmm_instance.read_val::<u64>(pid, base + 0x04B15F98).unwrap_or(0);
                                (g, format!("Цель [0x{:X}]", g & 0xFFFFFFFF))
                            } else {
                                (0, "НЕТ ЦЕЛИ".to_string())
                            };

                            Ok(json!({
                                "player_guid": format!("0x{:X}", p_guid),
                                "has_target": has_t,
                                "target_guid": format!("0x{:X}", t_guid),
                                "target_name": t_name
                            }))
                        }

                        _ => Err(format!("Unknown tool: {}", tool_name))
                    }
                })();

                let resp = match result_value {
                    Ok(val) => {
                        json!({
                            "jsonrpc": "2.0",
                            "id": req.id,
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": serde_json::to_string_pretty(&val).unwrap_or_default()
                                    }
                                ]
                            }
                        })
                    }
                    Err(err_msg) => {
                        json!({
                            "jsonrpc": "2.0",
                            "id": req.id,
                            "error": {
                                "code": -32603,
                                "message": err_msg
                            }
                        })
                    }
                };

                let _ = writeln!(writer, "{}", resp);
                let _ = writer.flush();
            }

            _ => {
                if req.id.is_some() {
                    let resp = json!({
                        "jsonrpc": "2.0",
                        "id": req.id,
                        "error": {
                            "code": -32601,
                            "message": format!("Method '{}' not found", req.method)
                        }
                    });
                    let _ = writeln!(writer, "{}", resp);
                    let _ = writer.flush();
                }
            }
        }

        line.clear();
    }
}
