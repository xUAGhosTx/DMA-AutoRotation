// language: Rust, file: src/cli.rs, target: Windows 11, MSVC x64
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use serde_json::{json, Value};

fn send_cmd(cmd: Value) -> Result<Value, String> {
    let mut stream = TcpStream::connect("127.0.0.1:8765")
        .map_err(|e| format!("Failed to connect to Rust DMA Daemon (127.0.0.1:8765): {}. Make sure dma_daemon is running.", e))?;

    let payload = format!("{}\n", cmd);
    stream.write_all(payload.as_bytes()).map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;

    serde_json::from_str(&line).map_err(|e| format!("Invalid JSON response: {}", e))
}

fn parse_addr(s: &str) -> u64 {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).unwrap_or(0)
    } else {
        s.parse::<u64>().unwrap_or(0)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: dma_cli <status|target|find|read|bytes|scan|cast> [args...]");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "status" => {
            match send_cmd(json!({ "cmd": "status" })) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { eprintln!("[-] Error: {}", e); std::process::exit(1); }
            }
        }
        "target" => {
            match send_cmd(json!({ "cmd": "get_target" })) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { eprintln!("[-] Error: {}", e); std::process::exit(1); }
            }
        }
        "find" => {
            let name = args.get(2).map(|s| s.as_str()).unwrap_or("Wow.exe");
            match send_cmd(json!({ "cmd": "find_process", "name": name })) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { eprintln!("[-] Error: {}", e); std::process::exit(1); }
            }
        }
        "read" => {
            if args.len() < 4 {
                eprintln!("Usage: dma_cli read <pid> <addr> [type: u8|u16|u32|u64|float|double]");
                std::process::exit(1);
            }
            let pid = args[2].parse::<u32>().unwrap_or(0);
            let addr = parse_addr(&args[3]);
            let type_name = args.get(4).map(|s| s.as_str()).unwrap_or("u64");
            match send_cmd(json!({ "cmd": "read_type", "pid": pid, "addr": addr, "type_name": type_name })) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { eprintln!("[-] Error: {}", e); std::process::exit(1); }
            }
        }
        "bytes" => {
            if args.len() < 5 {
                eprintln!("Usage: dma_cli bytes <pid> <addr> <size>");
                std::process::exit(1);
            }
            let pid = args[2].parse::<u32>().unwrap_or(0);
            let addr = parse_addr(&args[3]);
            let size = args[4].parse::<usize>().unwrap_or(32);
            match send_cmd(json!({ "cmd": "read_bytes", "pid": pid, "addr": addr, "size": size })) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { eprintln!("[-] Error: {}", e); std::process::exit(1); }
            }
        }
        "scan" => {
            if args.len() < 5 {
                eprintln!("Usage: dma_cli scan <pid> <module> <pattern>");
                std::process::exit(1);
            }
            let pid = args[2].parse::<u32>().unwrap_or(0);
            let module = &args[3];
            let pat = &args[4];
            let max_hits = args.get(5).and_then(|s| s.parse::<usize>().ok()).unwrap_or(20);
            match send_cmd(json!({ "cmd": "pattern_scan", "pid": pid, "module_name": module, "pattern": pat, "max_hits": max_hits })) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { eprintln!("[-] Error: {}", e); std::process::exit(1); }
            }
        }
        "refs" => {
            if args.len() < 5 {
                eprintln!("Usage: dma_cli refs <pid> <module> <target_va>");
                std::process::exit(1);
            }
            let pid = args[2].parse::<u32>().unwrap_or(0);
            let module = &args[3];
            let target_va = parse_addr(&args[4]);
            match send_cmd(json!({ "cmd": "ref_scan", "pid": pid, "module_name": module, "target_va": target_va })) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { eprintln!("[-] Error: {}", e); std::process::exit(1); }
            }
        }
        "snap" => {
            let pid = args.get(2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(16800);
            match send_cmd(json!({ "cmd": "snapshot", "pid": pid })) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { eprintln!("[-] Error: {}", e); std::process::exit(1); }
            }
        }
        "diff" => {
            let pid = args.get(2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(16800);
            match send_cmd(json!({ "cmd": "diff", "pid": pid })) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { eprintln!("[-] Error: {}", e); std::process::exit(1); }
            }
        }
        "scan_range" => {
            if args.len() < 6 {
                eprintln!("Usage: dma_cli scan_range <pid> <start_addr> <end_addr> <pattern> [max_hits]");
                std::process::exit(1);
            }
            let pid = args[2].parse::<u32>().unwrap_or(0);
            let start_addr = parse_addr(&args[3]);
            let end_addr = parse_addr(&args[4]);
            let pat = &args[5];
            let max_hits = args.get(6).and_then(|s| s.parse::<usize>().ok()).unwrap_or(20);
            match send_cmd(json!({ "cmd": "scan_range", "pid": pid, "start_addr": start_addr, "end_addr": end_addr, "pattern": pat, "max_hits": max_hits })) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { eprintln!("[-] Error: {}", e); std::process::exit(1); }
            }
        }
        "find_ptrs" => {
            if args.len() < 6 {
                eprintln!("Usage: dma_cli find_ptrs <pid> <target_addr> <start_addr> <end_addr> [max_hits]");
                std::process::exit(1);
            }
            let pid = args[2].parse::<u32>().unwrap_or(0);
            let target_addr = parse_addr(&args[3]);
            let start_addr = parse_addr(&args[4]);
            let end_addr = parse_addr(&args[5]);
            let max_hits = args.get(6).and_then(|s| s.parse::<usize>().ok()).unwrap_or(20);
            match send_cmd(json!({ "cmd": "find_ptrs", "pid": pid, "target_addr": target_addr, "start_addr": start_addr, "end_addr": end_addr, "max_hits": max_hits })) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { eprintln!("[-] Error: {}", e); std::process::exit(1); }
            }
        }
        "cast" => {
            let spell = args.get(2).map(|s| s.as_str()).unwrap_or("corruption");
            match send_cmd(json!({ "cmd": "cast", "spell": spell })) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { eprintln!("[-] Error: {}", e); std::process::exit(1); }
            }
        }
        "makcu" => {
            if args.len() < 3 {
                eprintln!("Usage: dma_cli makcu <raw_command_string>");
                std::process::exit(1);
            }
            let cmd_str = &args[2];
            match send_cmd(json!({ "cmd": "makcu", "command": cmd_str })) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                Err(e) => { eprintln!("[-] Error: {}", e); std::process::exit(1); }
            }
        }
        "send" => {
            if args.len() < 4 {
                eprintln!("Usage: dma_cli send <target_ip:port> <key>");
                std::process::exit(1);
            }
            let target_addr = &args[2];
            let key = &args[3];
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("Failed to bind UDP");
            let payload = format!("press:{}", key);
            match socket.send_to(payload.as_bytes(), target_addr) {
                Ok(bytes) => println!("{{\"sent_bytes\": {}, \"target\": \"{}\", \"key\": \"{}\"}}", bytes, target_addr, key),
                Err(e) => { eprintln!("[-] Failed to send UDP: {}", e); std::process::exit(1); }
            }
        }
        _ => {
            eprintln!("Unknown command. Use: status, target, find, read, bytes, scan, cast");
            std::process::exit(1);
        }
    }
}

