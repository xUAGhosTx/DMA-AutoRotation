// language: Rust, file: src/bin/input_agent.rs, target: Windows 11, MSVC x64
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

#[repr(C)]
struct INPUT {
    type_: u32,
    ki: KEYBDINPUT,
    padding: u64,
}

#[repr(C)]
struct KEYBDINPUT {
    w_vk: u16,
    w_scan: u16,
    dw_flags: u32,
    time: u32,
    dw_extra_info: usize,
}

const INPUT_KEYBOARD: u32 = 1;
const KEYEVENTF_KEYUP: u32 = 0x0002;
const KEYEVENTF_SCANCODE: u32 = 0x0008;

#[link(name = "user32")]
extern "system" {
    fn SendInput(cInputs: u32, pInputs: *const INPUT, cbSize: i32) -> u32;
}

fn key_to_scancode(key: &str) -> Option<u16> {
    match key.to_lowercase().trim() {
        "1" => Some(0x02),
        "2" => Some(0x03),
        "3" => Some(0x04),
        "4" => Some(0x05),
        "5" => Some(0x06),
        "6" => Some(0x07),
        "7" => Some(0x08),
        "8" => Some(0x09),
        "9" => Some(0x0A),
        "0" => Some(0x0B),
        "q" => Some(0x10),
        "w" => Some(0x11),
        "e" => Some(0x12),
        "r" => Some(0x13),
        "t" => Some(0x14),
        "a" => Some(0x1E),
        "s" => Some(0x1F),
        "d" => Some(0x20),
        "f" => Some(0x21),
        "space" | " " => Some(0x39),
        "tab" => Some(0x0F),
        _ => None,
    }
}

fn send_scancode(scan: u16, hold_ms: u64) {
    let down = INPUT {
        type_: INPUT_KEYBOARD,
        ki: KEYBDINPUT {
            w_vk: 0,
            w_scan: scan,
            dw_flags: KEYEVENTF_SCANCODE,
            time: 0,
            dw_extra_info: 0,
        },
        padding: 0,
    };
    unsafe { SendInput(1, &down, std::mem::size_of::<INPUT>() as i32); }

    thread::sleep(Duration::from_millis(hold_ms));

    let up = INPUT {
        type_: INPUT_KEYBOARD,
        ki: KEYBDINPUT {
            w_vk: 0,
            w_scan: scan,
            dw_flags: KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP,
            time: 0,
            dw_extra_info: 0,
        },
        padding: 0,
    };
    unsafe { SendInput(1, &up, std::mem::size_of::<INPUT>() as i32); }
}

fn main() {
    println!("========================================================");
    println!("   WOW DMA HIGH-SPEED UDP INPUT AGENT (GAMING PC)");
    println!("========================================================");

    let bind_addr = "0.0.0.0:9999";
    let socket = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Failed to bind UDP on {}: {}", bind_addr, e);
            std::process::exit(1);
        }
    };
    let _ = socket.set_broadcast(true);

    println!("[+] UDP Input Agent listening on {}", bind_addr);
    println!("[+] Zero-Config Auto-Discovery Beacon: ACTIVE (Broadcasting to LAN)");
    println!("[*] Ready to receive hardware keystroke commands from DMA PC");

    // Spawn automatic beacon thread: broadcasts presence to LAN every 2 seconds
    let beacon_sock = socket.try_clone().expect("Failed to clone socket");
    thread::spawn(move || {
        let beacon = b"WOW_INPUT_AGENT_BEACON";
        loop {
            let _ = beacon_sock.send_to(beacon, "255.255.255.255:9998");
            thread::sleep(Duration::from_secs(2));
        }
    });

    let mut buf = [0u8; 512];
    loop {
        if let Ok((len, src)) = socket.recv_from(&mut buf) {
            let msg = String::from_utf8_lossy(&buf[..len]).trim().to_string();
            
            // Handshake ping/pong
            if msg == "WOW_DISCOVER_PING" {
                let _ = socket.send_to(b"WOW_DISCOVER_PONG", src);
                println!("[*] Responded to DMA discovery ping from {}", src);
                continue;
            }

            let key = if let Some(stripped) = msg.strip_prefix("press:") {
                stripped
            } else {
                &msg
            };

            if let Some(scancode) = key_to_scancode(key) {
                println!("[*] Received from {}: '{}' -> Scancode 0x{:02X}", src, key, scancode);
                send_scancode(scancode, 60);
                println!("[+] Key '{}' pressed and released cleanly", key);
            } else {
                eprintln!("[-] Unknown key: '{}'", key);
            }
        }
    }
}
