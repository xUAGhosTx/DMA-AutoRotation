// language: Rust, file: src/makcu.rs, target: Windows x86_64
use std::io::Write;
use std::time::Duration;
use serialport::SerialPort;

pub struct Makcu {
    port: Option<Box<dyn SerialPort>>,
    port_name: String,
    baud: u32,
}

impl Makcu {
    pub fn new(port_name: &str) -> Self {
        // Try V4 high-speed 4,000,000 baud first, then fall back to 115,200
        let (p, baud) = match serialport::new(port_name, 4_000_000)
            .timeout(Duration::from_millis(50))
            .open()
        {
            Ok(port) => (Some(port), 4_000_000),
            Err(_) => match serialport::new(port_name, 115_200)
                .timeout(Duration::from_millis(50))
                .open()
            {
                Ok(port) => (Some(port), 115_200),
                Err(e) => {
                    eprintln!("[-] Failed to open Makcu on {}: {}", port_name, e);
                    (None, 0)
                }
            },
        };

        if p.is_some() {
            println!("[+] Hardware Input: MAKCU V4 Link ACTIVE on {} @ {} baud", port_name, baud);
        }

        Self {
            port: p,
            port_name: port_name.to_string(),
            baud,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.port.is_some()
    }

    pub fn send_command(&mut self, cmd: &str) -> bool {
        if let Some(ref mut p) = self.port {
            let data = format!("{}\r", cmd);
            if p.write_all(data.as_bytes()).is_ok() {
                let _ = p.flush();
                return true;
            }
        }
        false
    }

    pub fn send_command_with_response(&mut self, cmd: &str) -> (bool, String) {
        if let Some(ref mut p) = self.port {
            let data = format!("{}\r", cmd);
            if p.write_all(data.as_bytes()).is_ok() {
                let _ = p.flush();
                std::thread::sleep(Duration::from_millis(30));
                let mut buf = [0u8; 256];
                let n = p.read(&mut buf).unwrap_or(0);
                let resp = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                return (true, resp);
            }
        }
        (false, String::new())
    }

    // Query Physical Button State (0 = release, 1 = physically pressed)
    pub fn get_mouse_button(&mut self, btn: &str) -> u8 {
        let (_, resp) = self.send_command_with_response(&format!("km.{}()", btn));
        for line in resp.lines().rev() {
            let t = line.trim();
            if let Ok(val) = t.parse::<u8>() {
                return val;
            }
        }
        0
    }

    // Release all modifier keys to prevent stuck Shift/Ctrl/Alt states
    pub fn release_all_modifiers(&mut self) {
        self.send_command("km.up('shift')");
        std::thread::sleep(Duration::from_millis(5));
        self.send_command("km.up('ctrl')");
        std::thread::sleep(Duration::from_millis(5));
        self.send_command("km.up('alt')");
    }

    // Hardware Keyboard Simulation (MAKCU V4 Native)
    pub fn press_key(&mut self, key: &str) -> bool {
        self.press_key_held(key, 35)
    }

    pub fn press_key_held(&mut self, key: &str, hold_ms: u64) -> bool {
        let lower = key.trim().to_lowercase();
        let hold_duration = Duration::from_millis(hold_ms.max(1));

        if !lower.contains('+') {
            let norm_key = match lower.as_str() {
                "control" => "ctrl",
                other => other,
            };
            self.send_command(&format!("km.down('{}')", norm_key));
            std::thread::sleep(hold_duration);
            return self.send_command(&format!("km.up('{}')", norm_key));
        }

        // Parse key combinations (e.g. Shift+1, Ctrl+E, Alt+F, Ctrl+Shift+3)
        let parts: Vec<&str> = lower.split('+').map(|s| s.trim()).collect();
        if parts.is_empty() {
            return false;
        }
        let (mods, main_slice) = parts.split_at(parts.len() - 1);
        let main_key = main_slice[0];

        // 1. Press modifier keys down sequentially with pacing for MCU UART buffer
        for m in mods {
            let mk = match *m {
                "ctrl" | "control" => "ctrl",
                "shift" => "shift",
                "alt" => "alt",
                "win" | "cmd" => "gui",
                other => other,
            };
            self.send_command(&format!("km.down('{}')", mk));
            std::thread::sleep(Duration::from_millis(8));
        }

        // 2. Press main target key down, wait hold duration, then release
        self.send_command(&format!("km.down('{}')", main_key));
        std::thread::sleep(hold_duration);
        let ok = self.send_command(&format!("km.up('{}')", main_key));
        std::thread::sleep(Duration::from_millis(8));

        // 3. Release modifier keys in reverse order with pacing
        for m in mods.iter().rev() {
            let mk = match *m {
                "ctrl" | "control" => "ctrl",
                "shift" => "shift",
                "alt" => "alt",
                "win" | "cmd" => "gui",
                other => other,
            };
            self.send_command(&format!("km.up('{}')", mk));
            std::thread::sleep(Duration::from_millis(8));
        }

        ok
    }

    pub fn press_space(&mut self) -> bool {
        self.send_command("km.press('space')")
    }

    pub fn key_down(&mut self, key: &str) -> bool {
        self.send_command(&format!("km.down('{}')", key))
    }

    pub fn key_up(&mut self, key: &str) -> bool {
        self.send_command(&format!("km.up('{}')", key))
    }

    // Cast Corruption via '2'
    pub fn cast_corruption(&mut self) -> bool {
        self.press_key("2")
    }

    // Cast Immolate via '1'
    pub fn cast_immolate(&mut self) -> bool {
        self.press_key("1")
    }

    // Cast Shadow Bolt via '4'
    pub fn cast_shadow_bolt(&mut self) -> bool {
        self.press_key("4")
    }

    // Right Click
    pub fn right_click(&mut self) -> bool {
        self.send_command("km.right(1)\rkm.right(0)")
    }
}
