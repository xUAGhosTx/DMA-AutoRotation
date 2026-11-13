// language: Rust, file: src/scanner.rs, target: Windows x86_64
use std::collections::HashMap;
use std::time::Instant;

pub struct TargetDebuffs {
    pub corruption_exp: Option<Instant>,
    pub immolate_exp: Option<Instant>,
    pub agony_exp: Option<Instant>,
}

pub struct CombatTracker {
    pub targets: HashMap<u32, TargetDebuffs>,
    pub current_target_guid: u32,
    pub current_target_name: String,
    pub has_target: bool,
    pub player_guid: u32,
    pub last_cast_time: Instant,
}

impl CombatTracker {
    pub fn new() -> Self {
        Self {
            targets: HashMap::new(),
            current_target_guid: 0,
            current_target_name: String::new(),
            has_target: false,
            player_guid: 0,
            last_cast_time: Instant::now(),
        }
    }

    pub fn record_cast(&mut self, spell: &str) {
        if !self.has_target || self.current_target_guid == 0 {
            return;
        }
        let now = Instant::now();
        let entry = self.targets.entry(self.current_target_guid).or_insert(TargetDebuffs {
            corruption_exp: None,
            immolate_exp: None,
            agony_exp: None,
        });

        match spell {
            "corruption" => entry.corruption_exp = Some(now + std::time::Duration::from_secs(18)),
            "immolate" => entry.immolate_exp = Some(now + std::time::Duration::from_secs(15)),
            "agony" => entry.agony_exp = Some(now + std::time::Duration::from_secs(24)),
            _ => {}
        }
        self.last_cast_time = now;
    }

    pub fn get_remaining_secs(&self, guid: u32) -> (f32, f32, f32) {
        let now = Instant::now();
        if let Some(d) = self.targets.get(&guid) {
            let c = d.corruption_exp.map_or(0.0, |t| if t > now { (t - now).as_secs_f32() } else { 0.0 });
            let i = d.immolate_exp.map_or(0.0, |t| if t > now { (t - now).as_secs_f32() } else { 0.0 });
            let a = d.agony_exp.map_or(0.0, |t| if t > now { (t - now).as_secs_f32() } else { 0.0 });
            (c, i, a)
        } else {
            (0.0, 0.0, 0.0)
        }
    }

    pub fn recommend_next_spell(&self) -> (&'static str, &'static str) {
        if !self.has_target || self.current_target_guid == 0 {
            return ("НЕТ ЦЕЛИ", "Ожидание выбора противника");
        }

        let (c_rem, i_rem, _) = self.get_remaining_secs(self.current_target_guid);

        if c_rem <= 2.0 {
            ("ПОРЧА", "Приоритет #1 -> Наложить/Обновить Порчу")
        } else if i_rem <= 2.0 {
            ("ЖЕРТВЕННЫЙ ОГОНЬ", "Приоритет #2 -> Наложить/Обновить Огонь")
        } else {
            ("СТРЕЛА ТЬМЫ", "Приоритет #3 -> Спам филлера (доты активны)")
        }
    }

    pub fn render_bar(&self, spell: &str) -> String {
        let (c, i, a) = self.get_remaining_secs(self.current_target_guid);
        let (rem, total) = match spell {
            "corruption" => (c, 18.0),
            "immolate" => (i, 15.0),
            "agony" => (a, 24.0),
            _ => (0.0, 1.0),
        };
        let pct = (rem / total).clamp(0.0, 1.0);
        let filled = (pct * 20.0).round() as usize;
        let empty = 20 - filled;
        format!("[{}{}]", "█".repeat(filled), "░".repeat(empty))
    }

    pub fn get_debuff_display(&self, spell: &str) -> String {
        let (c, i, a) = self.get_remaining_secs(self.current_target_guid);
        let rem = match spell {
            "corruption" => c,
            "immolate" => i,
            "agony" => a,
            _ => 0.0,
        };
        if rem > 0.0 {
            format!("{:.1} сек", rem)
        } else {
            "НЕТ".to_string()
        }
    }
}

