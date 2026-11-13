// language: Rust, file: src/rotation.rs, target: Windows 11, MSVC x64
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum AuraTarget {
    Target,   // Цель
    Player,   // На себе
    None,     // Без условий (всегда доступно)
}

impl AuraTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuraTarget::Target => "Цель",
            AuraTarget::Player => "На себе",
            AuraTarget::None => "Без условий",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum AuraPresence {
    Absent,   // Отсутствует
    Present,  // Присутствует
}

impl AuraPresence {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuraPresence::Absent => "Отсутствует",
            AuraPresence::Present => "Присутствует",
        }
    }
}

fn default_aura_target() -> AuraTarget {
    AuraTarget::Target
}

fn default_aura_presence() -> AuraPresence {
    AuraPresence::Absent
}

fn default_aura_name() -> String {
    String::new()
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum ConditionType {
    MissingOrExpiring, // Refreshes if missing or <= threshold_ms
    MissingOnly,       // Casts only if completely missing
    AlwaysFiller,      // Always ready (spam/filler when all DoTs up)
}

impl Default for ConditionType {
    fn default() -> Self {
        ConditionType::MissingOrExpiring
    }
}

impl ConditionType {
    pub fn as_str(&self, threshold_ms: u32) -> String {
        match self {
            ConditionType::MissingOrExpiring => {
                let sec = (threshold_ms as f32) / 1000.0;
                format!("Нет / таймер < {:.1}с", sec)
            }
            ConditionType::MissingOnly => "Только если нет".to_string(),
            ConditionType::AlwaysFiller => "Всегда (Филлер)".to_string(),
        }
    }

    pub fn next(&self) -> Self {
        match self {
            ConditionType::MissingOrExpiring => ConditionType::MissingOnly,
            ConditionType::MissingOnly => ConditionType::AlwaysFiller,
            ConditionType::AlwaysFiller => ConditionType::MissingOrExpiring,
        }
    }
}

fn default_min_range() -> f32 { 0.0 }
fn default_max_range() -> f32 { 30.0 }

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum HpTarget {
    Target,   // Цель
    Player,   // На себе
}

impl Default for HpTarget {
    fn default() -> Self {
        HpTarget::Target
    }
}

impl HpTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            HpTarget::Target => "Цель",
            HpTarget::Player => "На себе",
        }
    }
}

fn default_hp_target() -> HpTarget {
    HpTarget::Target
}

fn default_min_hp() -> u32 { 0 }
fn default_max_hp() -> u32 { 100 }
fn default_interrupt_pct() -> u32 { 70 }

pub fn suggest_spell_range(name: &str) -> (bool, f32, f32) {
    let lower = name.to_lowercase();
    // Melee keywords
    if lower.contains("атак") || lower.contains("удар") || lower.contains("потрош") 
        || lower.contains("растерз") || lower.contains("кровоиз") || lower.contains("увечье")
        || lower.contains("раскалыв") || lower.contains("подрезать") || lower.contains("казнь")
        || lower.contains("разорвать") || lower.contains("удар бури") {
        (true, 0.0, 5.0)
    } else if lower.contains("выстрел") || lower.contains("залп") || lower.contains("прицел") || lower.contains("укус") {
        (true, 8.0, 35.0)
    } else if lower.contains("страх") || lower.contains("ослеп") || lower.contains("пытка") || lower.contains("лицо") {
        (true, 0.0, 20.0)
    } else if lower.contains("стрела") || lower.contains("огонь") || lower.contains("порча") 
        || lower.contains("боль") || lower.contains("шар") || lower.contains("гнев") 
        || lower.contains("молния") || lower.contains("кара") || lower.contains("шок") {
        (true, 0.0, 30.0)
    } else {
        // Buffs / Self spells / Default
        (false, 0.0, 30.0)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum ConditionLogic {
    #[serde(rename = "AND")]
    And,
    #[serde(rename = "OR")]
    Or,
}

impl Default for ConditionLogic {
    fn default() -> Self {
        ConditionLogic::And
    }
}

impl ConditionLogic {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConditionLogic::And => "И (AND)",
            ConditionLogic::Or => "ИЛИ (OR)",
        }
    }

    pub fn toggle(&self) -> Self {
        match self {
            ConditionLogic::And => ConditionLogic::Or,
            ConditionLogic::Or => ConditionLogic::And,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuraCondition {
    #[serde(default)]
    pub logic: ConditionLogic,
    #[serde(default = "default_aura_target")]
    pub aura_target: AuraTarget,
    #[serde(default = "default_aura_presence")]
    pub aura_presence: AuraPresence,
    #[serde(default = "default_aura_name")]
    pub aura_name: String,
    #[serde(default)]
    pub threshold_ms: u32,
}

impl Default for AuraCondition {
    fn default() -> Self {
        Self {
            logic: ConditionLogic::And,
            aura_target: AuraTarget::Target,
            aura_presence: AuraPresence::Absent,
            aura_name: String::new(),
            threshold_ms: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RotationRule {
    pub enabled: bool,
    pub name: String,
    pub spell_id: Option<u32>,
    pub key: String,
    #[serde(default)]
    pub condition: ConditionType,
    #[serde(default)]
    pub threshold_ms: u32,
    #[serde(default = "default_aura_target")]
    pub aura_target: AuraTarget,
    #[serde(default = "default_aura_presence")]
    pub aura_presence: AuraPresence,
    #[serde(default = "default_aura_name")]
    pub aura_name: String,
    #[serde(default)]
    pub conditions: Vec<AuraCondition>,
    #[serde(default)]
    pub check_hp: bool,
    #[serde(default = "default_hp_target")]
    pub hp_target: HpTarget,
    #[serde(default = "default_min_hp")]
    pub min_hp: u32,
    #[serde(default = "default_max_hp")]
    pub max_hp: u32,
    #[serde(default)]
    pub check_interrupt: bool,
    #[serde(default = "default_interrupt_pct")]
    pub interrupt_pct: u32,
    #[serde(default)]
    pub check_range: bool,
    #[serde(default = "default_min_range")]
    pub min_range: f32,
    #[serde(default = "default_max_range")]
    pub max_range: f32,
}

impl Default for RotationRule {
    fn default() -> Self {
        Self {
            enabled: true,
            name: String::new(),
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
            check_range: false,
            min_range: 0.0,
            max_range: 30.0,
        }
    }
}

impl RotationRule {
    pub fn get_conditions(&self) -> Vec<AuraCondition> {
        if !self.conditions.is_empty() {
            self.conditions.clone()
        } else {
            vec![AuraCondition {
                logic: ConditionLogic::And,
                aura_target: self.aura_target,
                aura_presence: self.aura_presence,
                aura_name: self.aura_name.clone(),
                threshold_ms: self.threshold_ms,
            }]
        }
    }

    pub fn sync_legacy_fields(&mut self) {
        if let Some(first) = self.conditions.first() {
            self.aura_target = first.aura_target;
            self.aura_presence = first.aura_presence;
            self.aura_name = first.aura_name.clone();
            self.threshold_ms = first.threshold_ms;
        }
    }

    pub fn condition_summary(&self) -> String {
        let conds = self.get_conditions();
        let id_prefix = if let Some(id) = self.spell_id {
            format!("ID: {} • ", id)
        } else {
            String::new()
        };

        let mut parts = Vec::new();
        for (idx, c) in conds.iter().enumerate() {
            let prefix = if idx == 0 {
                ""
            } else {
                match c.logic {
                    ConditionLogic::And => " И ",
                    ConditionLogic::Or => " ИЛИ ",
                }
            };

            let a_name = if c.aura_name.trim().is_empty() { &self.name } else { &c.aura_name };
            let part_str = match c.aura_target {
                AuraTarget::None => format!("{}Всегда", prefix),
                AuraTarget::Player => {
                    let st = match c.aura_presence {
                        AuraPresence::Absent => "нет",
                        AuraPresence::Present => "есть",
                    };
                    if c.threshold_ms > 0 && c.aura_presence == AuraPresence::Absent {
                        format!("{}На себе: {} (≤{}с) [{}]", prefix, st, c.threshold_ms / 1000, a_name)
                    } else {
                        format!("{}На себе: {} [{}]", prefix, st, a_name)
                    }
                }
                AuraTarget::Target => {
                    let st = match c.aura_presence {
                        AuraPresence::Absent => "нет",
                        AuraPresence::Present => "есть",
                    };
                    if c.threshold_ms > 0 && c.aura_presence == AuraPresence::Absent {
                        format!("{}На цели: {} (≤{}с) [{}]", prefix, st, c.threshold_ms / 1000, a_name)
                    } else {
                        format!("{}На цели: {} [{}]", prefix, st, a_name)
                    }
                }
            };
            parts.push(part_str);
        }

        let mut base_summary = format!("{}{}", id_prefix, parts.join(""));
        if self.check_hp {
            let who = match self.hp_target {
                HpTarget::Target => "Цель",
                HpTarget::Player => "Свое",
            };
            if self.min_hp == 0 && self.max_hp < 100 {
                base_summary = format!("{} • HP ({}): ≤{}%", base_summary, who, self.max_hp);
            } else if self.min_hp > 0 && self.max_hp == 100 {
                base_summary = format!("{} • HP ({}): ≥{}%", base_summary, who, self.min_hp);
            } else {
                base_summary = format!("{} • HP ({}): {}-{}%", base_summary, who, self.min_hp, self.max_hp);
            }
        }
        if self.check_interrupt {
            base_summary = format!("{} • Кик: ≥{}%", base_summary, self.interrupt_pct);
        }
        if self.check_range {
            if self.min_range > 0.0 {
                format!("{} • Дист: {:.0}-{:.0}я", base_summary, self.min_range, self.max_range)
            } else {
                format!("{} • Дист: ≤{:.0}я", base_summary, self.max_range)
            }
        } else {
            base_summary
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum MouseTrigger {
    Mouse4,  // ms1
    Mouse5,  // ms2
    Middle,  // middle
    Right,   // right
    Disabled,
}

impl MouseTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            MouseTrigger::Mouse4 => "Mouse 4 (Боковая 1)",
            MouseTrigger::Mouse5 => "Mouse 5 (Боковая 2)",
            MouseTrigger::Middle => "Колёсико (Middle)",
            MouseTrigger::Right => "Правая кнопка (ПКМ)",
            MouseTrigger::Disabled => "Отключен (Вручную)",
        }
    }

    pub fn to_cmd(&self) -> Option<&'static str> {
        match self {
            MouseTrigger::Mouse4 => Some("ms1"),
            MouseTrigger::Mouse5 => Some("ms2"),
            MouseTrigger::Middle => Some("middle"),
            MouseTrigger::Right => Some("right"),
            MouseTrigger::Disabled => None,
        }
    }

    pub fn next(&self) -> Self {
        match self {
            MouseTrigger::Mouse4 => MouseTrigger::Mouse5,
            MouseTrigger::Mouse5 => MouseTrigger::Middle,
            MouseTrigger::Middle => MouseTrigger::Disabled,
            MouseTrigger::Disabled => MouseTrigger::Mouse4,
            MouseTrigger::Right => MouseTrigger::Mouse4,
        }
    }
}

fn default_min_delay() -> u32 { 200 }
fn default_max_delay() -> u32 { 320 }
fn default_min_press() -> u32 { 80 }
fn default_max_press() -> u32 { 150 }
fn default_true() -> bool { true }
fn default_profile_name() -> String { "Чернокнижник (Афли)".to_string() }
fn default_auto_attack_key() -> String { "t".to_string() }

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RotationConfig {
    #[serde(default = "default_profile_name")]
    pub name: String,
    pub active: bool,
    pub trigger: MouseTrigger,
    pub rules: Vec<RotationRule>,
    #[serde(default = "default_min_delay")]
    pub min_delay_ms: u32,
    #[serde(default = "default_max_delay")]
    pub max_delay_ms: u32,
    #[serde(default = "default_min_press")]
    pub min_press_ms: u32,
    #[serde(default = "default_max_press")]
    pub max_press_ms: u32,
    #[serde(default = "default_true")]
    pub humanize: bool,

    #[serde(default = "default_true")]
    pub wait_cast: bool,
    #[serde(default = "default_true")]
    pub check_gcd: bool,
    #[serde(default = "default_true")]
    pub reset_on_target_change: bool,
    #[serde(default = "default_true")]
    pub protect_channeling: bool,
    #[serde(default)]
    pub auto_target: bool,
    #[serde(default)]
    pub auto_attack: bool,
    #[serde(default = "default_auto_attack_key")]
    pub auto_attack_key: String,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            name: "Чернокнижник (Афли)".into(),
            active: true,
            trigger: MouseTrigger::Mouse4,
            min_delay_ms: 200,
            max_delay_ms: 320,
            min_press_ms: 80,
            max_press_ms: 150,
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
                    name: "Шкура демона".into(),
                    spell_id: Some(687),
                    key: "9".into(),
                    condition: ConditionType::MissingOrExpiring,
                    threshold_ms: 0,
                    aura_target: AuraTarget::Player,
                    aura_presence: AuraPresence::Absent,
                    aura_name: "Шкура демона".into(),
                    ..Default::default()
                },
                RotationRule {
                    enabled: true,
                    name: "Порча".into(),
                    spell_id: Some(172),
                    key: "2".into(),
                    condition: ConditionType::MissingOrExpiring,
                    threshold_ms: 1500,
                    aura_target: AuraTarget::Target,
                    aura_presence: AuraPresence::Absent,
                    aura_name: "Порча".into(),
                    check_range: true,
                    max_range: 30.0,
                    ..Default::default()
                },
                RotationRule {
                    enabled: true,
                    name: "Жертвенный огонь".into(),
                    spell_id: Some(348),
                    key: "1".into(),
                    condition: ConditionType::MissingOrExpiring,
                    threshold_ms: 1500,
                    aura_target: AuraTarget::Target,
                    aura_presence: AuraPresence::Absent,
                    aura_name: "Жертвенный огонь".into(),
                    check_range: true,
                    max_range: 30.0,
                    ..Default::default()
                },
                RotationRule {
                    enabled: true,
                    name: "Стрела Тьмы".into(),
                    spell_id: Some(686),
                    key: "4".into(),
                    condition: ConditionType::AlwaysFiller,
                    threshold_ms: 0,
                    aura_target: AuraTarget::None,
                    aura_presence: AuraPresence::Absent,
                    aura_name: String::new(),
                    check_range: true,
                    max_range: 30.0,
                    ..Default::default()
                },
            ],
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RotationStore {
    pub active_index: usize,
    pub profiles: Vec<RotationConfig>,
}

impl Default for RotationStore {
    fn default() -> Self {
        Self {
            active_index: 0,
            profiles: vec![
                RotationConfig::default(),
                RotationConfig {
                    name: "Чернокнижник (Демон)".into(),
                    active: true,
                    trigger: MouseTrigger::Mouse5,
                    min_delay_ms: 200,
                    max_delay_ms: 320,
                    min_press_ms: 80,
                    max_press_ms: 150,
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
                            name: "Жертвенный огонь".into(),
                            spell_id: Some(348),
                            key: "1".into(),
                            condition: ConditionType::MissingOrExpiring,
                            threshold_ms: 1500,
                            aura_target: AuraTarget::Target,
                            aura_presence: AuraPresence::Absent,
                            aura_name: "Жертвенный огонь".into(),
                            check_range: true,
                            max_range: 30.0,
                            ..Default::default()
                        },
                        RotationRule {
                            enabled: true,
                            name: "Порча".into(),
                            spell_id: Some(172),
                            key: "2".into(),
                            condition: ConditionType::MissingOrExpiring,
                            threshold_ms: 1500,
                            aura_target: AuraTarget::Target,
                            aura_presence: AuraPresence::Absent,
                            aura_name: "Порча".into(),
                            check_range: true,
                            max_range: 30.0,
                            ..Default::default()
                        },
                        RotationRule {
                            enabled: true,
                            name: "Стрела Тьмы".into(),
                            spell_id: Some(686),
                            key: "4".into(),
                            condition: ConditionType::AlwaysFiller,
                            threshold_ms: 0,
                            aura_target: AuraTarget::None,
                            aura_presence: AuraPresence::Absent,
                            aura_name: String::new(),
                            check_range: true,
                            max_range: 30.0,
                            ..Default::default()
                        },
                    ],
                },
                RotationConfig {
                    name: "Быстрый Гринд / Фарм".into(),
                    active: true,
                    trigger: MouseTrigger::Middle,
                    min_delay_ms: 140,
                    max_delay_ms: 220,
                    min_press_ms: 50,
                    max_press_ms: 100,
                    humanize: true,
                    wait_cast: true,
                    check_gcd: true,
                    reset_on_target_change: true,
                    protect_channeling: true,
                    auto_target: true,
                    auto_attack: true,
                    auto_attack_key: "t".to_string(),
                    rules: vec![
                        RotationRule {
                            enabled: true,
                            name: "Порча".into(),
                            spell_id: Some(172),
                            key: "2".into(),
                            condition: ConditionType::MissingOnly,
                            threshold_ms: 0,
                            aura_target: AuraTarget::Target,
                            aura_presence: AuraPresence::Absent,
                            aura_name: "Порча".into(),
                            check_range: true,
                            max_range: 30.0,
                            ..Default::default()
                        },
                        RotationRule {
                            enabled: true,
                            name: "Проклятие агонии".into(),
                            spell_id: Some(980),
                            key: "3".into(),
                            condition: ConditionType::MissingOnly,
                            threshold_ms: 0,
                            aura_target: AuraTarget::Target,
                            aura_presence: AuraPresence::Absent,
                            aura_name: "Проклятие агонии".into(),
                            check_range: true,
                            max_range: 30.0,
                            ..Default::default()
                        },
                        RotationRule {
                            enabled: true,
                            name: "Стрела Тьмы".into(),
                            spell_id: Some(686),
                            key: "4".into(),
                            condition: ConditionType::AlwaysFiller,
                            threshold_ms: 0,
                            aura_target: AuraTarget::None,
                            aura_presence: AuraPresence::Absent,
                            aura_name: String::new(),
                            check_range: true,
                            max_range: 30.0,
                            ..Default::default()
                        },
                    ],
                },
            ],
        }
    }
}

impl RotationStore {
    pub fn load_or_default() -> Self {
        let candidate_paths = [
            "rotations.json",
            "wow_dma_app/rotations.json",
            r"C:\Users\1111\Desktop\WOW DMA\rotations.json",
            r"C:\Users\1111\Desktop\WOW DMA\wow_dma_app\target\release\rotations.json",
        ];
        for path in &candidate_paths {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(store) = serde_json::from_str::<RotationStore>(&content) {
                    if !store.profiles.is_empty() {
                        return store;
                    }
                }
            }
        }
        let def = Self::default();
        let _ = def.save();
        def
    }

    pub fn save(&self) -> bool {
        let json_str = match serde_json::to_string_pretty(self) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let paths = [
            "rotations.json",
            r"C:\Users\1111\Desktop\WOW DMA\rotations.json",
        ];
        let mut ok = false;
        for path in &paths {
            if std::fs::write(path, &json_str).is_ok() {
                ok = true;
            }
        }
        ok
    }

    pub fn active_config(&self) -> RotationConfig {
        if self.active_index < self.profiles.len() {
            self.profiles[self.active_index].clone()
        } else if let Some(first) = self.profiles.first() {
            first.clone()
        } else {
            RotationConfig::default()
        }
    }
}

