/// Runtime security settings from the Settings UI.
/// Shared between the UI thread and the watcher/engine via Arc<Mutex<>>.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSettings {
    pub ai_enabled: bool,
    pub monitoring_enabled: bool,
    /// Incremented on every settings transition, including off/on between events.
    pub revision: u64,
    pub extension_monitoring: bool,
    pub rate_limit: bool,
    pub entropy: bool,
    pub dns: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            ai_enabled: true,
            monitoring_enabled: true,
            revision: 0,
            extension_monitoring: true,
            rate_limit: true,
            entropy: true,
            dns: true,
        }
    }
}

impl AppSettings {
    pub fn set_from_name(&mut self, name: &str, value: bool) {
        let field = match name {
            "ai" => &mut self.ai_enabled,
            "monitoring" => &mut self.monitoring_enabled,
            "extension" => &mut self.extension_monitoring,
            "rate_limit" => &mut self.rate_limit,
            "entropy" => &mut self.entropy,
            "dns" => &mut self.dns,
            _ => return,
        };
        if *field != value {
            *field = value;
            self.revision = self.revision.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_from_name_updates_the_matching_field() {
        let mut s = AppSettings {
            extension_monitoring: false,
            rate_limit: false,
            entropy: false,
            dns: false,
            ..AppSettings::default()
        };
        s.set_from_name("extension", true);
        assert!(s.extension_monitoring);
        s.set_from_name("rate_limit", true);
        assert!(s.rate_limit);
        s.set_from_name("entropy", true);
        assert!(s.entropy);
        s.set_from_name("dns", true);
        assert!(s.dns);
    }

    #[test]
    fn set_from_name_ignores_unknown_key() {
        let mut s = AppSettings::default();
        let before = s.clone();
        s.set_from_name("not_a_real_setting", false);
        assert_eq!(before.extension_monitoring, s.extension_monitoring);
        assert_eq!(before.rate_limit, s.rate_limit);
        assert_eq!(before.entropy, s.entropy);
        assert_eq!(before.dns, s.dns);
    }
}
