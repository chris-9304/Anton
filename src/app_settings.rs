/// Runtime security settings from the Settings UI.
/// Shared between the UI thread and the watcher/engine via Arc<Mutex<>>.
#[derive(Debug, Clone)]
pub struct AppSettings {
    pub extension_monitoring: bool,
    pub rate_limit: bool,
    pub entropy: bool,
    pub dns: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            extension_monitoring: true,
            rate_limit: true,
            entropy: true,
            dns: true,
        }
    }
}

impl AppSettings {
    pub fn set_from_name(&mut self, name: &str, value: bool) {
        match name {
            "extension" => self.extension_monitoring = value,
            "rate_limit" => self.rate_limit = value,
            "entropy" => self.entropy = value,
            "dns" => self.dns = value,
            _ => {}
        }
    }
}
