//! Plugin manager for the Linux Memory Parser tool
use std::collections::HashMap;

pub mod files;
pub mod modules;
pub mod netstat;
pub mod plugin_trait;
pub mod pslist;
pub mod pstree;

pub use files::FilesPlugin;
pub use modules::ModulesPlugin;
pub use netstat::NetStatPlugin;
pub use pslist::PsListPlugin;
pub use pstree::PsTreePlugin;

// For now, use a simplified plugin manager that doesn't depend on the complex plugin modules
#[allow(dead_code)]
pub struct PluginManager {
    plugins: HashMap<String, String>, // Placeholder
}

#[allow(dead_code)]
impl PluginManager {
    pub fn new() -> Self {
        // For now, just return an empty manager
        Self {
            plugins: HashMap::new(),
        }
    }

    pub fn list_plugins(&self) -> Vec<(&str, &str)> {
        vec![
            ("pslist", "List running processes"),
            ("pstree", "Show process tree visualization"),
            ("netstat", "Extract network connections"),
            ("modules", "List loaded kernel modules"),
            ("files", "List open file handles (not yet implemented)"),
        ]
    }

    pub fn get_plugin_names(&self) -> Vec<String> {
        vec![
            "pslist".to_string(),
            "pstree".to_string(),
            "netstat".to_string(),
            "modules".to_string(),
            "files".to_string(),
        ]
    }
}
