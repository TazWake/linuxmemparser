//! JSON output formatter for the Linux Memory Parser tool
use crate::formats::traits::OutputFormatter;
use crate::kernel::{ProcessInfo, ConnectionInfo, ModuleInfo};
use crate::error::AnalysisError;
use serde_json;

#[derive(serde::Serialize)]
struct OutputWrapper<T> {
    plugin: String,
    timestamp: String,
    count: usize,
    results: Vec<T>,
}

/// JSON formatter that outputs data in JSON format with metadata
pub struct JsonFormatter;

impl OutputFormatter for JsonFormatter {
    fn format_processes(&self, processes: &[ProcessInfo]) -> Result<String, AnalysisError> {
        let wrapper = OutputWrapper {
            plugin: "pslist".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            count: processes.len(),
            results: processes.to_vec(),
        };
        
        let json = serde_json::to_string_pretty(&wrapper)?;
        Ok(json)
    }

    fn format_connections(&self, connections: &[ConnectionInfo]) -> Result<String, AnalysisError> {
        let wrapper = OutputWrapper {
            plugin: "netstat".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            count: connections.len(),
            results: connections.to_vec(),
        };
        
        let json = serde_json::to_string_pretty(&wrapper)?;
        Ok(json)
    }

    fn format_modules(&self, modules: &[ModuleInfo]) -> Result<String, AnalysisError> {
        let wrapper = OutputWrapper {
            plugin: "modules".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            count: modules.len(),
            results: modules.to_vec(),
        };
        
        let json = serde_json::to_string_pretty(&wrapper)?;
        Ok(json)
    }
}