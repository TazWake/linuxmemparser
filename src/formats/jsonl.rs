//! JSONL (JSON Lines) output formatter for the Linux Memory Parser tool
use crate::error::AnalysisError;
use crate::formats::traits::OutputFormatter;
use crate::kernel::{ConnectionInfo, ModuleInfo, ProcessInfo};
use serde_json;

/// JSONL formatter that outputs data as JSON objects, one per line
pub struct JsonlFormatter;

impl OutputFormatter for JsonlFormatter {
    fn format_processes(&self, processes: &[ProcessInfo]) -> Result<String, AnalysisError> {
        let mut output = String::new();

        for proc in processes {
            let line = serde_json::to_string(proc)?;
            output.push_str(&line);
            output.push('\n');
        }

        Ok(output)
    }

    fn format_connections(&self, connections: &[ConnectionInfo]) -> Result<String, AnalysisError> {
        let mut output = String::new();

        for conn in connections {
            let line = serde_json::to_string(conn)?;
            output.push_str(&line);
            output.push('\n');
        }

        Ok(output)
    }

    fn format_modules(&self, modules: &[ModuleInfo]) -> Result<String, AnalysisError> {
        let mut output = String::new();

        for module in modules {
            let line = serde_json::to_string(module)?;
            output.push_str(&line);
            output.push('\n');
        }

        Ok(output)
    }
}
