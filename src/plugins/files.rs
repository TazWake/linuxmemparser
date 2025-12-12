//! Files plugin - extracts open file handles (stub implementation)
use crate::error::AnalysisError;
use crate::plugins::plugin_trait::{AnalysisContext, ForensicPlugin, PluginOutput};

pub struct FilesPlugin;

impl ForensicPlugin for FilesPlugin {
    fn name(&self) -> &str {
        "files"
    }

    fn description(&self) -> &str {
        "List open file handles (not yet implemented)"
    }

    fn run(&self, _context: &AnalysisContext) -> Result<PluginOutput, AnalysisError> {
        Err(AnalysisError::PluginError(
            "Files plugin not yet implemented".to_string(),
        ))
    }
}
