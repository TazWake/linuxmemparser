//! PsList plugin - lists running processes
use crate::plugins::plugin_trait::{ForensicPlugin, AnalysisContext, PluginOutput};
use crate::kernel::process_extractor::ProcessExtractor;
use crate::error::AnalysisError;

pub struct PsListPlugin;

impl ForensicPlugin for PsListPlugin {
    fn name(&self) -> &str {
        "pslist"
    }

    fn description(&self) -> &str {
        "List running processes"
    }

    fn run(&self, context: &AnalysisContext) -> Result<PluginOutput, AnalysisError> {
        // Use the init_task_offset from context (already adjusted for KASLR)
        let init_task_offset = context.init_task_offset as u64;

        // Create a process extractor
        let process_extractor = ProcessExtractor::new();

        // Walk the process list starting at the found init_task offset
        let processes = process_extractor.walk_process_list(
            context.memory_map,
            context.translator,
            context.symbol_resolver,
            init_task_offset
        )?;

        Ok(PluginOutput::Processes(processes))
    }
}