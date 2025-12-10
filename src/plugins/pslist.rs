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
        // Find init_task using the existing method
        // Pass translator so it can check if symbol addresses are translatable
        let init_task_offset = context.symbol_resolver.find_init_task(
            &context.memory_map.mapped,
            Some(context.translator)
        )
        .ok_or_else(|| AnalysisError::SymbolNotFound("init_task".to_string()))?;

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