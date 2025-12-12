//! PsTree plugin - shows process tree visualization
use crate::error::AnalysisError;
use crate::kernel::process_extractor::ProcessExtractor;
use crate::kernel::ProcessInfo;
use crate::plugins::plugin_trait::{AnalysisContext, ForensicPlugin, PluginOutput};
use std::collections::HashMap;

pub struct PsTreePlugin;

// Simple tree structure to hold parent-child relationships
pub struct ProcessTree {
    process_map: HashMap<i32, ProcessInfo>,
    parent_map: HashMap<i32, Vec<i32>>, // parent PID -> list of child PIDs
    roots: Vec<i32>,                    // PID of root processes (no parents)
}

impl ProcessTree {
    pub fn new() -> Self {
        Self {
            process_map: HashMap::new(),
            parent_map: HashMap::new(),
            roots: Vec::new(),
        }
    }

    pub fn build_from_processes(processes: Vec<ProcessInfo>) -> Self {
        let mut tree = ProcessTree::new();

        // Index processes by PID
        for proc in processes {
            tree.process_map.insert(proc.pid, proc);
        }

        // Build parent-child relationships
        for proc in tree.process_map.values() {
            let parent_pid = proc.ppid;

            if tree.process_map.contains_key(&parent_pid) {
                // This process has a parent that's in our list
                tree.parent_map
                    .entry(parent_pid)
                    .or_insert_with(Vec::new)
                    .push(proc.pid);
            } else {
                // This process doesn't have a parent in our list, so it's a root
                tree.roots.push(proc.pid);
            }
        }

        tree
    }

    pub fn to_string(&self) -> String {
        let mut result = String::new();

        for &root_pid in &self.roots {
            self.add_process_to_string(root_pid, 0, &mut result);
        }

        result
    }

    fn add_process_to_string(&self, pid: i32, depth: usize, result: &mut String) {
        if let Some(proc) = self.process_map.get(&pid) {
            let indent = "  ".repeat(depth);
            result.push_str(&format!(
                "{}{} (PID: {}, PPID: {})\n",
                indent, proc.comm, proc.pid, proc.ppid
            ));

            // Add children
            if let Some(children) = self.parent_map.get(&pid) {
                for &child_pid in children {
                    self.add_process_to_string(child_pid, depth + 1, result);
                }
            }
        }
    }
}

impl ForensicPlugin for PsTreePlugin {
    fn name(&self) -> &str {
        "pstree"
    }

    fn description(&self) -> &str {
        "Show process tree visualization"
    }

    fn run(&self, context: &AnalysisContext) -> Result<PluginOutput, AnalysisError> {
        // Use the init_task_offset from context (already adjusted for KASLR)
        let init_task_offset = context.init_task_offset as u64;

        let process_extractor = ProcessExtractor::new();
        let processes = process_extractor.walk_process_list(
            context.memory_map,
            context.translator,
            context.symbol_resolver,
            init_task_offset,
        )?;

        // Build the process tree
        let tree = ProcessTree::build_from_processes(processes);
        let tree_str = tree.to_string();

        Ok(PluginOutput::Tree(tree_str))
    }
}
