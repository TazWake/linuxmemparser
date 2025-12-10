//! Process extraction module for parsing task_struct and extracting process information
use crate::kernel::ProcessInfo;
use crate::kernel::KernelParser;
use crate::symbols::SymbolResolver;
use crate::memory::MemoryMap;
use crate::translation::MemoryTranslator;
use crate::error::AnalysisError;

/// Process extractor for parsing task_struct and extracting process information
pub struct ProcessExtractor;

impl ProcessExtractor {
    /// Create a new process extractor
    pub fn new() -> Self {
        ProcessExtractor
    }

    /// Extract process information using symbol-based offsets
    pub fn extract_process_info(
        &self,
        memory_map: &MemoryMap,
        translator: &MemoryTranslator,
        symbol_resolver: &SymbolResolver,
        task_struct_offset: u64,
    ) -> Result<ProcessInfo, AnalysisError> {
        let mapped = &memory_map.mapped;

        // For now, we'll try to detect kernel version to use in offset resolution
        // In a real implementation, this would be detected once at the beginning
        let kernel_version = symbol_resolver.detect_kernel_version(mapped);

        // Get offsets from symbol resolver using the kernel version for better accuracy
        let pid_offset = symbol_resolver.get_struct_field_offset("task_struct", "pid", kernel_version.as_ref())
            .unwrap_or(0x328) as usize;  // Use more standard offset as fallback
        let comm_offset = symbol_resolver.get_struct_field_offset("task_struct", "comm", kernel_version.as_ref())
            .unwrap_or(0x4a8) as usize;  // Use more standard offset as fallback
        let comm_size = 16;  // Standard size for comm field
        let parent_offset = symbol_resolver.get_struct_field_offset("task_struct", "parent", kernel_version.as_ref())
            .unwrap_or(0x320) as usize;  // Use more standard offset as fallback
        let start_time_offset = symbol_resolver.get_struct_field_offset("task_struct", "start_time", kernel_version.as_ref())
            .unwrap_or(0x310) as usize;  // Use more standard offset as fallback
        let cred_offset = symbol_resolver.get_struct_field_offset("task_struct", "cred", kernel_version.as_ref())
            .unwrap_or(0x450) as usize;  // Use more standard offset as fallback
        let state_offset = symbol_resolver.get_struct_field_offset("task_struct", "state", kernel_version.as_ref())
            .unwrap_or(0x0) as usize;  // Use standard offset as fallback

        // Read PID
        let pid = KernelParser::read_i32(mapped, (task_struct_offset as usize) + pid_offset)
            .unwrap_or(0);

        // Read process name
        let comm = KernelParser::read_string(
            mapped,
            (task_struct_offset as usize) + comm_offset,
            comm_size,
        ).unwrap_or_else(|| "<unknown>".to_string());

        // Read parent PID by dereferencing the parent pointer
        let parent_ptr = KernelParser::read_u64(mapped, (task_struct_offset as usize) + parent_offset)
            .unwrap_or(0);

        let ppid = if parent_ptr != 0 {
            // Translate the virtual address of the parent task_struct to file offset
            if let Some(parent_file_offset) = translator.virtual_to_file_offset(parent_ptr) {
                // Read the PID from the parent task_struct
                KernelParser::read_i32(mapped, parent_file_offset as usize + pid_offset)
                    .unwrap_or(0)
            } else {
                0  // Default to 0 if translation fails
            }
        } else {
            0  // No parent pointer
        };

        // Read start time
        let start_time = KernelParser::read_u64(mapped, (task_struct_offset as usize) + start_time_offset)
            .unwrap_or(0);

        // Read credential information by dereferencing the cred pointer
        let cred_ptr = KernelParser::read_u64(mapped, (task_struct_offset as usize) + cred_offset)
            .unwrap_or(0);

        let (uid, gid) = if cred_ptr != 0 {
            // Translate the virtual address of the cred structure to file offset
            if let Some(cred_file_offset) = translator.virtual_to_file_offset(cred_ptr) {
                let uid_offset = symbol_resolver.get_struct_field_offset("cred", "uid", kernel_version.as_ref())
                    .unwrap_or(0x0) as usize;
                let gid_offset = symbol_resolver.get_struct_field_offset("cred", "gid", kernel_version.as_ref())
                    .unwrap_or(0x4) as usize;

                let uid = KernelParser::read_u32(mapped, cred_file_offset as usize + uid_offset)
                    .unwrap_or(0);
                let gid = KernelParser::read_u32(mapped, cred_file_offset as usize + gid_offset)
                    .unwrap_or(0);
                (uid, gid)
            } else {
                (0, 0)  // Default to 0 if translation fails
            }
        } else {
            (0, 0)  // No cred pointer
        };

        // Read process state
        let state_val = KernelParser::read_i32(mapped, (task_struct_offset as usize) + state_offset)
            .unwrap_or(0);
        let state = match state_val {
            0 => "Running".to_string(),
            1 => "Sleeping".to_string(),
            2 => "Stopped".to_string(),
            3 => "Zombie".to_string(),
            4 => "Tracing Stop".to_string(),
            _ => format!("Unknown ({})", state_val),
        };

        // Read command line (simplified for demonstration)
        // In a real implementation, this would require more complex parsing
        let cmdline = format!("[cmdline parsing not implemented]");

        Ok(ProcessInfo {
            offset: task_struct_offset,
            pid,
            comm,
            ppid,
            start_time,
            uid,
            gid,
            state,
            cmdline,
        })
    }

    /// Walk the process list starting at init_task with improved reliability
    pub fn walk_process_list(
        &self,
        memory_map: &MemoryMap,
        translator: &MemoryTranslator,
        symbol_resolver: &SymbolResolver,
        init_task_offset: u64,
    ) -> Result<Vec<ProcessInfo>, AnalysisError> {
        let mut processes = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut current_offset = init_task_offset as usize;
        let mapped = &memory_map.mapped;
        let max_iterations = 10000; // Safety limit to prevent infinite loops
        let mut iterations = 0;

        // Detect kernel version once for the entire walk
        let kernel_version = symbol_resolver.detect_kernel_version(mapped);

        // Get the tasks list offset from symbol resolver
        let tasks_offset = symbol_resolver.get_struct_field_offset("task_struct", "tasks", kernel_version.as_ref())
            .unwrap_or(0x0) as usize;  // List head offset within task_struct

        loop {
            // Safety checks
            if iterations >= max_iterations {
                eprintln!("Warning: Maximum iterations reached while walking process list");
                break;
            }

            if current_offset >= mapped.len() {
                eprintln!("Warning: Current offset exceeds memory map size");
                break;
            }

            if visited.contains(&current_offset) {
                // Reached the beginning of the circular list.
                break;
            }

            visited.insert(current_offset);
            iterations += 1;

            // Extract process information
            match self.extract_process_info(memory_map, translator, symbol_resolver, current_offset as u64) {
                Ok(process_info) => {
                    // Validate the process information before adding to results
                    if crate::kernel::validate_process_info(&process_info) {
                        processes.push(process_info);
                    } else {
                        eprintln!("Warning: Process validation failed for PID {}, skipping", process_info.pid);
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Failed to extract process info at offset 0x{:x}: {}", current_offset, e);
                    // Continue with the next process rather than breaking
                }
            }

            // Follow the "next" pointer in the tasks list.
            // The tasks field is a list_head structure, so we need to read the next pointer
            // The list_head structure contains: next (first field) and prev (second field)
            // So the next pointer is at the same offset as the tasks field
            let next_ptr = match KernelParser::read_u64(mapped, current_offset + tasks_offset) {
                Some(n) => n,
                None => {
                    eprintln!("Warning: Failed to read next pointer at offset 0x{:x}", current_offset + tasks_offset);
                    break;
                }
            };

            // Validate the next pointer
            if next_ptr == 0 {
                // Null pointer indicates end of list
                break;
            }

            // Convert virtual address to file offset using the translator
            let next_offset = match translator.virtual_to_file_offset(next_ptr) {
                Some(file_offset) => file_offset as usize,
                None => {
                    eprintln!("Warning: Failed to translate virtual address 0x{:x} to file offset", next_ptr);
                    break;
                }
            };

            // Check if we've reached the init_task again (circular list)
            if next_offset == init_task_offset as usize {
                break;
            }

            // Additional safety check for reasonable pointer values
            if next_offset >= mapped.len() {
                eprintln!("Warning: Next pointer 0x{:x} translates to offset beyond memory map", next_ptr);
                break;
            }

            current_offset = next_offset;
        }

        Ok(processes)
    }
}