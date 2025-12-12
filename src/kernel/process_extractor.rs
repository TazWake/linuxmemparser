//! Process extraction module for parsing task_struct and extracting process information
use crate::error::AnalysisError;
use crate::kernel::KernelParser;
use crate::kernel::ProcessInfo;
use crate::memory::MemoryMap;
use crate::symbols::SymbolResolver;
use crate::translation::MemoryTranslator;

// Macro for conditional debug output
macro_rules! debug {
    ($($arg:tt)*) => {
        if std::env::var("LINMEMPARSER_DEBUG").is_ok() {
            eprintln!($($arg)*);
        }
    };
}

// Macro for conditional warning output
macro_rules! warn {
    ($($arg:tt)*) => {
        if std::env::var("LINMEMPARSER_VERBOSE").is_ok() {
            eprintln!($($arg)*);
        }
    };
}

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
        let pid_offset = symbol_resolver
            .get_struct_field_offset("task_struct", "pid", kernel_version.as_ref())
            .unwrap_or(0x328) as usize; // Use more standard offset as fallback
        debug!("[DEBUG] extract_process_info: using pid_offset=0x{:x}, reading from file_offset=0x{:x}",
                  pid_offset, (task_struct_offset as usize) + pid_offset);
        let comm_offset = symbol_resolver
            .get_struct_field_offset("task_struct", "comm", kernel_version.as_ref())
            .unwrap_or(0x4a8) as usize; // Use more standard offset as fallback
        let comm_size = 16; // Standard size for comm field
        let parent_offset = symbol_resolver
            .get_struct_field_offset("task_struct", "parent", kernel_version.as_ref())
            .unwrap_or(0x320) as usize; // Use more standard offset as fallback
        let start_time_offset = symbol_resolver
            .get_struct_field_offset("task_struct", "start_time", kernel_version.as_ref())
            .unwrap_or(0x310) as usize; // Use more standard offset as fallback
        let cred_offset = symbol_resolver
            .get_struct_field_offset("task_struct", "cred", kernel_version.as_ref())
            .unwrap_or(0x450) as usize; // Use more standard offset as fallback
        let state_offset = symbol_resolver
            .get_struct_field_offset("task_struct", "state", kernel_version.as_ref())
            .unwrap_or(0x0) as usize; // Use standard offset as fallback

        // Read PID
        let pid =
            KernelParser::read_i32(mapped, (task_struct_offset as usize) + pid_offset).unwrap_or(0);

        // Read process name
        let comm = KernelParser::read_string(
            mapped,
            (task_struct_offset as usize) + comm_offset,
            comm_size,
        )
        .unwrap_or_else(|| "<unknown>".to_string());

        // Read parent PID by dereferencing the parent pointer
        let parent_ptr =
            KernelParser::read_u64(mapped, (task_struct_offset as usize) + parent_offset)
                .unwrap_or(0);

        let ppid = if parent_ptr != 0 {
            // Translate the virtual address of the parent task_struct to file offset
            if let Some(parent_file_offset) = translator.virtual_to_file_offset(parent_ptr) {
                // Read the PID from the parent task_struct
                KernelParser::read_i32(mapped, parent_file_offset as usize + pid_offset)
                    .unwrap_or(0)
            } else {
                0 // Default to 0 if translation fails
            }
        } else {
            0 // No parent pointer
        };

        // Read start time
        let start_time =
            KernelParser::read_u64(mapped, (task_struct_offset as usize) + start_time_offset)
                .unwrap_or(0);

        // Read credential information by dereferencing the cred pointer
        let cred_ptr = KernelParser::read_u64(mapped, (task_struct_offset as usize) + cred_offset)
            .unwrap_or(0);

        let (uid, gid) = if cred_ptr != 0 {
            // Translate the virtual address of the cred structure to file offset
            if let Some(cred_file_offset) = translator.virtual_to_file_offset(cred_ptr) {
                let uid_offset = symbol_resolver
                    .get_struct_field_offset("cred", "uid", kernel_version.as_ref())
                    .unwrap_or(0x0) as usize;
                let gid_offset = symbol_resolver
                    .get_struct_field_offset("cred", "gid", kernel_version.as_ref())
                    .unwrap_or(0x4) as usize;

                let uid = KernelParser::read_u32(mapped, cred_file_offset as usize + uid_offset)
                    .unwrap_or(0);
                let gid = KernelParser::read_u32(mapped, cred_file_offset as usize + gid_offset)
                    .unwrap_or(0);
                (uid, gid)
            } else {
                (0, 0) // Default to 0 if translation fails
            }
        } else {
            (0, 0) // No cred pointer
        };

        // Read process state
        let state_val =
            KernelParser::read_i32(mapped, (task_struct_offset as usize) + state_offset)
                .unwrap_or(0);
        let state = match state_val {
            0 => "Running".to_string(),
            1 => "Sleeping".to_string(),
            2 => "Stopped".to_string(),
            3 => "Zombie".to_string(),
            4 => "Tracing Stop".to_string(),
            _ => format!("Unknown ({})", state_val),
        };

        // Read command line by extracting from mm_struct
        let mm_offset = symbol_resolver
            .get_struct_field_offset("task_struct", "mm", kernel_version.as_ref())
            .unwrap_or(0x350) as usize;
        let mm_ptr =
            KernelParser::read_u64(mapped, (task_struct_offset as usize) + mm_offset).unwrap_or(0);

        debug!(
            "[DEBUG] PID {}: mm_offset=0x{:x}, mm_ptr=0x{:x}",
            pid, mm_offset, mm_ptr
        );

        let cmdline = if mm_ptr != 0 {
            // Translate mm_struct pointer to file offset
            if let Some(mm_file_offset) = translator.virtual_to_file_offset(mm_ptr) {
                debug!("[DEBUG] PID {}: mm_file_offset=0x{:x}", pid, mm_file_offset);

                // Get arg_start and arg_end offsets in mm_struct
                let arg_start_offset = symbol_resolver
                    .get_struct_field_offset("mm_struct", "arg_start", kernel_version.as_ref())
                    .unwrap_or(0x108) as usize;
                let arg_end_offset = symbol_resolver
                    .get_struct_field_offset("mm_struct", "arg_end", kernel_version.as_ref())
                    .unwrap_or(0x110) as usize;

                debug!(
                    "[DEBUG] PID {}: arg_start_offset=0x{:x}, arg_end_offset=0x{:x}",
                    pid, arg_start_offset, arg_end_offset
                );

                // Read arg_start and arg_end pointers
                let arg_start =
                    KernelParser::read_u64(mapped, mm_file_offset as usize + arg_start_offset)
                        .unwrap_or(0);
                let arg_end =
                    KernelParser::read_u64(mapped, mm_file_offset as usize + arg_end_offset)
                        .unwrap_or(0);

                debug!(
                    "[DEBUG] PID {}: arg_start=0x{:x}, arg_end=0x{:x}, len={}",
                    pid,
                    arg_start,
                    arg_end,
                    arg_end.saturating_sub(arg_start)
                );

                if arg_start != 0 && arg_end > arg_start {
                    let arg_len = (arg_end - arg_start) as usize;
                    // Sanity check - command lines shouldn't be too large
                    if arg_len > 0 && arg_len <= 4096 {
                        // Try to translate arg_start to file offset
                        // This works if the arguments are in captured memory
                        if let Some(args_file_offset) = translator.virtual_to_file_offset(arg_start)
                        {
                            debug!(
                                "[DEBUG] PID {}: args_file_offset=0x{:x}, reading {} bytes",
                                pid, args_file_offset, arg_len
                            );
                            // Read the argument buffer
                            let mut cmdline_bytes = Vec::new();
                            for i in 0..arg_len {
                                let offset = (args_file_offset as usize) + i;
                                if offset >= mapped.len() {
                                    break;
                                }
                                let byte = mapped[offset];
                                if byte == 0 {
                                    cmdline_bytes.push(b' '); // Replace NULL with space
                                } else {
                                    cmdline_bytes.push(byte);
                                }
                            }

                            // Convert to string and trim
                            String::from_utf8(cmdline_bytes)
                                .ok()
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .unwrap_or_else(|| "[cmdline not available]".to_string())
                        } else {
                            debug!(
                                "[DEBUG] PID {}: Failed to translate arg_start to file offset",
                                pid
                            );
                            "[cmdline not in memory]".to_string()
                        }
                    } else {
                        debug!("[DEBUG] PID {}: Invalid cmdline length: {}", pid, arg_len);
                        "[invalid cmdline length]".to_string()
                    }
                } else {
                    debug!("[DEBUG] PID {}: arg_start=0 or arg_end<=arg_start", pid);
                    "[no cmdline]".to_string()
                }
            } else {
                debug!(
                    "[DEBUG] PID {}: Failed to translate mm_ptr to file offset",
                    pid
                );
                "[mm_struct not in memory]".to_string()
            }
        } else {
            debug!("[DEBUG] PID {}: mm_ptr is NULL (kernel thread)", pid);
            "[kernel thread]".to_string()
        };

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
        let tasks_offset = symbol_resolver
            .get_struct_field_offset("task_struct", "tasks", kernel_version.as_ref())
            .unwrap_or(0x0) as usize; // List head offset within task_struct

        // Debug output to show what offset is being used
        debug!(
            "[DEBUG] Using tasks_offset: 0x{:x} ({} bytes)",
            tasks_offset, tasks_offset
        );
        if tasks_offset == 0 {
            warn!("[WARNING] tasks_offset is 0! This is likely incorrect and will cause process walking to fail.");
            warn!("[WARNING] The dwarf2json file may not contain the 'tasks' field offset.");
        }

        // Debug: Dump first 64 bytes of init_task to verify it looks reasonable
        debug!(
            "[DEBUG] First 64 bytes of init_task at offset 0x{:x}:",
            init_task_offset
        );
        if (init_task_offset as usize) + 64 <= mapped.len() {
            if std::env::var("LINMEMPARSER_DEBUG").is_ok() {
                for chunk in 0..4 {
                    let offset = init_task_offset as usize + (chunk * 16);
                    eprint!("[DEBUG]   0x{:04x}: ", chunk * 16);
                    for i in 0..16 {
                        eprint!("{:02x} ", mapped[offset + i]);
                    }
                    eprintln!();
                }
            }
        }

        loop {
            // Safety checks
            if iterations >= max_iterations {
                warn!("[WARNING] Maximum iterations reached while walking process list");
                break;
            }

            if current_offset >= mapped.len() {
                warn!("[WARNING] Current offset exceeds memory map size");
                break;
            }

            if visited.contains(&current_offset) {
                // Reached the beginning of the circular list.
                break;
            }

            visited.insert(current_offset);
            iterations += 1;

            // Extract process information
            match self.extract_process_info(
                memory_map,
                translator,
                symbol_resolver,
                current_offset as u64,
            ) {
                Ok(process_info) => {
                    // Validate the process information before adding to results
                    if crate::kernel::validate_process_info(&process_info) {
                        processes.push(process_info);
                    } else {
                        warn!(
                            "[WARNING] Process validation failed for PID {}, skipping",
                            process_info.pid
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "[WARNING] Failed to extract process info at offset 0x{:x}: {}",
                        current_offset, e
                    );
                    // Continue with the next process rather than breaking
                }
            }

            // Follow the "next" pointer in the tasks list.
            // The tasks field is a list_head structure, so we need to read the next pointer
            // The list_head structure contains: next (first field) and prev (second field)
            // So the next pointer is at the same offset as the tasks field
            let next_ptr = match KernelParser::read_u64(mapped, current_offset + tasks_offset) {
                Some(n) => {
                    debug!("[DEBUG] Read next_ptr: 0x{:x} from file_offset 0x{:x} (current=0x{:x} + tasks_offset=0x{:x})",
                              n, current_offset + tasks_offset, current_offset, tasks_offset);
                    n
                }
                None => {
                    warn!(
                        "[WARNING] Failed to read next pointer at offset 0x{:x}",
                        current_offset + tasks_offset
                    );
                    break;
                }
            };

            // Validate the next pointer
            if next_ptr == 0 {
                // Null pointer indicates end of list (this shouldn't happen in a circular list!)
                warn!("[WARNING] Found NULL next pointer at file_offset 0x{:x} - this shouldn't happen in a circular list!", current_offset + tasks_offset);
                warn!("[WARNING] This likely means:");
                warn!(
                    "[WARNING]   1. The tasks_offset (0x{:x}) is incorrect",
                    tasks_offset
                );
                warn!("[WARNING]   2. The memory region is corrupted");
                warn!("[WARNING]   3. The init_task location is wrong");

                // Try reading a few more bytes to see what's there
                if current_offset + tasks_offset + 32 <= mapped.len() {
                    if std::env::var("LINMEMPARSER_DEBUG").is_ok() {
                        eprint!(
                            "[DEBUG] Memory dump at offset 0x{:x}: ",
                            current_offset + tasks_offset
                        );
                        for i in 0..32 {
                            eprint!("{:02x} ", mapped[current_offset + tasks_offset + i]);
                        }
                        eprintln!();
                    }
                }
                break;
            }

            // Convert virtual address to file offset using the translator
            let next_list_head_offset = match translator.virtual_to_file_offset(next_ptr) {
                Some(file_offset) => file_offset as usize,
                None => {
                    warn!(
                        "[WARNING] Failed to translate virtual address 0x{:x} to file offset",
                        next_ptr
                    );
                    break;
                }
            };

            // CRITICAL: The next_ptr points to the list_head structure embedded in the next task_struct
            // We need to subtract tasks_offset to get back to the start of the task_struct
            // This is the container_of() pattern used in Linux kernel
            let next_offset = next_list_head_offset.saturating_sub(tasks_offset);

            debug!("[DEBUG] next_list_head_offset=0x{:x}, tasks_offset=0x{:x}, next_task_struct_offset=0x{:x}",
                     next_list_head_offset, tasks_offset, next_offset);

            // Check if we've reached the init_task again (circular list)
            if next_offset == init_task_offset as usize {
                debug!("[DEBUG] Completed circular list - back at init_task");
                break;
            }

            // Additional safety check for reasonable pointer values
            if next_offset >= mapped.len() {
                warn!(
                    "[WARNING] Next task_struct offset 0x{:x} beyond memory map",
                    next_offset
                );
                break;
            }

            current_offset = next_offset;
        }

        Ok(processes)
    }
}
