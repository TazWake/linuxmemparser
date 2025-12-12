//! Main entry point for the Linux Memory Parser tool
use clap::Parser;

mod memory;
mod symbols;
mod translation;
mod kernel;
mod error;
mod cli;
mod core;
mod plugins;
mod formats;

use memory::MemoryMap;
use symbols::SymbolResolver;
use translation::MemoryTranslator;
use error::AnalysisError;
use cli::args::{Cli, PluginCommand, OutputFormatArg};
use formats::traits::{OutputFormat, OutputDestination, OutputWriter};
use plugins::plugin_trait::{ForensicPlugin, AnalysisContext, PluginOutput};
use plugins::{PsListPlugin, PsTreePlugin, NetStatPlugin, ModulesPlugin, FilesPlugin};

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

fn main() -> Result<(), AnalysisError> {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Set environment variables for debug/verbose output
    if cli.debug {
        std::env::set_var("LINMEMPARSER_DEBUG", "1");
    }
    if cli.verbose || cli.debug {  // Debug implies verbose
        std::env::set_var("LINMEMPARSER_VERBOSE", "1");
    }

    // Handle --list-plugins
    if cli.list_plugins {
        println!("Available plugins:");
        println!("  pslist - List running processes");
        println!("  pstree - Show process tree visualization");
        println!("  netstat - Extract network connections");
        println!("  modules - List loaded kernel modules");
        println!("  files - List open file handles (not yet implemented)");
        return Ok(());
    }

    let open_msg = format!("Opening memory capture file: {}", cli.memory_dump.display());
    println!("{}", open_msg);

    // Open and memory-map the file.
    let memory_map = MemoryMap::new(&cli.memory_dump.to_string_lossy())?;
    let mapped = &memory_map.mapped;

    // --- Parse the LIME header (if present) and create translator --- //
    let regions = if memory_map.is_lime() {
        let header_msg = "LIME header detected. Parsing memory region information:";
        println!("{}", header_msg);
        if let Some(regs) = memory_map.parse_lime_header() {
            for (i, region) in regs.iter().enumerate() {
                let msg = format!(
                    "Region {}: Start: 0x{:x}, End: 0x{:x}, FileOffset: {}",
                    i, region.start, region.end, region.file_offset
                );
                println!("{}", msg);
            }

            // For now, we'll just print the regions to show the translator works
            println!("Memory translator will be initialized with {} regions", regs.len());
            Some(regs)
        } else {
            let msg = "LIME header detected, but no memory regions were found.";
            println!("{}", msg);
            None
        }
    } else {
        let msg = "No LIME header found; assuming raw memory capture.";
        println!("{}", msg);
        None
    };

    // Create memory translator with the parsed regions
    let mut translator = if let Some(regs) = regions {
        MemoryTranslator::new(regs)
    } else {
        // For raw dumps without LIME headers, we create a single region that maps everything
        // This is a fallback for testing with raw memory dumps
        use crate::memory::MemoryRegion;
        MemoryTranslator::new(vec![MemoryRegion {
            start: 0,
            end: mapped.len() as u64,
            file_offset: 0,
        }])
    };

    // --- Load symbols if provided --- //
    let mut symbol_resolver = SymbolResolver::new();
    if let Some(symbol_path) = &cli.symbols {
        let path_str = symbol_path.to_string_lossy();
        println!("Loading symbols from: {}", path_str);

        // Try to load as different formats
        if path_str.ends_with(".json") {
            // Try dwarf2json format first
            match symbol_resolver.load_dwarf2json(&path_str) {
                Ok(_) => {
                    println!("Successfully loaded symbols and structure offsets from dwarf2json file");
                },
                Err(e) => {
                    eprintln!("Failed to load as dwarf2json: {}", e);
                    eprintln!("Trying as System.map format...");
                    // Try as System.map format
                    symbol_resolver.load_system_map(&path_str)
                        .map_err(|_| AnalysisError::SymbolError("Failed to load symbols".to_string()))?;
                    println!("Successfully loaded symbols from System.map format");
                }
            }
        } else if path_str.contains("kallsyms") {
            // Try kallsyms format (handles 0 addresses differently)
            symbol_resolver.load_kallsyms(&path_str)
                .map_err(|_| AnalysisError::SymbolError("Failed to load kallsyms".to_string()))?;
            println!("Successfully loaded symbols from kallsyms format");
        } else {
            // Assume System.map format
            symbol_resolver.load_system_map(&path_str)
                .map_err(|_| AnalysisError::SymbolError("Failed to load symbols".to_string()))?;
            println!("Successfully loaded symbols from System.map format");
        }
    } else {
        // Try to locate symbols via heuristic search
        if let Some(marker_offset) = SymbolResolver::detect_symbol_table(mapped) {
            let marker_msg = format!("Kernel symbol table marker found at offset: 0x{:x}", marker_offset);
            println!("{}", marker_msg);
            println!("Symbol resolver initialized with {} symbols", symbol_resolver.symbol_count());
        } else {
            println!("Kernel symbol table marker not detected, continuing with heuristic search...");
        }
    }

    // Detect kernel version if possible
    let detected_version = symbol_resolver.detect_kernel_version(mapped);
    if let Some(version) = &detected_version {
        println!("Detected kernel version in memory dump: {}", version);

        // Warn if System.map might not match
        if cli.symbols.is_some() {
            println!("Note: Verify that System.map matches kernel version {}.{}",
                     version.major, version.minor);
            println!("      Mismatched versions can cause incorrect structure offsets.");
        }
    } else {
        println!("Warning: Could not detect kernel version from memory dump.");
        if cli.symbols.is_some() {
            println!("      Ensure System.map matches the kernel version in the memory dump.");
        }
    }

    // STEP 1: Detect KASLR offset and find init_task (with temp phys_base)
    // This uses heuristic search if needed and finds the CORRECT init_task location
    debug!("[DEBUG] Detecting KASLR offset to find actual init_task location...");
    let (_kaslr_offset, init_task_offset) = symbol_resolver.detect_kaslr_offset(mapped, &translator)
        .ok_or_else(|| AnalysisError::SymbolNotFound(
            "Could not detect KASLR offset - init_task with PID 0 not found. \
             This may indicate KASLR is enabled and the symbol addresses don't match the runtime kernel.".to_string()
        ))?;

    println!("Found init_task at file offset: 0x{:x}", init_task_offset);

    // STEP 2: Now recalculate phys_base using the CORRECT init_task location
    // This is critical - we need phys_base to translate virtual addresses in the process list
    let phys_base_candidates = symbol_resolver.calculate_phys_base_candidates();

    if phys_base_candidates.is_empty() {
        println!("Warning: Could not calculate phys_base candidates from _text symbol");
        println!("Using default phys_base: 0x{:x}", translator.get_phys_base());
        println!("This may cause incorrect address translation - ensure symbol file contains _text");
    } else {
        println!("\nRecalculating phys_base using found init_task location...");
        println!("Testing {} phys_base candidate(s)...", phys_base_candidates.len());

        let mut found_valid_phys_base = false;

        // Get the virtual address of init_task from symbols (if available)
        if let Some(init_task_vaddr) = symbol_resolver.get_symbol_address("init_task") {
            // Get PID offset from structure definitions
            let pid_offset = symbol_resolver.get_struct_field_offset("task_struct", "pid", None)
                .unwrap_or(2384); // Fallback to common offset if not in symbols

            debug!("[DEBUG] Validating phys_base candidates:");
            debug!("[DEBUG]   init_task vaddr from symbols: 0x{:x}", init_task_vaddr);
            debug!("[DEBUG]   init_task file offset found: 0x{:x}", init_task_offset);
            debug!("[DEBUG]   PID offset in task_struct: 0x{:x}", pid_offset);

            // Validate each candidate by checking if it correctly translates init_task vaddr to the found file offset
            for (i, &candidate) in phys_base_candidates.iter().enumerate() {
                translator.set_phys_base(candidate);

                // Try to translate init_task virtual address with this phys_base
                if let Some(translated_offset) = translator.virtual_to_file_offset(init_task_vaddr) {
                    debug!("[DEBUG]   Candidate {}: phys_base=0x{:x} translates to file_offset=0x{:x}",
                             i + 1, candidate, translated_offset);

                    // Check if this translation matches the init_task offset we found via heuristic search
                    // Allow a small tolerance for structure alignment
                    let offset_diff = if translated_offset > init_task_offset as u64 {
                        translated_offset - init_task_offset as u64
                    } else {
                        init_task_offset as u64 - translated_offset
                    };

                    if offset_diff < 0x1000 { // Within 4KB tolerance
                        // Verify by reading PID at the found location
                        let pid_file_offset = init_task_offset + pid_offset as usize;
                        if pid_file_offset + 4 <= mapped.len() {
                            let pid_bytes = &mapped[pid_file_offset..pid_file_offset + 4];
                            let pid = i32::from_le_bytes([pid_bytes[0], pid_bytes[1], pid_bytes[2], pid_bytes[3]]);

                            debug!("[DEBUG]     Translation matches found init_task (offset_diff=0x{:x}), PID={}",
                                     offset_diff, pid);

                            if pid == 0 {
                                println!("✓ Found valid phys_base: 0x{:x} (translates correctly to found init_task with PID 0)", candidate);
                                found_valid_phys_base = true;
                                break;
                            }
                        }
                    } else {
                        debug!("[DEBUG]     Translation doesn't match (offset_diff=0x{:x})", offset_diff);
                    }
                } else {
                    debug!("[DEBUG]   Candidate {}: phys_base=0x{:x} - translation failed", i + 1, candidate);
                }
            }

            if !found_valid_phys_base {
                println!("Warning: None of the phys_base candidates correctly translate init_task");
                println!("This likely means:");
                println!("  1. The memory regions in LIME header may be incomplete");
                println!("  2. The _text symbol address may be incorrect");
                println!("Attempting to calculate phys_base directly from found init_task...");

                // Try to calculate phys_base directly from the found init_task location
                // We know: file_offset = (vaddr - region.start) + region.file_offset
                // Rearranging: region.start = vaddr - (file_offset - region.file_offset)
                // For kernel: phys_base ≈ region.start (for main kernel region)

                // Find which region contains our init_task file offset
                for region in translator.get_regions() {
                    if init_task_offset >= region.file_offset as usize &&
                       init_task_offset < (region.file_offset + (region.end - region.start)) as usize {
                        // Calculate the physical address of init_task from the file offset
                        let offset_in_region = init_task_offset as u64 - region.file_offset;
                        let physical_addr = region.start + offset_in_region;

                        debug!("[DEBUG] Found init_task in region: start=0x{:x}, end=0x{:x}",
                                 region.start, region.end);
                        debug!("[DEBUG]   File offset in region: 0x{:x}", offset_in_region);
                        debug!("[DEBUG]   Physical address of init_task: 0x{:x}", physical_addr);
                        debug!("[DEBUG]   Virtual address from symbols: 0x{:x}", init_task_vaddr);

                        // Calculate phys_base using the kernel mapping formula:
                        // For kernel text (0xffffffff80000000+): physical = phys_base + (virtual - 0xffffffff80000000)
                        // Rearranging: phys_base = physical - (virtual - 0xffffffff80000000)
                        const KERNEL_MAP_BASE: u64 = 0xffffffff80000000;
                        let calculated_phys_base = physical_addr.wrapping_sub(init_task_vaddr - KERNEL_MAP_BASE);

                        debug!("[DEBUG]   Calculated phys_base: 0x{:x}", calculated_phys_base);
                        translator.set_phys_base(calculated_phys_base);

                        println!("✓ Calculated phys_base from memory region: 0x{:x}", calculated_phys_base);
                        found_valid_phys_base = true;
                        break;
                    }
                }

                if !found_valid_phys_base {
                    println!("Warning: Could not calculate phys_base from init_task location");
                    println!("Using first candidate: 0x{:x}", phys_base_candidates[0]);
                    translator.set_phys_base(phys_base_candidates[0]);
                }
            }
        } else {
            println!("Warning: init_task symbol not found, cannot validate phys_base");
            println!("Using first candidate: 0x{:x}", phys_base_candidates[0]);
            translator.set_phys_base(phys_base_candidates[0]);
        }
    }

    // STEP 3: Detect and validate PAGE_OFFSET for direct mapping translations
    debug!("[DEBUG] Detecting PAGE_OFFSET using candidate validation approach...");

    // Get structure field offsets
    let tasks_offset = symbol_resolver.get_struct_field_offset("task_struct", "tasks", None)
        .unwrap_or(0xa00) as usize;
    let pid_offset = symbol_resolver.get_struct_field_offset("task_struct", "pid", None)
        .unwrap_or(0xad0) as usize;
    let comm_offset = symbol_resolver.get_struct_field_offset("task_struct", "comm", None)
        .unwrap_or(0xcf0) as usize;
    let state_offset = symbol_resolver.get_struct_field_offset("task_struct", "__state", None)
        .or_else(|| symbol_resolver.get_struct_field_offset("task_struct", "state", None))
        .unwrap_or(0x18) as usize;

    // Read tasks.next pointer from init_task
    let tasks_next_ptr = kernel::KernelParser::read_u64(
        mapped,
        init_task_offset + tasks_offset
    ).ok_or_else(|| AnalysisError::ParseError("Failed to read tasks.next from init_task".to_string()))?;

    debug!("[DEBUG] tasks.next from init_task: 0x{:x}", tasks_next_ptr);

    // Check if tasks.next is in direct mapping range
    if tasks_next_ptr >= 0xffff000000000000 && tasks_next_ptr < 0xffffffff00000000 {
        debug!("[DEBUG] tasks.next is in direct mapping range");

        // Helper function to generate PAGE_OFFSET candidates
        let generate_page_offset_candidates = || -> Vec<u64> {
            let mut candidates = Vec::new();

            // Standard values (try these first)
            candidates.push(0xffff880000000000); // 4-level standard
            candidates.push(0xffff888000000000); // 5-level standard

            // KASLR variations in 1GB increments
            let start = 0xffff800000000000u64;
            let end = 0xffffb00000000000u64;
            let step = 0x40000000u64; // 1GB

            let mut addr = start;
            while addr <= end {
                if !candidates.contains(&addr) {
                    candidates.push(addr);
                }
                addr = addr.saturating_add(step);
            }

            candidates
        };

        // Helper function to translate physical address to file offset
        let phys_to_file_offset = |phys_addr: u64| -> Option<usize> {
            for region in translator.get_regions() {
                if phys_addr >= region.start && phys_addr < region.end {
                    let offset_in_region = phys_addr - region.start;
                    return Some((region.file_offset + offset_in_region) as usize);
                }
            }
            None
        };

        // Helper function to validate task_struct at given offset
        let validate_next_task_candidate = |file_offset: usize| -> Option<(u32, String)> {
            // Boundary check
            if file_offset + comm_offset + 16 > mapped.len() {
                return None;
            }

            let mut score = 0u32;

            // 1. Validate PID
            let pid = kernel::KernelParser::read_i32(mapped, file_offset + pid_offset)?;
            if pid <= 0 || pid >= 1000000 {
                return None;
            }
            score += 20;

            // 2. Validate comm
            let comm = kernel::KernelParser::read_string(mapped, file_offset + comm_offset, 16)
                .unwrap_or_default();
            if comm.len() < 2 {
                return None;
            }
            let has_alpha = comm.chars().any(|c| c.is_alphanumeric());
            if !has_alpha {
                return None;
            }
            if !comm.chars().all(|c| c.is_ascii_graphic() || c.is_whitespace()) {
                return None;
            }
            score += comm.len() as u32 * 10;
            score += comm.chars().filter(|c| c.is_alphanumeric()).count() as u32 * 5;

            // 3. Validate state
            let state = kernel::KernelParser::read_i32(mapped, file_offset + state_offset)?;
            if state < -1 || state > 1024 {
                return None;
            }
            score += 30;

            // 4. Validate tasks.next pointer
            let tasks_next = kernel::KernelParser::read_u64(mapped, file_offset + tasks_offset)?;
            if tasks_next < 0xffff800000000000 || tasks_next >= 0xffffffffffffffff {
                return None;
            }
            score += 20;

            // Bonus: Check for known good process names
            if comm.starts_with("systemd") || comm.starts_with("kthreadd") {
                score += 100;
            }

            Some((score, comm))
        };

        // Generate PAGE_OFFSET candidates
        let candidates = generate_page_offset_candidates();
        let candidates_count = candidates.len();
        debug!("[DEBUG] Testing {} PAGE_OFFSET candidates...", candidates_count);

        struct ValidCandidate {
            page_offset: u64,
            #[allow(dead_code)]  // Reserved for future use
            file_offset: usize,
            score: u32,
            comm: String,
            is_4level: bool,
        }

        let mut valid_candidates: Vec<ValidCandidate> = Vec::new();
        let mut rejections_logged = 0;

        // Test each PAGE_OFFSET candidate
        for candidate_page_offset in candidates {
            // Calculate expected physical address of next task
            let next_task_phys = tasks_next_ptr.wrapping_sub(candidate_page_offset);

            // Check if physical address is within ANY captured memory region
            let is_within_regions = translator.get_regions()
                .iter()
                .any(|region| next_task_phys >= region.start && next_task_phys <= region.end);

            if !is_within_regions {
                // Only log first 10 rejections to avoid spam
                if rejections_logged < 10 {
                    debug!("[DEBUG] Skipping candidate 0x{:x}: physical 0x{:x} not in any region",
                              candidate_page_offset, next_task_phys);
                    rejections_logged += 1;
                }
                continue;
            }

            // Translate to file offset
            let file_offset = match phys_to_file_offset(next_task_phys) {
                Some(offset) => offset,
                None => continue,
            };

            // tasks.next points to the 'tasks' field within task_struct, not the base
            // Subtract tasks_offset to get the actual struct base for validation
            let task_struct_base = file_offset.saturating_sub(tasks_offset);

            // Validate task_struct at this location
            if let Some((score, comm)) = validate_next_task_candidate(task_struct_base) {
                // Determine paging level (4-level vs 5-level)
                let diff_4level = (candidate_page_offset as i64 - 0xffff880000000000u64 as i64).abs();
                let diff_5level = (candidate_page_offset as i64 - 0xffff888000000000u64 as i64).abs();
                let is_4level = diff_4level < diff_5level;

                debug!("[DEBUG] ✓ Valid candidate: PAGE_OFFSET=0x{:x}, task_base=0x{:x}, comm='{}', score={}",
                         candidate_page_offset, task_struct_base, comm, score);

                valid_candidates.push(ValidCandidate {
                    page_offset: candidate_page_offset,
                    file_offset: task_struct_base,  // Store the base, not the tasks field offset
                    score,
                    comm,
                    is_4level,
                });
            }
        }

        // Log summary of candidate validation
        if rejections_logged >= 10 {
            debug!("[DEBUG] Tested {} candidates, found {} valid (showing only first 10 rejections)",
                     candidates_count, valid_candidates.len());
        }

        // Choose best candidate by score
        if !valid_candidates.is_empty() {
            valid_candidates.sort_by(|a, b| b.score.cmp(&a.score));

            debug!("[DEBUG] Found {} valid PAGE_OFFSET candidates:", valid_candidates.len());
            for (i, cand) in valid_candidates.iter().take(5).enumerate() {
                debug!("[DEBUG]   {}. PAGE_OFFSET=0x{:x}, comm='{}', score={}",
                         i+1, cand.page_offset, cand.comm, cand.score);
            }

            let best = &valid_candidates[0];
            debug!("[DEBUG] ✓ Selected best candidate: PAGE_OFFSET=0x{:x}, comm='{}'",
                     best.page_offset, best.comm);

            // Set PAGE_OFFSET based on paging level
            if best.is_4level {
                debug!("[DEBUG] ✓ Detected 4-level paging");
                translator.set_page_offset_4level(best.page_offset);
            } else {
                debug!("[DEBUG] ✓ Detected 5-level paging");
                translator.set_page_offset_5level(best.page_offset);
            }

            println!("✓ Successfully detected PAGE_OFFSET: 0x{:x}", best.page_offset);
        } else {
            warn!("[WARNING] Could not detect PAGE_OFFSET using candidate validation");
            debug!("[DEBUG] Attempting to derive PAGE_OFFSET from init_task...");

            // Stage 2: Try derivation method
            if let Some(derived_offset) = symbol_resolver.derive_page_offset_from_init_task(
                mapped,
                &translator,
                init_task_offset,
                tasks_offset
            ) {
                debug!("[DEBUG] ✓ Successfully derived PAGE_OFFSET: 0x{:x}", derived_offset);
                translator.set_page_offset_5level(derived_offset);
                translator.set_page_offset_4level(derived_offset);  // Set both to same value for KASLR
                println!("✓ Derived PAGE_OFFSET from init_task: 0x{:x}", derived_offset);
            } else {
                warn!("[WARNING] Could not derive PAGE_OFFSET - using defaults");
                warn!("[WARNING] Direct mapping translations may be incorrect");
            }
        }
    } else {
        debug!("[DEBUG] tasks.next not in direct mapping range (likely kernel text mapping)");
        debug!("[DEBUG] PAGE_OFFSET detection not needed for this kernel configuration");
    }

    // Create analysis context
    let context = AnalysisContext {
        memory_map: &memory_map,
        translator: &translator,
        symbol_resolver: &symbol_resolver,
        init_task_offset,  // Pass the KASLR-adjusted init_task offset
    };

    // Determine output format and destination
    let output_format = match cli.format {
        OutputFormatArg::Text => OutputFormat::Text,
        OutputFormatArg::Csv => OutputFormat::Csv,
        OutputFormatArg::Json => OutputFormat::Json,
        OutputFormatArg::Jsonl => OutputFormat::Jsonl,
    };

    let output_dest = if let Some(output_path) = &cli.output {
        OutputDestination::File(output_path.clone())
    } else {
        OutputDestination::Stdout
    };

    let output_writer = OutputWriter::new(output_format, output_dest);

    // Execute plugins based on CLI arguments
    if cli.all {
        // Run all plugins
        run_all_plugins(&context, &output_writer)?;
    } else if let Some(plugin_cmd) = &cli.plugin {
        // Run specific plugin
        run_plugin(plugin_cmd, &context, &output_writer)?;
    } else {
        // Default: run pslist if no plugin specified
        println!("No plugin specified, running pslist by default...");
        let plugin = PsListPlugin;
        execute_plugin(&plugin, &context, &output_writer, None, None)?;
    }

    Ok(())
}

/// Run a specific plugin based on the command
fn run_plugin(
    plugin_cmd: &PluginCommand,
    context: &AnalysisContext,
    output_writer: &OutputWriter,
) -> Result<(), AnalysisError> {
    match plugin_cmd {
        PluginCommand::Pslist { pid, name } => {
            let plugin = PsListPlugin;
            execute_plugin(&plugin, context, output_writer, *pid, name.as_deref())?;
        }
        PluginCommand::Pstree => {
            let plugin = PsTreePlugin;
            execute_plugin(&plugin, context, output_writer, None, None)?;
        }
        PluginCommand::Netstat { pid: _ } => {
            let plugin = NetStatPlugin;
            execute_plugin(&plugin, context, output_writer, None, None)?;
        }
        PluginCommand::Modules => {
            let plugin = ModulesPlugin;
            execute_plugin(&plugin, context, output_writer, None, None)?;
        }
        PluginCommand::Files { pid: _ } => {
            let plugin = FilesPlugin;
            execute_plugin(&plugin, context, output_writer, None, None)?;
        }
    }
    Ok(())
}

/// Run all available plugins
fn run_all_plugins(
    context: &AnalysisContext,
    output_writer: &OutputWriter,
) -> Result<(), AnalysisError> {
    let plugins: Vec<Box<dyn ForensicPlugin>> = vec![
        Box::new(PsListPlugin),
        Box::new(PsTreePlugin),
        Box::new(NetStatPlugin),
        Box::new(ModulesPlugin),
        // Skip FilesPlugin as it's not implemented
    ];

    for plugin in plugins {
        println!("\n=== Running plugin: {} ===", plugin.name());
        execute_plugin(plugin.as_ref(), context, output_writer, None, None)?;
    }

    Ok(())
}

/// Execute a plugin and handle its output
fn execute_plugin(
    plugin: &dyn ForensicPlugin,
    context: &AnalysisContext,
    output_writer: &OutputWriter,
    filter_pid: Option<i32>,
    filter_name: Option<&str>,
) -> Result<(), AnalysisError> {
    // Run the plugin
    let output = plugin.run(context)?;

    // Handle plugin output based on type
    match output {
        PluginOutput::Processes(mut processes) => {
            // Apply filters if provided
            if let Some(pid) = filter_pid {
                processes.retain(|p| p.pid == pid);
            }
            if let Some(name_pattern) = filter_name {
                use regex::Regex;
                let re = Regex::new(name_pattern)
                    .map_err(|e| AnalysisError::RegexError(e))?;
                processes.retain(|p| re.is_match(&p.comm));
            }

            if processes.is_empty() {
                println!("No processes found matching the specified criteria.");
            } else {
                output_writer.write_processes(&processes)?;
            }
        }
        PluginOutput::Connections(connections) => {
            if connections.is_empty() {
                println!("No network connections found.");
            } else {
                output_writer.write_connections(&connections)?;
            }
        }
        PluginOutput::Modules(modules) => {
            if modules.is_empty() {
                println!("No kernel modules found.");
            } else {
                output_writer.write_modules(&modules)?;
            }
        }
        PluginOutput::Tree(tree_str) => {
            // Tree output is already formatted, just print it
            println!("{}", tree_str);
        }
        PluginOutput::Custom(custom_str) => {
            println!("{}", custom_str);
        }
    }

    Ok(())
}