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

fn main() -> Result<(), AnalysisError> {
    // Parse command-line arguments
    let cli = Cli::parse();

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
    let translator = if let Some(regs) = regions {
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

    // Find init_task - this is needed for most plugins
    // Pass translator so it can check if symbol addresses are translatable
    let init_task_offset = symbol_resolver.find_init_task(mapped, Some(&translator))
        .ok_or_else(|| AnalysisError::SymbolNotFound("init_task not found in memory".to_string()))?;
    
    println!("Found init_task at file offset: 0x{:x}", init_task_offset);

    // Create analysis context
    let context = AnalysisContext {
        memory_map: &memory_map,
        translator: &translator,
        symbol_resolver: &symbol_resolver,
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