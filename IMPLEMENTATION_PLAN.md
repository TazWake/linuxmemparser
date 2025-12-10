# Implementation Plan - linmemparser

**Version:** 1.0  
**Date:** 2025-12-10  
**Language:** Rust  
**Target:** Production-ready forensic analysis tool for Linux LIME memory dumps  

## Table of Contents

1. [Overview](#overview)
2. [Development Environment](#development-environment)
3. [Phase-by-Phase Implementation](#phase-by-phase-implementation)
4. [Output Format System](#output-format-system)
5. [Test Plan](#test-plan)
6. [Dependencies and Crates](#dependencies-and-crates)
7. [Quality Assurance](#quality-assurance)
8. [Timeline and Milestones](#timeline-and-milestones)

---

## Overview

This document provides a detailed, actionable implementation plan for building linmemparser in Rust. The project will be developed in 7 phases over approximately 12 weeks, with comprehensive testing throughout.

### Core Principles

- **Rust-First:** Leverage Rust's safety, performance, and ecosystem
- **Modular Design:** Clear separation of concerns for maintainability
- **Test-Driven:** Write tests before or alongside implementation
- **User-Focused:** Support multiple output formats and clear error messages
- **Performance:** Target <60s for 1GB memory dump processing

---

## Development Environment

### Required Tools

```bash
# Rust toolchain (1.56+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable

# Development tools
rustup component add rustfmt clippy
cargo install cargo-watch cargo-edit cargo-audit

# Testing tools
cargo install cargo-tarpaulin  # Code coverage
cargo install cargo-criterion  # Benchmarking
```

### Recommended IDE Setup

**VS Code:**

```json
{
  "extensions": [
    "rust-lang.rust-analyzer",
    "vadimcn.vscode-lldb",
    "serayuzgur.crates"
  ]
}
```

### Project Structure

```text
linmemparser/
├── Cargo.toml                    # Project manifest
├── Cargo.lock                    # Dependency lock file
├── src/
│   ├── main.rs                   # CLI entry point
│   ├── lib.rs                    # Library root (for testing)
│   ├── cli/
│   │   ├── mod.rs               # CLI module
│   │   ├── args.rs              # Argument parsing
│   │   └── output.rs            # Output formatting
│   ├── core/
│   │   ├── mod.rs               # Core framework
│   │   ├── memory.rs            # Memory access layer
│   │   ├── symbols.rs           # Symbol resolution
│   │   ├── translation.rs       # Address translation
│   │   └── kernel.rs            # Kernel structure parsing
│   ├── plugins/
│   │   ├── mod.rs               # Plugin manager
│   │   ├── plugin_trait.rs      # Plugin interface
│   │   ├── pslist.rs            # Process list plugin
│   │   ├── pstree.rs            # Process tree plugin
│   │   ├── netstat.rs           # Network plugin
│   │   ├── modules.rs           # Kernel modules plugin
│   │   └── files.rs             # Open files plugin
│   ├── formats/
│   │   ├── mod.rs               # Format implementations
│   │   ├── csv.rs               # CSV output
│   │   ├── json.rs              # JSON output
│   │   ├── jsonl.rs             # JSON Lines output
│   │   ├── text.rs              # Text table output
│   │   └── traits.rs            # Format traits
│   └── error.rs                  # Error types
├── tests/
│   ├── integration_tests.rs      # Integration tests
│   ├── format_tests.rs           # Output format tests
│   └── fixtures/                 # Test data
├── benches/
│   └── benchmarks.rs             # Performance benchmarks
├── TESTDATA/                      # Sample memory dumps
└── docs/                          # Additional documentation
```

---

## Phase-by-Phase Implementation

### Phase 1: Core Infrastructure Enhancement (Weeks 1-2)

**Goal:** Fix critical issues and establish solid foundation

#### Week 1: Address Translation & Structure Offsets

**Tasks:**

1. **Integrate MemoryTranslator into ProcessExtractor** (2 days)

   ```rust
   // src/core/kernel.rs
   impl ProcessExtractor {
       pub fn extract_process_info(
           &self,
           memory_map: &MemoryMap,
           translator: &MemoryTranslator,  // NEW PARAMETER
           symbol_resolver: &SymbolResolver,
           task_struct_offset: u64,
       ) -> Result<ProcessInfo, AnalysisError> {
           // Use translator for pointer dereferencing
       }
   }
   ```

2. **Implement pointer dereferencing helper** (1 day)

   ```rust
   // src/core/kernel.rs
   impl KernelParser {
       /// Dereference a virtual address pointer
       pub fn dereference_pointer(
           mapped: &[u8],
           translator: &MemoryTranslator,
           virtual_addr: u64,
       ) -> Result<u64, AnalysisError> {
           // Translate virtual addr to file offset
           let offset = translator.virtual_to_file_offset(virtual_addr)
               .ok_or(AnalysisError::AddressTranslationFailed(virtual_addr))?;

           // Read u64 at that offset
           Self::read_u64(mapped, offset as usize)
               .ok_or(AnalysisError::InvalidStructure(
                   format!("Cannot read at offset 0x{:x}", offset)
               ))
       }
   }
   ```

3. **Create structure offset database** (2 days)

   ```rust
   // src/core/offsets.rs (NEW FILE)
   pub struct StructureOffsets {
       kernel_version: KernelVersion,
       offsets: HashMap<String, HashMap<String, usize>>,
   }

   impl StructureOffsets {
       pub fn for_kernel(version: &KernelVersion) -> Self {
           // Load offsets for specific kernel version
       }

       pub fn get_offset(&self, struct_name: &str, field_name: &str) -> Option<usize> {
           self.offsets.get(struct_name)?.get(field_name).copied()
       }
   }
   ```

**Deliverable:** Proper pointer dereferencing with address translation

**Tests:**

```rust
#[test]
fn test_pointer_dereferencing() {
    let translator = /* setup */;
    let mapped = /* test data */;
    let result = KernelParser::dereference_pointer(&mapped, &translator, 0xffffffff81e00000);
    assert!(result.is_ok());
}
```

#### Week 2: Symbol Resolution & Kernel Version Detection

**Tasks:**

1. **Implement kernel version detection** (2 days)

   ```rust
   // src/core/symbols.rs
   impl SymbolResolver {
       pub fn detect_kernel_version(mapped: &[u8]) -> Option<KernelVersion> {
           // Search for "Linux version" string
           let banner = Self::find_linux_banner(mapped)?;
           Self::parse_kernel_version(&banner)
       }

       fn find_linux_banner(mapped: &[u8]) -> Option<String> {
           let pattern = b"Linux version ";
           memmem::find(mapped, pattern)?;
           // Extract full banner string
       }
   }
   ```

2. **Enhance symbol resolution with fallbacks** (2 days)

   ```rust
   impl SymbolResolver {
       pub fn get_struct_field_offset(
           &self,
           struct_name: &str,
           field_name: &str,
       ) -> Option<u64> {
           // 1. Check symbol table
           if let Some(offset) = self.lookup_symbol_offset(struct_name, field_name) {
               return Some(offset);
           }

           // 2. Use structure offset database
           if let Some(version) = &self.kernel_version {
               let db = StructureOffsets::for_kernel(version);
               if let Some(offset) = db.get_offset(struct_name, field_name) {
                   return Some(offset as u64);
               }
           }

           // 3. No offset available
           None
       }
   }
   ```

3. **Add validation checks** (1 day)

   ```rust
   pub fn validate_process_info(info: &ProcessInfo) -> bool {
       // PID should be positive
       if info.pid < 0 {
           return false;
       }

       // Process name should be printable ASCII
       if !info.comm.chars().all(|c| c.is_ascii_graphic() || c.is_whitespace()) {
           return false;
       }

       // UID/GID should be reasonable
       if info.uid > 65535 || info.gid > 65535 {
           return false;
       }

       true
   }
   ```

**Deliverable:** Automatic kernel version detection with offset resolution

**Tests:**

```rust
#[test]
fn test_kernel_version_detection() {
    let sample = include_bytes!("../TESTDATA/EXAMPLE.lime");
    let version = SymbolResolver::detect_kernel_version(sample);
    assert!(version.is_some());
}

#[test]
fn test_offset_fallback() {
    let resolver = SymbolResolver::new();
    // Should fall back to database when symbol not found
    let offset = resolver.get_struct_field_offset("task_struct", "pid");
    assert!(offset.is_some());
}
```

---

### Phase 2: Symbol System (Weeks 3-4)

**Goal:** Multi-format symbol support with external files

#### Week 3: System.map and kallsyms Parsers

**Tasks:**

1. **Implement System.map parser** (2 days)

   ```rust
   // src/core/symbols.rs
   impl SymbolResolver {
       pub fn load_system_map(&mut self, path: &Path) -> Result<(), AnalysisError> {
           let content = fs::read_to_string(path)?;
           for line in content.lines() {
               let parts: Vec<&str> = line.split_whitespace().collect();
               if parts.len() >= 3 {
                   let address = u64::from_str_radix(parts[0], 16)?;
                   let symbol_type = parts[1];
                   let name = parts[2].to_string();
                   self.symbols.insert(name, address);
               }
           }
           Ok(())
       }
   }
   ```

2. **Implement kallsyms parser** (1 day)

   ```rust
   // Same format as System.map, reuse parser
   pub fn load_kallsyms(&mut self, path: &Path) -> Result<(), AnalysisError> {
       self.load_system_map(path)  // Identical format
   }
   ```

3. **Add symbol lookup utilities** (2 days)

   ```rust
   impl SymbolResolver {
       pub fn lookup_symbol(&self, name: &str) -> Option<u64> {
           self.symbols.get(name).copied()
       }

       pub fn find_symbol_by_pattern(&self, pattern: &str) -> Vec<(String, u64)> {
           let re = Regex::new(pattern).ok()?;
           self.symbols.iter()
               .filter(|(name, _)| re.is_match(name))
               .map(|(n, a)| (n.clone(), *a))
               .collect()
       }
   }
   ```

**Deliverable:** System.map and kallsyms support

**Tests:**

```rust
#[test]
fn test_system_map_parsing() {
    let mut resolver = SymbolResolver::new();
    resolver.load_system_map(Path::new("testdata/System.map")).unwrap();
    assert!(resolver.lookup_symbol("init_task").is_some());
}
```

#### Week 4: dwarf2json Parser & Documentation

**Tasks:**

1. **Implement dwarf2json parser** (3 days)

   ```rust
   // src/core/dwarf.rs (NEW FILE)
   use serde::{Deserialize, Serialize};

   #[derive(Debug, Deserialize)]
   pub struct DwarfSymbols {
       symbols: HashMap<String, u64>,
       user_types: HashMap<String, DwarfStruct>,
   }

   #[derive(Debug, Deserialize)]
   pub struct DwarfStruct {
       size: usize,
       fields: HashMap<String, DwarfField>,
   }

   #[derive(Debug, Deserialize)]
   pub struct DwarfField {
       offset: usize,
       #[serde(rename = "type")]
       field_type: String,
   }

   impl SymbolResolver {
       pub fn load_dwarf2json(&mut self, path: &Path) -> Result<(), AnalysisError> {
           let content = fs::read_to_string(path)?;
           let dwarf: DwarfSymbols = serde_json::from_str(&content)?;

           // Load symbols
           self.symbols.extend(dwarf.symbols);

           // Load structure definitions
           for (struct_name, struct_def) in dwarf.user_types {
               for (field_name, field) in struct_def.fields {
                   let key = format!("{}::{}", struct_name, field_name);
                   self.struct_offsets.insert(key, field.offset as u64);
               }
           }

           Ok(())
       }
   }
   ```

2. **Create symbol generation documentation** (2 days)
   - Document all three methods in USER_GUIDE.md
   - Add troubleshooting for each method
   - Include distribution-specific instructions

**Deliverable:** dwarf2json support + complete symbol documentation

**Tests:**

```rust
#[test]
fn test_dwarf2json_parsing() {
    let mut resolver = SymbolResolver::new();
    resolver.load_dwarf2json(Path::new("testdata/kernel.json")).unwrap();

    // Should load both symbols and structure offsets
    assert!(resolver.lookup_symbol("init_task").is_some());
    assert!(resolver.get_struct_field_offset("task_struct", "pid").is_some());
}
```

---

### Phase 3: Output Format System (Week 5)

**Goal:** Implement all output formats (CSV, JSON, JSONL, Text, stdout)

#### Output Format Architecture

```rust
// src/formats/traits.rs
pub trait OutputFormatter: Send + Sync {
    fn format_processes(&self, processes: &[ProcessInfo]) -> Result<String, AnalysisError>;
    fn format_connections(&self, connections: &[ConnectionInfo]) -> Result<String, AnalysisError>;
    fn format_modules(&self, modules: &[ModuleInfo]) -> Result<String, AnalysisError>;
}

pub enum OutputFormat {
    Text,
    CSV,
    JSON,
    JSONL,
}

pub struct OutputWriter {
    format: Box<dyn OutputFormatter>,
    destination: OutputDestination,
}

pub enum OutputDestination {
    Stdout,
    File(PathBuf),
}
```

#### Week 5: Format Implementations

**Tasks:**

1. **Text (Table) Format** (1 day)

   ```rust
   // src/formats/text.rs
   use prettytable::{Table, Row, Cell, format};

   pub struct TextFormatter;

   impl OutputFormatter for TextFormatter {
       fn format_processes(&self, processes: &[ProcessInfo]) -> Result<String, AnalysisError> {
           let mut table = Table::new();
           table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

           // Header
           table.add_row(row!["PID", "PPID", "UID", "GID", "COMM", "STATE", "START_TIME", "CMDLINE"]);

           // Data rows
           for proc in processes {
               table.add_row(row![
                   proc.pid,
                   proc.ppid,
                   proc.uid,
                   proc.gid,
                   proc.comm,
                   proc.state,
                   proc.start_time,
                   proc.cmdline
               ]);
           }

           Ok(table.to_string())
       }
   }
   ```

2. **CSV Format** (1 day)

   ```rust
   // src/formats/csv.rs
   use csv::Writer;

   pub struct CsvFormatter;

   impl OutputFormatter for CsvFormatter {
       fn format_processes(&self, processes: &[ProcessInfo]) -> Result<String, AnalysisError> {
           let mut wtr = Writer::from_writer(vec![]);

           // Header
           wtr.write_record(&["pid", "ppid", "uid", "gid", "comm", "state",
                             "start_time", "cmdline"])?;

           // Data
           for proc in processes {
               wtr.write_record(&[
                   proc.pid.to_string(),
                   proc.ppid.to_string(),
                   proc.uid.to_string(),
                   proc.gid.to_string(),
                   proc.comm.clone(),
                   proc.state.clone(),
                   proc.start_time.to_string(),
                   proc.cmdline.clone(),
               ])?;
           }

           wtr.flush()?;
           Ok(String::from_utf8(wtr.into_inner()?)?)
       }
   }
   ```

3. **JSON Format** (1 day)

   ```rust
   // src/formats/json.rs
   use serde_json;

   pub struct JsonFormatter {
       pretty: bool,
   }

   impl OutputFormatter for JsonFormatter {
       fn format_processes(&self, processes: &[ProcessInfo]) -> Result<String, AnalysisError> {
           #[derive(Serialize)]
           struct Output {
               plugin: String,
               timestamp: String,
               count: usize,
               results: Vec<ProcessInfo>,
           }

           let output = Output {
               plugin: "pslist".to_string(),
               timestamp: chrono::Utc::now().to_rfc3339(),
               count: processes.len(),
               results: processes.to_vec(),
           };

           if self.pretty {
               Ok(serde_json::to_string_pretty(&output)?)
           } else {
               Ok(serde_json::to_string(&output)?)
           }
       }
   }
   ```

4. **JSONL (JSON Lines) Format** (1 day)

   ```rust
   // src/formats/jsonl.rs
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
   }
   ```

5. **Output Writer** (1 day)

   ```rust
   // src/formats/mod.rs
   impl OutputWriter {
       pub fn new(format: OutputFormat, destination: OutputDestination) -> Self {
           let formatter: Box<dyn OutputFormatter> = match format {
               OutputFormat::Text => Box::new(TextFormatter),
               OutputFormat::CSV => Box::new(CsvFormatter),
               OutputFormat::JSON => Box::new(JsonFormatter { pretty: true }),
               OutputFormat::JSONL => Box::new(JsonlFormatter),
           };

           Self { format: formatter, destination }
       }

       pub fn write_processes(&self, processes: &[ProcessInfo]) -> Result<(), AnalysisError> {
           let content = self.format.format_processes(processes)?;

           match &self.destination {
               OutputDestination::Stdout => {
                   println!("{}", content);
               }
               OutputDestination::File(path) => {
                   fs::write(path, content)?;
               }
           }

           Ok(())
       }
   }
   ```

**Deliverable:** All 5 output formats working

**Tests:**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_processes() -> Vec<ProcessInfo> {
        vec![
            ProcessInfo {
                pid: 1,
                ppid: 0,
                uid: 0,
                gid: 0,
                comm: "systemd".to_string(),
                state: "RUNNING".to_string(),
                start_time: 1736939391,
                cmdline: "/sbin/init".to_string(),
                offset: 0,
            },
        ]
    }

    #[test]
    fn test_text_format() {
        let formatter = TextFormatter;
        let result = formatter.format_processes(&sample_processes());
        assert!(result.is_ok());
        assert!(result.unwrap().contains("systemd"));
    }

    #[test]
    fn test_csv_format() {
        let formatter = CsvFormatter;
        let result = formatter.format_processes(&sample_processes()).unwrap();
        assert!(result.contains("pid,ppid"));
        assert!(result.contains("1,0"));
    }

    #[test]
    fn test_json_format() {
        let formatter = JsonFormatter { pretty: true };
        let result = formatter.format_processes(&sample_processes()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["count"], 1);
    }

    #[test]
    fn test_jsonl_format() {
        let formatter = JsonlFormatter;
        let result = formatter.format_processes(&sample_processes()).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: ProcessInfo = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.pid, 1);
    }
}
```

---

### Phase 4: Core Plugins (Weeks 6-7)

**Goal:** Implement 5 core analysis plugins

#### Plugin Architecture

```rust
// src/plugins/plugin_trait.rs
pub trait ForensicPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn run(&self, context: &AnalysisContext) -> Result<PluginOutput, AnalysisError>;
}

pub struct AnalysisContext<'a> {
    pub memory_map: &'a MemoryMap,
    pub translator: &'a MemoryTranslator,
    pub symbol_resolver: &'a SymbolResolver,
}

pub enum PluginOutput {
    Processes(Vec<ProcessInfo>),
    Connections(Vec<ConnectionInfo>),
    Modules(Vec<ModuleInfo>),
    Files(Vec<FileInfo>),
}
```

#### Week 6: Process Plugins

**Tasks:**

1. **PsList Plugin** (1 day)

   ```rust
   // src/plugins/pslist.rs
   pub struct PsListPlugin;

   impl ForensicPlugin for PsListPlugin {
       fn name(&self) -> &str { "pslist" }

       fn description(&self) -> &str {
           "List running processes"
       }

       fn run(&self, context: &AnalysisContext) -> Result<PluginOutput, AnalysisError> {
           let extractor = ProcessExtractor::new();

           // Find init_task
           let init_task_offset = context.symbol_resolver
               .find_init_task(context.memory_map.mapped)?;

           // Walk process list
           let processes = extractor.walk_process_list(
               context.memory_map,
               context.translator,
               context.symbol_resolver,
               init_task_offset,
           )?;

           Ok(PluginOutput::Processes(processes))
       }
   }
   ```

2. **PsTree Plugin** (2 days)

   ```rust
   // src/plugins/pstree.rs
   pub struct PsTreePlugin;

   impl PsTreePlugin {
       fn build_process_tree(&self, processes: Vec<ProcessInfo>) -> ProcessTree {
           let mut tree = ProcessTree::new();
           let mut process_map: HashMap<i32, ProcessInfo> = HashMap::new();

           // Index by PID
           for proc in processes {
               process_map.insert(proc.pid, proc);
           }

           // Build parent-child relationships
           for proc in process_map.values() {
               if let Some(parent) = process_map.get(&proc.ppid) {
                   tree.add_child(parent.pid, proc.pid);
               } else {
                   tree.add_root(proc.pid);
               }
           }

           tree
       }
   }
   ```

3. **Plugin Manager** (2 days)

   ```rust
   // src/plugins/mod.rs
   pub struct PluginManager {
       plugins: HashMap<String, Box<dyn ForensicPlugin>>,
   }

   impl PluginManager {
       pub fn new() -> Self {
           let mut manager = Self {
               plugins: HashMap::new(),
           };

           // Register built-in plugins
           manager.register(Box::new(PsListPlugin));
           manager.register(Box::new(PsTreePlugin));

           manager
       }

       pub fn register(&mut self, plugin: Box<dyn ForensicPlugin>) {
           self.plugins.insert(plugin.name().to_string(), plugin);
       }

       pub fn run_plugin(
           &self,
           name: &str,
           context: &AnalysisContext,
       ) -> Result<PluginOutput, AnalysisError> {
           let plugin = self.plugins.get(name)
               .ok_or_else(|| AnalysisError::PluginError(
                   format!("Plugin '{}' not found", name)
               ))?;

           plugin.run(context)
       }

       pub fn list_plugins(&self) -> Vec<(&str, &str)> {
           self.plugins.values()
               .map(|p| (p.name(), p.description()))
               .collect()
       }
   }
   ```

**Deliverable:** PsList, PsTree plugins + Plugin Manager

**Tests:**

```rust
#[test]
fn test_plugin_registration() {
    let manager = PluginManager::new();
    let plugins = manager.list_plugins();
    assert!(plugins.iter().any(|(name, _)| *name == "pslist"));
}

#[test]
fn test_process_tree_building() {
    let processes = vec![
        ProcessInfo { pid: 1, ppid: 0, /* ... */ },
        ProcessInfo { pid: 100, ppid: 1, /* ... */ },
        ProcessInfo { pid: 101, ppid: 1, /* ... */ },
    ];

    let plugin = PsTreePlugin;
    let tree = plugin.build_process_tree(processes);

    assert_eq!(tree.children_of(1).len(), 2);
}
```

#### Week 7: Network & Module Plugins

**Tasks:**

1. **NetStat Plugin** (2 days)

   ```rust
   // src/plugins/netstat.rs
   pub struct NetStatPlugin;

   impl ForensicPlugin for NetStatPlugin {
       fn name(&self) -> &str { "netstat" }

       fn run(&self, context: &AnalysisContext) -> Result<PluginOutput, AnalysisError> {
           let mut connections = Vec::new();

           // Find network namespace structures
           let init_net = context.symbol_resolver.lookup_symbol("init_net")
               .ok_or_else(|| AnalysisError::SymbolNotFound("init_net".to_string()))?;

           // Parse TCP hash table
           connections.extend(self.parse_tcp_connections(context, init_net)?);

           // Parse UDP hash table
           connections.extend(self.parse_udp_sockets(context, init_net)?);

           Ok(PluginOutput::Connections(connections))
       }
   }
   ```

2. **Modules Plugin** (2 days)

   ```rust
   // src/plugins/modules.rs
   pub struct ModulesPlugin;

   impl ForensicPlugin for ModulesPlugin {
       fn name(&self) -> &str { "modules" }

       fn run(&self, context: &AnalysisContext) -> Result<PluginOutput, AnalysisError> {
           let modules_list = context.symbol_resolver.lookup_symbol("modules")
               .ok_or_else(|| AnalysisError::SymbolNotFound("modules".to_string()))?;

           let modules = self.walk_module_list(context, modules_list)?;

           Ok(PluginOutput::Modules(modules))
       }
   }
   ```

3. **Files Plugin** (stub for future) (1 day)

   ```rust
   // src/plugins/files.rs
   pub struct FilesPlugin;

   impl ForensicPlugin for FilesPlugin {
       fn name(&self) -> &str { "files" }

       fn run(&self, context: &AnalysisContext) -> Result<PluginOutput, AnalysisError> {
           // To be implemented in Phase 5
           Err(AnalysisError::PluginError(
               "Files plugin not yet implemented".to_string()
           ))
       }
   }
   ```

**Deliverable:** NetStat, Modules plugins

---

### Phase 5: CLI Integration (Week 8)

**Goal:** Full-featured command-line interface

#### Tasks

1. **Argument Parsing with clap** (2 days)

   ```rust
   // src/cli/args.rs
   use clap::{Parser, Subcommand, ValueEnum};

   #[derive(Parser)]
   #[command(name = "linmemparser")]
   #[command(about = "Linux Memory Forensics Tool", long_about = None)]
   pub struct Cli {
       /// Path to LIME memory dump
       #[arg(value_name = "MEMORY_DUMP")]
       pub memory_dump: PathBuf,

       /// Plugin to run
       #[command(subcommand)]
       pub plugin: Option<PluginCommand>,

       /// Run all plugins
       #[arg(short, long)]
       pub all: bool,

       /// Path to symbol file (System.map, kallsyms, or dwarf2json)
       #[arg(short, long, value_name = "FILE")]
       pub symbols: Option<PathBuf>,

       /// Output format
       #[arg(short, long, value_enum, default_value = "text")]
       pub format: OutputFormatArg,

       /// Output file (default: stdout)
       #[arg(short, long, value_name = "FILE")]
       pub output: Option<PathBuf>,

       /// Increase verbosity (-v, -vv, -vvv)
       #[arg(short, long, action = clap::ArgAction::Count)]
       pub verbose: u8,

       /// List available plugins
       #[arg(short, long)]
       pub list_plugins: bool,
   }

   #[derive(Subcommand)]
   pub enum PluginCommand {
       /// List running processes
       Pslist {
           /// Filter by PID
           #[arg(long)]
           pid: Option<i32>,

           /// Filter by process name (regex)
           #[arg(long)]
           name: Option<String>,
       },

       /// Show process tree
       Pstree,

       /// Network connections
       Netstat {
           /// Filter by PID
           #[arg(long)]
           pid: Option<i32>,
       },

       /// Kernel modules
       Modules,

       /// Open files (not yet implemented)
       Files {
           /// Filter by PID
           #[arg(long)]
           pid: Option<i32>,
       },
   }

   #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
   pub enum OutputFormatArg {
       Text,
       Csv,
       Json,
       Jsonl,
   }
   ```

2. **Main Application Logic** (2 days)

   ```rust
   // src/main.rs
   use clap::Parser;

   fn main() -> Result<(), Box<dyn std::error::Error>> {
       let cli = Cli::parse();

       // Setup logging based on verbosity
       setup_logging(cli.verbose);

       // Handle --list-plugins
       if cli.list_plugins {
           list_plugins();
           return Ok(());
       }

       // Load memory dump
       info!("Loading memory dump: {:?}", cli.memory_dump);
       let memory_map = MemoryMap::new(&cli.memory_dump)?;

       // Parse LIME header
       let regions = memory_map.parse_lime_header()
           .ok_or("Failed to parse LIME header")?;
       let translator = MemoryTranslator::new(regions);

       // Load symbols
       let mut resolver = SymbolResolver::new();
       if let Some(symbol_path) = cli.symbols {
           info!("Loading symbols from: {:?}", symbol_path);
           load_symbols(&mut resolver, &symbol_path)?;
       }

       // Detect kernel version
       if let Some(version) = resolver.detect_kernel_version(memory_map.mapped) {
           info!("Detected kernel version: {}", version);
       }

       // Create analysis context
       let context = AnalysisContext {
           memory_map: &memory_map,
           translator: &translator,
           symbol_resolver: &resolver,
       };

       // Initialize plugin manager
       let plugin_manager = PluginManager::new();

       // Determine output writer
       let output_dest = match cli.output {
           Some(path) => OutputDestination::File(path),
           None => OutputDestination::Stdout,
       };
       let output_format = match cli.format {
           OutputFormatArg::Text => OutputFormat::Text,
           OutputFormatArg::Csv => OutputFormat::CSV,
           OutputFormatArg::Json => OutputFormat::JSON,
           OutputFormatArg::Jsonl => OutputFormat::JSONL,
       };
       let writer = OutputWriter::new(output_format, output_dest);

       // Run plugin(s)
       if cli.all {
           run_all_plugins(&plugin_manager, &context, &writer)?;
       } else if let Some(plugin_cmd) = cli.plugin {
           run_plugin(&plugin_manager, &context, &writer, plugin_cmd)?;
       } else {
           // Default: run pslist
           run_plugin(&plugin_manager, &context, &writer, PluginCommand::Pslist { pid: None, name: None })?;
       }

       Ok(())
   }
   ```

3. **Progress Indicators** (1 day)

   ```rust
   use indicatif::{ProgressBar, ProgressStyle};

   fn with_progress<F, T>(message: &str, f: F) -> T
   where
       F: FnOnce() -> T,
   {
       let pb = ProgressBar::new_spinner();
       pb.set_style(
           ProgressStyle::default_spinner()
               .template("{spinner:.green} {msg}")
               .unwrap()
       );
       pb.set_message(message.to_string());
       pb.enable_steady_tick(std::time::Duration::from_millis(100));

       let result = f();

       pb.finish_with_message(format!("{} ✓", message));
       result
   }
   ```

**Deliverable:** Full CLI with all options

**Tests:**

```rust
#[test]
fn test_cli_parsing() {
    let args = Cli::parse_from(&[
        "linmemparser",
        "test.lime",
        "pslist",
        "--format", "json",
        "--output", "out.json",
    ]);

    assert_eq!(args.memory_dump, PathBuf::from("test.lime"));
    assert!(matches!(args.plugin, Some(PluginCommand::Pslist { .. })));
}
```

---

### Phase 6: Advanced Features (Weeks 9-10)

**Tasks:**

1. **PsScan Plugin** (dead process scan) - Week 9
2. **BashHistory Plugin** - Week 9
3. **Enhanced filtering and search** - Week 10
4. **Performance optimization** - Week 10

---

### Phase 7: Testing & Documentation (Weeks 11-12)

See [Test Plan](#test-plan) section below.

---

## Test Plan

### Test Structure

```text
tests/
├── unit/                          # Unit tests (in src/*)
├── integration/
│   ├── test_process_extraction.rs
│   ├── test_network_analysis.rs
│   ├── test_output_formats.rs
│   ├── test_symbol_loading.rs
│   └── test_cli.rs
├── fixtures/
│   ├── minimal.lime               # Minimal synthetic dump
│   ├── kernel_4.19.lime          # Real dump from 4.19
│   ├── kernel_5.15.lime          # Real dump from 5.15
│   ├── kernel_6.1.lime           # Real dump from 6.1
│   ├── System.map-4.19
│   ├── System.map-5.15
│   └── kernel-6.1.json           # dwarf2json
└── benchmarks/
    └── performance_tests.rs
```

### Unit Tests (Target: 70% Coverage)

**Core Modules:**

```rust
// src/core/memory.rs
#[cfg(test)]
mod tests {
    #[test]
    fn test_lime_header_parsing() { /* ... */ }

    #[test]
    fn test_memory_region_contains() { /* ... */ }

    #[test]
    fn test_virtual_to_file_offset() { /* ... */ }
}

// src/core/symbols.rs
#[cfg(test)]
mod tests {
    #[test]
    fn test_kernel_version_detection() { /* ... */ }

    #[test]
    fn test_system_map_parsing() { /* ... */ }

    #[test]
    fn test_dwarf2json_parsing() { /* ... */ }

    #[test]
    fn test_offset_fallback() { /* ... */ }
}

// src/core/translation.rs
#[cfg(test)]
mod tests {
    #[test]
    fn test_address_translation_success() { /* ... */ }

    #[test]
    fn test_address_translation_failure() { /* ... */ }

    #[test]
    fn test_find_region() { /* ... */ }
}
```

**Format Modules:**

```rust
// tests/format_tests.rs
#[test]
fn test_all_formats_produce_valid_output() {
    let processes = sample_processes();

    // Text
    let text = TextFormatter.format_processes(&processes).unwrap();
    assert!(text.contains("PID"));

    // CSV
    let csv = CsvFormatter.format_processes(&processes).unwrap();
    let mut reader = csv::Reader::from_reader(csv.as_bytes());
    assert_eq!(reader.records().count(), processes.len());

    // JSON
    let json = JsonFormatter { pretty: false }.format_processes(&processes).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["count"], processes.len());

    // JSONL
    let jsonl = JsonlFormatter.format_processes(&processes).unwrap();
    assert_eq!(jsonl.lines().count(), processes.len());
}
```

### Integration Tests

```rust
// tests/integration/test_process_extraction.rs
#[test]
fn test_extract_processes_from_real_dump() {
    let dump_path = "tests/fixtures/kernel_5.15.lime";
    let symbol_path = "tests/fixtures/System.map-5.15";

    // Load memory
    let memory_map = MemoryMap::new(dump_path).unwrap();
    let regions = memory_map.parse_lime_header().unwrap();
    let translator = MemoryTranslator::new(regions);

    // Load symbols
    let mut resolver = SymbolResolver::new();
    resolver.load_system_map(Path::new(symbol_path)).unwrap();

    // Extract processes
    let context = AnalysisContext {
        memory_map: &memory_map,
        translator: &translator,
        symbol_resolver: &resolver,
    };

    let plugin = PsListPlugin;
    let output = plugin.run(&context).unwrap();

    if let PluginOutput::Processes(processes) = output {
        // Should find init (PID 1)
        assert!(processes.iter().any(|p| p.pid == 1));

        // Should find multiple processes
        assert!(processes.len() > 10);

        // All PIDs should be valid
        for proc in &processes {
            assert!(proc.pid > 0);
            assert!(validate_process_info(proc));
        }
    } else {
        panic!("Expected Processes output");
    }
}

#[test]
fn test_process_extraction_across_kernel_versions() {
    let test_cases = vec![
        ("tests/fixtures/kernel_4.19.lime", "tests/fixtures/System.map-4.19"),
        ("tests/fixtures/kernel_5.15.lime", "tests/fixtures/System.map-5.15"),
        ("tests/fixtures/kernel_6.1.lime", "tests/fixtures/kernel-6.1.json"),
    ];

    for (dump, symbols) in test_cases {
        println!("Testing with: {}", dump);
        // Run extraction and verify results
        // ...
    }
}
```

### End-to-End CLI Tests

```rust
// tests/integration/test_cli.rs
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_pslist_text_output() {
    let mut cmd = Command::cargo_bin("linmemparser").unwrap();
    cmd.arg("tests/fixtures/kernel_5.15.lime")
        .arg("pslist")
        .arg("--format").arg("text");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("PID"))
        .stdout(predicate::str::contains("systemd"));
}

#[test]
fn test_cli_pslist_json_output() {
    let mut cmd = Command::cargo_bin("linmemparser").unwrap();
    cmd.arg("tests/fixtures/kernel_5.15.lime")
        .arg("pslist")
        .arg("--format").arg("json")
        .arg("--output").arg("test_output.json");

    cmd.assert().success();

    // Verify JSON is valid
    let content = std::fs::read_to_string("test_output.json").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["plugin"], "pslist");

    std::fs::remove_file("test_output.json").ok();
}

#[test]
fn test_cli_with_symbol_file() {
    let mut cmd = Command::cargo_bin("linmemparser").unwrap();
    cmd.arg("tests/fixtures/kernel_5.15.lime")
        .arg("pslist")
        .arg("--symbols").arg("tests/fixtures/System.map-5.15");

    cmd.assert().success();
}

#[test]
fn test_cli_list_plugins() {
    let mut cmd = Command::cargo_bin("linmemparser").unwrap();
    cmd.arg("--list-plugins");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("pslist"))
        .stdout(predicate::str::contains("pstree"));
}
```

### Performance Tests

```rust
// benches/benchmarks.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

fn benchmark_process_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_extraction");

    let sizes = vec!["1GB", "4GB", "8GB"];

    for size in sizes {
        let dump_path = format!("benches/fixtures/dump_{}.lime", size);

        group.bench_with_input(BenchmarkId::from_parameter(size), &dump_path, |b, path| {
            b.iter(|| {
                // Run full extraction
                let memory_map = MemoryMap::new(path).unwrap();
                let regions = memory_map.parse_lime_header().unwrap();
                let translator = MemoryTranslator::new(regions);
                let resolver = SymbolResolver::new();

                let context = AnalysisContext {
                    memory_map: &memory_map,
                    translator: &translator,
                    symbol_resolver: &resolver,
                };

                let plugin = PsListPlugin;
                black_box(plugin.run(&context).unwrap());
            });
        });
    }

    group.finish();
}

criterion_group!(benches, benchmark_process_extraction);
criterion_main!(benches);
```

### Test Execution

```bash
# Run all tests
cargo test

# Run with coverage
cargo tarpaulin --out Html --output-dir coverage

# Run benchmarks
cargo bench

# Run specific test
cargo test test_process_extraction -- --nocapture

# Run integration tests only
cargo test --test integration_tests
```

### Continuous Integration

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Run tests
        run: cargo test --all-features
      - name: Check formatting
        run: cargo fmt -- --check
      - name: Run clippy
        run: cargo clippy -- -D warnings

  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
      - name: Install tarpaulin
        run: cargo install cargo-tarpaulin
      - name: Generate coverage
        run: cargo tarpaulin --out Xml
      - name: Upload to codecov
        uses: codecov/codecov-action@v3
```

---

## Dependencies and Crates

### Core Dependencies

```toml
[dependencies]
# Memory and parsing
memmap2 = "0.9"           # Memory-mapped file I/O
goblin = "0.8"            # ELF parsing
memchr = "2.7"            # Fast byte searching

# CLI
clap = { version = "4.5", features = ["derive"] }
indicatif = "0.17"        # Progress bars

# Output formats
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"        # JSON
csv = "1.3"               # CSV
prettytable-rs = "0.10"   # Text tables

# Utilities
chrono = "0.4"            # Date/time
regex = "1.10"            # Pattern matching
thiserror = "1.0"         # Error handling
anyhow = "1.0"            # Error context
log = "0.4"               # Logging facade
env_logger = "0.11"       # Logging implementation

[dev-dependencies]
assert_cmd = "2.0"        # CLI testing
predicates = "3.1"        # Assertions
tempfile = "3.10"         # Temporary files
criterion = "0.5"         # Benchmarking
proptest = "1.4"          # Property testing

[build-dependencies]
# None needed initially
```

### Feature Flags

```toml
[features]
default = ["cli"]
cli = ["clap", "indicatif"]
```

---

## Quality Assurance

### Code Quality Checks

```bash
# Format code
cargo fmt

# Lint code
cargo clippy -- -D warnings

# Security audit
cargo audit

# Check for outdated dependencies
cargo outdated
```

### Pre-commit Hooks

```bash
# .git/hooks/pre-commit
#!/bin/bash
cargo fmt -- --check
cargo clippy -- -D warnings
cargo test
```

---

## Timeline and Milestones

### Week-by-Week Breakdown

| Week | Phase | Milestone | Deliverable |
|------|-------|-----------|-------------|
| 1 | Phase 1 | Address Translation | Working pointer dereferencing |
| 2 | Phase 1 | Symbol System Foundation | Kernel version detection |
| 3 | Phase 2 | External Symbols | System.map/kallsyms support |
| 4 | Phase 2 | DWARF Support | dwarf2json parser + docs |
| 5 | Phase 3 | Output Formats | All 5 formats working |
| 6 | Phase 4 | Process Plugins | PsList, PsTree |
| 7 | Phase 4 | Network & Modules | NetStat, Modules plugins |
| 8 | Phase 5 | CLI Integration | Full-featured CLI |
| 9 | Phase 6 | Advanced Plugins | PsScan, BashHistory |
| 10 | Phase 6 | Optimization | Performance tuning |
| 11 | Phase 7 | Testing | Comprehensive test suite |
| 12 | Phase 7 | Documentation | User docs, release prep |

### Definition of Done

Each phase is complete when:

- [ ] All code implemented and committed
- [ ] Unit tests written and passing (>70% coverage)
- [ ] Integration tests passing
- [ ] Code reviewed and clippy clean
- [ ] Documentation updated
- [ ] Performance benchmarks meet targets

### Release Checklist

- [ ] All tests passing (unit + integration)
- [ ] Code coverage >70%
- [ ] Performance targets met
- [ ] Documentation complete (README, USER_GUIDE, SPECIFICATION)
- [ ] Security audit passed
- [ ] Examples working
- [ ] CHANGELOG updated
- [ ] Version tagged

---

**Next Steps:**
Begin Phase 1, Week 1 - Address Translation Integration

**Success Criteria:**

- Process extraction working on real LIME dumps
- All 5 output formats functional
- >70% test coverage
- <60 second processing time for 1GB dumps
