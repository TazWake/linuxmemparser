# Linux Memory Forensics Tool - Technical Specification

**Version:** 1.0  
**Date:** 2025-12-10  
**Status:** Draft  

## 1. Executive Summary

This document specifies the requirements and design for a Linux memory forensics tool that parses LIME-format memory captures and extracts forensically relevant artifacts. The tool aims to provide capabilities comparable to Volatility 3 for Linux memory analysis, with a focus on performance, usability, and extensibility.

**Language:** Rust (confirmed - leveraging safety, performance, and rich ecosystem)
**License:** Apache 2.0 or MIT (permissive open source)
**Target Users:** Digital forensics investigators, incident responders, security researchers

**See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for detailed phase-by-phase development plan.**  

## 2. Project Goals

### 2.1 Primary Objectives

1. **Parse LIME memory dumps** with robust error handling
2. **Extract forensic artifacts** comparable to Volatility 3's Linux capabilities
3. **Provide flexible output** in multiple formats (human-readable, JSON, CSV)
4. **Support symbol resolution** from both in-memory and external sources
5. **Enable modular analysis** through plugin architecture
6. **Deliver high performance** on large memory images (multi-GB files)

### 2.2 Success Criteria

- Successfully parse LIME captures from kernel versions 4.x, 5.x, and 6.x
- Extract process, network, and file system artifacts with >95% accuracy
- Process 8GB memory image in <5 minutes on modern hardware
- Provide clear documentation for symbol table generation and usage
- Support batch analysis and automation through scripting

## 3. Functional Requirements

### 3.1 Core Analysis Capabilities

#### 3.1.1 Process Analysis

##### FR-PROC-001: Running Process List

- Extract all active processes from kernel task list
- Display: PID, PPID, name, state, start time, UID/GID, priority
- Support filtering by PID, name, UID, state
- **Priority:** Critical

##### FR-PROC-002: Process Tree Visualization

- Build and display parent-child process hierarchy
- Show process relationships in tree format
- Include all metadata from FR-PROC-001
- **Priority:** High

##### FR-PROC-003: Dead/Exited Process Scan

- Scan entire memory for task_struct signatures
- Identify processes not in active task list (recently exited)
- Mark as "inactive" or "terminated" with last known state
- **Priority:** Medium

##### FR-PROC-004: Command Line Recovery

- Extract full command line arguments for each process
- Handle truncated/partial arguments gracefully
- Display environment variables if available in mm_struct
- **Priority:** High

##### FR-PROC-005: Process Memory Maps

- List memory-mapped regions for each process (VMA structures)
- Show: start/end addresses, permissions, file backing, offset
- Identify anonymous vs file-backed mappings
- **Priority:** Medium

#### 3.1.2 Network Analysis

##### FR-NET-001: Active Network Connections

- Extract TCP connections (ESTABLISHED, LISTEN, etc.)
- Extract UDP sockets
- Display: protocol, local/remote IP:port, state, PID, inode
- **Priority:** High

##### FR-NET-002: Network Statistics

- Count connections by state, protocol, process
- Identify suspicious ports or connection patterns
- **Priority:** Low

##### FR-NET-003: Unix Domain Sockets

- Extract Unix sockets from kernel structures
- Show socket path, type (STREAM/DGRAM), connected processes
- **Priority:** Medium

#### 3.1.3 File System Artifacts

##### FR-FS-001: Open File Handles

- Extract file descriptors for each process
- Display: FD number, file path, flags, position
- **Priority:** High

##### FR-FS-002: Loaded Kernel Modules

- List all loaded kernel modules (LKMs)
- Show: name, size, load address, used-by count
- Detect hidden modules (not in module list)
- **Priority:** High

##### FR-FS-003: Mount Points

- Extract mounted filesystems from kernel
- Display: device, mount point, filesystem type, flags
- **Priority:** Medium

#### 3.1.4 Memory Artifacts

##### FR-MEM-001: Kernel Messages (dmesg)

- Extract kernel ring buffer contents
- Display with timestamps if available
- **Priority:** Low

##### FR-MEM-002: Shell History Extraction

- Scan for bash/zsh/sh history in process memory
- Reconstruct command history per user/process
- **Priority:** Medium

##### FR-MEM-003: Credential Structures

- Extract credential information (uid, gid, capabilities)
- Identify privilege escalation artifacts
- **Priority:** Medium

#### 3.1.5 Security Analysis

##### FR-SEC-001: Rootkit Detection

- Compare kernel function pointers against known-good values
- Detect syscall table hooks
- Identify suspicious kernel modules
- **Priority:** Medium

##### FR-SEC-002: eBPF Programs

- Extract loaded eBPF programs
- Show program type, attachment points, bytecode
- **Priority:** Low (future enhancement)

### 3.2 Symbol Resolution

#### FR-SYM-001: In-Memory Symbol Extraction

- Automatically detect and parse kallsyms from memory
- Use as primary symbol source if available
- **Priority:** High

#### FR-SYM-002: External Symbol Files

- Support System.map files (standard kernel symbol format)
- Support /proc/kallsyms dumps
- Support dwarf2json format (Volatility 3 compatible)
- **Priority:** Critical

#### FR-SYM-003: Kernel Version Detection

- Auto-detect kernel version from linux_banner string
- Display detected version to user
- Warn if symbol table version mismatch detected
- **Priority:** High

#### FR-SYM-004: Structure Offset Database

- Maintain database of common structure offsets per kernel version
- Use as fallback when symbols unavailable
- **Priority:** Medium

### 3.3 User Interface

#### FR-UI-001: Command-Line Interface

- Support subcommand structure: `linmemparser <dump.lime> <plugin> [options]`
- Example plugins: `pslist`, `pstree`, `netstat`, `modules`, `files`
- **Priority:** Critical

#### FR-UI-002: Plugin Selection

- `--plugin <name>` or `<name>` positional argument
- `--all` runs all available plugins
- `--list-plugins` shows available analysis modules
- **Priority:** High

#### FR-UI-003: Output Formats

- `--format [text|json|jsonl|csv]` for structured output
- Supported formats:
  - **text:** Human-readable table format (default, to stdout)
  - **json:** Pretty-printed JSON with metadata
  - **jsonl:** JSON Lines format (one object per line)
  - **csv:** Comma-separated values for spreadsheet import
- `--output <file>` to save results to file (optional, default stdout)
- All formats support both stdout and file output
- **Priority:** Critical

#### FR-UI-004: Filtering and Search

- Support common filters: `--pid`, `--name`, `--uid`
- Regex support for pattern matching
- **Priority:** Medium

#### FR-UI-005: Verbosity Control

- `-v/--verbose` for debug output
- `-q/--quiet` for minimal output
- Progress indicators for long-running operations
- **Priority:** Low

### 3.4 Plugin System

#### FR-PLUG-001: Plugin Architecture

- Define stable plugin API/trait interface
- Plugins implement standard trait with methods:
  - `name()` - plugin identifier
  - `description()` - human-readable description
  - `run(context)` - execute analysis, return results
- **Priority:** Medium

#### FR-PLUG-002: Built-in Plugins

- All core functionality implemented as plugins
- Ensures API is complete and usable
- **Priority:** High

#### FR-PLUG-003: External Plugin Loading

- Support loading .so/.dll plugin libraries (future)
- Sandbox plugin execution for security
- **Priority:** Low (future enhancement)

## 4. Non-Functional Requirements

### 4.1 Performance

**NFR-PERF-001:** Process 1GB memory image in <60 seconds on mid-range hardware (Intel i5, 8GB RAM)

**NFR-PERF-002:** Memory usage should not exceed 2x the input file size

**NFR-PERF-003:** Use memory-mapped I/O for efficient large file handling

### 4.2 Reliability

**NFR-REL-001:** Gracefully handle corrupted or incomplete memory dumps

**NFR-REL-002:** Never crash on invalid data (return errors instead)

**NFR-REL-003:** Provide meaningful error messages with context

**NFR-REL-004:** Validate all pointer dereferences before access

### 4.3 Usability

**NFR-USE-001:** Comprehensive documentation including:

- User guide with examples
- Symbol table generation tutorial
- Plugin development guide
- Troubleshooting section

**NFR-USE-002:** Sensible defaults requiring minimal configuration

**NFR-USE-003:** Clear, actionable error messages

### 4.4 Maintainability

**NFR-MAIN-001:** Modular codebase with clear separation of concerns

**NFR-MAIN-002:** Comprehensive unit tests (>70% code coverage)

**NFR-MAIN-003:** Integration tests with real LIME dumps

**NFR-MAIN-004:** Code documentation with rustdoc comments

### 4.5 Compatibility

**NFR-COMPAT-001:** Support x86-64 architecture (primary)

**NFR-COMPAT-002:** Support ARM64 architecture (secondary, future)

**NFR-COMPAT-003:** Run on Linux, Windows, macOS hosts

**NFR-COMPAT-004:** Parse memory dumps from Linux kernel 4.x, 5.x, 6.x

## 5. Technical Architecture

### 5.1 System Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                     CLI Interface Layer                      │
│  (Argument parsing, output formatting, user interaction)     │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────┴───────────────────────────────┐
│                    Plugin Manager Layer                      │
│  (Plugin discovery, loading, execution, result aggregation)  │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────┴───────────────────────────────┐
│                   Analysis Plugins Layer                     │
│  [Process] [Network] [Files] [Modules] [Memory] [Security]  │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────┴───────────────────────────────┐
│                  Core Analysis Framework                     │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐    │
│  │   Symbol    │  │   Memory    │  │   Kernel Data    │    │
│  │  Resolver   │  │ Translator  │  │ Structure Parser │    │
│  └─────────────┘  └─────────────┘  └──────────────────┘    │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────┴───────────────────────────────┐
│                  Memory Access Layer                         │
│  (LIME parser, memory-mapped I/O, region management)         │
└──────────────────────────────────────────────────────────────┘
```

### 5.2 Core Components

#### 5.2.1 Memory Access Layer

- **MemoryMap:** Memory-mapped file access (memmap2 crate)
- **LimeParser:** LIME format header and region parsing
- **MemoryRegion:** Physical memory region representation

#### 5.2.2 Core Analysis Framework

- **SymbolResolver:** Symbol table management and lookup
- **MemoryTranslator:** Virtual-to-physical address translation
- **KernelParser:** Low-level structure parsing utilities
- **StructureDatabase:** Kernel structure offset database

#### 5.2.3 Analysis Plugins

Each plugin implements the `ForensicPlugin` trait:

```rust
pub trait ForensicPlugin {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn run(&self, context: &AnalysisContext) -> Result<PluginOutput, AnalysisError>;
}
```

Planned plugins:

- **PsList:** Running processes
- **PsTree:** Process hierarchy
- **PsScan:** Dead process scan
- **NetStat:** Network connections
- **Modules:** Kernel modules
- **Files:** Open files
- **MountInfo:** Mount points
- **BashHistory:** Shell command history

#### 5.2.4 Plugin Manager

- Plugin registration and discovery
- Plugin execution orchestration
- Result collection and formatting

#### 5.2.5 CLI Interface

- Argument parsing (clap crate)
- Output formatting (prettytable, serde_json)
- Progress indicators

### 5.3 Data Flow

1. **Initialization:**
   - Parse command-line arguments
   - Open and memory-map LIME file
   - Parse LIME header, extract memory regions
   - Initialize MemoryTranslator with regions

2. **Symbol Resolution:**
   - Attempt in-memory kallsyms extraction
   - If provided, load external symbol file
   - Auto-detect kernel version
   - Load structure offset database for detected version

3. **Plugin Execution:**
   - Instantiate requested plugin(s)
   - Pass AnalysisContext to plugin
   - Plugin performs analysis using core framework
   - Collect results

4. **Output:**
   - Format results according to --format option
   - Write to stdout or --output file
   - Report any errors or warnings

### 5.4 Key Algorithms

#### 5.4.1 Process List Walking

```text
1. Locate init_task symbol or heuristically search for PID 0/1
2. Read task_struct at init_task address
3. Follow tasks.next linked list pointer
4. For each task_struct:
   a. Translate virtual address to file offset
   b. Extract process fields (PID, comm, cred, etc.)
   c. Dereference pointers (parent, mm, cred) with translation
   d. Add to results list
5. Stop when returning to init_task (circular list complete)
```

#### 5.4.2 Virtual Address Translation

```text
1. Input: virtual address (VA)
2. Iterate through memory regions:
   a. Check if VA >= region.start AND VA < region.end
   b. If match: return (VA - region.start) + region.file_offset
3. If no match: return None (address not in capture)
```

#### 5.4.3 Symbol Resolution

```text
1. Try in-memory kallsyms:
   a. Search for kallsyms markers in memory
   b. Parse symbol table if found
2. If not found or incomplete:
   a. Load external symbol file (System.map or dwarf2json)
   b. Parse and store in symbol table
3. For structure field lookups:
   a. Check if symbol exists in table
   b. If not, consult structure offset database
   c. Use kernel version to select correct offsets
```

## 6. Symbol Table Requirements

### 6.1 Symbol Table Formats

The tool must support three symbol table formats:

#### 6.1.1 System.map Format

Standard Linux kernel symbol map:

```text
ffffffffa1c00000 T _text
ffffffffa1c00100 T startup_64
ffffffffa1e00000 D init_task
```

**Generation:**

```bash
# From kernel source after build:
cp /boot/System.map-$(uname -r) ./system.map

# Or from running system:
sudo cat /proc/kallsyms > kallsyms.txt
```

#### 6.1.2 kallsyms Format

In-memory or /proc/kallsyms dump:

```text
ffffffffa1c00000 t _text
ffffffffa1c00100 t startup_64
ffffffffa1e00000 d init_task
```

Same format as System.map, tool treats identically.

#### 6.1.3 dwarf2json Format (Volatility 3 Compatible)

JSON format with structure definitions and offsets:

```json
{
  "symbols": {
    "init_task": 0xffffffffa1e00000,
    "linux_banner": 0xffffffffa2000000
  },
  "user_types": {
    "task_struct": {
      "size": 9216,
      "fields": {
        "pid": {"offset": 800, "type": "int"},
        "comm": {"offset": 1176, "type": "char[16]"}
      }
    }
  }
}
```

**Generation:**

```bash
# Install dwarf2json
git clone https://github.com/volatilityfoundation/dwarf2json
cd dwarf2json && go build

# Generate from kernel with debug symbols
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > kernel.json
```

### 6.2 Symbol Table Documentation

The tool documentation must include:

1. **Symbol Generation Tutorial**
   - Step-by-step guide for each format
   - OS-specific instructions (Debian, RHEL, Arch, etc.)
   - Handling custom kernels

2. **Symbol Usage**
   - Command-line flag: `--symbols <file>`
   - Auto-detection of format from file content
   - Fallback behavior when symbols unavailable

3. **Troubleshooting**
   - Kernel version mismatches
   - Missing debug symbols
   - Partial symbol tables

## 7. Output Formats

### 7.1 Table Format (Default)

Human-readable columnar output:

```text
PID    PPID   UID    GID    COMM             STATE      START_TIME           CMDLINE
1      0      0      0      systemd          RUNNING    2025-01-15 10:23:11  /sbin/init
245    1      0      0      systemd-journal  RUNNING    2025-01-15 10:23:12  /lib/systemd/systemd-journald
```

### 7.2 JSON Format

Structured JSON for programmatic consumption:

```json
{
  "plugin": "pslist",
  "timestamp": "2025-12-10T15:30:00Z",
  "results": [
    {
      "pid": 1,
      "ppid": 0,
      "uid": 0,
      "gid": 0,
      "comm": "systemd",
      "state": "RUNNING",
      "start_time": 1736939391,
      "cmdline": "/sbin/init"
    }
  ]
}
```

### 7.3 CSV Format

For spreadsheet import:

```csv
pid,ppid,uid,gid,comm,state,start_time,cmdline
1,0,0,0,systemd,RUNNING,1736939391,/sbin/init
245,1,0,0,systemd-journal,RUNNING,1736939392,/lib/systemd/systemd-journald
```

### 7.4 JSONL (JSON Lines) Format

One JSON object per line for streaming/batch processing:

```jsonl
{"pid":1,"ppid":0,"uid":0,"gid":0,"comm":"systemd","state":"RUNNING","start_time":1736939391,"cmdline":"/sbin/init"}
{"pid":245,"ppid":1,"uid":0,"gid":0,"comm":"systemd-journal","state":"RUNNING","start_time":1736939392,"cmdline":"/lib/systemd/systemd-journald"}
```

**Use case:** Processing large result sets with stream processors (jq, grep, etc.)

## 8. Command-Line Interface

### 8.1 Basic Usage

```bash
# List all running processes
linmemparser memory.lime pslist

# Show process tree
linmemparser memory.lime pstree

# Network connections
linmemparser memory.lime netstat

# Run all plugins
linmemparser memory.lime --all

# Output as JSON
linmemparser memory.lime pslist --format json

# With external symbols
linmemparser memory.lime pslist --symbols /path/to/System.map
```

### 8.2 Advanced Usage

```bash
# Filter by PID
linmemparser memory.lime pslist --pid 1234

# Filter by process name (regex)
linmemparser memory.lime pslist --name "ssh.*"

# Save output to file
linmemparser memory.lime pslist --output processes.json --format json

# Verbose debug output
linmemparser memory.lime pslist -vv

# List available plugins
linmemparser --list-plugins

# Show version and capabilities
linmemparser --version
```

### 8.3 Full Command Syntax

```bash
linmemparser [OPTIONS] <MEMORY_DUMP> [PLUGIN] [PLUGIN_OPTIONS]

ARGS:
    <MEMORY_DUMP>    Path to LIME format memory dump file
    [PLUGIN]         Plugin to run (pslist, pstree, netstat, etc.)

OPTIONS:
    -a, --all                    Run all available plugins
    -s, --symbols <FILE>         Path to symbol file (System.map, kallsyms, or dwarf2json)
    -f, --format <FORMAT>        Output format: text, json, jsonl, csv [default: text]
    -o, --output <FILE>          Write output to file instead of stdout
    -v, --verbose                Increase verbosity (-v, -vv, -vvv)
    -q, --quiet                  Suppress non-essential output
    -l, --list-plugins           List available analysis plugins
    -h, --help                   Print help information
    -V, --version                Print version information

PLUGIN OPTIONS (plugin-specific):
    --pid <PID>                  Filter by process ID
    --name <PATTERN>             Filter by process name (regex)
    --uid <UID>                  Filter by user ID
    --state <STATE>              Filter by process state

OUTPUT FORMAT DETAILS:
    text     Human-readable table (default, auto-formats for terminal width)
    json     Pretty-printed JSON with metadata (indent=2)
    jsonl    JSON Lines format (one object per line, no pretty-printing)
    csv      RFC 4180 compliant CSV with header row
```

## 9. Implementation Phases

### Phase 1: Core Infrastructure Enhancement (Weeks 1-2)

- Fix virtual-to-physical address translation integration
- Implement robust init_task location
- Create structure offset database for kernel 4.x, 5.x, 6.x
- Comprehensive error handling
- **Deliverable:** Reliable process extraction from real LIME dumps

### Phase 2: Symbol System (Weeks 3-4)

- Implement System.map parser
- Implement kallsyms parser
- Implement dwarf2json parser
- Auto-detect kernel version from linux_banner
- Create symbol generation documentation
- **Deliverable:** Multi-format symbol support with docs

### Phase 3: Output Format System (Week 5)

- Implement text/table formatter (prettytable-rs)
- Implement CSV formatter (csv crate)
- Implement JSON formatter (serde_json)
- Implement JSONL formatter
- Output writer with stdout and file support
- **Deliverable:** All 5 output formats working with tests

### Phase 4: Core Plugins (Weeks 6-7)

- PsList plugin (running processes)
- PsTree plugin (process hierarchy)
- NetStat plugin (network connections)
- Modules plugin (kernel modules)
- Files plugin (open file handles)
- **Deliverable:** 5 core analysis plugins

### Phase 5: CLI Integration (Week 8)

- Command-line argument parsing (clap)
- Plugin manager implementation
- Table/JSON/CSV output formatters
- Progress indicators
- **Deliverable:** Full-featured CLI interface

### Phase 6: Advanced Analysis (Weeks 9-10)

- PsScan plugin (dead process scan)
- MountInfo plugin
- BashHistory plugin
- Credential analysis
- **Deliverable:** Advanced forensic capabilities

### Phase 7: Testing & Documentation (Weeks 11-12)

- Unit test suite (>70% coverage)
- Integration tests with diverse LIME dumps
- User guide with examples
- Plugin development guide
- Performance benchmarking
- **Deliverable:** Production-ready release

### Phase 8: Future Enhancements (Post-Release)

- External plugin loading system
- ARM64 architecture support
- eBPF analysis
- Rootkit detection
- GUI interface (optional)

## 10. Testing Strategy

### 10.1 Unit Tests

- Memory parsing functions
- Symbol resolution logic
- Address translation algorithms
- Structure field extraction
- **Target:** 70% code coverage

### 10.2 Integration Tests

- End-to-end analysis on real LIME dumps
- Multiple kernel versions (4.19, 5.4, 5.15, 6.1)
- Corrupted/truncated dumps
- Missing symbol scenarios

### 10.3 Test Data

- Curated LIME dumps in TESTDATA/ directory
- Minimal synthetic dumps for specific test cases
- Known-good output baselines for comparison

### 10.4 Performance Tests

- Benchmark with 1GB, 4GB, 8GB, 16GB dumps
- Memory usage profiling
- Identify and optimize bottlenecks

## 11. Success Metrics

### 11.1 Functional Metrics

- Extract processes with >95% accuracy vs ground truth
- Parse network connections with >90% accuracy
- Handle 100% of test LIME dumps without crashing
- Support kernel versions 4.x, 5.x, 6.x

### 11.2 Performance Metrics

- Process 1GB dump in <60 seconds
- Process 8GB dump in <5 minutes
- Memory usage <2x input file size

### 11.3 Usability Metrics

- Documentation covers all common use cases
- Symbol generation tutorial tested on 3+ distros
- Clear error messages for all common failures

## 12. Risk Analysis

### 12.1 Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Kernel structure changes break parsing | High | Medium | Structure offset database, dwarf2json support |
| Performance issues with large dumps | Medium | Low | Memory-mapped I/O, lazy evaluation |
| Incomplete symbol tables | Medium | High | Multiple symbol formats, fallback offsets |
| Corrupted memory dumps | Low | Medium | Extensive validation, graceful degradation |

### 12.2 Project Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Scope creep beyond Volatility parity | Medium | Medium | Clear feature prioritization, phased releases |
| Rust expertise gaps | Low | Low | Well-documented codebase, community support |
| Lack of diverse test data | High | Medium | Community contributions, synthetic test generation |

## 13. Open Questions

1. **Language Choice:** Is Rust the best choice, or should we consider Python (Volatility compatibility) or C (performance)?
   - **Recommendation:** Stay with Rust. Performance + safety benefits outweigh Python compatibility concerns.

2. **Plugin Distribution:** How should external plugins be distributed and loaded?
   - **Recommendation:** Phase 7 enhancement, use dynamic library loading with safety sandboxing.

3. **GUI Interface:** Should we include a graphical interface?
   - **Recommendation:** CLI first, consider Volatility Workbench-style GUI in future.

4. **Volatility 3 Compatibility:** Should we aim for plugin/symbol format compatibility?
   - **Recommendation:** Support dwarf2json format for symbols, but independent plugin system.

## 14. References

- [Volatility 3 Documentation](https://volatilityfoundation.org/the-volatility-framework/)
- [LIME (Linux Memory Extractor)](https://github.com/504ensicsLabs/LiME)
- [dwarf2json Tool](https://github.com/volatilityfoundation/dwarf2json)
- [Linux Kernel Documentation](https://www.kernel.org/doc/html/latest/)
- [Efficient Linux Memory Forensics with Volatility 3 (2025 Edition)](https://blog.ivanov.ninja/forensics-with-volatility-3-2025-edition/)
- [Volatility 3: The Next Generation of Memory Forensics](https://medium.com/@shehabahmed485/volatility-3-the-next-generation-of-memory-forensics-22e7399ccea3)

## 15. Appendices

### Appendix A: Volatility 3 Linux Plugin Comparison

| Volatility 3 Plugin | Equivalent Feature | Priority |
|---------------------|-------------------|----------|
| linux.pslist | PsList plugin | Critical |
| linux.pstree | PsTree plugin | High |
| linux.psaux | PsList with full details | High |
| linux.lsof | Files plugin | High |
| linux.netstat | NetStat plugin | High |
| linux.lsmod | Modules plugin | High |
| linux.mount | MountInfo plugin | Medium |
| linux.bash | BashHistory plugin | Medium |
| linux.proc_maps | MemoryMaps plugin | Medium |
| linux.hidden_modules | Modules (hidden detection) | Medium |
| linux.check_syscall | Rootkit detection | Low |
| linux.check_creds | Credential analysis | Low |
| linux.keyboard_notifiers | Security analysis | Low |

### Appendix B: Structure Offset Examples

Common task_struct offsets (x86-64):

| Kernel Version | PID Offset | COMM Offset | Parent Offset | Cred Offset |
|----------------|------------|-------------|---------------|-------------|
| 4.19.x | 0x318 | 0x498 | 0x310 | 0x440 |
| 5.4.x | 0x320 | 0x4a0 | 0x318 | 0x448 |
| 5.15.x | 0x328 | 0x4a8 | 0x320 | 0x450 |
| 6.1.x | 0x330 | 0x4b0 | 0x328 | 0x458 |

*Note: Offsets vary based on kernel config options. Use dwarf2json for accurate offsets.*

### Appendix C: Error Handling Strategy

All functions return `Result<T, AnalysisError>` where:

```rust
pub enum AnalysisError {
    IoError(std::io::Error),
    MemoryMapError(String),
    ParseError(String),
    SymbolNotFound(String),
    AddressTranslationFailed(u64),
    InvalidStructure(String),
    PluginError(String),
}
```

Error messages include:

- Context (what operation failed)
- Location (file offset, virtual address)
- Suggestion (how to resolve)

Example: `"Failed to translate virtual address 0xffffffff81e00000: Address not in any memory region. Check LIME header parsing."`

---

**Document Status:** Draft for review  
**Next Review Date:** Upon Phase 1 completion  
**Approval Required:** Project lead, technical architect  
