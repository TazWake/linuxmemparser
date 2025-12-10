# User Guide - linmemparser

This guide provides practical instructions for using linmemparser to analyze Linux LIME memory dumps.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Symbol Tables](#symbol-tables)
5. [Available Plugins](#available-plugins)
6. [Output Formats](#output-formats)
7. [Common Workflows](#common-workflows)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

## Getting Started

### What You'll Need

- **Memory Dump:** A LIME-format memory capture from a Linux system
- **Rust:** Version 1.56 or later for building from source
- **Symbol File (Optional):** System.map, kallsyms, or dwarf2json file matching your kernel version

### Quick Test

```bash
# Build the tool
cargo build --release

# Test with sample data
./target/release/linmemparser TESTDATA/EXAMPLE.lime
```

## Installation

### Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd linmemparser

# Build release version (recommended)
cargo build --release

# Binary location:
# - Linux/macOS: ./target/release/linmemparser
# - Windows: .\target\release\linuxmemparser.exe
```

### Verifying Installation

```bash
# Run on test data
./target/release/linmemparser TESTDATA/EXAMPLE.lime

# You should see:
# - LIME header detection
# - Memory region parsing
# - Process list extraction (if successful)
```

## Basic Usage

### Current Functionality

The tool currently supports basic process extraction:

```bash
# Basic process list
./target/release/linmemparser memory.lime

# This will display:
# - Process ID (PID)
# - Parent Process ID (PPID)
# - Process name (comm)
# - Process state
# - User ID (UID)
# - Group ID (GID)
# - Start time
# - Command line (basic)
```

### Future Planned Usage

When fully implemented, the tool will support:

```bash
# List running processes
linmemparser memory.lime pslist

# Show process tree
linmemparser memory.lime pstree

# Network connections
linmemparser memory.lime netstat

# Kernel modules
linmemparser memory.lime modules

# Open files
linmemparser memory.lime files

# Run all plugins
linmemparser memory.lime --all
```

## Symbol Tables

### Why Do I Need Symbols?

Linux kernel structures vary between versions. Symbol tables provide:

- Accurate structure field offsets
- Kernel symbol addresses
- Version-specific information

Without symbols, the tool uses heuristic searches and may produce incomplete or inaccurate results.

### Generating Symbol Files

#### Method 1: System.map (Easiest)

If you have access to the system that created the memory dump:

```bash
# Copy from boot directory
sudo cp /boot/System.map-$(uname -r) ./system.map

# Transfer to your analysis machine
# Then use: linmemparser memory.lime pslist --symbols system.map
```

#### Method 2: kallsyms Dump

From the running system:

```bash
# Dump kernel symbols
sudo cat /proc/kallsyms > kallsyms.txt

# Transfer to your analysis machine
# Then use: linmemparser memory.lime pslist --symbols kallsyms.txt
```

#### Method 3: dwarf2json (Most Accurate)

For systems with debug symbols installed:

```bash
# Install dwarf2json
git clone https://github.com/volatilityfoundation/dwarf2json
cd dwarf2json
go build

# Generate symbol file
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > kernel.json

# Use with linmemparser
linmemparser memory.lime pslist --symbols kernel.json
```

#### Debug Symbols by Distribution

**Debian/Ubuntu:**

```bash
sudo apt-get install linux-image-$(uname -r)-dbg
```

**RHEL/CentOS:**

```bash
sudo debuginfo-install kernel
```

**Arch Linux:**

```bash
# Debug packages in separate repository
# See: https://wiki.archlinux.org/title/Debugging
```

### Using Symbol Files

```bash
# With System.map
linmemparser memory.lime pslist --symbols /path/to/System.map

# With kallsyms
linmemparser memory.lime pslist --symbols /path/to/kallsyms.txt

# With dwarf2json
linmemparser memory.lime pslist --symbols /path/to/kernel.json
```

## Available Plugins

### Currently Implemented

#### Process List (Basic - No Plugin System Yet)

Currently, the tool extracts process information automatically. When the plugin system is implemented:

```bash
linmemparser memory.lime pslist
```

**Output includes:**

- PID, PPID
- Process name
- Process state
- UID, GID
- Start time
- Command line (basic)

### Planned Plugins

See [SPECIFICATION.md Section 3.1](SPECIFICATION.md#31-core-analysis-capabilities) for complete plugin specifications.

#### PsTree - Process Tree (Planned)

```bash
linmemparser memory.lime pstree
```

#### PsScan - Dead Process Scan (Planned)

```bash
linmemparser memory.lime psscan
```

#### NetStat - Network Connections (Planned)

```bash
linmemparser memory.lime netstat
```

#### Modules - Kernel Modules (Planned)

```bash
linmemparser memory.lime modules
```

#### Files - Open Files (Planned)

```bash
linmemparser memory.lime files --pid 1234
```

## Output Formats

### Planned Output Options

#### Table Format (Default)

```bash
linmemparser memory.lime pslist
# Human-readable columnar output
```

#### JSON Format

```bash
linmemparser memory.lime pslist --format json
# Structured JSON for programmatic use
```

#### CSV Format

```bash
linmemparser memory.lime pslist --format csv
# CSV for spreadsheet import
```

#### Save to File

```bash
linmemparser memory.lime pslist --output processes.txt
linmemparser memory.lime pslist --format json --output processes.json
```

## Common Workflows

### Workflow 1: Initial Triage

```bash
# 1. Verify memory dump integrity
file memory.lime
# Should show: LIME format or binary data

# 2. Run basic analysis
./target/release/linmemparser memory.lime

# 3. Review process list for suspicious processes
# Look for:
# - Unexpected processes
# - Processes running as root
# - Processes with suspicious names
```

### Workflow 2: Targeted Investigation

When fully implemented:

```bash
# 1. Get process list
linmemparser memory.lime pslist --output procs.json --format json

# 2. Check network connections for suspicious process
linmemparser memory.lime netstat --pid 1234

# 3. Review open files
linmemparser memory.lime files --pid 1234

# 4. Check loaded modules for rootkits
linmemparser memory.lime modules
```

### Workflow 3: Comparing to Known Good

```bash
# 1. Analyze suspicious system
linmemparser suspicious.lime pslist > suspicious-procs.txt

# 2. Analyze known-good reference system
linmemparser reference.lime pslist > reference-procs.txt

# 3. Compare outputs
diff suspicious-procs.txt reference-procs.txt
```

## Troubleshooting

### Issue: "Could not find init_task in memory"

**Symptoms:** Tool cannot locate the init process to start walking the process list.

**Possible Causes:**

1. Memory dump is corrupted or incomplete
2. Kernel structures differ from expected offsets
3. LIME header is malformed

**Solutions:**

```bash
# 1. Verify LIME dump is valid
hexdump -C memory.lime | head -20
# Look for LIME magic bytes at start

# 2. Check file is not compressed
file memory.lime

# 3. Try with symbol file (when implemented)
linmemparser memory.lime pslist --symbols System.map

# 4. Check kernel version
strings memory.lime | grep "Linux version"
```

### Issue: "No processes found" or "Few processes found"

**Symptoms:** Tool finds init_task but extracts few or no processes.

**Possible Causes:**

1. Virtual-to-physical address translation issues
2. Incorrect structure offsets
3. Corrupted process list

**Solutions:**

```bash
# 1. Enable verbose output (when implemented)
linmemparser memory.lime pslist -vv

# 2. Use symbol file matching kernel version
# Check kernel version first:
strings memory.lime | grep "Linux version"
# Then use matching symbol file

# 3. Try different kernel offset database (when implemented)
linmemparser memory.lime pslist --kernel-version 5.15
```

### Issue: "Invalid or corrupted process information"

**Symptoms:** Process names contain garbage characters, PIDs are unrealistic.

**Possible Causes:**

1. Wrong structure field offsets
2. Endianness mismatch
3. Memory corruption

**Solutions:**

```bash
# 1. Verify symbol file matches kernel
# 2. Check architecture matches (x86-64 vs ARM64)
# 3. Report issue with:
#    - Kernel version from memory dump
#    - Architecture
#    - Sample output showing corruption
```

### Issue: Performance Problems

**Symptoms:** Analysis takes very long time or uses excessive memory.

**Current Status:** Not yet optimized. Expected in Phase 5-7.

**Workarounds:**

```bash
# 1. Use release build (much faster than debug)
cargo build --release

# 2. Run on system with adequate RAM
# Recommend: 2x memory dump size + 2GB

# 3. Close other applications

# 4. For very large dumps (>16GB), consider:
#    - Running on dedicated analysis workstation
#    - Using SSD for better I/O performance
```

## Best Practices

### Memory Acquisition

1. **Use LIME for acquisition:**

   ```bash
   # On target system
   sudo insmod lime.ko "path=/tmp/memory.lime format=lime"
   ```

2. **Capture symbol information immediately:**

   ```bash
   sudo cp /boot/System.map-$(uname -r) /tmp/
   sudo cat /proc/kallsyms > /tmp/kallsyms.txt
   ```

3. **Document system information:**

   ```bash
   uname -a > system-info.txt
   lsmod > loaded-modules.txt
   ps aux > running-processes.txt
   netstat -tulpn > network-connections.txt
   ```

### Analysis Environment

1. **Work on copies, not originals**
2. **Use dedicated analysis workstation if possible**
3. **Document analysis steps and findings**
4. **Verify tool version and options used**
5. **Save all output for reports**

### Reporting Findings

When documenting findings:

```bash
# 1. Tool version
./target/release/linmemparser --version

# 2. Command used
echo "linmemparser memory.lime pslist --symbols System.map" > analysis-commands.txt

# 3. Kernel version from dump
strings memory.lime | grep "Linux version" > kernel-version.txt

# 4. Save all output
linmemparser memory.lime pslist --output analysis-results.txt
```

## Advanced Topics

### Understanding LIME Format

LIME dumps contain:

- Header with magic bytes
- Multiple memory regions (physical RAM segments)
- Each region has: start address, size, data

The tool parses this to build a memory map for address translation.

### Kernel Structure Basics

Key structures parsed:

- **task_struct:** Process information
- **cred:** User credentials
- **mm_struct:** Memory mappings
- **files_struct:** Open files
- **net:** Network information

### Symbol Resolution Process

1. Tool searches for kallsyms in memory
2. If not found, loads external symbol file
3. Uses symbols to find structure field offsets
4. Falls back to offset database for known kernel versions

## Getting Help

### Resources

- **Technical Specification:** [SPECIFICATION.md](SPECIFICATION.md)
- **Development Guide:** [CLAUDE.md](CLAUDE.md)
- **Project README:** [README.md](README.md)

### Reporting Issues

When reporting problems, include:

1. Tool version and build type (debug/release)
2. Command used
3. Kernel version from memory dump
4. Architecture (x86-64, ARM64, etc.)
5. Error messages (full output)
6. Sample data if possible (anonymized)

### Community

- GitHub Issues: For bug reports and feature requests
- Discussions: For questions and general discussion

---

**Last Updated:** 2025-12-10
**Version:** 0.1.0 (Early Development)
