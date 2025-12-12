# Linux Memory Parser (linuxmemparser)

[![CI](https://github.com/TazWake/linuxmemparser/workflows/CI/badge.svg)](https://github.com/TazWake/linuxmemparser/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/release/TazWake/linuxmemparser.svg)](https://github.com/TazWake/linuxmemparser/releases/latest)
[![Coverage](https://codecov.io/gh/TazWake/linuxmemparser/branch/main/graph/badge.svg)](https://codecov.io/gh/TazWake/linuxmemparser)

## Project Summary

**linuxmemparser** is a forensic analysis tool written in Rust for parsing and analyzing Linux LIME (Linux Memory Extractor) memory dumps. Designed for digital forensics investigators, incident responders, and security researchers, it extracts forensically relevant artifacts from memory captures with a focus on performance, reliability, and ease of use.

### Key Features

- **Process Analysis**: Extract running processes, process trees, command-line arguments, and dead/exited processes
- **Network Analysis**: Identify active TCP/UDP connections and listening sockets
- **Kernel Module Detection**: List loaded kernel modules
- **File System Artifacts**: Analyze open files and mount points
- **Flexible Output Formats**: Support for table, JSON, CSV, and JSONL output formats
- **Multi-format Symbol Support**: Works with System.map, kallsyms, and dwarf2json (Volatility 3 compatible)
- **Plugin Architecture**: Extensible design for custom analysis modules

### Tooling & Technology Stack

**Language & Runtime:**

- Rust 2021 Edition
- Cargo package manager

**Core Dependencies:**

- `memmap2` - Memory-mapped file I/O for efficient large file handling
- `goblin` - ELF and binary format parsing
- `memchr` - Fast byte searching algorithms
- `regex` - Pattern matching for filtering and searching

**CLI & User Interface:**

- `clap` - Modern command-line argument parsing with derive macros
- `indicatif` - Progress indicators for long-running operations

**Output & Serialization:**

- `serde` / `serde_json` - JSON serialization
- `csv` - CSV formatting
- `prettytable-rs` - Formatted table output

**Utilities:**

- `chrono` - Date and time handling
- `log` / `env_logger` - Structured logging
- `thiserror` / `anyhow` - Comprehensive error handling

**Development & Testing:**

- `criterion` - Benchmarking framework
- `assert_cmd` / `predicates` - Integration testing utilities
- `tempfile` - Temporary file handling for tests
