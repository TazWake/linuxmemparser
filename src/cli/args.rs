//! Command-line argument parsing for the Linux Memory Parser tool
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "linmemparser")]
#[command(about = "Linux Memory Forensics Tool", long_about = None)]
pub struct Cli {
    /// Path to LIME memory dump
    #[arg(value_name = "MEMORY_DUMP")]
    pub memory_dump: std::path::PathBuf,

    /// Plugin to run
    #[command(subcommand)]
    pub plugin: Option<PluginCommand>,

    /// Run all plugins
    #[arg(short, long)]
    pub all: bool,

    /// Path to symbol file (System.map, kallsyms, or dwarf2json)
    #[arg(short, long, value_name = "FILE")]
    pub symbols: Option<std::path::PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    pub format: OutputFormatArg,

    /// Output file (default: stdout)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<std::path::PathBuf>,

    /// Enable debug output
    #[arg(short, long)]
    pub debug: bool,

    /// Enable verbose output (warnings, status messages)
    #[arg(short, long)]
    pub verbose: bool,

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