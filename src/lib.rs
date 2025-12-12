//! Library crate for the Linux Memory Parser
pub mod error;
pub mod kernel;
pub mod memory;
pub mod symbols;
pub mod translation;

// Core modules
pub mod core {
    pub mod dwarf;
    pub mod offsets;
}

// CLI modules
pub mod cli {
    pub mod args;
}

// Plugin modules
pub mod plugins {
    pub mod files;
    pub mod modules;
    pub mod netstat;
    pub mod plugin_trait;
    pub mod pslist;
    pub mod pstree;
}

// Format modules
pub mod formats {
    pub mod csv;
    pub mod json;
    pub mod jsonl;
    pub mod text;
    pub mod traits;
}
