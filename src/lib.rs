//! Library crate for the Linux Memory Parser
pub mod memory;
pub mod symbols;
pub mod translation;
pub mod kernel;
pub mod error;

// Core modules
pub mod core {
    pub mod offsets;
    pub mod dwarf;
}

// CLI modules  
pub mod cli {
    pub mod args;
}

// Plugin modules
pub mod plugins {
    pub mod plugin_trait;
    pub mod pslist;
    pub mod pstree;
    pub mod netstat;
    pub mod modules;
    pub mod files;
}

// Format modules
pub mod formats {
    pub mod traits;
    pub mod text;
    pub mod csv;
    pub mod json;
    pub mod jsonl;
}