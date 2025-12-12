//! Library crate for the Linux Memory Parser

// Allow clippy lints that would require significant refactoring
#![allow(clippy::new_without_default)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::useless_format)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::inherent_to_string)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::unwrap_or_default)]

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
