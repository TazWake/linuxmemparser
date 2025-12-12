//! Plugin system trait for the Linux Memory Parser tool
use crate::memory::MemoryMap;
use crate::translation::MemoryTranslator;
use crate::symbols::SymbolResolver;
use crate::kernel::{ProcessInfo, ConnectionInfo, ModuleInfo};
use crate::error::AnalysisError;

/// Analysis context that provides access to all necessary components
pub struct AnalysisContext<'a> {
    pub memory_map: &'a MemoryMap,
    pub translator: &'a MemoryTranslator,
    pub symbol_resolver: &'a SymbolResolver,
    pub init_task_offset: usize,  // File offset of init_task (with KASLR applied)
}

/// Output from plugins - different types of data
pub enum PluginOutput {
    Processes(Vec<ProcessInfo>),
    Connections(Vec<ConnectionInfo>),
    Modules(Vec<ModuleInfo>),
    Tree(String), // For process tree output
    #[allow(dead_code)]
    Custom(String), // For any custom output format
}

/// Trait that all forensic plugins must implement
pub trait ForensicPlugin: Send + Sync {
    /// Get the name of the plugin
    fn name(&self) -> &str;
    
    /// Get a description of what the plugin does
    #[allow(dead_code)]
    fn description(&self) -> &str;
    
    /// Run the plugin with the provided analysis context
    fn run(&self, context: &AnalysisContext) -> Result<PluginOutput, AnalysisError>;
}