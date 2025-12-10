//! Output format traits for the Linux Memory Parser tool
use crate::kernel::{ProcessInfo, ConnectionInfo, ModuleInfo};
use crate::error::AnalysisError;

/// Trait for output formatters
pub trait OutputFormatter: Send + Sync {
    fn format_processes(&self, processes: &[ProcessInfo]) -> Result<String, AnalysisError>;
    fn format_connections(&self, connections: &[ConnectionInfo]) -> Result<String, AnalysisError>;
    fn format_modules(&self, modules: &[ModuleInfo]) -> Result<String, AnalysisError>;
}

/// Enum for output format types
#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Text,
    Csv,
    Json,
    Jsonl,
}

/// Enum for output destination
#[derive(Debug, Clone)]
pub enum OutputDestination {
    Stdout,
    File(std::path::PathBuf),
}

/// Output writer that combines format and destination
pub struct OutputWriter {
    formatter: Box<dyn OutputFormatter>,
    destination: OutputDestination,
}

impl OutputWriter {
    /// Create a new output writer
    pub fn new(format: OutputFormat, destination: OutputDestination) -> Self {
        let formatter: Box<dyn OutputFormatter> = match format {
            OutputFormat::Text => Box::new(crate::formats::text::TextFormatter),
            OutputFormat::Csv => Box::new(crate::formats::csv::CsvFormatter),
            OutputFormat::Json => Box::new(crate::formats::json::JsonFormatter),
            OutputFormat::Jsonl => Box::new(crate::formats::jsonl::JsonlFormatter),
        };

        Self {
            formatter,
            destination,
        }
    }

    /// Write processes to the configured destination
    pub fn write_processes(&self, processes: &[ProcessInfo]) -> Result<(), AnalysisError> {
        let content = self.formatter.format_processes(processes)?;
        
        match &self.destination {
            OutputDestination::Stdout => {
                println!("{}", content);
            },
            OutputDestination::File(path) => {
                std::fs::write(path, content)?;
            }
        }
        
        Ok(())
    }

    /// Write connections to the configured destination
    pub fn write_connections(&self, connections: &[ConnectionInfo]) -> Result<(), AnalysisError> {
        let content = self.formatter.format_connections(connections)?;
        
        match &self.destination {
            OutputDestination::Stdout => {
                println!("{}", content);
            },
            OutputDestination::File(path) => {
                std::fs::write(path, content)?;
            }
        }
        
        Ok(())
    }

    /// Write modules to the configured destination
    pub fn write_modules(&self, modules: &[ModuleInfo]) -> Result<(), AnalysisError> {
        let content = self.formatter.format_modules(modules)?;
        
        match &self.destination {
            OutputDestination::Stdout => {
                println!("{}", content);
            },
            OutputDestination::File(path) => {
                std::fs::write(path, content)?;
            }
        }
        
        Ok(())
    }
}