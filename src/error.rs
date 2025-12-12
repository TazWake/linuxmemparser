//! Custom error types for the application
use std::fmt;

#[derive(Debug)]
pub enum AnalysisError {
    IoError(std::io::Error),
    #[allow(dead_code)]
    MemoryMapError(String),
    #[allow(dead_code)]
    ParseError(String),
    SymbolError(String),
    SymbolNotFound(String),
    #[allow(dead_code)]
    TranslationError(String),
    #[allow(dead_code)]
    AddressTranslationFailed(u64),
    #[allow(dead_code)]
    InvalidStructure(String),
    PluginError(String),
    SerdeJsonError(serde_json::Error),
    RegexError(regex::Error),
    CsvError(csv::Error),
    CsvIntoInnerError(csv::IntoInnerError<csv::Writer<Vec<u8>>>),
    FromUtf8Error(std::string::FromUtf8Error),
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AnalysisError::IoError(e) => write!(f, "IO error: {}", e),
            AnalysisError::MemoryMapError(msg) => write!(f, "Memory map error: {}", msg),
            AnalysisError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            AnalysisError::SymbolError(msg) => write!(f, "Symbol error: {}", msg),
            AnalysisError::SymbolNotFound(msg) => write!(f, "Symbol not found: {}", msg),
            AnalysisError::TranslationError(msg) => write!(f, "Translation error: {}", msg),
            AnalysisError::AddressTranslationFailed(addr) => {
                write!(f, "Address translation failed: 0x{:x}", addr)
            }
            AnalysisError::InvalidStructure(msg) => write!(f, "Invalid structure: {}", msg),
            AnalysisError::PluginError(msg) => write!(f, "Plugin error: {}", msg),
            AnalysisError::SerdeJsonError(e) => write!(f, "JSON error: {}", e),
            AnalysisError::RegexError(e) => write!(f, "Regex error: {}", e),
            AnalysisError::CsvError(e) => write!(f, "CSV error: {}", e),
            AnalysisError::CsvIntoInnerError(e) => write!(f, "CSV into_inner error: {}", e),
            AnalysisError::FromUtf8Error(e) => write!(f, "UTF-8 conversion error: {}", e),
        }
    }
}

impl std::error::Error for AnalysisError {}

impl From<std::io::Error> for AnalysisError {
    fn from(error: std::io::Error) -> Self {
        AnalysisError::IoError(error)
    }
}

impl From<serde_json::Error> for AnalysisError {
    fn from(error: serde_json::Error) -> Self {
        AnalysisError::SerdeJsonError(error)
    }
}

impl From<regex::Error> for AnalysisError {
    fn from(error: regex::Error) -> Self {
        AnalysisError::RegexError(error)
    }
}

impl From<csv::Error> for AnalysisError {
    fn from(error: csv::Error) -> Self {
        AnalysisError::CsvError(error)
    }
}

impl From<csv::IntoInnerError<csv::Writer<Vec<u8>>>> for AnalysisError {
    fn from(error: csv::IntoInnerError<csv::Writer<Vec<u8>>>) -> Self {
        AnalysisError::CsvIntoInnerError(error)
    }
}

impl From<std::string::FromUtf8Error> for AnalysisError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        AnalysisError::FromUtf8Error(error)
    }
}
