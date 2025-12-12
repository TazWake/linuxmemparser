//! dwarf2json parser for loading Volatility 3 compatible symbol files
use std::collections::HashMap;
use std::fs;
use serde::Deserialize;
use serde_json::Value;
use crate::error::AnalysisError;

/// Symbol entry in the new format (6.x)
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SymbolEntryNew {
    #[serde(rename = "type")]
    symbol_type: Value,  // Can be complex, we ignore it
    address: u64,
}

/// Field entry in user_types - type can be complex object or string
#[derive(Debug, Deserialize)]
pub struct DwarfField {
    #[serde(default)]
    pub offset: usize,
    #[serde(rename = "type", default)]
    #[allow(dead_code)]
    pub field_type: Value,  // Can be string or complex object, we don't use it
}

/// Structure definition
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DwarfStruct {
    #[serde(default)]
    pub size: usize,
    #[serde(default)]
    pub fields: Option<HashMap<String, DwarfField>>,
    #[serde(default)]
    pub kind: Option<String>,
}

/// Metadata section (optional, in newer formats)
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Metadata {
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    producer: Option<Value>,
}

/// Main dwarf2json structure - handles both old and new formats
#[derive(Debug, Deserialize)]
pub struct DwarfSymbols {
    #[serde(default)]
    #[allow(dead_code)]
    metadata: Option<Metadata>,
    #[serde(default)]
    symbols: HashMap<String, Value>,  // Can be old format (u64) or new format (object with address field)
    #[serde(default)]
    user_types: HashMap<String, DwarfStruct>,
    #[serde(default)]
    #[allow(dead_code)]
    base_types: Option<HashMap<String, Value>>,
}

impl DwarfSymbols {
    /// Load a dwarf2json file and parse it into symbols and structures
    #[allow(dead_code)]  // Reserved for future symbol-based analysis
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, AnalysisError> {
        let content = fs::read_to_string(path)?;
        let dwarf: DwarfSymbols = serde_json::from_str(&content)?;
        Ok(dwarf)
    }

    /// Get the address of a symbol by name
    /// Handles both old format (direct u64) and new format (object with "address" field)
    #[allow(dead_code)]  // Reserved for future symbol resolution
    pub fn get_symbol_address(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).and_then(|value| {
            // Try new format first (object with "address" field)
            if let Some(obj) = value.as_object() {
                if let Some(addr) = obj.get("address") {
                    return addr.as_u64();
                }
            }
            // Try old format (direct u64)
            value.as_u64()
        })
    }

    /// Get the offset of a field within a structure
    #[allow(dead_code)]  // Reserved for future offset lookup
    pub fn get_field_offset(&self, struct_name: &str, field_name: &str) -> Option<usize> {
        self.user_types
            .get(struct_name)?
            .fields
            .as_ref()?
            .get(field_name)
            .map(|field| field.offset)
    }

    /// Get all symbols as a HashMap of name -> address
    pub fn get_symbols(&self) -> HashMap<String, u64> {
        self.symbols.iter()
            .filter_map(|(name, value)| {
                // Try new format first (object with "address" field)
                if let Some(obj) = value.as_object() {
                    if let Some(addr) = obj.get("address") {
                        return addr.as_u64().map(|a| (name.clone(), a));
                    }
                }
                // Try old format (direct u64)
                value.as_u64().map(|a| (name.clone(), a))
            })
            .collect()
    }

    /// Get all structure field offsets
    pub fn get_struct_offsets(&self, struct_name: &str) -> Option<HashMap<String, usize>> {
        self.user_types
            .get(struct_name)?
            .fields
            .as_ref()
            .map(|fields| {
                fields.iter()
                    .map(|(name, field)| (name.clone(), field.offset))
                    .collect()
            })
    }

    /// Get all structures
    #[allow(dead_code)]
    pub fn get_structs(&self) -> &HashMap<String, DwarfStruct> {
        &self.user_types
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_dwarf_symbols_old_format() -> Result<(), Box<dyn std::error::Error>> {
        // Create a temporary file with old dwarf2json format
        let mut temp_file = NamedTempFile::new()?;
        let sample_content = r#"{
            "symbols": {
                "init_task": 281473568538624
            },
            "user_types": {
                "task_struct": {
                    "size": 9216,
                    "fields": {
                        "pid": {
                            "offset": 808,
                            "type": "int"
                        }
                    }
                }
            }
        }"#;
        temp_file.write_all(sample_content.as_bytes())?;
        temp_file.flush()?;

        let dwarf = DwarfSymbols::load_from_file(temp_file.path())?;
        assert_eq!(dwarf.get_symbol_address("init_task"), Some(281473568538624));
        assert_eq!(dwarf.get_field_offset("task_struct", "pid"), Some(808));

        Ok(())
    }

    #[test]
    fn test_dwarf_symbols_new_format() -> Result<(), Box<dyn std::error::Error>> {
        // Create a temporary file with new dwarf2json format (6.x)
        let mut temp_file = NamedTempFile::new()?;
        let sample_content = r#"{
            "metadata": {
                "format": "6.2.0"
            },
            "symbols": {
                "init_task": {
                    "type": {
                        "kind": "struct",
                        "name": "task_struct"
                    },
                    "address": 18446744071610414144
                }
            },
            "user_types": {
                "task_struct": {
                    "size": 9664,
                    "fields": {
                        "pid": {
                            "type": {
                                "kind": "base",
                                "name": "int"
                            },
                            "offset": 1112
                        },
                        "comm": {
                            "type": {
                                "kind": "array",
                                "count": 16,
                                "subtype": {
                                    "kind": "base",
                                    "name": "char"
                                }
                            },
                            "offset": 1320
                        }
                    }
                }
            }
        }"#;
        temp_file.write_all(sample_content.as_bytes())?;
        temp_file.flush()?;

        let dwarf = DwarfSymbols::load_from_file(temp_file.path())?;
        assert_eq!(dwarf.get_symbol_address("init_task"), Some(18446744071610414144));
        assert_eq!(dwarf.get_field_offset("task_struct", "pid"), Some(1112));
        assert_eq!(dwarf.get_field_offset("task_struct", "comm"), Some(1320));

        Ok(())
    }
}
