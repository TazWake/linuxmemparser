//! dwarf2json parser for loading Volatility 3 compatible symbol files
use std::collections::HashMap;
use std::fs;
use serde::Deserialize;
use crate::error::AnalysisError;

#[derive(Debug, Deserialize)]
struct SymbolEntry {
    address: u64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DwarfField {
    #[serde(default)]
    pub offset: usize,
    #[serde(rename = "type", default)]
    pub field_type: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DwarfStruct {
    #[serde(default)]
    pub size: usize,
    #[serde(default)]
    pub fields: Option<HashMap<String, DwarfField>>,
}

#[derive(Debug, Deserialize)]
pub struct DwarfSymbols {
    #[serde(default)]
    symbols: HashMap<String, SymbolEntry>,
    #[serde(default)]
    #[allow(dead_code)]
    user_types: HashMap<String, DwarfStruct>,
}

impl DwarfSymbols {
    /// Load a dwarf2json file and parse it into symbols and structures
    #[allow(dead_code)]
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, AnalysisError> {
        let content = fs::read_to_string(path)?;
        let dwarf: DwarfSymbols = serde_json::from_str(&content)?;
        Ok(dwarf)
    }

    /// Get the address of a symbol by name
    #[allow(dead_code)]
    pub fn get_symbol_address(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).map(|entry| entry.address)
    }

    /// Get the offset of a field within a structure
    #[allow(dead_code)]
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
            .map(|(name, entry)| (name.clone(), entry.address))
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
    fn test_dwarf_symbols_creation() {
        let mut symbols = HashMap::new();
        symbols.insert("init_task".to_string(), 0xffffffffa1e00000);
        let mut fields = HashMap::new();
        fields.insert("pid".to_string(), DwarfField {
            offset: 0x328,
            field_type: "int".to_string(),
        });
        let mut user_types = HashMap::new();
        user_types.insert("task_struct".to_string(), DwarfStruct {
            size: 9216,
            fields,
        });

        let dwarf = DwarfSymbols {
            symbols,
            user_types,
        };

        assert_eq!(dwarf.get_symbol_address("init_task"), Some(0xffffffffa1e00000));
        assert_eq!(dwarf.get_field_offset("task_struct", "pid"), Some(0x328));
    }

    #[test]
    fn test_load_from_file() -> Result<(), Box<dyn std::error::Error>> {
        // Create a temporary file with sample dwarf2json content
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
}