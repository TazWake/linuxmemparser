//! Symbol resolution module for finding kernel symbols
use memchr::memmem;
use std::collections::HashMap;
use std::io::BufRead;
use crate::error::AnalysisError;

/// Structure to hold symbol information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
}

/// Symbol resolver for finding kernel symbols in memory or external files
pub struct SymbolResolver {
    symbols: HashMap<String, u64>,
    // Store structure field offsets from dwarf2json: "struct_name::field_name" -> offset
    struct_offsets: HashMap<String, usize>,
    // Store the dwarf2json file path to reload offsets when needed
    dwarf2json_path: Option<String>,
}

impl SymbolResolver {
    /// Create a new symbol resolver
    pub fn new() -> Self {
        SymbolResolver {
            symbols: HashMap::new(),
            struct_offsets: HashMap::new(),
            dwarf2json_path: None,
        }
    }

    /// Perform a heuristic search for a kernel symbol table marker
    pub fn detect_symbol_table(mapped: &[u8]) -> Option<usize> {
        let markers = ["kallsyms", "kallsyms_addresses", "kallsyms_names", "kallsyms_num"];
        for marker in markers.iter() {
            if let Some(pos) = memmem::find(mapped, marker.as_bytes()) {
                return Some(pos);
            }
        }
        None
    }

    /// Add a symbol to the resolver
    pub fn add_symbol(&mut self, name: String, address: u64) {
        self.symbols.insert(name, address);
    }

    /// Get the address of a symbol by name
    pub fn get_symbol_address(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
    }

    /// Get all symbols
    #[allow(dead_code)]
    pub fn get_symbols(&self) -> &HashMap<String, u64> {
        &self.symbols
    }

    /// Get the number of symbols
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Extract kernel version from System.map file by looking for linux_banner symbol
    #[allow(dead_code)]
    pub fn extract_kernel_version_from_system_map(_file_path: &str) -> Option<crate::core::offsets::KernelVersion> {
        // System.map doesn't directly contain version, but we can try to find it
        // by looking for version-related symbols or comments
        // For now, return None - version should be detected from memory dump
        None
    }

    /// Parse an external symbol file (e.g., System.map or kallsyms dump) - System.map parser
    pub fn load_system_map(&mut self, file_path: &str) -> Result<(), AnalysisError> {
        use std::fs::File;
        use std::io::BufReader;

        let file = File::open(file_path)?;
        let reader = BufReader::new(file);

        for line_result in reader.lines() {
            let line = line_result?;
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 3 {
                let address_str = parts[0];
                let symbol_type = parts[1];
                let symbol_name = parts[2];

                // Validate symbol type (System.map uses single letter types like T, D, etc.)
                if symbol_type.len() == 1 {
                    if let Ok(address) = u64::from_str_radix(address_str.trim_start_matches("0x"), 16) {
                        self.add_symbol(symbol_name.to_string(), address);
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse kallsyms dump (same format as System.map, but may have more entries with 0 addresses)
    pub fn load_kallsyms(&mut self, file_path: &str) -> Result<(), AnalysisError> {
        use std::fs::File;
        use std::io::BufReader;

        let file = File::open(file_path)?;
        let reader = BufReader::new(file);

        for line_result in reader.lines() {
            let line = line_result?;
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 3 {
                let address_str = parts[0];
                let symbol_type = parts[1];
                let symbol_name = parts[2];

                // Parse address - skip if it's 0 (absolute symbols in modules)
                if let Ok(address) = u64::from_str_radix(address_str.trim_start_matches("0x"), 16) {
                    // Skip zero addresses - these are usually absolute symbols from modules
                    // Only skip if this looks like a module symbol (has [module] suffix)
                    if address == 0 {
                        // Check if this is a module symbol
                        if parts.len() > 3 && parts[parts.len() - 1].starts_with('[') {
                            continue; // Skip module symbols with 0 address
                        }
                        // For kernel symbols with 0 address, we still skip them
                        // as they're not useful for address translation
                        continue;
                    }
                    
                    // Validate symbol type (kallsyms uses single letter types like T, D, etc.)
                    if symbol_type.len() == 1 {
                        self.add_symbol(symbol_name.to_string(), address);
                    }
                }
            }
        }

        Ok(())
    }

    /// Load symbols from dwarf2json format
    pub fn load_dwarf2json(&mut self, file_path: &str) -> Result<(), AnalysisError> {
        use std::fs;
        
        let content = fs::read_to_string(file_path)?;
        let dwarf: crate::core::dwarf::DwarfSymbols = serde_json::from_str(&content)
            .map_err(|e| AnalysisError::SymbolError(format!("Failed to parse dwarf2json: {}", e)))?;

        // Load symbols (convert from HashMap to iterator)
        let symbols = dwarf.get_symbols();
        for (name, addr) in symbols {
            self.add_symbol(name, addr);
        }

        // Load structure offsets from dwarf2json
        // Store them as "struct_name::field_name" -> offset for easy lookup
        // We'll iterate through known structs we care about
        let structs_to_load = vec!["task_struct", "cred"];
        for struct_name in structs_to_load {
            if let Some(fields) = dwarf.get_struct_offsets(struct_name) {
                for (field_name, offset) in fields {
                    let key = format!("{}::{}", struct_name, field_name);
                    self.struct_offsets.insert(key, offset);
                }
            }
        }
        
        // Store the path for potential future use
        self.dwarf2json_path = Some(file_path.to_string());
        
        Ok(())
    }
    
    /// Load structure offsets from dwarf2json (deprecated - now handled in load_dwarf2json)
    #[allow(dead_code)]
    pub fn load_dwarf2json_offsets(&mut self, _file_path: &str) -> Result<(), AnalysisError> {
        // This is now handled in load_dwarf2json
        Ok(())
    }

    /// Find symbol by pattern using regex
    #[allow(dead_code)]
    pub fn find_symbol_by_pattern(&self, pattern: &str) -> Result<Vec<(String, u64)>, AnalysisError> {
        use regex::Regex;

        let re = Regex::new(pattern)?;
        let mut matches = Vec::new();

        for (name, &addr) in &self.symbols {
            if re.is_match(name) {
                matches.push((name.clone(), addr));
            }
        }

        Ok(matches)
    }

    /// Get the offset of a field within a structure
    /// Implements a fallback chain:
    /// 1. Check dwarf2json structure offsets (most accurate)
    /// 2. Check structure offset database (based on kernel version)
    /// 3. Fallback to hardcoded offsets
    pub fn get_struct_field_offset(&self, struct_name: &str, field_name: &str, kernel_version: Option<&crate::core::offsets::KernelVersion>) -> Option<u64> {
        // 1. First, try to get from dwarf2json structure offsets (most accurate)
        let key = format!("{}::{}", struct_name, field_name);
        if let Some(offset) = self.struct_offsets.get(&key) {
            return Some(*offset as u64);
        }
        
        // 2. Try structure offset database if we have kernel version
        if let Some(version) = kernel_version {
            let db = crate::core::offsets::StructureOffsets::for_kernel(version);
            if let Some(offset) = db.get_offset(struct_name, field_name) {
                return Some(offset as u64);
            }
        }

        // 3. Fallback to hardcoded offsets
        match (struct_name, field_name) {
            ("task_struct", "pid") => Some(0x328), // Updated to more standard offset
            ("task_struct", "comm") => Some(0x4a8), // Updated to more standard offset
            ("task_struct", "parent") => Some(0x320), // Updated to more standard offset
            ("task_struct", "start_time") => Some(0x310), // Updated to more standard offset
            ("task_struct", "cred") => Some(0x450), // Updated to more standard offset
            ("task_struct", "state") => Some(0x0), // Updated to more standard offset
            ("task_struct", "tasks") => Some(0x0), // The linked list pointer, offset may vary
            ("cred", "uid") => Some(0x0),
            ("cred", "gid") => Some(0x4),
            _ => None,
        }
    }

    /// Convenience method with no kernel version (uses only fallbacks)
    pub fn get_struct_field_offset_fallback(&self, struct_name: &str, field_name: &str) -> Option<u64> {
        self.get_struct_field_offset(struct_name, field_name, None)
    }

    /// Validate if a memory offset could be a valid task_struct with specific offsets
    fn validate_task_struct_with_offsets(&self, mapped: &[u8], offset: usize, pid_offset: usize, comm_offset: usize) -> bool {
        let state_offset = self.get_struct_field_offset_fallback("task_struct", "state").unwrap_or(0x0) as usize;
        let comm_size = 16;

        // Check bounds
        if offset + comm_offset + comm_size > mapped.len() {
            return false;
        }

        // Read PID - should be a reasonable value (0 to 2^22, Linux max PID)
        let pid = match read_i32_helper(mapped, offset + pid_offset) {
            Some(p) if p >= 0 && p <= 4194304 => p,
            _ => return false,
        };

        // Read comm - must be a valid process name
        let comm = match read_string_helper(mapped, offset + comm_offset, comm_size) {
            Some(c) if !c.is_empty() => c,
            _ => return false,
        };

        // Stricter validation: comm should be null-terminated and contain valid characters
        let comm_trimmed = comm.trim_end_matches('\0').trim();
        if comm_trimmed.is_empty() {
            return false;
        }

        // Check for obviously invalid process names (containing '=' or ')' suggests we're reading wrong data)
        // Allow ')' only at the end (for process names like "swapper/0)")
        if comm_trimmed.contains('=') || (comm_trimmed.contains(')') && !comm_trimmed.ends_with(')')) {
            return false;
        }

        // Check that most characters are printable ASCII (at least 80% for valid process names)
        let printable_count = comm_trimmed.chars().filter(|c| c.is_ascii() && !c.is_control()).count();
        if printable_count < (comm_trimmed.len() * 4 / 5) {
            return false;
        }

        // For PID 0, comm should be "swapper" or "swapper/0" or similar
        if pid == 0 {
            if !comm_trimmed.starts_with("swapper") {
                return false;
            }
        }

        // Read state - should be a small value (0-5 typically)
        if let Some(state) = read_i32_helper(mapped, offset + state_offset) {
            if state < -1 || state > 10 {
                return false;
            }
        } else {
            return false;
        }

        true
    }

    /// Validate if a memory offset could be a valid task_struct
    /// Checks PID range, comm field for valid process names, and state value
    /// Uses default offsets from symbol resolver
    #[allow(dead_code)]
    fn validate_task_struct(&self, mapped: &[u8], offset: usize) -> bool {
        // Get offsets for validation
        let pid_offset = self.get_struct_field_offset_fallback("task_struct", "pid").unwrap_or(0x328) as usize;
        let comm_offset = self.get_struct_field_offset_fallback("task_struct", "comm").unwrap_or(0x4a8) as usize;
        
        // Use the new validation function with specific offsets
        self.validate_task_struct_with_offsets(mapped, offset, pid_offset, comm_offset)
    }

    /// Detect kernel version from the linux_banner string
    pub fn detect_kernel_version(&self, mapped: &[u8]) -> Option<crate::core::offsets::KernelVersion> {
        // Search for "Linux version " string in memory
        let linux_version_pattern = b"Linux version ";
        let finder = memchr::memmem::Finder::new(linux_version_pattern);

        if let Some(match_pos) = finder.find(mapped) {
            // Extract from match_pos to newline or reasonable end
            let slice = &mapped[match_pos..];
            let end_pos = slice.iter().position(|&c| c == b'\n' || c == b'\r').unwrap_or(slice.len());
            let banner_str = String::from_utf8_lossy(&slice[..end_pos]);

            // Parse kernel version from banner like "Linux version 5.15.0-91-generic"
            if let Some(version_part) = banner_str.split("Linux version ").nth(1) {
                return parse_kernel_version(version_part);
            }
        }

        None
    }

    /// Find the init_task address in memory
    /// This is the starting point for walking the process list
    /// If translator is provided, checks if symbol address can be translated to file offset
    pub fn find_init_task(&self, mapped: &[u8], translator: Option<&crate::translation::MemoryTranslator>) -> Option<u64> {
        println!("Searching for init_task in memory...");

        // Strategy 1: Look for init_task symbol if we have it
        if let Some(addr) = self.get_symbol_address("init_task") {
            println!("Found init_task symbol at address: 0x{:x}", addr);
            
            // Check if we can translate this address to a file offset
            if let Some(translator) = translator {
                if let Some(file_offset) = translator.virtual_to_file_offset(addr) {
                    println!("Translated init_task to file offset: 0x{:x}", file_offset);
                    return Some(file_offset);
                } else {
                    // Can't translate - likely a raw dump with kernel virtual address
                    // Fall through to heuristic search
                    println!("Cannot translate init_task address to file offset, using heuristic search...");
                }
            } else {
                // No translator available, assume it's already a file offset or use as-is
                return Some(addr);
            }
        }

        println!("init_task symbol not found or untranslatable, using heuristic search...");

        // Strategy 2: Search for known init process patterns
        // Try multiple offset combinations for different kernel versions
        let kernel_version = self.detect_kernel_version(mapped);

        // Build offset combinations with priority order:
        // 1. dwarf2json offsets (most accurate)
        // 2. Kernel version specific offsets
        // 3. Common fallback offsets
        let mut offset_combinations = Vec::new();

        // Priority 1: Check dwarf2json struct_offsets first (most accurate)
        let dwarf_pid_offset = self.struct_offsets.get("task_struct::pid").copied();
        let dwarf_comm_offset = self.struct_offsets.get("task_struct::comm").copied();

        if let (Some(pid_off), Some(comm_off)) = (dwarf_pid_offset, dwarf_comm_offset) {
            println!("Using dwarf2json offsets: pid=0x{:x}, comm=0x{:x}", pid_off, comm_off);
            offset_combinations.push((pid_off, comm_off));
        }

        // Priority 2: Try kernel version-specific offsets if available
        if let Some(version) = &kernel_version {
            let db = crate::core::offsets::StructureOffsets::for_kernel(version);
            let version_pid = db.get_offset("task_struct", "pid").unwrap_or(0x328) as usize;
            let version_comm = db.get_offset("task_struct", "comm").unwrap_or(0x4a8) as usize;

            // Only add if different from dwarf2json offsets (avoid duplicates)
            if dwarf_pid_offset != Some(version_pid) || dwarf_comm_offset != Some(version_comm) {
                offset_combinations.push((version_pid, version_comm));
            }
        }

        // Priority 3: Add common fallback offsets if we don't have dwarf2json
        if dwarf_pid_offset.is_none() || dwarf_comm_offset.is_none() {
            offset_combinations.extend_from_slice(&[
                (0x328, 0x4a8), // 5.15.x default
                (0x320, 0x4a0), // 5.4.x
                (0x318, 0x498), // 4.19.x
                (0x330, 0x4b0), // 6.1.x
            ]);
        }

        let comm_size = 16;

        // Search for "swapper" string which is usually the init task (PID 0)
        let swapper_pattern = b"swapper";
        let finder = memchr::memmem::Finder::new(swapper_pattern);

        for match_pos in finder.find_iter(mapped) {
            // Try each offset combination
            for (pid_offset, comm_offset) in &offset_combinations {
                // Check if this could be the comm field of a task_struct
                if match_pos < *comm_offset {
                    continue;
                }

                let potential_task_offset = match_pos - comm_offset;

                // Validate this looks like a task_struct with these offsets
                if self.validate_task_struct_with_offsets(mapped, potential_task_offset, *pid_offset, *comm_offset) {
                    // Check if PID is 0 or 1
                    if let Some(pid) = read_i32_helper(mapped, potential_task_offset + pid_offset) {
                        if pid == 0 || pid == 1 {
                            println!("Found potential init_task at offset 0x{:x} (PID: {})", potential_task_offset, pid);

                            // Additional validation: read comm to confirm
                            if let Some(comm) = read_string_helper(mapped, potential_task_offset + comm_offset, comm_size) {
                                println!("  Process name: {}", comm.trim_end_matches('\0'));
                                // Update offsets for this kernel version if we detected it
                                if kernel_version.is_none() {
                                    println!("  Using offsets: pid=0x{:x}, comm=0x{:x}", pid_offset, comm_offset);
                                }
                                return Some(potential_task_offset as u64);
                            }
                        }
                    }
                }
            }
        }

        // Strategy 3: Search for "init" string (PID 1 usually)
        let init_pattern = b"init";
        let finder = memchr::memmem::Finder::new(init_pattern);

        for match_pos in finder.find_iter(mapped) {
            // Try each offset combination
            for (pid_offset, comm_offset) in &offset_combinations {
                // Check if this could be the comm field of a task_struct
                if match_pos < *comm_offset {
                    continue;
                }

                let potential_task_offset = match_pos - comm_offset;

                // Validate this looks like a task_struct with these offsets
                if self.validate_task_struct_with_offsets(mapped, potential_task_offset, *pid_offset, *comm_offset) {
                    // Check if PID is 1
                    if let Some(pid) = read_i32_helper(mapped, potential_task_offset + pid_offset) {
                        if pid == 1 {
                            println!("Found potential init_task at offset 0x{:x} (PID: {})", potential_task_offset, pid);

                            // Additional validation: read comm to confirm
                            if let Some(comm) = read_string_helper(mapped, potential_task_offset + comm_offset, comm_size) {
                                println!("  Process name: {}", comm.trim_end_matches('\0'));
                                return Some(potential_task_offset as u64);
                            }
                        }
                    }
                }
            }
        }

        println!("Warning: Could not find init_task in memory");
        None
    }
}

/// Parse kernel version from a version string like "5.15.0-91-generic"
fn parse_kernel_version(version_str: &str) -> Option<crate::core::offsets::KernelVersion> {
    let version_clean = version_str.split_whitespace().next()?;
    let parts: Vec<&str> = version_clean.split('.').collect();

    if parts.len() >= 2 {
        let major = parts[0].parse::<u32>().ok()?;
        let minor = parts[1].parse::<u32>().ok()?;

        let patch: u32;
        let extra: String;

        if parts.len() >= 3 {
            // Split patch from extra info like "0-91-generic"
            let patch_part = parts[2];
            let patch_extra: Vec<&str> = patch_part.split('-').collect();
            patch = patch_extra[0].parse::<u32>().unwrap_or(0);
            extra = if patch_extra.len() > 1 {
                format!("-{}", patch_extra[1..].join("-"))
            } else {
                String::new()
            };
        } else {
            patch = 0;
            extra = String::new();
        }

        Some(crate::core::offsets::KernelVersion {
            major,
            minor,
            patch,
            extra,
        })
    } else {
        None
    }
}

// Helper functions for reading data (duplicated from KernelParser to avoid circular dependency)
fn read_i32_helper(mapped: &[u8], offset: usize) -> Option<i32> {
    if offset + 4 <= mapped.len() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&mapped[offset..offset + 4]);
        Some(i32::from_ne_bytes(buf))
    } else {
        None
    }
}

fn read_string_helper(mapped: &[u8], offset: usize, length: usize) -> Option<String> {
    if offset + length <= mapped.len() {
        let slice = &mapped[offset..offset + length];
        let nul_pos = slice.iter().position(|&c| c == 0).unwrap_or(length);
        Some(String::from_utf8_lossy(&slice[..nul_pos]).to_string())
    } else {
        None
    }
}