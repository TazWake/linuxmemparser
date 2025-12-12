//! Symbol resolution module for finding kernel symbols
use memchr::memmem;
use std::collections::HashMap;
use std::io::BufRead;
use crate::error::AnalysisError;

// Macro for conditional debug output
macro_rules! debug {
    ($($arg:tt)*) => {
        if std::env::var("LINMEMPARSER_DEBUG").is_ok() {
            eprintln!($($arg)*);
        }
    };
}

// Macro for conditional warning output
macro_rules! warn {
    ($($arg:tt)*) => {
        if std::env::var("LINMEMPARSER_VERBOSE").is_ok() {
            eprintln!($($arg)*);
        }
    };
}

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

    /// Calculate phys_base using multiple heuristics
    ///
    /// This tries different approaches to determine the correct phys_base value:
    /// 1. Standard calculation from _text symbol
    /// 2. Alternative: assume _text physical is at kernel load address
    ///
    /// Returns a list of candidate phys_base values to try
    pub fn calculate_phys_base_candidates(&self) -> Vec<u64> {
        const KERNEL_MAP_BASE: u64 = 0xffffffff80000000;
        const TYPICAL_TEXT_PHYSICAL: u64 = 0x1000000; // 16MB - standard for x86-64

        let mut candidates = Vec::new();

        // Get _text symbol
        if let Some(text_vaddr) = self.get_symbol_address("_text") {
            // Candidate 1: Standard KASLR calculation
            // For typical kernel: _text virtual is 0xffffffff81000000, physical is 0x1000000
            // This gives: phys_base = 0x1000000 - 0x1000000 = 0x0
            if let Some(offset) = text_vaddr.checked_sub(KERNEL_MAP_BASE) {
                if let Some(pb) = TYPICAL_TEXT_PHYSICAL.checked_sub(offset) {
                    candidates.push(pb);
                }
            }

            // Candidate 2: Assume phys_base directly is the typical load address
            // This works when physical memory starts at 16MB
            candidates.push(TYPICAL_TEXT_PHYSICAL);

            // Candidate 3: Try 0x0 (kernel at start of physical memory)
            if !candidates.contains(&0x0) {
                candidates.push(0x0);
            }

            // Candidate 4: Calculate assuming _text is at KERNEL_TEXT_BASE virtually
            // and at TYPICAL_TEXT_PHYSICAL physically
            const KERNEL_TEXT_BASE: u64 = 0xffffffff81000000;
            if let Some(text_offset) = text_vaddr.checked_sub(KERNEL_TEXT_BASE) {
                // If _text moved due to KASLR, adjust phys_base accordingly
                if let Some(pb) = TYPICAL_TEXT_PHYSICAL.checked_add(text_offset) {
                    if !candidates.contains(&pb) {
                        candidates.push(pb);
                    }
                }
            }
        }

        candidates
    }

    /// Detect KASLR offset by finding where init_task actually is in memory
    /// Returns (kaslr_offset, actual_init_task_file_offset)
    /// Heuristic search for init_task by finding "swapper" string in memory
    /// This is a fallback when KASLR detection fails
    fn find_init_task_by_swapper_string(
        &self,
        memory: &[u8],
    ) -> Option<usize> {
        debug!("[DEBUG] Attempting heuristic search for init_task by scanning for 'swapper' string...");

        let comm_offset = self.get_struct_field_offset_fallback("task_struct", "comm")
            .unwrap_or(0xcf0) as usize;
        let pid_offset = self.get_struct_field_offset_fallback("task_struct", "pid")
            .unwrap_or(0xad0) as usize;
        let tasks_offset = self.get_struct_field_offset_fallback("task_struct", "tasks")
            .unwrap_or(0xa00) as usize;

        // Search for "swapper" string
        let finder = memmem::Finder::new(b"swapper");

        let mut matches = 0;
        for match_pos in finder.find_iter(memory) {
            matches += 1;

            // Calculate potential task_struct start by subtracting comm_offset
            if match_pos < comm_offset {
                continue; // Can't subtract comm_offset
            }

            let potential_task_struct = match_pos - comm_offset;

            // Check if PID field is 0
            if potential_task_struct + pid_offset + 4 > memory.len() {
                continue;
            }

            if let Some(pid) = crate::kernel::KernelParser::read_i32(memory, potential_task_struct + pid_offset) {
                if pid == 0 {
                    debug!("[DEBUG] Found 'swapper' at offset 0x{:x}, potential task_struct at 0x{:x}, PID={}",
                             match_pos, potential_task_struct, pid);

                    // Validate: check tasks.next pointer
                    if potential_task_struct + tasks_offset + 8 <= memory.len() {
                        if let Some(tasks_next) = crate::kernel::KernelParser::read_u64(memory, potential_task_struct + tasks_offset) {
                            const MIN_KERNEL_ADDR: u64 = 0xffff800000000000;
                            const MAX_KERNEL_ADDR: u64 = 0xfffffffffff00000;

                            if tasks_next >= MIN_KERNEL_ADDR && tasks_next < MAX_KERNEL_ADDR && tasks_next != 0xffffffffffffffff {
                                debug!("[DEBUG] ✓ Valid init_task found at file offset 0x{:x}", potential_task_struct);
                                debug!("[DEBUG] ✓ comm='swapper', PID=0, tasks.next=0x{:x}", tasks_next);
                                return Some(potential_task_struct);
                            } else {
                                debug!("[DEBUG]   - Rejected: tasks.next=0x{:x} not a valid kernel address", tasks_next);
                            }
                        }
                    }
                }
            }
        }

        debug!("[DEBUG] Scanned {} 'swapper' occurrences, none matched init_task criteria", matches);
        None
    }

    pub fn detect_kaslr_offset(
        &self,
        memory: &[u8],
        translator: &crate::translation::MemoryTranslator,
    ) -> Option<(i64, usize)> {
        // Get the static init_task address from symbols
        let static_init_task = self.get_symbol_address("init_task")?;

        debug!("[DEBUG] Static init_task address from dwarf2json: 0x{:x}", static_init_task);

        // Get the PID offset and tasks offset
        let pid_offset = self.get_struct_field_offset_fallback("task_struct", "pid")
            .unwrap_or(0xad0) as usize;
        let tasks_offset = self.get_struct_field_offset_fallback("task_struct", "tasks")
            .unwrap_or(0xa00) as usize;
        let comm_offset = self.get_struct_field_offset_fallback("task_struct", "comm")
            .unwrap_or(0xcf0) as usize;

        debug!("[DEBUG] Attempting to detect KASLR offset...");
        debug!("[DEBUG] Using offsets: pid=0x{:x}, tasks=0x{:x}, comm=0x{:x}",
                 pid_offset, tasks_offset, comm_offset);

        // Try different KASLR offsets (typically aligned to 0x100000 = 1MB)
        // KASLR can shift the kernel by 0 to ~512MB in 1MB increments
        let mut debug_failures_logged = 0;
        for kaslr_offset in (-512i64..=512).step_by(1) {
            let offset_bytes = kaslr_offset * 0x100000; // 1MB increments
            let test_addr = (static_init_task as i64 + offset_bytes) as u64;

            // Try to translate this address
            if let Some(file_offset) = translator.virtual_to_file_offset(test_addr) {
                let file_offset_usize = file_offset as usize;

                // Check if we can read a PID at this location
                if file_offset_usize + pid_offset + 4 <= memory.len() {
                    if let Some(pid) = crate::kernel::KernelParser::read_i32(memory, file_offset_usize + pid_offset) {
                        if pid == 0 {
                            // Verify this is a real task_struct, not a zero-filled page
                            // Check that at least SOME fields are non-zero
                            let mut non_zero_count = 0;
                            let sample_offsets = [0usize, 8, 16, 24, 32, 40, 48, 56, 64, 72]; // Sample 10 locations
                            for &sample_off in &sample_offsets {
                                if file_offset_usize + sample_off + 8 <= memory.len() {
                                    if let Some(val) = crate::kernel::KernelParser::read_u64(memory, file_offset_usize + sample_off) {
                                        if val != 0 {
                                            non_zero_count += 1;
                                        }
                                    }
                                }
                            }

                            // Require at least 3 non-zero fields (to avoid zero-filled pages)
                            if non_zero_count >= 3 {
                                // CRITICAL: Also verify that tasks.next pointer is non-zero
                                // The tasks field is a list_head, so tasks.next is at tasks_offset
                                if file_offset_usize + tasks_offset + 8 <= memory.len() {
                                    if let Some(tasks_next) = crate::kernel::KernelParser::read_u64(memory, file_offset_usize + tasks_offset) {
                                        if tasks_next == 0 {
                                            if debug_failures_logged < 10 {
                                                debug!("[DEBUG] Found PID 0 at 0x{:x} but tasks.next is NULL - not a valid circular list - skipping",
                                                         test_addr);
                                                debug_failures_logged += 1;
                                            }
                                            continue;
                                        }

                                        // Validate that tasks.next is a valid kernel virtual address
                                        // On x86-64, kernel addresses are in high canonical address space
                                        // They should start with 0xffff8... or higher
                                        // BUT also reject sentinel values like 0xffffffffffffffff (-1)
                                        const MIN_KERNEL_ADDR: u64 = 0xffff800000000000;
                                        const MAX_KERNEL_ADDR: u64 = 0xfffffffffff00000; // Leave room for kernel end

                                        if tasks_next < MIN_KERNEL_ADDR || tasks_next >= MAX_KERNEL_ADDR {
                                            if debug_failures_logged < 10 {
                                                debug!("[DEBUG] Found PID 0 at 0x{:x} but tasks.next=0x{:x} is not a valid kernel address - skipping",
                                                         test_addr, tasks_next);
                                                debug_failures_logged += 1;
                                            }
                                            continue;
                                        }

                                        // Reject sentinel values
                                        if tasks_next == 0xffffffffffffffff || tasks_next == 0xfffffffffffffffe {
                                            if debug_failures_logged < 10 {
                                                debug!("[DEBUG] Found PID 0 at 0x{:x} but tasks.next=0x{:x} is a sentinel value - skipping",
                                                         test_addr, tasks_next);
                                                debug_failures_logged += 1;
                                            }
                                            continue;
                                        }

                                        // CRITICAL: For init_task, comm MUST be "swapper" or "swapper/N"
                                        // This is a kernel constant and the most reliable validation
                                        let comm = crate::kernel::KernelParser::read_string(memory, file_offset_usize + comm_offset, 16)
                                            .unwrap_or_else(|| String::new());
                                        let comm_trimmed = comm.trim_end_matches('\0');

                                        // Strict validation: must start with "swapper"
                                        if !comm_trimmed.starts_with("swapper") {
                                            if debug_failures_logged < 10 {
                                                debug!("[DEBUG] Found PID 0 at 0x{:x} but comm={:?} is not 'swapper' - skipping",
                                                         test_addr, comm_trimmed);
                                                debug_failures_logged += 1;
                                            }
                                            continue;
                                        }

                                        debug!("[DEBUG] ✓ Found PID 0 at virtual address 0x{:x} (file offset 0x{:x})",
                                                 test_addr, file_offset_usize);
                                        debug!("[DEBUG] ✓ Verified: {} out of {} sample fields are non-zero",
                                                 non_zero_count, sample_offsets.len());
                                        debug!("[DEBUG] ✓ tasks.next = 0x{:x} (valid kernel virtual address)",
                                                 tasks_next);
                                        debug!("[DEBUG] ✓ comm = {:?} (valid ASCII)", comm_trimmed);
                                        debug!("[DEBUG] ✓ KASLR offset detected: {} MB (0x{:x} bytes)",
                                                 kaslr_offset, offset_bytes);
                                        return Some((offset_bytes, file_offset_usize));
                                    }
                                }
                            } else {
                                if debug_failures_logged < 10 {
                                    debug!("[DEBUG] Found PID 0 at 0x{:x} but structure appears to be zero-filled ({} non-zero fields) - skipping",
                                             test_addr, non_zero_count);
                                    debug_failures_logged += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        if debug_failures_logged >= 10 {
            debug!("[DEBUG] Tested 1024 KASLR offsets (showing only first 10 failures)");
        }
        warn!("[WARNING] Could not detect KASLR offset using virtual address scanning");
        warn!("[WARNING] Falling back to heuristic search for 'swapper' string...");

        // Fallback: search for "swapper" string in memory
        if let Some(init_task_offset) = self.find_init_task_by_swapper_string(memory) {
            debug!("[DEBUG] ✓ Heuristic search succeeded!");
            // Return dummy KASLR offset of 0 since we found it directly by file offset
            return Some((0, init_task_offset));
        }

        eprintln!("[ERROR] All init_task detection methods failed");
        None
    }

    /// Calculate phys_base from the _text symbol (returns first candidate)
    ///
    /// For compatibility with existing code. Returns the first candidate value.
    /// For better results, use calculate_phys_base_candidates() and validate.
    #[allow(dead_code)]  // May be used by future plugins
    pub fn calculate_phys_base(&self) -> Option<u64> {
        self.calculate_phys_base_candidates().first().copied()
    }

    /// Read the phys_base value from kernel memory (DEPRECATED - circular dependency)
    ///
    /// This method has a circular dependency: it needs phys_base for address translation
    /// but is trying to read phys_base from memory. Use calculate_phys_base() instead.
    #[allow(dead_code)]
    pub fn read_phys_base(&self, translator: &crate::translation::MemoryTranslator, mapped: &[u8]) -> Option<u64> {
        // Get the virtual address of the phys_base variable
        let phys_base_vaddr = self.get_symbol_address("phys_base")?;

        // Translate to file offset
        let file_offset = translator.virtual_to_file_offset(phys_base_vaddr)?;

        // Read the 64-bit value at that location
        if (file_offset as usize) + 8 <= mapped.len() {
            let bytes = &mapped[file_offset as usize..file_offset as usize + 8];
            Some(u64::from_le_bytes(bytes.try_into().ok()?))
        } else {
            None
        }
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
                debug!("[DEBUG] Loaded {} fields for struct '{}':", fields.len(), struct_name);
                for (field_name, offset) in fields {
                    let key = format!("{}::{}", struct_name, field_name);
                    debug!("[DEBUG]   {}::{} = 0x{:x} ({} bytes)", struct_name, field_name, offset, offset);
                    self.struct_offsets.insert(key, offset);
                }
            } else {
                warn!("[WARNING] No fields found for struct '{}' in dwarf2json", struct_name);
            }
        }

        // Check specifically for critical fields
        let critical_fields = vec![
            ("task_struct", "pid"),
            ("task_struct", "comm"),
            ("task_struct", "tasks"),
            ("task_struct", "parent"),
            ("task_struct", "state"),
            ("task_struct", "__state"),  // Renamed in kernel 5.14+
        ];
        debug!("[DEBUG] Checking critical field offsets:");
        for (struct_name, field_name) in critical_fields {
            let key = format!("{}::{}", struct_name, field_name);
            match self.struct_offsets.get(&key) {
                Some(offset) => debug!("[DEBUG]   ✓ {} = 0x{:x}", key, offset),
                None => {
                    // Don't warn if both state and __state are missing (one should exist)
                    if !(field_name == "state" && self.struct_offsets.contains_key("task_struct::__state")) &&
                       !(field_name == "__state" && self.struct_offsets.contains_key("task_struct::state")) {
                        warn!("[WARNING]   ✗ {} NOT FOUND in dwarf2json!", key);
                    }
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

        // Handle field name changes across kernel versions
        // In kernel 5.14+, "state" was renamed to "__state"
        if struct_name == "task_struct" && field_name == "state" {
            let alt_key = format!("task_struct::__state");
            if let Some(offset) = self.struct_offsets.get(&alt_key) {
                return Some(*offset as u64);
            }
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
    #[allow(dead_code)]  // Legacy method, prefer detect_kaslr_offset
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

    /// Derive PAGE_OFFSET from known init_task and tasks.next relationship
    ///
    /// This works backward from what we know:
    /// - init_task location in memory (file offset and corresponding memory region)
    /// - tasks.next virtual address (read from init_task in memory)
    /// - tasks.next should translate to a valid physical address within captured regions
    ///
    /// We try each region and calculate what PAGE_OFFSET would make tasks.next
    /// translate into that region, then validate by checking for a valid task_struct.
    pub fn derive_page_offset_from_init_task(
        &self,
        memory: &[u8],
        translator: &crate::translation::MemoryTranslator,
        init_task_file_offset: usize,
        tasks_offset: usize,
    ) -> Option<u64> {
        use crate::kernel;

        // Read tasks.next pointer from init_task
        let tasks_next_vaddr = match kernel::KernelParser::read_u64(
            memory,
            init_task_file_offset + tasks_offset
        ) {
            Some(addr) => addr,
            None => {
                debug!("[DEBUG] Could not read tasks.next from init_task");
                return None;
            }
        };

        debug!("[DEBUG] Deriving PAGE_OFFSET from tasks.next=0x{:x}", tasks_next_vaddr);

        // Ensure it's in the direct mapping range
        if tasks_next_vaddr < 0xffff800000000000 || tasks_next_vaddr >= 0xffffc00000000000 {
            debug!("[DEBUG] tasks.next not in direct mapping range");
            return None;
        }

        // Try each memory region to see if tasks.next could point into it
        // Process smaller regions first as they're more likely to contain process structures
        let mut regions_with_sizes: Vec<_> = translator.get_regions()
            .iter()
            .enumerate()
            .map(|(i, r)| (i, r, r.end - r.start))
            .collect();
        regions_with_sizes.sort_by_key(|(_, _, size)| *size);

        for (i, region, region_size) in regions_with_sizes {
            // Skip small regions (< 1MB) - unlikely to contain task_structs
            if region_size < 1024 * 1024 {
                continue;
            }

            // Use larger step size for very large regions to avoid excessive iterations
            let step_size = if region_size > 512 * 1024 * 1024 {
                0x10000  // 64KB steps for regions >512MB
            } else {
                0x1000   // 4KB steps for smaller regions
            };

            // Limit iterations per region to prevent hanging
            let max_iterations = 50000;
            let mut iterations = 0;

            for offset in (0..region_size).step_by(step_size as usize) {
                iterations += 1;
                if iterations > max_iterations {
                    debug!("[DEBUG] Region {} exceeded max iterations, moving to next region", i);
                    break;
                }
                let candidate_phys = region.start + offset;

                // Calculate what PAGE_OFFSET would produce this physical address
                let candidate_page_offset = tasks_next_vaddr.wrapping_sub(candidate_phys);

                // Validate PAGE_OFFSET is in reasonable range
                if candidate_page_offset < 0xffff800000000000 ||
                   candidate_page_offset >= 0xffffb00000000000 {
                    continue;
                }

                // Translate to file offset
                let file_offset = region.file_offset + offset;

                // tasks.next points to 'tasks' field, so subtract to get struct base
                if file_offset < tasks_offset as u64 {
                    continue;
                }
                let task_base = file_offset - tasks_offset as u64;

                // Validate this looks like a task_struct
                // Use hardcoded offsets for now (should potentially use offsets from self)
                if let Some(pid) = kernel::KernelParser::read_i32(memory, (task_base + 0xad0).try_into().unwrap()) {
                    if pid > 0 && pid < 1000000 {
                        if let Some(comm) = kernel::KernelParser::read_string(memory, (task_base + 0xcf0).try_into().unwrap(), 16) {
                            if comm.len() >= 2 && comm.chars().all(|c| c.is_ascii_graphic() || c.is_whitespace()) {
                                debug!("[DEBUG] ✓ Derived PAGE_OFFSET: 0x{:x} (found PID={}, comm='{}')",
                                          candidate_page_offset, pid, comm);
                                return Some(candidate_page_offset);
                            }
                        }
                    }
                }
            }
        }

        debug!("[DEBUG] Could not derive PAGE_OFFSET from any region");
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