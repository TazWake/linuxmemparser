//! Kernel data structure parsing module
use serde::Serialize;

/// Structure to hold process information.
#[derive(Debug, Serialize, Clone)]
pub struct ProcessInfo {
    pub offset: u64, // File offset where the task_struct is found
    pub pid: i32,
    pub comm: String,
    pub ppid: i32,       // Parent process ID
    pub start_time: u64, // Process start time
    pub uid: u32,        // User ID
    pub gid: u32,        // Group ID
    pub state: String,   // Process state
    pub cmdline: String, // Command line arguments
}

/// Structure to hold network connection information.
#[derive(Debug, Serialize, Clone)]
pub struct ConnectionInfo {
    pub offset: u64,
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: i32,
}

/// Structure to hold kernel module information.
#[derive(Debug, Serialize, Clone)]
pub struct ModuleInfo {
    pub offset: u64,
    pub name: String,
    pub size: u64,
    pub address: u64,
    pub init_address: u64,
}

/// Helper functions for reading data from memory
pub struct KernelParser;

impl KernelParser {
    /// Read a u64 (8 bytes) from the mapped memory at a given file offset.
    pub fn read_u64(mapped: &[u8], offset: usize) -> Option<u64> {
        if offset + 8 <= mapped.len() {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&mapped[offset..offset + 8]);
            Some(u64::from_ne_bytes(buf))
        } else {
            None
        }
    }

    /// Read an i32 (4 bytes) from the mapped memory at a given file offset.
    pub fn read_i32(mapped: &[u8], offset: usize) -> Option<i32> {
        if offset + 4 <= mapped.len() {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&mapped[offset..offset + 4]);
            Some(i32::from_ne_bytes(buf))
        } else {
            None
        }
    }

    /// Read a u32 (4 bytes) from the mapped memory at a given file offset.
    pub fn read_u32(mapped: &[u8], offset: usize) -> Option<u32> {
        if offset + 4 <= mapped.len() {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&mapped[offset..offset + 4]);
            Some(u32::from_ne_bytes(buf))
        } else {
            None
        }
    }

    /// Read a u16 (2 bytes) from the mapped memory at a given file offset.
    #[allow(dead_code)]
    pub fn read_u16(mapped: &[u8], offset: usize) -> Option<u16> {
        if offset + 2 <= mapped.len() {
            let mut buf = [0u8; 2];
            buf.copy_from_slice(&mapped[offset..offset + 2]);
            Some(u16::from_ne_bytes(buf))
        } else {
            None
        }
    }

    /// Read a string of fixed length from the mapped memory at a given file offset.
    pub fn read_string(mapped: &[u8], offset: usize, length: usize) -> Option<String> {
        if offset + length <= mapped.len() {
            let slice = &mapped[offset..offset + length];
            let nul_pos = slice.iter().position(|&c| c == 0).unwrap_or(length);
            Some(String::from_utf8_lossy(&slice[..nul_pos]).to_string())
        } else {
            None
        }
    }

    /// Read a null-terminated string from the mapped memory at a given file offset.
    #[allow(dead_code)]
    pub fn read_cstring(mapped: &[u8], offset: usize) -> Option<String> {
        if offset >= mapped.len() {
            return None;
        }

        let slice = &mapped[offset..];
        let nul_pos = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        Some(String::from_utf8_lossy(&slice[..nul_pos]).to_string())
    }

    /// Dereference a virtual address pointer using the memory translator
    #[allow(dead_code)]
    pub fn dereference_pointer(
        mapped: &[u8],
        translator: &crate::translation::MemoryTranslator,
        virtual_addr: u64,
    ) -> Result<u64, crate::error::AnalysisError> {
        if virtual_addr == 0 {
            return Err(crate::error::AnalysisError::AddressTranslationFailed(0));
        }

        // Translate virtual address to file offset
        let file_offset = translator
            .virtual_to_file_offset(virtual_addr)
            .ok_or_else(|| crate::error::AnalysisError::AddressTranslationFailed(virtual_addr))?;

        // Read the 8-byte pointer value at that file offset
        let pointer_value = Self::read_u64(mapped, file_offset as usize).ok_or_else(|| {
            crate::error::AnalysisError::InvalidStructure(format!(
                "Cannot read pointer at offset 0x{:x}",
                file_offset
            ))
        })?;

        Ok(pointer_value)
    }
}

// Include the process extractor module
pub mod process_extractor;

/// Format start_time from nanoseconds since boot to human-readable elapsed time
pub fn format_start_time(start_time_ns: u64) -> String {
    if start_time_ns == 0 {
        return "0".to_string();
    }

    let start_secs = start_time_ns / 1_000_000_000;

    let days = start_secs / 86400;
    let hours = (start_secs % 86400) / 3600;
    let minutes = (start_secs % 3600) / 60;
    let seconds = start_secs % 60;

    if days > 0 {
        format!("{}d {:02}h {:02}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{:02}h {:02}m {:02}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{:02}m {:02}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

/// Validate process information to ensure it represents valid kernel data
pub fn validate_process_info(proc: &ProcessInfo) -> bool {
    let debug = std::env::var("LINMEMPARSER_DEBUG").is_ok();

    if debug {
        eprintln!(
            "[DEBUG] Validating PID {}: comm='{}', uid={}, gid={}",
            proc.pid, proc.comm, proc.uid, proc.gid
        );
    }

    // Check that PID is reasonable (>= 0 and within Linux limits)
    if proc.pid < 0 || proc.pid > 4194304 {
        // Linux max PID
        if debug {
            eprintln!("[DEBUG] Validation failed: PID {} out of range", proc.pid);
        }
        return false;
    }

    // Special handling for PID 0 (swapper/idle task)
    // This is a kernel thread that may have empty or unusual comm field due to offset mismatches
    if proc.pid == 0 {
        if debug {
            eprintln!("[DEBUG] PID 0 detected (swapper) - relaxing validation");
        }
        // For PID 0, we only check that it exists, don't validate comm/uid/gid strictly
        return true;
    }

    // Check that process name is not empty and contains reasonable characters
    if proc.comm.is_empty() {
        if debug {
            eprintln!("[DEBUG] Validation failed: comm is empty");
        }
        return false;
    }

    // Check that comm field contains mostly printable ASCII characters
    let printable_count = proc
        .comm
        .chars()
        .filter(|c| c.is_ascii() && !c.is_control())
        .count();

    // For kernel threads (typically PID < 300), be more lenient with comm validation
    // They may have unusual names or the offset might be slightly off
    let required_ratio = if proc.pid < 300 { 0.3 } else { 0.5 };
    let required_printable = (proc.comm.len() as f64 * required_ratio) as usize;

    if printable_count < required_printable {
        if debug {
            eprintln!(
                "[DEBUG] Validation failed: comm '{}' has only {}/{} printable chars (need {})",
                proc.comm,
                printable_count,
                proc.comm.len(),
                required_printable
            );
        }
        return false;
    }

    // Check that UID and GID are reasonable values
    if proc.uid > 65535 || proc.gid > 65535 {
        if debug {
            eprintln!(
                "[DEBUG] Validation failed: uid={} or gid={} out of range",
                proc.uid, proc.gid
            );
        }
        return false;
    }

    if debug {
        eprintln!("[DEBUG] Validation passed for PID {}", proc.pid);
    }

    // Additional validation checks could go here
    true
}
