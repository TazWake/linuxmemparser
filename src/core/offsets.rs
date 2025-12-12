//! Structure offset database for different kernel versions
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub extra: String, // Additional version info like "-generic"
}

impl std::fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}{}",
            self.major, self.minor, self.patch, self.extra
        )
    }
}

/// Structure to hold offset information for different kernel versions
pub struct StructureOffsets {
    kernel_version: Option<KernelVersion>,
    offsets: HashMap<String, HashMap<String, usize>>,
}

impl StructureOffsets {
    /// Create a new structure offsets database
    pub fn new() -> Self {
        Self {
            kernel_version: None,
            offsets: HashMap::new(),
        }
    }

    /// Get offsets for a specific kernel version
    pub fn for_kernel(version: &KernelVersion) -> Self {
        let mut db = Self::new();
        db.kernel_version = Some(version.clone());

        // Populate offsets based on kernel version
        db.load_offsets_for_version(version);
        db
    }

    /// Load offsets for a specific kernel version
    fn load_offsets_for_version(&mut self, version: &KernelVersion) {
        // Load offsets for common kernel versions
        match (version.major, version.minor) {
            (4, 19) => self.load_offsets_4_19(),
            (5, 4) => self.load_offsets_5_4(),
            (5, 15) => self.load_offsets_5_15(),
            (6, 1) => self.load_offsets_6_1(),
            _ => self.load_default_offsets(), // For unhandled versions
        }
    }

    /// Load offsets for kernel 4.19.x
    fn load_offsets_4_19(&mut self) {
        let mut task_struct_offsets = HashMap::new();
        task_struct_offsets.insert("pid".to_string(), 0x318); // PID offset
        task_struct_offsets.insert("comm".to_string(), 0x498); // Process name offset
        task_struct_offsets.insert("parent".to_string(), 0x310); // Parent pointer offset
        task_struct_offsets.insert("cred".to_string(), 0x440); // Credential pointer offset
        task_struct_offsets.insert("state".to_string(), 0x0); // Process state offset
        task_struct_offsets.insert("tasks".to_string(), 0x0); // Tasks list head offset
        task_struct_offsets.insert("start_time".to_string(), 0x300); // Start time offset

        let mut cred_offsets = HashMap::new();
        cred_offsets.insert("uid".to_string(), 0x0); // UID offset
        cred_offsets.insert("gid".to_string(), 0x4); // GID offset

        self.offsets
            .insert("task_struct".to_string(), task_struct_offsets);
        self.offsets.insert("cred".to_string(), cred_offsets);
    }

    /// Load offsets for kernel 5.4.x
    fn load_offsets_5_4(&mut self) {
        let mut task_struct_offsets = HashMap::new();
        task_struct_offsets.insert("pid".to_string(), 0x320); // PID offset
        task_struct_offsets.insert("comm".to_string(), 0x4a0); // Process name offset
        task_struct_offsets.insert("parent".to_string(), 0x318); // Parent pointer offset
        task_struct_offsets.insert("cred".to_string(), 0x448); // Credential pointer offset
        task_struct_offsets.insert("state".to_string(), 0x0); // Process state offset
        task_struct_offsets.insert("tasks".to_string(), 0x0); // Tasks list head offset
        task_struct_offsets.insert("start_time".to_string(), 0x308); // Start time offset

        let mut cred_offsets = HashMap::new();
        cred_offsets.insert("uid".to_string(), 0x0); // UID offset
        cred_offsets.insert("gid".to_string(), 0x4); // GID offset

        self.offsets
            .insert("task_struct".to_string(), task_struct_offsets);
        self.offsets.insert("cred".to_string(), cred_offsets);
    }

    /// Load offsets for kernel 5.15.x
    fn load_offsets_5_15(&mut self) {
        let mut task_struct_offsets = HashMap::new();
        task_struct_offsets.insert("pid".to_string(), 0x328); // PID offset
        task_struct_offsets.insert("comm".to_string(), 0x4a8); // Process name offset
        task_struct_offsets.insert("parent".to_string(), 0x320); // Parent pointer offset
        task_struct_offsets.insert("cred".to_string(), 0x450); // Credential pointer offset
        task_struct_offsets.insert("state".to_string(), 0x0); // Process state offset
        task_struct_offsets.insert("tasks".to_string(), 0x0); // Tasks list head offset
        task_struct_offsets.insert("start_time".to_string(), 0x310); // Start time offset

        let mut cred_offsets = HashMap::new();
        cred_offsets.insert("uid".to_string(), 0x0); // UID offset
        cred_offsets.insert("gid".to_string(), 0x4); // GID offset

        self.offsets
            .insert("task_struct".to_string(), task_struct_offsets);
        self.offsets.insert("cred".to_string(), cred_offsets);
    }

    /// Load offsets for kernel 6.1.x
    fn load_offsets_6_1(&mut self) {
        let mut task_struct_offsets = HashMap::new();
        task_struct_offsets.insert("pid".to_string(), 0x330); // PID offset
        task_struct_offsets.insert("comm".to_string(), 0x4b0); // Process name offset
        task_struct_offsets.insert("parent".to_string(), 0x328); // Parent pointer offset
        task_struct_offsets.insert("cred".to_string(), 0x458); // Credential pointer offset
        task_struct_offsets.insert("state".to_string(), 0x0); // Process state offset
        task_struct_offsets.insert("tasks".to_string(), 0x0); // Tasks list head offset
        task_struct_offsets.insert("start_time".to_string(), 0x318); // Start time offset

        let mut cred_offsets = HashMap::new();
        cred_offsets.insert("uid".to_string(), 0x0); // UID offset
        cred_offsets.insert("gid".to_string(), 0x4); // GID offset

        self.offsets
            .insert("task_struct".to_string(), task_struct_offsets);
        self.offsets.insert("cred".to_string(), cred_offsets);
    }

    /// Load default/common offsets
    fn load_default_offsets(&mut self) {
        let mut task_struct_offsets = HashMap::new();
        task_struct_offsets.insert("pid".to_string(), 0x328); // Default PID offset
        task_struct_offsets.insert("comm".to_string(), 0x4a8); // Default process name offset
        task_struct_offsets.insert("parent".to_string(), 0x320); // Default parent pointer offset
        task_struct_offsets.insert("cred".to_string(), 0x450); // Default credential pointer offset
        task_struct_offsets.insert("state".to_string(), 0x0); // Default process state offset
        task_struct_offsets.insert("tasks".to_string(), 0x0); // Default tasks list head offset
        task_struct_offsets.insert("start_time".to_string(), 0x310); // Default start time offset

        let mut cred_offsets = HashMap::new();
        cred_offsets.insert("uid".to_string(), 0x0); // Default UID offset
        cred_offsets.insert("gid".to_string(), 0x4); // Default GID offset

        self.offsets
            .insert("task_struct".to_string(), task_struct_offsets);
        self.offsets.insert("cred".to_string(), cred_offsets);
    }

    /// Get the offset of a field within a structure
    pub fn get_offset(&self, struct_name: &str, field_name: &str) -> Option<usize> {
        self.offsets.get(struct_name)?.get(field_name).copied()
    }

    /// Get the kernel version this database is for
    #[allow(dead_code)]
    pub fn get_kernel_version(&self) -> Option<&KernelVersion> {
        self.kernel_version.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structure_offsets_creation() {
        let offsets = StructureOffsets::new();
        assert!(offsets.offsets.is_empty());
        assert!(offsets.kernel_version.is_none());
    }

    #[test]
    fn test_kernel_version_parsing() {
        let version = KernelVersion {
            major: 5,
            minor: 15,
            patch: 0,
            extra: "-generic".to_string(),
        };

        let offsets = StructureOffsets::for_kernel(&version);
        assert_eq!(offsets.get_kernel_version().unwrap().major, 5);
        assert_eq!(offsets.get_kernel_version().unwrap().minor, 15);
    }

    #[test]
    fn test_offsets_for_kernel_5_15() {
        let version = KernelVersion {
            major: 5,
            minor: 15,
            patch: 0,
            extra: "".to_string(),
        };

        let offsets = StructureOffsets::for_kernel(&version);
        assert_eq!(offsets.get_offset("task_struct", "pid"), Some(0x328));
        assert_eq!(offsets.get_offset("task_struct", "comm"), Some(0x4a8));
        assert_eq!(offsets.get_offset("cred", "uid"), Some(0x0));
    }

    #[test]
    fn test_offsets_for_kernel_4_19() {
        let version = KernelVersion {
            major: 4,
            minor: 19,
            patch: 0,
            extra: "".to_string(),
        };

        let offsets = StructureOffsets::for_kernel(&version);
        assert_eq!(offsets.get_offset("task_struct", "pid"), Some(0x318));
        assert_eq!(offsets.get_offset("task_struct", "comm"), Some(0x498));
        assert_eq!(offsets.get_offset("cred", "uid"), Some(0x0));
    }
}
