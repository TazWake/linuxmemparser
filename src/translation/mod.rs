//! Memory translation module for converting between virtual, physical, and file offsets
use crate::memory::MemoryRegion;

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

// x86-64 kernel address space constants
#[allow(dead_code)]
const KERNEL_TEXT_BASE: u64 = 0xffffffff81000000; // _text (actual kernel text start)
const KERNEL_MAP_BASE: u64 = 0xffffffff80000000; // __START_KERNEL_map (mapping base)
const PAGE_OFFSET_4LEVEL: u64 = 0xffff880000000000; // 4-level paging
const PAGE_OFFSET_5LEVEL: u64 = 0xffff888000000000; // 5-level paging

/// Memory translation layer for converting between address spaces
pub struct MemoryTranslator {
    regions: Vec<MemoryRegion>,
    /// Physical base address where kernel is loaded
    /// This is read from the phys_base kernel variable or defaulted
    phys_base: u64,
    /// PAGE_OFFSET for 4-level paging (can be adjusted for KASLR)
    page_offset_4level: u64,
    /// PAGE_OFFSET for 5-level paging (can be adjusted for KASLR)
    page_offset_5level: u64,
}

impl MemoryTranslator {
    /// Create a new memory translator with the given regions
    /// Uses default phys_base of 0x1000000 (16MB) which is standard for x86-64
    pub fn new(regions: Vec<MemoryRegion>) -> Self {
        MemoryTranslator {
            regions,
            phys_base: 0x1000000,                   // Default 16MB
            page_offset_4level: PAGE_OFFSET_4LEVEL, // Standard 4-level paging
            page_offset_5level: PAGE_OFFSET_5LEVEL, // Standard 5-level paging
        }
    }

    /// Set the physical base address from kernel symbols or auto-detection
    pub fn set_phys_base(&mut self, phys_base: u64) {
        self.phys_base = phys_base;
    }

    /// Get the current physical base address
    pub fn get_phys_base(&self) -> u64 {
        self.phys_base
    }

    /// Set the detected PAGE_OFFSET for 4-level paging (for KASLR)
    pub fn set_page_offset_4level(&mut self, offset: u64) {
        self.page_offset_4level = offset;
    }

    /// Set the detected PAGE_OFFSET for 5-level paging (for KASLR)
    pub fn set_page_offset_5level(&mut self, offset: u64) {
        self.page_offset_5level = offset;
    }

    /// Get the current PAGE_OFFSET for 4-level paging
    #[allow(dead_code)] // Reserved for diagnostic/debug features
    pub fn get_page_offset_4level(&self) -> u64 {
        self.page_offset_4level
    }

    /// Get the current PAGE_OFFSET for 5-level paging
    #[allow(dead_code)] // Reserved for diagnostic/debug features
    pub fn get_page_offset_5level(&self) -> u64 {
        self.page_offset_5level
    }

    /// Convert a kernel virtual address to physical address
    ///
    /// For x86-64 Linux kernel:
    /// - Kernel text (.text, .data, etc.): virtual >= 0xffffffff81000000 -> physical = (virtual - 0xffffffff80000000) + phys_base
    /// - Direct mapping: virtual PAGE_OFFSET + offset -> physical 0x0 + offset
    fn virtual_to_physical(&self, virtual_addr: u64) -> Option<u64> {
        debug!("[DEBUG] Translating virtual address: 0x{:x}", virtual_addr);
        debug!("[DEBUG] Using phys_base: 0x{:x}", self.phys_base);

        // Check if it's in kernel text/data region (0xffffffff80000000 - 0xffffffffff000000)
        if virtual_addr >= KERNEL_MAP_BASE && virtual_addr < 0xffffffffff000000 {
            // Kernel text mapping:
            // Virtual addresses in this range map to: phys_base + (virtual - __START_KERNEL_map)
            let offset = virtual_addr - KERNEL_MAP_BASE;
            let physical = self.phys_base + offset;

            debug!(
                "[DEBUG] Kernel text mapping: offset=0x{:x}, physical=0x{:x}",
                offset, physical
            );

            return Some(physical);
        }

        // Check if it's in 5-level paging direct mapping (0xffff888000000000 - 0xffffc87fffffffff)
        if virtual_addr >= self.page_offset_5level && virtual_addr < 0xffffc88000000000 {
            let physical = virtual_addr - self.page_offset_5level;

            debug!("[DEBUG] 5-level paging direct mapping: physical=0x{:x} (page_offset_5level=0x{:x})",
                          physical, self.page_offset_5level);

            return Some(physical);
        }

        // Check if it's in 4-level paging direct mapping (0xffff880000000000 - 0xffffc7ffffffffff)
        if virtual_addr >= self.page_offset_4level && virtual_addr < 0xffffc80000000000 {
            let physical = virtual_addr - self.page_offset_4level;

            debug!("[DEBUG] 4-level paging direct mapping: physical=0x{:x} (page_offset_4level=0x{:x})",
                          physical, self.page_offset_4level);

            return Some(physical);
        }

        // Address doesn't match known kernel mappings
        debug!("[DEBUG] Address not in known kernel mappings");

        None
    }

    /// Translate a virtual kernel address to a file offset
    ///
    /// This function:
    /// 1. Converts virtual address to physical address using kernel mapping rules
    /// 2. Finds which LIME region contains the physical address
    /// 3. Calculates the file offset within that region
    pub fn virtual_to_file_offset(&self, virtual_addr: u64) -> Option<u64> {
        // First, try to convert virtual address to physical
        let physical_addr = self.virtual_to_physical(virtual_addr)?;

        // Now find which region contains this physical address
        for region in &self.regions {
            if physical_addr >= region.start && physical_addr <= region.end {
                let offset_in_region = physical_addr - region.start;
                return Some(region.file_offset + offset_in_region);
            }
        }

        None
    }

    /// Find which region contains a virtual address
    #[allow(dead_code)]
    pub fn find_region(&self, virtual_addr: u64) -> Option<&MemoryRegion> {
        // Convert virtual to physical first
        let physical_addr = self.virtual_to_physical(virtual_addr)?;
        self.regions
            .iter()
            .find(|region| region.contains(physical_addr))
    }

    /// Get all memory regions
    #[allow(dead_code)]
    pub fn get_regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Get the number of regions
    #[allow(dead_code)]
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }
}
