//! Memory translation module for converting between virtual, physical, and file offsets
use crate::memory::MemoryRegion;

/// Memory translation layer for converting between address spaces
pub struct MemoryTranslator {
    regions: Vec<MemoryRegion>,
}

impl MemoryTranslator {
    /// Create a new memory translator with the given regions
    pub fn new(regions: Vec<MemoryRegion>) -> Self {
        MemoryTranslator { regions }
    }

    /// Translate a virtual kernel address to a file offset
    pub fn virtual_to_file_offset(&self, virtual_addr: u64) -> Option<u64> {
        for region in &self.regions {
            if let Some(offset) = region.virtual_to_file_offset(virtual_addr) {
                return Some(offset);
            }
        }
        None
    }

    /// Find which region contains a virtual address
    #[allow(dead_code)]
    pub fn find_region(&self, virtual_addr: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|region| region.contains(virtual_addr))
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