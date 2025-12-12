//! Memory module for handling LIME format memory dumps
use crate::error::AnalysisError;
use memmap2::Mmap;
use std::fs::File;

/// Structure to hold a memory region parsed from the LIME header.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
}

impl MemoryRegion {
    /// Check if an address is within this memory region
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address <= self.end
    }

    /// Convert a virtual address to a file offset within this region
    #[allow(dead_code)] // Reserved for future region-based translation
    pub fn virtual_to_file_offset(&self, virtual_addr: u64) -> Option<u64> {
        if self.contains(virtual_addr) {
            let offset = virtual_addr - self.start;
            Some(self.file_offset + offset)
        } else {
            None
        }
    }
}

/// Memory mapped file handle
pub struct MemoryMap {
    _file: File,
    pub mapped: Mmap,
}

impl MemoryMap {
    /// Create a new memory map from a file path
    pub fn new(file_path: &str) -> Result<Self, AnalysisError> {
        let file = File::open(file_path)?;
        let mapped = unsafe { Mmap::map(&file)? };
        Ok(MemoryMap {
            _file: file,
            mapped,
        })
    }

    /// Check if the beginning of the file is the LIME signature.
    pub fn is_lime(&self) -> bool {
        // LIME magic bytes: 0x45 0x4D 0x69 0x4C = "EMiL" in ASCII
        if self.mapped.len() < 4 {
            return false;
        }

        // Check for LiME magic
        let magic = u32::from_le_bytes([
            self.mapped[0],
            self.mapped[1],
            self.mapped[2],
            self.mapped[3],
        ]);

        // When bytes [0x45, 0x4D, 0x69, 0x4C] are read as little-endian u32 = 0x4C694D45
        magic == 0x4C694D45
    }

    /// Parse the LIME header from the memory capture and return memory regions.
    /// LIME format structure (32 bytes per segment header):
    /// - Magic: 4 bytes (0x4C694D45 when bytes [0x45, 0x4D, 0x69, 0x4C] read as LE u32)
    /// - Version: 4 bytes (u32)
    /// - Start: 8 bytes (u64) - physical address start
    /// - End: 8 bytes (u64) - physical address end
    /// - Reserved: 8 bytes
    /// After each header comes the actual memory data for that region.
    pub fn parse_lime_header(&self) -> Option<Vec<MemoryRegion>> {
        const LIME_MAGIC: u32 = 0x4C694D45; // bytes [0x45, 0x4D, 0x69, 0x4C] = "EMiL" ASCII
        const HEADER_SIZE: usize = 32;

        if self.mapped.len() < HEADER_SIZE {
            return None;
        }

        let mut regions = Vec::new();
        let mut offset = 0usize;

        // Parse all LIME segment headers
        while offset + HEADER_SIZE <= self.mapped.len() {
            // Read magic
            let magic = u32::from_le_bytes([
                self.mapped[offset],
                self.mapped[offset + 1],
                self.mapped[offset + 2],
                self.mapped[offset + 3],
            ]);

            // If not LIME magic, we've reached the end of headers or invalid data
            if magic != LIME_MAGIC {
                break;
            }

            // Read version (offset 4-7)
            let _version = u32::from_le_bytes([
                self.mapped[offset + 4],
                self.mapped[offset + 5],
                self.mapped[offset + 6],
                self.mapped[offset + 7],
            ]);

            // Read start address (offset 8-15)
            let start = u64::from_le_bytes([
                self.mapped[offset + 8],
                self.mapped[offset + 9],
                self.mapped[offset + 10],
                self.mapped[offset + 11],
                self.mapped[offset + 12],
                self.mapped[offset + 13],
                self.mapped[offset + 14],
                self.mapped[offset + 15],
            ]);

            // Read end address (offset 16-23)
            let end = u64::from_le_bytes([
                self.mapped[offset + 16],
                self.mapped[offset + 17],
                self.mapped[offset + 18],
                self.mapped[offset + 19],
                self.mapped[offset + 20],
                self.mapped[offset + 21],
                self.mapped[offset + 22],
                self.mapped[offset + 23],
            ]);

            // Reserved bytes at offset 24-31 (not used)

            // Calculate the size of this region's data
            let region_size = (end - start + 1) as usize;

            // The file offset for this region's data starts after the header
            let file_offset = (offset + HEADER_SIZE) as u64;

            // Add the region
            regions.push(MemoryRegion {
                start,
                end,
                file_offset,
            });

            // Move to the next segment (header + data)
            offset += HEADER_SIZE + region_size;
        }

        if regions.is_empty() {
            None
        } else {
            Some(regions)
        }
    }

    /// Get a slice of the mapped memory at the specified offset and length
    #[allow(dead_code)]
    pub fn get_slice(&self, offset: usize, length: usize) -> Option<&[u8]> {
        if offset + length <= self.mapped.len() {
            Some(&self.mapped[offset..offset + length])
        } else {
            None
        }
    }

    /// Get the size of the mapped memory
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.mapped.len()
    }

    /// Check if the mapped memory is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.mapped.is_empty()
    }
}
