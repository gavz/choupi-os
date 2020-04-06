// The MIT License (MIT)
//
// Copyright (c) 2020, National Cybersecurity Agency of France (ANSSI)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//! Platform definition for the stm32f401re

use flash::SectorInfo;
use {flash, fs};

// Semantically this is a 0x80000-aligned 0x80000 byte array (but a more-than-0x8000-aligned type
// appears to not be supported)
#[cfg(feature = "big_ram")]
/// RAM memory organization
pub struct RamAligned {
    unaligned: [u8; 0x1000000],
    align: usize,
    size: usize,
}

#[cfg(not(feature = "big_ram"))]
/// RAM memory organization
pub struct RamAligned {
    unaligned: [u8; 0x100000],
    align: usize,
    size: usize,
}

/// Flash memory organization
pub struct FlashAligned {
    unaligned: [u8; 0x100000],
    align: usize,
    size: usize,
}

/// RAM accessor
impl RamAligned {
    /// Const getter memory access
    pub fn get(&self) -> &[u8] {
        let begin_addr = &self.unaligned[0] as *const _ as usize;
        let aligned_begin_addr = (begin_addr & !(self.align - 1)) + self.align;
        let offset = aligned_begin_addr - begin_addr;
        &self.unaligned[offset..(offset + self.size)]
    }
    /// non const getter memory access
    pub fn get_mut(&mut self) -> &mut [u8] {
        let begin_addr = &self.unaligned[0] as *const _ as usize;
        let aligned_begin_addr = (begin_addr & !(self.align - 1)) + self.align;
        let offset = aligned_begin_addr - begin_addr;
        &mut self.unaligned[offset..(offset + self.size)]
    }
}

/// FLASH accessor
impl FlashAligned {
    /// Const getter memory access
    pub fn get(&self) -> &[u8] {
        let begin_addr = &self.unaligned[0] as *const _ as usize;
        let aligned_begin_addr = (begin_addr & !(self.align - 1)) + self.align;
        let offset = aligned_begin_addr - begin_addr;
        &self.unaligned[offset..(offset + self.size)]
    }
    /// non const getter memory access
    pub fn get_mut(&mut self) -> &mut [u8] {
        let begin_addr = &self.unaligned[0] as *const _ as usize;
        let aligned_begin_addr = (begin_addr & !(self.align - 1)) + self.align;
        let offset = aligned_begin_addr - begin_addr;
        &mut self.unaligned[offset..(offset + self.size)]
    }
}

#[cfg(feature = "big_ram")]
/// RAM structure
pub static mut RAM: RamAligned = RamAligned {
    unaligned: [0; 0x1000000],
    align: 0x200000,
    size: 0x200000,
};
#[cfg(not(feature = "big_ram"))]
pub static mut RAM: RamAligned = RamAligned {
    unaligned: [0; 0x100000],
    align: 0x20000,
    size: 0x20000,
};

/// Flash structure
pub static mut FLASH: FlashAligned = FlashAligned {
    unaligned: [0xFF; 0x100000],
    align: 0x80000,
    size: 0x80000,
};

/// List of flash sectors addresses
pub static SECTORS: [(usize, usize); 8] = [
    // (begin, size)
    (0, 0x4000),
    (0x4000, 0x4000),
    (0x8000, 0x4000),
    (0xC000, 0x4000),
    (0x10000, 0x10000),
    (0x20000, 0x20000),
    (0x40000, 0x20000),
    (0x60000, 0x20000),
];

/// Number of buckets for the flash lock hashset
pub const FLASH_LOCK_BUCKETS: usize = 16;

/// Get the flash sectors list
pub fn flash_sectors() -> Vec<SectorInfo> {
    SECTORS
        .iter()
        .enumerate()
        .map(|(i, &(begin, size))| SectorInfo {
            num: i as u32,
            start: unsafe { (&mut FLASH.get_mut()[0] as *mut _ as *mut u8).offset(begin as isize) },
            length: size,
        })
        .collect()
}

/// Flash program sector
pub const FLASH_PROGRAM_SECTORS: &[flash::SectorID] = &[flash::SectorID(0), flash::SectorID(7)];

/// Flash sector list
pub const FLASH_FS_SECTORS: &[flash::SectorID] = &[
    flash::SectorID(1),
    flash::SectorID(2),
    flash::SectorID(3),
    flash::SectorID(4),
    flash::SectorID(5),
    flash::SectorID(6),
];

/// The sector uses to defrag other flash memory sector.
pub const FLASH_DEFRAG_SECTOR: fs::SectorID = fs::SectorID(5); // Reserve sector 6 as applet sector
/// The sector where applet are stored.
pub const FLASH_APPLET_SECTOR: fs::SectorID = fs::SectorID(4); // Reserve sector 5 as applet sector

/// MPU sector size
pub const MPU_SECTORS: usize = 8;
/// MPU min size allow
pub const MPU_MIN_SIZE: usize = 32;

/// Get program begin address
pub fn program_begin() -> *const u8 {
    (unsafe { &FLASH.get()[0] as *const u8 }).wrapping_offset(SECTORS[7].0 as isize)
}

/// Get program size
pub fn program_size() -> usize {
    SECTORS[7].1
}

/// Get applet begin adress
pub fn applet_begin() -> *const u8 {
    (unsafe { &FLASH.get()[0] as *const u8 }).wrapping_offset(SECTORS[5].0 as isize)
}

/// Get applet size
pub fn applet_size() -> usize {
    SECTORS[5].1
}

/// Get RAM begin address
pub fn ram_begin() -> *const u8 {
    0 as *const u8 //  &RAM.get()[0]
}

/// Get RAM size
pub fn ram_size() -> usize {
    0x800000000000000 as usize // uunsafe { RAM.get().len() }
}

/// Get shared RO start address
pub fn shared_ro_start() -> *const u8 {
    unsafe { &RAM.get()[0] }
}

/// Get shared RO size
pub fn shared_ro_size() -> usize {
    0x800
}

/// Get shared RW start
pub fn shared_rw_start() -> *const u8 {
    unsafe { &RAM.get()[0x800] }
}

/// Get shared RW size
pub fn shared_rw_size() -> usize {
    0x400
}

/// Getting argbuf starting address
pub fn argbuf_start() -> *const u8 {
    unsafe { &RAM.get()[0xC00] }
}

/// Get argbuf size
pub fn argbuf_size() -> usize {
    0x400
}

/// Get shared RW total size
pub fn shared_rw_total_size() -> usize {
    0x800
}
