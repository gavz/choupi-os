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
use tools::LinkerSymbol;
use {flash, fs};

/// Number of sectors in the MPU
pub const MPU_SECTORS: usize = 8;

/// Minimal size of a MPU sector
///
/// Can be determined by writing `0xFFFFFFFF` to `0xE000ED9C` then reading it back, and taking the
/// number of trailing zeroes.
pub const MPU_MIN_SIZE: usize = 32;

/// List of sectors in the flash
const FLASH_SECTORS: &[SectorInfo; 8] = &[
    SectorInfo {
        num: 0,
        start: 0x8000000 as *mut u8,
        length: 0x4000,
    },
    SectorInfo {
        num: 1,
        start: 0x8004000 as *mut u8,
        length: 0x4000,
    },
    SectorInfo {
        num: 2,
        start: 0x8008000 as *mut u8,
        length: 0x4000,
    },
    SectorInfo {
        num: 3,
        start: 0x800c000 as *mut u8,
        length: 0x4000,
    },
    SectorInfo {
        num: 4,
        start: 0x8010000 as *mut u8,
        length: 0x10000,
    },
    SectorInfo {
        num: 5,
        start: 0x8020000 as *mut u8,
        length: 0x20000,
    },
    SectorInfo {
        num: 6,
        start: 0x8040000 as *mut u8,
        length: 0x20000,
    },
    SectorInfo {
        num: 7,
        start: 0x8060000 as *mut u8,
        length: 0x20000,
    },
];

/// Number of buckets for the flash lock hashset
pub const FLASH_LOCK_BUCKETS: usize = 16;

/// List of sectors
pub const fn flash_sectors() -> &'static [SectorInfo] {
    FLASH_SECTORS
}

/// Sectors reserved for the code
pub const FLASH_PROGRAM_SECTORS: &[flash::SectorID] = &[flash::SectorID(0), flash::SectorID(7)];

/// Sectors used for the filesystem
pub const FLASH_FS_SECTORS: &[flash::SectorID] = &[
    flash::SectorID(1),
    flash::SectorID(2),
    flash::SectorID(3),
    flash::SectorID(4),
    flash::SectorID(5),
    flash::SectorID(6),
];

/// Sector reserved for defragmenting (inside the sectors used for the filesystem)
pub const FLASH_DEFRAG_SECTOR: fs::SectorID = fs::SectorID(5); // Reserve sector 6 as defrag sector

/// Sector reserved for applets (inside the sectors used for the filesystem)
pub const FLASH_APPLET_SECTOR: fs::SectorID = fs::SectorID(4); // Reserve sector 5 as applet sector

/// Address at the beginning of the running program
pub const fn program_begin() -> *const u8 {
    flash_sectors()[7].start
}

/// Size of the running program
pub const fn program_size() -> usize {
    flash_sectors()[7].length
}

/// Address at the beginning of the applet sector
pub const fn applet_begin() -> *const u8 {
    flash_sectors()[5].start
}

/// Size of the applet sector
pub const fn applet_size() -> usize {
    flash_sectors()[5].length
}

/// Begin of the RAM
pub const fn ram_begin() -> *const u8 {
    0x20000000 as *const u8
}

/// Size of the RAM
pub const fn ram_size() -> usize {
    0x18000
}

#[allow(improper_ctypes)]
extern "C" {
    static mpu_shared_ro_start: LinkerSymbol;
    static mpu_shared_ro_size: LinkerSymbol;
    static mpu_shared_rw_start: LinkerSymbol;
    static mpu_shared_rw_size: LinkerSymbol;
    static mpu_argbuf_size: LinkerSymbol;
}

/// Begin address of the range reserved to shared data by the linker script
pub fn shared_ro_start() -> *const u8 {
    unsafe { &mpu_shared_ro_start as *const _ as _ }
}

/// Size of the range reserved to shared data by the linker script
pub fn shared_ro_size() -> usize {
    unsafe { &mpu_shared_ro_size as *const _ as _ }
}

/// Begin address of the range reserved to shared data
pub fn shared_rw_start() -> *const u8 {
    unsafe { &mpu_shared_rw_start as *const _ as _ }
}

/// Size of the range reserved to shared data (excluding the argument buffer)
pub fn shared_rw_size() -> usize {
    unsafe { &mpu_shared_rw_size as *const _ as usize - &mpu_argbuf_size as *const _ as usize }
}

/// Begin address of the argument buffer
pub fn argbuf_start() -> *const u8 {
    unsafe {
        (&mpu_shared_rw_start as *const _ as *const u8).wrapping_offset(shared_rw_size() as isize)
    }
}

/// Size of the argument buffer
pub fn argbuf_size() -> usize {
    unsafe { &mpu_argbuf_size as *const _ as _ }
}

/// Size of the range reserved to shared data (including the argument buffer)
pub fn shared_rw_total_size() -> usize {
    unsafe { &mpu_shared_rw_size as *const _ as _ }
}
