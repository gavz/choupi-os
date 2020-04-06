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

//! Emulate flash accessors

use spin::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use {privilege, FLASH, SECTORS};

/// Flash lock flag
static LOCKED: AtomicBool = AtomicBool::new(true);
/// Flash mutex simulator
pub static FLASH_TEST_RUNNING: Mutex<()> = Mutex::new(());

/// Emulate flasg sectors access
pub fn sectors() -> Vec<::flash::SectorInfo> {
    SECTORS
        .iter()
        .enumerate()
        .map(|(i, &(begin, size))| ::flash::SectorInfo {
            num: i as u32,
            start: unsafe { (&mut FLASH.get_mut()[0] as *mut u8).offset(begin as isize) },
            length: size,
        })
        .collect()
}

/// Emulate flash locked flag
pub fn locked() -> bool {
    LOCKED.load(Ordering::SeqCst)
}

/// Emulate flash unlock flag
pub unsafe fn unlock() {
    assert!(locked() && privilege::is_privileged());
    LOCKED.store(false, Ordering::SeqCst);
}

/// Emulate flash lock flag
pub unsafe fn lock() {
    assert!(!locked() && privilege::is_privileged());
    LOCKED.store(true, Ordering::SeqCst);
}

/// Emulate flash setup
pub unsafe fn setup() {
    assert!(!locked() && privilege::is_privileged());
}

/// Emulate flash check error flag
pub unsafe fn has_error() -> u32 {
    assert!(privilege::is_privileged());
    0
}

/// Emulate flash clear error flag
pub unsafe fn clear_error() {
    assert!(privilege::is_privileged());
}

/// Emulate flash busy flag
pub unsafe fn currently_busy() -> bool {
    assert!(privilege::is_privileged());
    false
}

/// Erasing flash sector
pub unsafe fn erase(sector: u32) {
    assert!(!locked() && privilege::is_privileged());
    let (begin, size) = SECTORS[sector as usize];
    for i in begin..(begin + size) {
        FLASH.get_mut()[i] = 0xFF;
    }
}

/// Writing flash method
pub unsafe fn write(addr: *mut u32, val: u32) {
    assert!(!locked() && privilege::is_privileged());
    *addr &= val;
}
