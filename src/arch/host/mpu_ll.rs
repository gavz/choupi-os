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

//! Functions describing the low-level working of the MPU

use libc;
use spin::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use privilege;

static SETUP: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug)]
struct Region {
    start: usize,
    size: usize,
    writable: bool,
    executable: bool,
    sub_region_disable: Option<[bool; 8]>,
}

static REGIONS: Mutex<[Region; 8]> = Mutex::new(
    [Region {
        start: 0,
        size: 0,
        writable: true,
        executable: true,
        sub_region_disable: None,
    }; 8],
);

/// Check addr is in an allowed region
/// This function being executed inside other preempted functions, trying to call eg. println!
/// will cause a deadlock.
pub fn allows_addr(addr: *const u8) -> i32 {
    let mut final_prot = libc::PROT_NONE;
    let a = addr as usize;
    let r = REGIONS.try_lock();
    if r.is_none() {
        return libc::PROT_NONE; // fail if unable to recover r
    }
    let r = r.unwrap();
    for reg in r.iter() {
        if reg.start <= a && a < reg.start + reg.size {
            if !reg.sub_region_disable.is_none() {
                return libc::PROT_NONE; // SRD is not implemented yet
            }
            // Only highest-numbered region takes effect
            final_prot = libc::PROT_READ;
            if reg.writable {
                final_prot |= libc::PROT_WRITE;
            }
            if reg.executable {
                final_prot |= libc::PROT_EXEC;
            }
        }
    }
    if privilege::is_privileged() {
        final_prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    }
    final_prot
}

/// Set SETUP to true and assert it was to false beforehand
pub unsafe fn setup() {
    assert!(!SETUP.fetch_or(true, Ordering::SeqCst));
}

/// Set SETUP to false and assert it was to true beforehand
pub unsafe fn deinitialize() {
    assert!(SETUP.fetch_and(false, Ordering::SeqCst));
}

/// Set unpriviledged MPU region
pub unsafe fn set_unprivileged_region(
    region: usize,
    start: *const u8,
    size: usize,
    writable: bool,
    executable: bool,
    sub_region_disable: Option<[bool; 8]>,
) {
    assert!(SETUP.load(Ordering::SeqCst));
    assert_eq!(
        sub_region_disable, None,
        "SRD bits aren't tested yet, don't use them"
    );
    let mut r = REGIONS.try_lock().unwrap();
    r[region] = Region {
        start: start as usize,
        size,
        writable,
        executable,
        sub_region_disable,
    };
}

#[cfg(test)]
use speculate::speculate;

#[cfg(test)]
use std::ptr::null_mut;
#[cfg(test)]
use {emulator, tools, RAM};

#[cfg(test)]
speculate! {
    describe "mpu_ll_" {

        before {
            let _lock = emulator::one_test_at_a_time();
            unsafe { mpu_ll::setup(); }
            let _autodeinit = tools::run_on_drop(Box::new(|| unsafe { mpu_ll::deinitialize() }));
        }

        #[should_panic(expected = "assertion failed: !SETUP.fetch")]
        it "refuses initializing twice" {
            unsafe { mpu_ll::setup(); }
        }

        it "allows RW access to RAM when privileged" {
            emulator::run(|| {
                unsafe {
                    RAM.get_mut()[0] = 42;
                    assert_eq!(RAM.get()[0], 42);
                }
            });
        }

        #[should_panic(expected = "offset 0x2a")]
        it "disallows write-access to RAM when unprivileged" {
            emulator::run(|| {
                unsafe {
                    privilege::drop(null_mut());
                    RAM.get_mut()[42] = 12;
                }
            });
        }

        it "allows RW access out of the mprotected region, even if inside the same page" {
            emulator::run(|| {
                unsafe {
                    mpu_ll::set_unprivileged_region(0, &RAM.get()[0], 128, true, false, None);
                    mpu_ll::set_unprivileged_region(1, &RAM.get()[32], 32, false, false, None);
                    privilege::drop(null_mut());
                    RAM.get_mut()[31] = 42;
                    RAM.get_mut()[64] = 24;
                    assert_eq!(RAM.get()[31] + RAM.get()[64], 66);
                }
            });
        }

        #[should_panic(expected = "offset 0x3")]
        it "disallows write access to RAM when configured" {
            unsafe { println!("RAM is at {:?}", &RAM.get()[0] as *const _) };
            emulator::run(|| {
                unsafe {
                    println!("before setting unpriv region");
                    mpu_ll::set_unprivileged_region(0, &RAM.get()[0], 32, false, false, None);
                    privilege::drop(null_mut());
                    println!("after setting unpriv region");
                    RAM.get_mut()[3] = 42;
                }
            });
        }

        #[should_panic(expected = "offset 0x20")]
        it "doesn't allow off-by-one lower bound" {
            emulator::run(|| {
                unsafe {
                    mpu_ll::set_unprivileged_region(0, &RAM.get()[32], 32, false, false, None);
                    privilege::drop(null_mut());
                    RAM.get_mut()[32] = 42;
                }
            });
        }

        #[should_panic(expected = "offset 0x3f")]
        it "doesn't allow off-by-one upper bound" {
            emulator::run(|| {
                unsafe {
                    mpu_ll::set_unprivileged_region(0, &RAM.get()[32], 32, false, false, None);
                    privilege::drop(null_mut());
                    RAM.get_mut()[63] = 42;
                }
            });
        }
    }
}
