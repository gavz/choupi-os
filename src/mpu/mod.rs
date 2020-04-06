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

//! Low-level MPU handling.
//!
//! The MPU allows to set segments of the memory space as protected. Write-protection will apply
//! only to userspace processes, while execution-protection will apply to kernel space too.
//!
//! Strong restrictions apply: the MPU can only protect power-of-two-sized naturally-aligned
//! regions.

mod tests;

use spin::{Mutex, MutexGuard};
use {
    applet_begin, applet_size, mpu_ll, program_begin, program_size, shared_ro_size,
    shared_ro_start, shared_rw_start, shared_rw_total_size, MPU_MIN_SIZE, MPU_SECTORS,
};

/// Mutex to record whether an `Mpu` object already has taken ownership of the MPU.
static MPU_IN_USE: Mutex<()> = Mutex::new(());

/// Main structure for handling the MPU.
pub struct Mpu {
    /// Mutex guard holding `MPU_IN_USE` locked so long as this object exists
    _guard: MutexGuard<'static, ()>,
}

/// Whether a MPU segment should be writable
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Writable {
    /// It shouldn't
    No = 0,
    /// It should
    Yes = 1,
}

/// Whether a MPU segment should be executable
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Executable {
    /// It shouldn't
    No = 0,
    /// It should
    Yes = 1,
}

/// Index for a region of the MPU
pub struct Region(usize);

impl Region {
    /// Checks the index `x` is correct
    ///
    /// # Panics
    ///
    /// Panics if `x` is not a valid region index
    pub fn new(x: usize) -> Region {
        assert!(x < MPU_SECTORS);
        Region(x)
    }
}

impl Mpu {
    /// Initializes the MPU with a map all-permissive for Privileged mode and all-denying for
    /// Unprivideged mode
    /// Doesn't do anything but return an object allowed to setup the MPU. See `setup()` for
    /// one-time initialization.
    pub fn get() -> Mpu {
        Mpu {
            _guard: MPU_IN_USE.lock(),
        }
    }

    /// Enables the MPU with the default memory map enabled (ie. privileged mode able to RW all the
    /// memory)
    pub fn setup(&mut self) {
        unsafe { mpu_ll::setup() };
    }

    /// Sets permissions for an unprivileged region (along with enabling it)
    ///
    /// As all (important) rust code runs privileged, so this function cannot cause memory unsafety
    /// in the context of the OS.
    ///
    /// `region` is the number of the region to change
    ///
    /// `start` is a pointer to the beginning of the region to protect.
    ///
    /// `size` is the size of the region to protect.
    ///
    /// `writable` and `executable` define whether the region should be writable (by the guest)
    /// and/or executable (by both the host and the guest).
    ///
    /// `sub_region_disable` is the `SRD` field from ARMv7-M `MPU_RASR` register definition.
    ///
    /// # Panics
    ///
    /// Panics if trying to make a page both executable and writable.
    ///
    /// Also panics if `size` is not a power of two, or if `start` is not `size`-aligned.
    ///
    /// Can also panic if `sub_region_disable` is set with a `size` of less than 256 bytes (see
    /// ARMv7-M).
    #[inline(never)]
    pub fn set_unprivileged_region(
        &mut self,
        region: Region,
        start: *const u8,
        size: usize,
        writable: Writable,
        executable: Executable,
        sub_region_disable: Option<[bool; 8]>,
    ) {
        debug!(
            "(MPU) Setting unpriv {} ({:#p}-{:#p}) as {}",
            region.0,
            start,
            start.wrapping_offset(size as isize),
            match (writable, executable) {
                (Writable::Yes, Executable::Yes) => "RWX",
                (Writable::Yes, Executable::No) => "RW",
                (Writable::No, Executable::Yes) => "RX",
                (Writable::No, Executable::No) => "RO",
            }
        );
        assert_eq!(size & (size - 1), 0, "Size must be a power of two");
        assert!(
            size >= MPU_MIN_SIZE,
            "Size must be at least {} bytes",
            MPU_MIN_SIZE
        );
        assert_eq!(
            (start as usize) & (size - 1),
            0,
            "Start must be size-aligned"
        );
        assert!(
            !(executable == Executable::Yes && writable == Writable::Yes),
            "Disallowing writable-and-executable pages"
        );
        assert!(
            sub_region_disable.is_none() || size >= 256,
            "Cannot use SRD with regions sized below 256 bytes"
        );
        unsafe {
            mpu_ll::set_unprivileged_region(
                region.0,
                start,
                size,
                writable == Writable::Yes,
                executable == Executable::Yes,
                sub_region_disable,
            );
        }
    }

    /// Sets up unprivileged regions to get ready to run userland programs
    ///
    /// Calling `switch_userland` will also be necessary to run them successfully.
    pub fn setup_unpriv_regions(&mut self) {
        // Regions 0-2: Unused yet
        // Region 3: Allow RO access to CAP files
        self.set_unprivileged_region(
            Region::new(3),
            applet_begin(),
            applet_size(),
            Writable::No,
            Executable::No,
            None,
        );
        // Region 4: Allow RW access to shared-rw section
        self.set_unprivileged_region(
            Region::new(4),
            shared_rw_start(),
            shared_rw_total_size(),
            Writable::Yes,
            Executable::No,
            None,
        );
        // Region 5: Allow RO access to global variables
        self.set_unprivileged_region(
            Region::new(5),
            shared_ro_start(),
            shared_ro_size(),
            Writable::No,
            Executable::No,
            None,
        );
        // Region 6: Reserved for allowing the segment of RAM reserved for the context
        // Region 7: Allow RX access to firmware code
        self.set_unprivileged_region(
            Region::new(7),
            program_begin(),
            program_size(),
            Writable::No,
            Executable::Yes,
            None,
        );
    }

    /// Switch the segment allowing userland to access RAM to the one given in parameters
    pub fn switch_userland(&mut self, begin: *const u8, size: usize) {
        self.set_unprivileged_region(
            Region::new(6),
            begin,
            size,
            Writable::Yes,
            Executable::No,
            None,
        );
    }
}
