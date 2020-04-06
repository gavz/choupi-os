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

//! Low-level Flash handling.
//!
//! The flash is cut into sectors, by hardware design. Memory can be written from 1 to 0 at any
//! bit level, but writing from 0 to 1 requires to erase an entire sector.

mod tests;

use alloc::vec::Vec;
use core::borrow::Borrow;
use core::ops::Deref;
use core::ptr::{read_unaligned, read_volatile};
use core::slice;
use hashset::HashSet;
use spin::{Mutex, MutexGuard};
use {core, flash_ll, FLASH_LOCK_BUCKETS};

/// Errors that can happen when trying to initialize the flash datastructures.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum InitError {
    /// Another [`Flash`] object already locked the flash for its own usage.
    ///
    /// [`Flash`]: struct.Flash.html
    FlashInUse,
}

/// Errors that can happen when performing IO on the flash.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IOError {
    /// The picked location is already locked (in an incompatible with current access RW-lock
    /// mode).
    LockedError,

    /// The index has been given out of bounds.
    OutOfBounds,

    /// An unknown error happened.
    ///
    /// In this case, the argument is the contents of the FLASH_SR register masked with the
    /// [`FLASH_SR_ERR`] error bit mask.
    ///
    /// [`FLASH_SR_ERR`]: constant.FLASH_SR_ERR.html
    UnknownError(u32), // Argument is the contents of the FLASH_SR register
                       // masked with the error bit mask
}

/// Information describing a sector's low-level informations.
///
/// It is used only for passing arguments to [`Flash::new`].
///
/// [`Flash::new`]: struct.Flash.html#method.new
pub struct SectorInfo {
    /// `num` is only used to associate a sector with its flash-level identifier.  All along the
    /// code, the `id` arguments refer to the order in which the [`SectorInfo`]'s are given to
    /// [`Flash::new`] (and are of type [`flash::SectorID`]), not to the sector number given here.
    ///
    /// [`SectorInfo`]: struct.SectorInfo.html
    /// [`Flash::new`]: struct.Flash.html#method.new
    /// [`flash::SectorID`]: struct.SectorID.html
    pub num: u32,

    /// Pointer to the first byte of the flash sector in its memory-mapped region.
    pub start: *mut u8,

    /// Length of the flash sector.
    pub length: usize,
}

/// An identifier of sector as an index into the array given as a parameter of [`Flash::new`].
///
/// [`Flash::new`]: struct.Flash.html#method.new
#[derive(Copy, Clone)]
pub struct SectorID(pub usize); // A pointer into the `sectors` array

/// Main structure for handling the flash.
pub struct Flash {
    /// Mutex guard holding [`FLASH_IN_USE`] locked so long as this object exists
    ///
    /// [`FLASH_IN_USE`]: static.FLASH_IN_USE.html
    _guard: MutexGuard<'static, ()>,

    /// Lock that will be taken so long as the flash is open in writing (ie. between FLASH_KEYR
    /// being keyed in and FLASH_CR being locked again)
    locked: Mutex<()>,

    /// List of the sectors
    sectors: Vec<Sector>,
}

/// Internal structure for handling a sector
#[derive(Debug)]
pub struct Sector {
    /// Flash-level number for the sector
    num: u32,

    /// Pointer to the first byte of the sector
    start: *mut u8,

    /// Length of the sector
    length: usize,

    /// Set of all locks currently taken on this sector
    ///
    /// The elements are first a boolean that records whether the lock is a write-lock (true if it
    /// is), then the start index (within the sector), then the length of the borrowed block.
    locks: Mutex<HashSet<(bool, usize, usize)>>,
}

/// A read-only block of flash
pub struct FlashBlock<'a> {
    /// Index of the first byte in the parent sector
    start: usize,

    /// Length of the block
    length: usize,

    /// Reference to the parent sector
    sector: &'a Sector,
}

/// A read-write block of flash
pub struct FlashBlockMut<'a> {
    /// Index of the first byte in the parent sector
    start: usize,

    /// Length of the block
    length: usize,

    /// Reference to the parent sector
    sector: &'a Sector,
}

/// Mutex to record whether a [`Flash`] object already has taken ownership of the flash.
///
/// [`Flash`]: struct.Flash.html
static FLASH_IN_USE: Mutex<()> = Mutex::new(());

impl Flash {
    /// Initializes a Flash object from the list of sector information for the platform.
    ///
    /// # Errors
    ///
    /// Errors if the flash is already locked by another existing Flash object.
    ///
    /// # Safety
    ///
    /// The caller will be believed as to where the sectors are, so information provided has to fit
    /// the platform specifications.
    ///
    /// For direct use, sectors have to be less than 2GB long and to be 32-bit aligned.
    ///
    /// For use in a [`FileSystem`], sectors in addition have to be less than 128MB (2 ** (32 - 15)).
    ///
    /// Finally, this currently enables x32 parallelism, which means this function requires the
    /// chip to be powered in the 2.7V-3.6V range.
    ///
    /// [`FileSystem`]: ../fs/struct.FileSystem.html
    pub unsafe fn new(si: &[SectorInfo]) -> Result<Flash, InitError> {
        let guard = get!(FLASH_IN_USE
            .try_lock()
            .map_or(Err(InitError::FlashInUse), Ok));
        let sectors = si
            .into_iter()
            .map(|x| Sector {
                num: x.num,
                start: x.start,
                length: x.length,
                locks: Mutex::new(HashSet::new(FLASH_LOCK_BUCKETS)),
            })
            .collect();
        let res = Flash {
            _guard: guard,
            locked: Mutex::new(()),
            sectors: sectors,
        };
        with_flash_unlocked(&res, || {
            flash_ll::setup();
        })
        .expect("Only possible error should be flash already locked, and it has just been created");
        Ok(res)
    }

    /// Retrieves a reference to a sector in the flash.
    ///
    /// # Panics
    ///
    /// Panics if `id` is not a valid `SectorID`, ie. if the contained value is above
    /// `sectors.len()`.
    pub fn sector(&self, SectorID(id): SectorID) -> &Sector {
        &self.sectors[id]
    }
}

/// Returns an `IOError` if there is an error waiting in the `FLASH_SR` register.
fn test_for_error() -> Result<(), IOError> {
    unsafe {
        let res = match flash_ll::has_error() {
            0 => Ok(()),
            err => err!(IOError::UnknownError(err)),
        };
        if res.is_err() {
            flash_ll::clear_error();
        }
        res
    }
}

/// Returns true if `[a_start; a_length]` and `[b_start; b_length]` overlap on at least a byte.
///
/// Note: if `a_length` or `b_length` is 0, they will be treated as being 1.
fn overlap(a_start: usize, a_length: usize, b_start: usize, b_length: usize) -> bool {
    b_start < (a_start + a_length) && a_start < (b_start + b_length)
}

/// Waits for a flash operation to complete.
fn sync() {
    unsafe {
        while flash_ll::currently_busy() {
            // Busy wait for the flash not to be busy any longer
        }
    }
}

/// Calls callback `f` with the flash unlocked (ie. with the flash ready to receive writes).
fn with_flash_unlocked<F, T>(flash: &Flash, f: F) -> Result<T, IOError>
where
    F: FnOnce() -> T,
{
    let _lock = get!(flash
        .locked
        .try_lock()
        .map_or(Err(IOError::LockedError), Ok));
    unsafe {
        flash_ll::unlock();
    }
    let res = f();
    unsafe {
        flash_ll::lock();
    }
    Ok(res)
}

impl Sector {
    /// Add a lock to the lock table `self.locks`.
    ///
    /// # Errors
    ///
    /// This can error if an incompatible lock (ie. at least one is read-write) is already taken on
    /// a region intersecting with the one requested.
    fn lock(&self, rw: bool, start: usize, length: usize) -> Result<(), IOError> {
        let mut locks = self.locks.lock();
        // Check no borrow matches
        for &(lrw, lstart, llength) in locks.iter() {
            if (lrw || rw) && overlap(start, length, lstart, llength) {
                return err!(IOError::LockedError);
            }
        }
        // Add own borrow
        locks.insert((rw, start, length));
        Ok(())
    }

    /// Remove a lock from the lock table `self.locks`.
    ///
    /// # Safety
    ///
    /// This function cannot check that the lock is effectively released, hence it should only be
    /// called when [`FlashBlock`] and [`FlashBlockMut`] are dropped.
    ///
    /// [`FlashBlock`]: struct.FlashBlock.html
    /// [`FlashBlockMut`]: struct.FlashBlockMut.html
    unsafe fn unlock(&self, rw: bool, start: usize, length: usize) {
        let mut locks = self.locks.lock();
        // Remove borrow
        locks.remove(&(rw, start, length));
    }

    /// Returns the low-level number of this sector
    pub fn num(&self) -> usize {
        self.num as usize
    }

    /// Returns the length of the sector
    pub fn len(&self) -> usize {
        self.length
    }

    /// Returns a read-only flash block on the requested portion of this sector
    ///
    /// # Errors
    ///
    /// Errors if the requested portion of this sector exceeds the size of it, or if there is an
    /// incompatible lock on it.
    pub fn read(&self, start: usize, length: usize) -> Result<FlashBlock, IOError> {
        if start >= self.length || length > self.length || start + length > self.length {
            err!(IOError::OutOfBounds)
        } else {
            Ok(get!(FlashBlock::new(start, length, self)))
        }
    }

    /// Calls a callback, giving it a [`FlashBlockMut`] on the requested portion of this sector
    ///
    /// # Errors
    ///
    /// Errors if the portion exceeds the size of the sector, or if there is an incompatible lock
    /// on it.
    pub fn with_writer<F, T>(
        &self,
        flash: &Flash,
        start: usize,
        length: usize,
        f: F,
    ) -> Result<T, IOError>
    where
        F: FnOnce(FlashBlockMut) -> T,
    {
        if start >= self.length || length > self.length || start + length > self.length {
            err!(IOError::OutOfBounds)
        } else {
            get!(with_flash_unlocked(flash, || {
                get!(self.lock(true, start, length));
                let res = f(FlashBlockMut {
                    start: start,
                    length: length,
                    sector: self,
                });
                sync();
                unsafe {
                    self.unlock(true, start, length);
                }
                Ok(res)
            }))
        }
    }

    /// Erases the sector
    ///
    /// # Errors
    ///
    /// Errors if there is an IO error during the erase operation, or if there is an incompatible
    /// lock held anywhere on the sector.
    pub fn erase(&self, flash: &Flash) -> Result<(), IOError> {
        get!(with_flash_unlocked(flash, || {
            get!(self.lock(true, 0, self.length));
            unsafe {
                flash_ll::clear_error();
                flash_ll::erase(self.num);
                sync();
                self.unlock(true, 0, self.length);
                test_for_error()
            }
        }))
    }
}

impl<'a> FlashBlock<'a> {
    /// Locks the requested block in the requested sector then moves on
    fn new(start: usize, length: usize, sector: &Sector) -> Result<FlashBlock, IOError> {
        get!(sector.lock(false, start, length));
        Ok(FlashBlock {
            start: start,
            length: length,
            sector: sector,
        })
    }

    /// Returns the sector this block is defined on
    pub fn sector(&self) -> &Sector {
        self.sector
    }

    /// Returns the index of the first byte of this block in the sector it is defined on
    pub fn start(&self) -> usize {
        self.start
    }

    /// Returns a sub-FlashBlock in this sector (`start` is relative to the beginning of this
    /// sector)
    ///
    /// # Errors
    ///
    /// Errors if the requested `start + length` exceeds the current block's length.
    pub fn read(&self, start: usize, length: usize) -> Result<FlashBlock<'a>, IOError> {
        if start >= self.length || length > self.length || start + length > self.length {
            err!(IOError::OutOfBounds)
        } else {
            Ok(FlashBlock::new(self.start + start, length, self.sector)
                .expect("Unable to read-borrow a block despite it being already read-borrowed"))
        }
    }
}

impl<'a> Clone for FlashBlock<'a> {
    fn clone(&self) -> FlashBlock<'a> {
        FlashBlock::new(self.start, self.length, self.sector)
            .expect("Unable to read-borrow a block despite it being already read-borrowed")
    }
}

impl<'a> Drop for FlashBlock<'a> {
    fn drop(&mut self) {
        unsafe {
            self.sector.unlock(false, self.start, self.length);
        }
    }
}

impl<'a> Deref for FlashBlock<'a> {
    type Target = [u8];

    // Assumes self.start and self.length are sanely defined
    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.sector.start.offset(self.start as isize), self.length) }
    }
}

impl<'a> Borrow<[u8]> for FlashBlock<'a> {
    fn borrow(&self) -> &[u8] {
        &*self
    }
}

impl<'a> core::fmt::Debug for FlashBlock<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", (self as &[u8]))
    }
}

impl<'a> Deref for FlashBlockMut<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.sector.start.offset(self.start as isize), self.length) }
    }
}

impl<'a> FlashBlockMut<'a> {
    /// Writes a byte in this block
    ///
    /// # Errors
    ///
    /// Errors if the requested index is farther than the length of this block.
    pub fn write(&mut self, i: usize, v: u8) -> Result<(), IOError> {
        if i >= self.length {
            return err!(IOError::OutOfBounds);
        }
        unsafe {
            let aligned = (self.start + i) & !0b11; // Align to 32-bits boundary
            let addr = self.sector.start.offset(aligned as isize) as *mut u32;
            let pos = ((self.start + i) & 0b11) * 8; // Position of the byte inside the word
            let old = read_volatile(addr);
            let new = (old & !(0xFF << pos)) | ((v as u32) << pos);
            flash_ll::clear_error();
            flash_ll::write(addr, new);
            sync();
            Ok(get!(test_for_error()))
        }
    }

    fn write_block_generic<F8: Fn(usize) -> u8, F32: Fn(usize) -> u32>(
        &mut self,
        b: usize,
        length: usize,
        get_u8: F8,
        get_u32: F32,
    ) -> Result<(), IOError> {
        if b >= self.length || length > self.length || b + length > self.length {
            return err!(IOError::OutOfBounds);
        }
        let mut i = 0;
        // Byte-by-byte write until the first 32-bit aligned word
        while (self.start + b + i) & 0b11 != 0 && i < length {
            get!(self.write(b + i, get_u8(i)));
            i += 1;
        }
        // Word-by-word write until the last 32-bit aligned word
        unsafe {
            while (i + 3) < length {
                let addr = self.sector.start.offset((self.start + b + i) as isize);
                flash_ll::clear_error();
                flash_ll::write(addr as *mut u32, get_u32(i));
                sync();
                get!(test_for_error());
                i += 4;
            }
        }
        // Byte-by-byte write until the end
        while i < length {
            get!(self.write(b + i, get_u8(i)));
            i += 1;
        }
        Ok(())
    }

    /// Writes a block of contiguous memory in this block
    ///
    /// `b` is considered as being the starting index in this block of where to put `v`.
    ///
    /// # Errors
    ///
    /// Errors if `v` doesn't fit in this block when starting from index `b`.
    pub fn write_block(&mut self, b: usize, v: &[u8]) -> Result<(), IOError> {
        self.write_block_generic(
            b,
            v.len(),
            |x| v[x],
            |x| unsafe { read_unaligned(&v[x] as *const u8 as *const u32) },
        )
    }

    /// Writes a block of zeros in this block
    ///
    /// `b` is considered as being the starting index in this block of where to put `length` zeros.
    ///
    /// # Errors
    ///
    /// Errors if a block of `length` zeros doesn't fit in this block when starting from index `b`.
    pub fn zero_block(&mut self, b: usize, length: usize) -> Result<(), IOError> {
        self.write_block_generic(b, length, |_| 0, |_| 0)
    }
}
