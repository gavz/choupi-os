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

//! Module for syscalls handling IO via the USART

use alloc::boxed::Box;
use alloc::vec::Vec;
use context::CURRENT_CONTEXT;
use core::cmp::min;
use core::ptr::{null, null_mut};
use core::{mem, ptr, slice};
use flash::{Flash, Sector};
use fs::FileSystem;
use syscall::{syscall, Syscall};
use {
    context, filename, flash, flash_sectors, fs, registers, FLASH_APPLET_SECTOR,
    FLASH_DEFRAG_SECTOR, FLASH_FS_SECTORS, FLASH_PROGRAM_SECTORS,
};

static mut FLASH: *const Flash = null();
static mut FS_SECTORS: *mut Vec<&'static Sector> = null_mut();
static mut FS: *mut FileSystem = null_mut();

/// An error occurred while initializing the filesystem
#[derive(Debug)]
pub enum FsInitError {
    /// It was while initializing the flash hardware
    FlashInit(flash::InitError),
    /// It was while setting up the datastructures used to handle the filesystem
    FsInit(fs::Error),
}

/// Initialize the filesystem. *Must* be called before any other filesystem syscall, and from
/// privileged code.
pub unsafe fn privileged_fs_init() -> Result<(), FsInitError> {
    // Init the flash
    let f = get!(Flash::new(&flash_sectors()).map_err(FsInitError::FlashInit));
    // Lock program sectors
    for &s in FLASH_PROGRAM_SECTORS {
        let sector = f.sector(s);
        mem::forget(sector.read(0, sector.len()));
    }
    FLASH = Box::into_raw(Box::new(f));

    // Init the filesystem
    FS_SECTORS = Box::into_raw(Box::new(
        FLASH_FS_SECTORS
            .iter()
            .map(|&x| (*FLASH).sector(x))
            .collect(),
    ));
    FS = Box::into_raw(Box::new(get!(FileSystem::new(
        &*FLASH,
        &*FS_SECTORS,
        FLASH_DEFRAG_SECTOR,
        FLASH_APPLET_SECTOR
    )
    .map_err(FsInitError::FsInit))));
    Ok(())
}

/// Returns a pointer to the flash object (that can only be used from privileged code, hence the
/// `privileged_` prefix)
pub unsafe fn privileged_get_flash() -> *const Flash {
    FLASH
}

fn pass_tag(tag: &[u8]) -> [u8; 33] {
    let mut res = [0; 33];
    res[0] = tag.len() as u8;
    res[1..tag.len() + 1].copy_from_slice(tag);
    res
}

// This 'static is a bit of cheating: it's actually much less than this, so the reference must not
// be preserved longer than the syscall
unsafe fn retrieve_tag(tagaddr: usize) -> &'static [u8] {
    assert!(context::is_readable_from_current_context(tagaddr, 33));
    let tag: &[u8; 33] = (tagaddr as *const [u8; 33])
        .as_ref()
        .expect("Received null tag from userland");
    assert!(tag[0] < 32);
    &tag[1..tag[0] as usize + 1]
}

fn flash_error_to_usize(e: flash::IOError) -> usize {
    0x40000000
        | match e {
            flash::IOError::LockedError => 1,
            flash::IOError::OutOfBounds => 2,
            flash::IOError::UnknownError(e) => !0xF0000000 & e as usize,
        }
}

fn usize_to_flash_error(e: usize) -> flash::IOError {
    match e & !0x40000000 {
        1 => flash::IOError::LockedError,
        2 => flash::IOError::OutOfBounds,
        x => flash::IOError::UnknownError(x as u32),
    }
}

fn fs_error_to_usize(e: fs::Error) -> usize {
    0x80000000
        | match e {
            fs::Error::OutOfFlash => 1,
            fs::Error::NoSuchTag => 2,
            fs::Error::InvalidLengthForTag => 3,
            fs::Error::IO(e) => flash_error_to_usize(e),
        }
}

fn usize_to_fs_error(e: usize) -> fs::Error {
    match e & !0x80000000 {
        1 => fs::Error::OutOfFlash,
        2 => fs::Error::NoSuchTag,
        3 => fs::Error::InvalidLengthForTag,
        x => fs::Error::IO(usize_to_flash_error(x)),
    }
}

/// Returns `true` iff. the given tag exists on the file system
pub fn exists(tag: &[u8]) -> bool {
    unsafe { syscall(Syscall::FsExists, tag.as_ptr() as usize, tag.len(), 0) != 0 }
}

pub fn syscall_exists(ptr: usize, len: usize, _: usize) -> Option<usize> {
    unsafe {
        assert!(context::is_readable_from_current_context(ptr, len));
        let tag = slice::from_raw_parts(ptr as *const u8, len);
        assert!(filename::can_read(CURRENT_CONTEXT.ctxid(), tag));
        Some((*FS).has_tag(tag) as usize)
    }
}

/// Reads the `buffer.len()` first bytes (at most) of the file tagged `tag` into `buffer`
pub fn read(tag: &[u8], buffer: &mut [u8]) -> Result<(), fs::Error> {
    unsafe {
        let t = pass_tag(tag);
        let res = syscall(
            Syscall::FsRead,
            t.as_ptr() as usize,
            buffer.as_ptr() as usize,
            buffer.len(),
        );
        if res == 0 {
            Ok(())
        } else {
            Err(usize_to_fs_error(res))
        }
    }
}

pub fn syscall_read(tagaddr: usize, bufptr: usize, buflen: usize) -> Option<usize> {
    unsafe {
        assert!(context::is_writable_from_current_context(bufptr, buflen));
        let tag = retrieve_tag(tagaddr);
        assert!(filename::can_read(CURRENT_CONTEXT.ctxid(), tag));
        let res = syscall_read_impl(
            &mut *FS,
            retrieve_tag(tagaddr),
            slice::from_raw_parts_mut(bufptr as *mut u8, buflen),
        );
        Some(match res {
            Ok(()) => 0,
            Err(e) => fs_error_to_usize(e),
        })
    }
}

fn syscall_read_impl(fs: &mut FileSystem, tag: &[u8], buffer: &mut [u8]) -> Result<(), fs::Error> {
    let res = fs.read(tag)?;
    let len = min(buffer.len(), res.len());
    buffer[0..len].copy_from_slice(&res[0..len]);
    Ok(())
}

/// Returns a pointer to the file tagged `tag`
///
/// # Safety
///
/// The `'static` in the returned reference means there has to be a reboot after any addition or
/// removal of a file in the 'inplace' zone
pub unsafe fn read_inplace(tag: &[u8]) -> Result<&'static [u8], fs::Error> {
    let t = pass_tag(tag);
    let mut dataptrret: *const u8 = null();
    let mut datalenret: usize = 0;
    let err = syscall(
        Syscall::FsReadInplace,
        t.as_ptr() as usize,
        &mut dataptrret as *mut *const u8 as usize,
        &mut datalenret as *mut usize as usize,
    );
    if err == 0 {
        Ok(slice::from_raw_parts(dataptrret, datalenret))
    } else {
        Err(usize_to_fs_error(err))
    }
}

pub fn syscall_read_inplace(tagaddr: usize, dataptrret: usize, datalenret: usize) -> Option<usize> {
    unsafe {
        assert!(
            context::is_writable_from_current_context(dataptrret, mem::size_of::<usize>())
                && context::is_writable_from_current_context(datalenret, mem::size_of::<usize>())
        );
        let tag = retrieve_tag(tagaddr);
        assert!(filename::can_read(CURRENT_CONTEXT.ctxid(), tag));
        let res = match (*FS).read(tag) {
            Ok(b) => b,
            Err(e) => return Some(fs_error_to_usize(e)),
        };
        *(dataptrret as *mut *const u8) = &res[0] as *const u8;
        *(datalenret as *mut usize) = res.len();
        Some(0)
    }
}

/// Reads one byte from the file `tag` at offset `offset`
pub fn read_1b_at(tag: &[u8], offset: usize) -> Result<u8, fs::Error> {
    unsafe {
        let t = pass_tag(tag);
        let mut data = 0;
        let res = syscall(
            Syscall::FsRead1b,
            t.as_ptr() as usize,
            offset,
            &mut data as *mut _ as usize,
        );
        if res == 0 {
            Ok(data)
        } else {
            Err(usize_to_fs_error(res))
        }
    }
}

pub fn syscall_read_1b_at(tagaddr: usize, offset: usize, retaddr: usize) -> Option<usize> {
    unsafe {
        assert!(context::is_writable_from_current_context(retaddr, 1));
        let tag = retrieve_tag(tagaddr);
        assert!(filename::can_read(CURRENT_CONTEXT.ctxid(), tag));
        match (*FS).read(tag) {
            Ok(b) => {
                *(retaddr as *mut u8) = b[offset];
                Some(0)
            }
            Err(e) => Some(fs_error_to_usize(e)),
        }
    }
}

/// Writes byte `data` to the file `tag` at offset `offset`
pub fn write_1b_at(tag: &[u8], offset: usize, data: u8) -> Result<(), fs::Error> {
    unsafe {
        let t = pass_tag(tag);
        let res = syscall(
            Syscall::FsWrite1b,
            t.as_ptr() as usize,
            offset,
            data as usize,
        );
        if res == 0 {
            Ok(())
        } else {
            Err(usize_to_fs_error(res))
        }
    }
}

pub fn syscall_write_1b_at(tagaddr: usize, offset: usize, data: usize) -> Option<usize> {
    unsafe {
        let tag = retrieve_tag(tagaddr);
        assert!(filename::can_write(CURRENT_CONTEXT.ctxid(), tag));
        match (*FS).edit_at(tag, offset, &[data as u8]) {
            Ok(()) => Some(0),
            Err(e) => Some(fs_error_to_usize(e)),
        }
    }
}

/// Reads two bytes from the file `tag` at offset `offset` (`offset` being considered as a number
/// of 2-byte words)
pub fn read_2b_at(tag: &[u8], offset: usize) -> Result<u16, fs::Error> {
    unsafe {
        let t = pass_tag(tag);
        let mut data = 0;
        let res = syscall(
            Syscall::FsRead2b,
            t.as_ptr() as usize,
            offset,
            &mut data as *mut _ as usize,
        );
        if res == 0 {
            Ok(data)
        } else {
            Err(usize_to_fs_error(res))
        }
    }
}

pub fn syscall_read_2b_at(tagaddr: usize, offset: usize, retaddr: usize) -> Option<usize> {
    unsafe {
        assert!(retaddr & 1 == 0);
        assert!(context::is_writable_from_current_context(retaddr, 2));
        let tag = retrieve_tag(tagaddr);
        assert!(filename::can_read(CURRENT_CONTEXT.ctxid(), tag));
        match (*FS).read(tag) {
            Ok(b) => {
                *(retaddr as *mut u16) = ptr::read_unaligned(
                    (&b[0] as *const u8 as *const u16).wrapping_offset(offset as isize),
                );
                Some(0)
            }
            Err(e) => Some(fs_error_to_usize(e)),
        }
    }
}

/// Writes two bytes `data` to the file `tag` at offset `offset` (`offset` being considered as a
/// number of 2-byte words)
pub fn write_2b_at(tag: &[u8], offset: usize, data: u16) -> Result<(), fs::Error> {
    unsafe {
        let t = pass_tag(tag);
        let res = syscall(
            Syscall::FsWrite2b,
            t.as_ptr() as usize,
            2 * offset,
            data as usize,
        );
        if res == 0 {
            Ok(())
        } else {
            Err(usize_to_fs_error(res))
        }
    }
}

pub fn syscall_write_2b_at(tagaddr: usize, offset: usize, data: usize) -> Option<usize> {
    unsafe {
        let tag = retrieve_tag(tagaddr);
        assert!(filename::can_write(CURRENT_CONTEXT.ctxid(), tag));
        let d: [u8; 2] = mem::transmute(data as u16);
        match (*FS).edit_at(tag, offset, &d) {
            Ok(()) => Some(0),
            Err(e) => Some(fs_error_to_usize(e)),
        }
    }
}

/// Reads four bytes from the file `tag` at offset `offset` (`offset` being considered as a number
/// of 4-byte words)
pub fn read_4b_at(tag: &[u8], offset: usize) -> Result<u32, fs::Error> {
    unsafe {
        let t = pass_tag(tag);
        let mut data = 0;
        let res = syscall(
            Syscall::FsRead4b,
            t.as_ptr() as usize,
            offset,
            &mut data as *mut _ as usize,
        );
        if res == 0 {
            Ok(data)
        } else {
            Err(usize_to_fs_error(res))
        }
    }
}

pub fn syscall_read_4b_at(tagaddr: usize, offset: usize, retaddr: usize) -> Option<usize> {
    unsafe {
        assert!(retaddr & 3 == 0);
        assert!(context::is_writable_from_current_context(retaddr, 4));
        let tag = retrieve_tag(tagaddr);
        assert!(filename::can_read(CURRENT_CONTEXT.ctxid(), tag));
        match (*FS).read(tag) {
            Ok(b) => {
                *(retaddr as *mut u32) = ptr::read_unaligned(
                    (&b[0] as *const u8 as *const u32).wrapping_offset(offset as isize),
                );
                Some(0)
            }
            Err(e) => Some(fs_error_to_usize(e)),
        }
    }
}

/// Writes four bytes `data` to the file `tag` at offset `offset` (`offset` being considered as a
/// number of 4-byte words)
pub fn write_4b_at(tag: &[u8], offset: usize, data: u32) -> Result<(), fs::Error> {
    unsafe {
        let t = pass_tag(tag);
        let res = syscall(
            Syscall::FsWrite4b,
            t.as_ptr() as usize,
            4 * offset,
            data as usize,
        );
        if res == 0 {
            Ok(())
        } else {
            Err(usize_to_fs_error(res))
        }
    }
}

pub fn syscall_write_4b_at(tagaddr: usize, offset: usize, data: usize) -> Option<usize> {
    unsafe {
        let tag = retrieve_tag(tagaddr);
        assert!(filename::can_write(CURRENT_CONTEXT.ctxid(), tag));
        let d: [u8; 4] = mem::transmute(data as u32);
        match (*FS).edit_at(tag, offset, &d) {
            Ok(()) => Some(0),
            Err(e) => Some(fs_error_to_usize(e)),
        }
    }
}

/// Writes `data` as the new file named `tag`
pub fn write(tag: &[u8], data: &[u8]) -> Result<(), fs::Error> {
    unsafe {
        let t = pass_tag(tag);
        let res = syscall(
            Syscall::FsWrite,
            t.as_ptr() as usize,
            data.as_ptr() as usize,
            data.len(),
        );
        if res == 0 {
            Ok(())
        } else {
            Err(usize_to_fs_error(res))
        }
    }
}

pub fn syscall_write(tagaddr: usize, bufptr: usize, buflen: usize) -> Option<usize> {
    unsafe {
        assert!(context::is_readable_from_current_context(bufptr, buflen));
        let tag = retrieve_tag(tagaddr);
        assert!(filename::can_write(CURRENT_CONTEXT.ctxid(), tag) && !filename::is_applet(tag));
        let res = (*FS).write(tag, slice::from_raw_parts(bufptr as *const u8, buflen));
        Some(match res {
            Ok(()) => 0,
            Err(e) => fs_error_to_usize(e),
        })
    }
}

/// Writes `data` as an applet under tag `tag`
pub fn write_applet(tag: &[u8], data: &[u8]) -> ! {
    unsafe {
        let t = pass_tag(tag);
        syscall(
            Syscall::FsWriteApplet,
            t.as_ptr() as usize,
            data.as_ptr() as usize,
            data.len(),
        );
        panic!("Should never reach this point")
    }
}

pub fn syscall_write_applet(tagaddr: usize, bufptr: usize, buflen: usize) -> Option<usize> {
    unsafe {
        assert!(context::is_readable_from_current_context(bufptr, buflen));
        let tag = retrieve_tag(tagaddr);
        assert!(filename::can_write(CURRENT_CONTEXT.ctxid(), tag) && filename::is_applet(tag));
        (*FS)
            .write_applet(tag, slice::from_raw_parts(bufptr as *const u8, buflen))
            .expect("Unable to write applet");
        registers::reboot();
    }
}

/// Removes the file named `tag`
pub fn erase(tag: &[u8]) -> Result<(), fs::Error> {
    unsafe {
        let res = syscall(Syscall::FsErase, tag.as_ptr() as usize, tag.len(), 0);
        if res == 0 {
            Ok(())
        } else {
            Err(usize_to_fs_error(res))
        }
    }
}

pub fn syscall_erase(ptr: usize, len: usize, _: usize) -> Option<usize> {
    unsafe {
        assert!(context::is_readable_from_current_context(ptr, len));
        let tag = slice::from_raw_parts(ptr as *const u8, len);
        assert!(filename::can_write(CURRENT_CONTEXT.ctxid(), tag) && !filename::is_applet(tag));
        let res = (*FS).erase(tag);
        Some(match res {
            Ok(()) => 0,
            Err(e) => fs_error_to_usize(e),
        })
    }
}

/// Removes the applet named `tag`
pub fn erase_applet(tag: &[u8]) -> ! {
    unsafe {
        syscall(Syscall::FsEraseApplet, tag.as_ptr() as usize, tag.len(), 0);
        panic!("Should never reach this point");
    }
}

pub fn syscall_erase_applet(ptr: usize, len: usize, _: usize) -> Option<usize> {
    unsafe {
        assert!(context::is_readable_from_current_context(ptr, len));
        let tag = slice::from_raw_parts(ptr as *const u8, len);
        assert!(filename::can_write(CURRENT_CONTEXT.ctxid(), tag) && filename::is_applet(tag));
        (*FS).erase(tag).expect("Unable to erase applet");
        registers::reboot();
    }
}

/// Retrieves the length of the file tagged `tag`
pub fn length(tag: &[u8]) -> Result<usize, fs::Error> {
    unsafe {
        let mut len = 0;
        let res = syscall(
            Syscall::FsLength,
            tag.as_ptr() as usize,
            tag.len(),
            &mut len as *mut usize as usize,
        );
        if res == 0 {
            Ok(len)
        } else {
            Err(usize_to_fs_error(res))
        }
    }
}

pub fn syscall_length(ptr: usize, len: usize, lenret: usize) -> Option<usize> {
    unsafe {
        assert!(
            context::is_readable_from_current_context(ptr, len)
                && context::is_writable_from_current_context(lenret, mem::size_of::<usize>())
        );
        let tag = slice::from_raw_parts(ptr as *const u8, len);
        assert!(filename::can_read(CURRENT_CONTEXT.ctxid(), tag));
        match (*FS).read(tag) {
            Ok(b) => {
                ptr::write_unaligned(lenret as *mut usize, b.len());
                Some(0)
            }
            Err(e) => Some(fs_error_to_usize(e)),
        }
    }
}
