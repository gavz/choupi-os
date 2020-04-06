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

//! Definition of all functions reachable from C

#[cfg(feature = "embedded")]
use contextallocator::allocate_contexts;
#[cfg(feature = "embedded")]
use contextallocator::AllocatableContext as Context;
#[cfg(feature = "embedded")]
use core::alloc::{GlobalAlloc, Layout};
#[cfg(feature = "embedded")]
use core::ptr::write_bytes;
use core::slice;
#[cfg(feature = "embedded")]
use mpu::Mpu;
#[cfg(feature = "embedded")]
use {allocator, core, privilege, ram_begin, ram_size};
use {argbuf, context, filename, flash, fs, syscall};

#[cfg(feature = "host")]
use contextallocator::allocate_contexts;
#[cfg(feature = "host")]
use contextallocator::AllocatableContext as Context;
#[cfg(feature = "host")]
use mpu::Mpu;
#[cfg(feature = "host")]
use {emulator, privilege, ram_begin, ram_size, RAM};

/*************\
 * Allocator *
\*************/

/// Allocate a memory block of size `size` with alignment `align`
///
/// Panics on memory shortage
#[cfg(feature = "embedded")]
#[no_mangle]
pub unsafe extern "C" fn rust_allocate(size: usize, align: usize) -> *mut u8 {
    (&allocator::ALLOCATOR).alloc(Layout::from_size_align(size, align).unwrap())
}

/// Allocates a memory block filled with zero's of size `size` with alignment `align`
///
/// Panics on memory shortage
#[cfg(feature = "embedded")]
#[no_mangle]
pub unsafe extern "C" fn rust_allocate_zeroed(size: usize, align: usize) -> *mut u8 {
    let res = rust_allocate(size, align);
    write_bytes(res, 0, size);
    res
}

/// Announces that memory block at `ptr` with size `size` and alignment `align`
/// will no longer be used
///
/// Unsafe as it will both assume it was actually a memory block returned by
/// `rust_allocate` and that this block will no longer be used.
#[cfg(feature = "embedded")]
#[no_mangle]
pub unsafe extern "C" fn rust_deallocate(ptr: *mut u8, size: usize, align: usize) {
    (&allocator::ALLOCATOR).dealloc(ptr, Layout::from_size_align(size, align).unwrap())
}

/// Changes the size of block at `ptr` with alignment `align` from `old_size` to
/// `size`, if possible in-place, else by copying it
///
/// Returns a pointer to the new block
#[cfg(feature = "embedded")]
#[no_mangle]
pub unsafe extern "C" fn rust_reallocate(
    ptr: *mut u8,
    old_size: usize,
    size: usize,
    align: usize,
) -> *mut u8 {
    (&allocator::ALLOCATOR).realloc(ptr, Layout::from_size_align(old_size, align).unwrap(), size)
}

/*******\
 * MPU *
\*******/

/// Initializes the heap for context 0
///
/// This must be called *before* any attempt to dynamically allocate memory,
/// else the allocation will fail and panic.
#[cfg(feature = "embedded")]
#[no_mangle]
pub unsafe extern "C" fn heap_init() {
    allocator::initialize_heap();
}

/// Initializes the MPU and sets up context heaps. Also drops privileges.
///
/// This function is unsafe as it will drop privileges, which could lead to
/// unexpected consequences could be entailed by this.
#[cfg(feature = "embedded")]
#[no_mangle]
pub unsafe extern "C" fn mpu_init() {
    extern "C" {
        fn do_malloc();
    }

    let mut mpu = Mpu::get();
    mpu.setup();
    mpu.setup_unpriv_regions();
    mpu.switch_userland(ram_begin(), ram_size().next_power_of_two());
    drop(mpu); // Release lock to leave it open for interrupt handler

    let contexts = allocate_contexts(&[
        Context {
            // Context 0 is privileged, kernel context
            entrypoint: |_caller, _, _| {
                assert_eq!(_caller, 0);
                let _value = 0;
                debug!(
                    "REMOTE CALL TO CTX 0 from {}, stack at {:p}",
                    _caller, &_value
                );
                debug!("Do malloc on root context");
                do_malloc();
                debug!("Malloc done");

                0
            },
        },
        Context {
            entrypoint: |_caller, _, _| {
                let _value = 0;
                debug!(
                    "Remote call to ctx 1 from {}, stack at {:p}",
                    _caller, &_value
                );
                42
            },
        },
        Context {
            entrypoint: |_caller, _, _| {
                let _value = 0;
                debug!(
                    "Remote call to ctx 2 from {}, stack at {:p}",
                    _caller, &_value
                );
                syscall::remote_call(context::ContextID::from_id_unchecked(1), 0, 0)
                    + syscall::remote_call(context::ContextID::from_id_unchecked(1), 0, 0)
            },
        },
        Context {
            entrypoint: |_caller, x, _| {
                let _value = 0;
                debug!(
                    "Remote call to ctx 3 from {}, stack at {:p}, arg valued {}",
                    _caller, &_value, x
                );

                debug!("Do malloc on root unpriviledge context");
                do_malloc();
                debug!("Malloc done");

                if x > 1 {
                    x * syscall::remote_call(context::ContextID::from_id_unchecked(3), x - 1, 0)
                } else {
                    1
                }
            },
        },
        Context {
            entrypoint: |_caller, _x, _max| {
                let _value = 0;
                debug!(
                    "Remote call to ctx 4 from {}, stack at {:p}, arg valued {}",
                    _caller, &_value, _x
                );
                if _x > 1 {
                    syscall::remote_call(
                        context::ContextID::from_id_unchecked(5),
                        _x + 1,
                        if _x > _max { _x } else { _max },
                    )
                } else {
                    _max
                }
            },
        },
        Context {
            entrypoint: |_caller, _x, _max| {
                assert_eq!(_caller, 4);
                let _value = 0;
                debug!(
                    "Remote call to ctx 5 from {}, stack at {:p}, arg valued {}",
                    _caller, &_value, _x
                );
                if _x > 1 {
                    syscall::remote_call(
                        context::ContextID::from_id_unchecked(4),
                        _x / 2,
                        if _x > _max { _x } else { _max },
                    )
                } else {
                    _max
                }
            },
        },
    ]);

    context::init_contexts(contexts);
    privilege::drop(0x2001_7000 as *mut ());

    debug!("About to test syscall");
    syscall::test();
    debug!("Outside of test syscall");
    let _value = 0;
    debug!(
        "About to call function in remote context, current stack pointer is around {:p}",
        &_value
    );

    let _res = syscall::remote_call(context::ContextID::from_id_unchecked(1), 0, 0);
    debug!("Outside of remote call, result is {}", _res);
    debug!(
        "Next remote call (ctx2), result is {}",
        syscall::remote_call(context::ContextID::new(2), 0, 0)
    );
    debug!(
        "Next remote call (ctx0), result is {}",
        syscall::remote_call(context::ContextID::new(0), 0, 0)
    );
    debug!(
        "Using arguments, 6! = {}",
        syscall::remote_call(context::ContextID::new(3), 6, 0)
    );
    debug!("Interleaved recursion:");
    debug!(
        "Result: {}",
        syscall::remote_call(context::ContextID::new(4), 9, 0)
    );
}

/// Initializes the MPU and sets up context heaps. Also drops privileges.
///
/// This function is unsafe as it will drop privileges, which could lead to
/// unexpected consequences could be entailed by this.
#[no_mangle]
#[cfg(feature = "embedded")]
pub unsafe extern "C" fn mpu_init_javacard() {
    extern "C" {
        /// This function is the JCVM interpreter main function which will run
        /// inside the secure environment.
        fn runtime(package: u8, class: u8, method: u8);
        fn starting_jcre() -> u32;
    }

    let mut mpu = Mpu::get();
    mpu.setup();
    mpu.setup_unpriv_regions();
    mpu.switch_userland(ram_begin(), ram_size().next_power_of_two());
    drop(mpu); // Release lock to leave it open for interrupt handler

    let contexts = allocate_contexts(&[
        Context {
            // Context 0 is privileged, kernel context
            entrypoint: |_, _, _| {
                starting_jcre();
                0
            },
        },
        Context {
            // Context 1: APDU buffer?
            entrypoint: |_, _, _|
            // TODO: Implement APDU buffer handler.
            0,
        },
        Context {
            // Context 2 has Installer privileges
            // XXX: current implementation only update packages' table.
            entrypoint: |_, _arg, _| {
                let (package, class, method) = compute_method_info(_arg as u32);
                runtime(package, class, method);
                0
            },
        },
        Context {
            // Context 3
            entrypoint: |_, _arg, _| 0,
        },
    ]);

    context::init_contexts(contexts);
    privilege::drop(0x2001_7000 as *mut ());
}

/// Beginning of the shared RW segment (excluding the argument buffer)
#[no_mangle]
pub unsafe extern "C" fn shared_rw_start() -> *const u8 {
    ::shared_rw_start()
}

/// Size of the shared RW segment (excluding the argument buffer)
#[no_mangle]
pub unsafe extern "C" fn shared_rw_size() -> u32 {
    ::shared_rw_size() as u32
}

/// Sets up the argument buffer
#[no_mangle]
pub unsafe extern "C" fn setup_argbuf() {
    argbuf::setup_argbuf();
}

/// Retrieves the `len` first bytes of the argument buffer into `ret`. Note that
/// this will crash if a `set_argbuf` wasn't called just before with the same
/// `len` argument. This function also clears the read bytes.
#[no_mangle]
pub unsafe extern "C" fn get_argbuf(ret: *mut u8, len: u32) {
    argbuf::get_argbuf(slice::from_raw_parts_mut(ret, len as usize));
}

/// Sets the `len` first bytes of the argument buffer to `data`. Note that this
/// will crash if a `get_argbuf` wasn't called just before, or no `set_argbuf`
/// was called before in the card's lifetime.
#[no_mangle]
pub unsafe extern "C" fn set_argbuf(data: *const u8, len: u32) {
    argbuf::set_argbuf(slice::from_raw_parts(data, len as usize));
}

/// Calls the remote call handler for context `ctx` with arguments `arg1, arg2`.
/// The returned value of the handler will be passed back as the return value of
/// this function.
#[no_mangle]
pub unsafe extern "C" fn remote_call(ctx: u32, arg1: u32, arg2: u32) -> u32 {
    syscall::remote_call(
        context::ContextID::new(ctx as usize),
        arg1 as usize,
        arg2 as usize,
    ) as u32
}

/************\
 * Syscalls *
\************/

#[cfg(feature = "embedded")]
use std::os::raw::{c_char, c_int};
/// Write some data to the USART
#[cfg(feature = "embedded")]
#[no_mangle]
pub unsafe extern "C" fn _write(_: c_int, ptr: *const c_char, len: c_int) -> c_int {
    syscall::usart_output(core::str::from_utf8_unchecked(slice::from_raw_parts(
        ptr as *const u8,
        len as usize,
    )));
    len
}

/***************************\
 * Flash-related functions *
\***************************/

/// Result error code of the last flash operation.
///
/// This is used just like `errno` would be in C, in order not to make the
/// normal `return` scheme more complex with structs or pointers.
///
/// It is the caller's responsibility to make sure this value is set to 0
/// between calls.
#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut flash_error: u32 = 0;

/// Converts a `flash::IOError` to an error code
fn flash_io_error_to_errno(e: flash::IOError) -> u32 {
    match e {
        flash::IOError::LockedError => 1,
        flash::IOError::OutOfBounds => 2,
        flash::IOError::UnknownError(_) => 3,
    }
}

/// Converts a `flash::InitError` to an error code
fn flash_init_error_to_errno(e: flash::InitError) -> u32 {
    match e {
        flash::InitError::FlashInUse => 1,
    }
}

/// Get a pointer to the current flash memory.
#[no_mangle]
#[cfg(feature = "host")]
pub unsafe extern "C" fn flash_pointer() -> *mut u8 {
    &mut ::arch::FLASH.get_mut()[0]
}

/// Writes a byte to the flash.
///
/// Writes byte `val` to sector `sector` at index `idx`. The [`flash_error`]
/// global variable will be set to a non-zero value on failure.
///
/// # Panics
///
/// Panics if `sector` is not a valid sector number.
///
/// # Errors
///
/// Errors in case of flash I/O error or if an out-of-bounds index is given. If
/// the byte position being written is currently locked in reading, an error
/// will also be raised.
///
/// # Safety
///
/// [`flash_init`] must have been called before this function.
///
/// [`flash_error`]: static.flash_error.html
/// [`flash_init`]: fn.flash_init.html
#[no_mangle]
pub unsafe extern "C" fn flash_write(sector: u8, idx: u32, val: u8) {
    let res = (*syscall::privileged_get_flash())
        .sector(flash::SectorID(sector as usize))
        .with_writer(
            &*syscall::privileged_get_flash(),
            idx as usize,
            1,
            |mut b| b.write(0, val),
        );
    match res {
        Ok(Ok(_)) => (),
        Err(e) | Ok(Err(e)) => {
            flash_error = flash_io_error_to_errno(e);
        }
    }
}

/// Reads a byte from the flash.
///
/// Reads byte on sector `sector` at index `idx` and returns it. If an error is
/// raised, the [`flash_error`] global variable will be set to a non-zero value.
///
/// # Panics
///
/// Panics if `sector` is not a valid sector number.
///
/// # Errors
///
/// Errors in case of flash I/O error, of an out-of-bounds index, or if the byte
/// position trying to be read is currently locked in writing somewhere else.
///
/// # Safety
///
/// [`flash_init`] must have been called before this function.
///
/// [`flash_error`]: static.flash_error.html
/// [`flash_init`]: fn.flash_init.html
#[no_mangle]
pub unsafe extern "C" fn flash_read(sector: u8, idx: u32) -> u8 {
    let res = (*syscall::privileged_get_flash())
        .sector(flash::SectorID(sector as usize))
        .read(idx as usize, 1);
    match res {
        Ok(x) => x[0],
        Err(e) => {
            flash_error = flash_io_error_to_errno(e);
            0
        }
    }
}

/// Erases a flash sector.
///
/// Erases flash sector `sector`. [`flash_error`] will be set to a non-zero
/// value if an error is raised.
///
/// # Panics
///
/// Panics if `sector` is not a valid sector number.
///
/// # Errors
///
/// Errors in case of flash I/O error or if a part of the sector is currently
/// being locked in reading or writing somewhere else.
///
/// # Safety
///
/// [`flash_init`] must have been called before this function.
///
/// [`flash_error`]: static.flash_error.html
/// [`flash_init`]: fn.flash_init.html
#[no_mangle]
pub unsafe extern "C" fn flash_erase(sector: u8) {
    let res = (*syscall::privileged_get_flash())
        .sector(flash::SectorID(sector as usize))
        .erase(&*syscall::privileged_get_flash());
    if let Err(e) = res {
        flash_error = flash_io_error_to_errno(e);
    }
}

/// Erases a flash sector with 0's.
///
/// Erases flash sector `sector` with 0's. [`flash_error`] will be set to a
/// non-zero value if an error is raised.
///
/// # Panics
///
/// Panics if `sector` is not a valid sector number.
///
/// # Errors
///
/// Errors in case of flash I/O error or if a part of the sector is currently
/// being locked in reading or writing somewhere else.
///
/// # Safety
///
/// [`flash_init`] must have been called before this function.
///
/// [`flash_error`]: static.flash_error.html
/// [`flash_init`]: fn.flash_init.html
#[no_mangle]
pub unsafe extern "C" fn flash_erase0(sector: u8) {
    let s = (*syscall::privileged_get_flash()).sector(flash::SectorID(sector as usize));
    let res = s.with_writer(&*syscall::privileged_get_flash(), 0, s.len(), |mut b| {
        b.zero_block(0, s.len())
    });
    match res {
        Ok(Ok(_)) => (),
        Err(e) | Ok(Err(e)) => {
            flash_error = flash_io_error_to_errno(e);
        }
    }
}

/********************************\
 * FileSystem-related functions *
\********************************/

/// Initializes [`fs`].
///
/// Returns a non-zero value on failure.
///
/// # Errors
///
/// Errors if the [`FileSystem`] instance could not be successfully created.
///
/// # Safety
///
/// This function is not interrupt-safe, and so should not be called in a non-monothread-like
/// context.
///
/// [`fs`]: static.fs.html
/// [`FileSystem`]: fs/struct.FileSystem.html
#[no_mangle]
pub unsafe extern "C" fn fs_init() -> u8 {
    match syscall::privileged_fs_init() {
        Ok(()) => 0,
        Err(syscall::FsInitError::FlashInit(e)) => flash_init_error_to_errno(e) as u8,
        Err(syscall::FsInitError::FsInit(e)) => fs_error_to_errno(e) as u8 | 0x40, // Disambiguate
    }
}

/// Converts a `fs::Error` to an error code
fn fs_error_to_errno(e: fs::Error) -> u8 {
    match e {
        fs::Error::OutOfFlash => 1,
        fs::Error::NoSuchTag => 2,
        fs::Error::InvalidLengthForTag => 3,
        fs::Error::IO(e) => 0x80 | flash_io_error_to_errno(e) as u8,
    }
}

/// Writes a file onto the file system.
///
/// This function writes a file, tagged by `tag` (whose length is in `taglen`), and containing data
/// `data` (whose length is in `datalen`) onto the file system. It will return a non-zero value on
/// error.
///
/// Note that if a file tagged by `tag` was already present on the file system, it will be erased.
///
/// # Errors
///
/// This function will error in case of flash i/o error or if the flash is currently full and
/// cannot be defragmented enough to save space for the newly created file.
///
/// # Safety
///
/// This function must be called after a [`fs_init`]. In addition, `tag` (resp. `data`) must point
/// to a buffer of size at least `taglen` (resp. `datalen`).
///
/// [`fs_init`]: fn.fs_init.html
#[no_mangle]
pub unsafe extern "C" fn fs_write(tag: *const u8, taglen: u8, data: *const u8, datalen: u32) -> u8 {
    let res = syscall::fs_write(
        slice::from_raw_parts(tag, taglen as usize),
        slice::from_raw_parts(data, datalen as usize),
    );
    match res {
        Ok(()) => 0,
        Err(e) => fs_error_to_errno(e),
    }
}

/// Writes an applet onto the file system.
///
/// This function writes a file, tagged by `tag` (whose length is in `taglen`), and containing data
/// `data` (whose length is in `datalen`) onto the file system, in the applet sector. It never
/// returns but rather reboots.
///
/// Note that if a file tagged by `tag` was already present on the file system, it will be erased.
#[no_mangle]
pub unsafe extern "C" fn fs_write_applet(
    tag: *const u8,
    taglen: u8,
    data: *const u8,
    datalen: u32,
) {
    syscall::fs_write_applet(
        slice::from_raw_parts(tag, taglen as usize),
        slice::from_raw_parts(data, datalen as usize),
    )
}

/// Erases a file from the file system.
///
/// This function erases the file, tagged by `tag` (whose length is in `taglen`). It will return a
/// non-zero value on error.
///
/// # Errors
///
/// This function will error in case of flash i/o error or if no file tagged by `tag` currently
/// exists on the file system.
///
/// # Safety
///
/// This function must be called after a `fs_init`. In addition, `tag` must point to a buffer of
/// size at least `taglen`.
#[no_mangle]
pub unsafe extern "C" fn fs_erase(tag: *const u8, taglen: u8) -> u8 {
    let res = syscall::fs_erase(slice::from_raw_parts(tag, taglen as usize));
    match res {
        Ok(()) => 0,
        Err(e) => fs_error_to_errno(e),
    }
}

/// Erases an applet from the file system.
///
/// This function erases the file, tagged by `tag` (whose length is in `taglen`). It never returns
/// but rather reboots.
#[no_mangle]
pub unsafe extern "C" fn fs_erase_applet(tag: *const u8, taglen: u8) {
    syscall::fs_erase_applet(slice::from_raw_parts(tag, taglen as usize))
}

/// Checks whether a file exists on the filesystem.
///
/// This function will return `1` if the requested tag exists, and `0` otherwise.
///
/// # Safety
///
/// This function must be called after a [`fs_init`]. In addition, `tag` must point to a buffer of
/// size at least `taglen`.
///
/// [`fs_init`]: fn.fs_init.html
#[no_mangle]
pub unsafe extern "C" fn fs_exists(tag: *const u8, taglen: u8) -> u8 {
    if syscall::fs_exists(slice::from_raw_parts(tag, taglen as usize)) {
        1
    } else {
        0
    }
}

/// Reads a file from the file system.
///
/// This function retrieves the data contained in the file of tag `tag` (whose length is in
/// `taglen`).
/// It will point `dataret` to a space containing the said data, and set `datalenret` to
/// the size of it.
/// A non-zero value will be returned in case of error.
///
/// The `dataret` buffer should be freed with [`fs_free`] in order to avoid memory leaks.
///
/// # Errors
///
/// This function can error in case of flash i/o error, or if the said file is currently being
/// locked in writing.
///
/// # Safety
///
/// This function must be called after a [`fs_init`]. In addition, `tag` must point to a buffer of
/// size at least `taglen`.
///
/// [`fs_init`]: fn.fs_init.html
/// [`fs_free`]: fn.fs_free.html
#[no_mangle]
pub unsafe extern "C" fn fs_read_inplace(
    tag: *const u8,
    taglen: u8,
    dataret: *mut *const u8,
    datalenret: *mut u32,
) -> u8 {
    match syscall::fs_read_inplace(slice::from_raw_parts(tag, taglen as usize)) {
        Ok(block) => {
            *dataret = block.as_ptr();
            *datalenret = block.len() as u32;
            0
        }
        Err(e) => fs_error_to_errno(e),
    }
}

/// Copies in `dataret` the `datalen` first bytes of the file of tag `tag` (whose length is in
/// `taglen`). Returns non-zero if an error occurs.
#[no_mangle]
pub unsafe extern "C" fn fs_read(tag: *const u8, taglen: u8, dataret: *mut u8, datalen: u32) -> u8 {
    match syscall::fs_read(
        slice::from_raw_parts(tag, taglen as usize),
        slice::from_raw_parts_mut(dataret, datalen as usize),
    ) {
        Ok(()) => 0,
        Err(e) => fs_error_to_errno(e),
    }
}

/// Reads into `res` the byte at offset `offset` of the file of tag `tag` (whose length is in
/// `taglen`). Returns non-zero if an error occurs.
#[no_mangle]
pub unsafe extern "C" fn fs_read_1b_at(
    tag: *const u8,
    taglen: u8,
    offset: u32,
    res: *mut u8,
) -> u8 {
    match syscall::fs_read_1b_at(slice::from_raw_parts(tag, taglen as usize), offset as usize) {
        Ok(v) => {
            *res = v;
            0
        }
        Err(e) => fs_error_to_errno(e),
    }
}

/// Reads into `res` the two bytes at offset `offset` of the file of tag `tag` (whose length is in
/// `taglen`). Note that `offset` is to be considered as an offset in 2-byte words: it acts as
/// though the file was an array of 2-byte words and the `offset`-th was asked for. Returns
/// non-zero if an error occurs.
#[no_mangle]
pub unsafe extern "C" fn fs_read_2b_at(
    tag: *const u8,
    taglen: u8,
    offset: u32,
    res: *mut u16,
) -> u8 {
    match syscall::fs_read_2b_at(slice::from_raw_parts(tag, taglen as usize), offset as usize) {
        Ok(v) => {
            *res = v;
            0
        }
        Err(e) => fs_error_to_errno(e),
    }
}

/// Reads into `res` the four bytes at offset `offset` of the file of tag `tag` (whose length is in
/// `taglen`). Note that `offset` is to be considered as an offset in 4-byte words: it acts as
/// though the file was an array of 4-byte words and the `offset`-th was asked for. Returns
/// non-zero if an error occurs.
#[no_mangle]
pub unsafe extern "C" fn fs_read_4b_at(
    tag: *const u8,
    taglen: u8,
    offset: u32,
    res: *mut u32,
) -> u8 {
    match syscall::fs_read_4b_at(slice::from_raw_parts(tag, taglen as usize), offset as usize) {
        Ok(v) => {
            *res = v;
            0
        }
        Err(e) => fs_error_to_errno(e),
    }
}

/// Writes `data` at offset `offset` of the file tagged `tag` (whose length is in `taglen`).
/// Returns non-zero if an error occurs.
#[no_mangle]
pub unsafe extern "C" fn fs_write_1b_at(tag: *const u8, taglen: u8, offset: u32, data: u8) -> u8 {
    match syscall::fs_write_1b_at(
        slice::from_raw_parts(tag, taglen as usize),
        offset as usize,
        data,
    ) {
        Ok(()) => 0,
        Err(e) => fs_error_to_errno(e),
    }
}

/// Writes `data` at offset `offset` (counted in 2-byte words) of the file tagged `tag` (whose
/// length is in `taglen`).
/// Returns non-zero if an error occurs.
#[no_mangle]
pub unsafe extern "C" fn fs_write_2b_at(tag: *const u8, taglen: u8, offset: u32, data: u16) -> u8 {
    match syscall::fs_write_2b_at(
        slice::from_raw_parts(tag, taglen as usize),
        offset as usize,
        data,
    ) {
        Ok(()) => 0,
        Err(e) => fs_error_to_errno(e),
    }
}

/// Writes `data` at offset `offset` (counted in 4-byte words) of the file tagged `tag` (whose
/// length is in `taglen`).
/// Returns non-zero if an error occurs.
#[no_mangle]
pub unsafe extern "C" fn fs_write_4b_at(tag: *const u8, taglen: u8, offset: u32, data: u32) -> u8 {
    match syscall::fs_write_4b_at(
        slice::from_raw_parts(tag, taglen as usize),
        offset as usize,
        data,
    ) {
        Ok(()) => 0,
        Err(e) => fs_error_to_errno(e),
    }
}

/// Returns in `res` the length (in bytes) of the file of tag `tag` (whose length is in `taglen`),
/// returning non-zero if an error occurred.
#[no_mangle]
pub unsafe extern "C" fn fs_length(tag: *const u8, taglen: u8, res: *mut u32) -> u8 {
    match syscall::fs_length(slice::from_raw_parts(tag, taglen as usize)) {
        Ok(v) => {
            *res = v as u32;
            0
        }
        Err(e) => fs_error_to_errno(e),
    }
}

/// Extracts `package`, `class` and `method` value to execute from `value`.
/// Returns `package`, `class` and `method` value computed from `value`.
pub fn compute_method_info(value: u32) -> (u8, u8, u8) {
    let package = ((value >> 16) & 0x0000_FFFF) as u8;
    let class = ((value >> 8) & 0x0000_FFFF) as u8;
    let method = (value & 0x0000_FFFF) as u8;

    (package, class, method)
}

/// Starting emulator for x86 execution
#[no_mangle]
#[cfg(feature = "host")]
pub extern "C" fn run_emulator() {
    extern "C" {
        /// This function is the JCVM interpreter main function which will run
        /// inside the secure environment.
        fn runtime(package: u8, class: u8, method: u8);
        fn starting_jcre() -> u32;
    }

    emulator::run(|| {
        let mut msg = "RELEASE version";
        if cfg!(debug_assertions) {
            msg = "DEBUG version";
        }

        println!(
            "========= Running the Java Card secure OS [{}] =========",
            msg
        );

        /*
        let flash_sectors = flash_ll::sectors();
        let flash = unsafe { Flash::new(&flash_sectors) }.unwrap();
        flash.sector(flash::SectorID(0)).erase(&flash).unwrap();
        flash.sector(flash::SectorID(7)).erase(&flash).unwrap();
        for i in 1..7 {
            flash.sector(flash::SectorID(i)).erase(&flash).unwrap();
        }
        drop(flash);
         */

        unsafe {
            print!("Initialising MPU ...");
            let mut mpu = Mpu::get();
            mpu.setup();
            mpu.setup_unpriv_regions();
            mpu.switch_userland(ram_begin(), ram_size().next_power_of_two());
            drop(mpu); // Release lock to leave it open for interrupt handler
            println!(" ok");

            print!("Initialising FS ...");
            fs_init();
            println!(" ok");

            let contexts = allocate_contexts(&[
                Context {
                    // Context 0 is privileged, kernel context
                    entrypoint: |_caller, _, _| {
                        let value = 0;
                        println!(
                            "REMOTE CALL TO CTX 0 from {}, stack at {:p}",
                            _caller, &value
                        );
                        starting_jcre();
                        0
                    },
                },
                Context {
                    // Context 1: APDU buffer?
                    entrypoint: |_caller, _, _| {
                        let _value = 0;
                        println!(
                            "REMOTE CALL TO CTX 1 from {}, stack at {:p}",
                            _caller, &_value
                        );
                        0
                    },
                },
                Context {
                    // Context 2 has Installer privileges
                    // XXX: current implementation only update packages' table.
                    entrypoint: |_caller, _arg, _| {
                        let _value = 0;
                        println!(
                            "REMOTE CALL TO CTX 2 from {}, stack at {:p}",
                            _caller, &_value
                        );

                        let (package, class, method) = compute_method_info(_arg as u32);
                        runtime(package, class, method);
                        0
                    },
                },
                Context {
                    entrypoint: |_caller, _, _| {
                        let _value = 0;
                        println!(
                            "REMOTE CALL TO CTX 3 from {}, stack at {:p}",
                            _caller, &_value
                        );
                        0
                    },
                },
                Context {
                    entrypoint: |_caller, _, _| {
                        let _value = 0;
                        println!(
                            "REMOTE CALL TO CTX 4 from {}, stack at {:p}",
                            _caller, &_value
                        );
                        0
                    },
                },
                Context {
                    entrypoint: |_caller, _, _| {
                        assert_eq!(_caller, 4);
                        let _value = 0;
                        debug!(
                            "REMOTE CALL TO CTX 5 from {}, stack at {:p}",
                            _caller, &_value
                        );
                        0
                    },
                },
            ]);

            context::init_contexts(contexts);
            privilege::drop((&mut RAM.get_mut()[0x17FFF] as *mut u8).wrapping_offset(1) as *mut ());

            setup_argbuf();
            remote_call(0, 0, 0);
        }

        // println!("========= Stopping the Java Card secure OS =========");
    });
}

/******************************\
 * Filename-related functions *
\******************************/

/// Writes to (`tagret`, `lenret`) the path to the package list file
#[no_mangle]
pub unsafe extern "C" fn path_package_list(tagret: *mut [u8; 32], lenret: *mut u8) {
    filename::package_list(&mut *tagret, &mut *lenret);
}

/// Writes to (`tagret`, `lenret`) the path to the CAP file of package `pkg`
#[no_mangle]
pub unsafe extern "C" fn path_cap(pkg: u8, tagret: *mut [u8; 32], lenret: *mut u8) {
    filename::cap(pkg, &mut *tagret, &mut *lenret);
}

/// Writes to (`tagret`, `lenret`) the path to the `static_id`-th static of package `pkg`
#[no_mangle]
pub unsafe extern "C" fn path_static(
    pkg: u8,
    static_id: u8,
    tagret: *mut [u8; 32],
    lenret: *mut u8,
) {
    filename::static_field(pkg, static_id, &mut *tagret, &mut *lenret);
}

/// Writes to (`tagret`, `lenret`) the path to the `field`-th field of applet `applet` in package
/// `pkg`
#[no_mangle]
pub unsafe extern "C" fn path_applet_field(
    applet: u8,
    pkg: u8,
    claz: u8,
    field: u8,
    tagret: *mut [u8; 32],
    lenret: *mut u8,
) {
    filename::applet_field(applet, pkg, claz, field, &mut *tagret, &mut *lenret);
}
