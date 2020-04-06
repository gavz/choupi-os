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

//! Handle syscalls

use context;
use syscall_ll;

mod tests;

mod fs;
mod remotecall;
mod test;
mod usart;
pub use self::fs::erase as fs_erase;
pub use self::fs::erase_applet as fs_erase_applet;
pub use self::fs::exists as fs_exists;
pub use self::fs::length as fs_length;
pub use self::fs::read as fs_read;
pub use self::fs::read_1b_at as fs_read_1b_at;
pub use self::fs::read_2b_at as fs_read_2b_at;
pub use self::fs::read_4b_at as fs_read_4b_at;
pub use self::fs::read_inplace as fs_read_inplace;
pub use self::fs::write as fs_write;
pub use self::fs::write_1b_at as fs_write_1b_at;
pub use self::fs::write_2b_at as fs_write_2b_at;
pub use self::fs::write_4b_at as fs_write_4b_at;
pub use self::fs::write_applet as fs_write_applet;
pub use self::fs::{privileged_fs_init, privileged_get_flash, FsInitError};
pub use self::remotecall::remote_call;
pub use self::test::test;
pub use self::usart::output as usart_output;
pub use self::usart::privileged_output as privileged_usart_output;

/// Type for the actual handler of a syscall function
///
/// The return is an `Option` so that the syscall can opt out of its caller overwriting a register
/// with the returned result.
type SyscallFn = fn(usize, usize, usize) -> Option<usize>;

/// Association from a syscall name to an ID
///
/// Note: Adding a value to the enum should also entail setting it in the `impl Syscall` and in the
/// `impl Into<SyscallFn> for Syscall`.
#[repr(usize)]
#[derive(Debug, Clone, Copy)]
pub enum Syscall {
    /// Remote call syscall
    RemoteCall = 0,
    /// Return a result to a remote call
    RemoteResult = 1, // BEWARE this value is hardcoded in `arch/host/context_ll.rs`
    /// Test syscall
    Test = 2,
    /// Output data on the USART syscall
    UsartOutput = 3,
    /// Whether a file exists
    FsExists = 4,
    /// Reads a file into a buffer
    FsRead = 5,
    /// Returns a pointer to a file in flash
    FsReadInplace = 6,
    /// Writes a file from a buffer
    FsWrite = 7,
    /// Removes a file
    FsErase = 8,
    /// Reads one byte from a file at some offset
    FsRead1b = 9,
    /// Reads two bytes from a file at some offset
    FsRead2b = 10,
    /// Reads four bytes from a file at some offset
    FsRead4b = 11,
    /// Retrieves the length of a file (in bytes)
    FsLength = 12,
    /// Writes an applet from a buffer
    FsWriteApplet = 13,
    /// Erases an applet
    FsEraseApplet = 14,
    /// Writes one byte to a file at some offset
    FsWrite1b = 15,
    /// Writes two bytes to a file at some offset
    FsWrite2b = 16,
    /// Writes four bytes to a file at some offset
    FsWrite4b = 17,
}

impl Syscall {
    /// Converts an integer into a `Syscall` if possible.
    pub fn from_usize(x: usize) -> Option<Syscall> {
        match x {
            0 => Some(Syscall::RemoteCall),
            1 => Some(Syscall::RemoteResult),
            2 => Some(Syscall::Test),
            3 => Some(Syscall::UsartOutput),
            4 => Some(Syscall::FsExists),
            5 => Some(Syscall::FsRead),
            6 => Some(Syscall::FsReadInplace),
            7 => Some(Syscall::FsWrite),
            8 => Some(Syscall::FsErase),
            9 => Some(Syscall::FsRead1b),
            10 => Some(Syscall::FsRead2b),
            11 => Some(Syscall::FsRead4b),
            12 => Some(Syscall::FsLength),
            13 => Some(Syscall::FsWriteApplet),
            14 => Some(Syscall::FsEraseApplet),
            15 => Some(Syscall::FsWrite1b),
            16 => Some(Syscall::FsWrite2b),
            17 => Some(Syscall::FsWrite4b),
            _ => None,
        }
    }
}

impl Into<SyscallFn> for Syscall {
    fn into(self) -> SyscallFn {
        match self {
            Syscall::RemoteCall => remotecall::syscall_remote_call,
            Syscall::RemoteResult => remotecall::syscall_remote_result,
            Syscall::Test => test::syscall_test,
            Syscall::UsartOutput => usart::syscall_output,
            Syscall::FsExists => fs::syscall_exists,
            Syscall::FsRead => fs::syscall_read,
            Syscall::FsReadInplace => fs::syscall_read_inplace,
            Syscall::FsWrite => fs::syscall_write,
            Syscall::FsErase => fs::syscall_erase,
            Syscall::FsRead1b => fs::syscall_read_1b_at,
            Syscall::FsRead2b => fs::syscall_read_2b_at,
            Syscall::FsRead4b => fs::syscall_read_4b_at,
            Syscall::FsLength => fs::syscall_length,
            Syscall::FsWriteApplet => fs::syscall_write_applet,
            Syscall::FsEraseApplet => fs::syscall_erase_applet,
            Syscall::FsWrite1b => fs::syscall_write_1b_at,
            Syscall::FsWrite2b => fs::syscall_write_2b_at,
            Syscall::FsWrite4b => fs::syscall_write_4b_at,
        }
    }
}

/// Performs a syscall with given arguments
pub unsafe fn syscall(num: Syscall, arg1: usize, arg2: usize, arg3: usize) -> usize {
    #[cfg(feature = "host")]
    println!("Calling {:?}({}, {}, {})", num, arg1, arg2, arg3);
    syscall_ll::syscall(num as usize, arg1, arg2, arg3)
}

/// Performs a syscall with given arguments, saving all registers
///
/// It also clears all registers before triggering the syscall, for security reasons
pub unsafe fn syscall_saveall(num: Syscall, arg1: usize, arg2: usize, arg3: usize) -> usize {
    syscall_ll::syscall_saveall(num as usize, arg1, arg2, arg3)
}

/// Function called privileged when a syscall is performed
pub fn syscall_received(num: usize, arg1: usize, arg2: usize, arg3: usize) -> () {
    context::switch_to_heap(context::ContextID::zero());
    let num = Syscall::from_usize(num).expect("Invalid syscall number given!");
    #[cfg(feature = "host")]
    println!("Received syscall {:?}({}, {}, {})", num, arg1, arg2, arg3);
    let syscall: SyscallFn = num.into();
    let syscall_res = syscall(arg1, arg2, arg3);
    if let Some(res) = syscall_res {
        let mut cur_context = context::current_context();
        context::send_result(res, &mut cur_context);
    }
    context::switch_to_heap(context::CURRENT_CONTEXT.ctxid());
}
