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

//! Various helpers for manipulating the registers

use bindings::{SCB_AIRCR_SYSRESETREQ_Pos, SCB_Type, SCB_BASE};
use core::ptr::{read_volatile, write_volatile};

/// Retrieves the current value of the `CONTROL` register
pub fn get_control() -> u32 {
    let res;
    unsafe {
        asm!("mrs $0, CONTROL" : "=r"(res) : : : "volatile");
    }
    res
}

/// Returns value in the MSP
pub fn get_msp() -> u32 {
    let res;
    unsafe {
        asm!("mrs $0, MSP" : "=r"(res) ::: "volatile");
    }
    res
}

/// Struct encapsulating a (user-controlled) PSP that (should) point to a `Context` structure
pub struct UntrustedPsp(u32);
impl UntrustedPsp {
    /// Retrieves the PSP value. Unsafe because it's entirely user-controlled
    pub unsafe fn get(&self) -> u32 {
        self.0
    }
}

/// Returns value in the PSP
pub fn get_psp() -> UntrustedPsp {
    let res;
    unsafe {
        asm!("mrs $0, PSP" : "=r"(res) ::: "volatile");
    }
    UntrustedPsp(res)
}

/// Type of stack current code is executing in
#[derive(Debug, PartialEq, Eq)]
pub enum Stack {
    /// Thread-mode stack (PSP)
    Thread,
    /// Exception-mode stack (MSP)
    Exception,
}

/// Returns the type of stack current code is executing in
pub fn current_stack() -> Stack {
    let res: u32;
    unsafe {
        asm!("mrs $0, IPSR" : "=r"(res));
    }
    if res as u8 == 0 {
        // Get only low-order bits
        Stack::Thread
    } else {
        Stack::Exception
    }
}

/// Soft-reboots the card. Unsafe only because it likely can easily break unsafe code
pub unsafe fn reboot() -> ! {
    let aircr = &mut (*(SCB_BASE as *mut SCB_Type)).AIRCR;
    write_volatile(
        aircr,
        (0x05FA << 16) | // Key to enable the lock
                   (read_volatile(aircr) & 0x700) | // Keep priority group unchanged
                   (1 << SCB_AIRCR_SYSRESETREQ_Pos),
    ); // And reboot
    asm!("dmb"::::"volatile");
    loop {}
}
