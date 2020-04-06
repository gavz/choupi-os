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

//! Handling privilege level change

use bindings::{CONTROL_SPSEL_Msk, CONTROL_nPRIV_Msk};
use registers;
use registers::{current_stack, Stack};

/// Drops privileges and switches to PSP
///
/// # Panics
///
/// Panics if the function is being called while handling an exception: we only allow to drop
/// privileges from the thread mode
///
/// # Safety
///
/// This function is unsafe because it will lose access to anything in the OS. From here on only
/// the regions allowed in the MPU to unprivileged processes will be allowed.
///
/// In addition, the `interrupt_stack` address will be assumed correct and to point to a place
/// suitable for interrupts.
pub unsafe fn drop(interrupt_stack: *mut ()) {
    assert_eq!(
        current_stack(),
        Stack::Thread,
        "privilege::drop() can only be called in thread mode"
    );
    let control_reg = registers::get_control();
    assert_eq!(
        control_reg & CONTROL_SPSEL_Msk,
        0,
        "privilege::drop() can only be called from MSP"
    );
    asm!("mrs r0, MSP
          msr PSP, r0
          msr MSP, r1
          msr CONTROL, r2
          isb"
      :: "{r1}"(interrupt_stack), "{r2}"(control_reg | CONTROL_nPRIV_Msk | CONTROL_SPSEL_Msk)
       : "r0"
       : "volatile");
}

/// Returns true if current code is running privileged
pub fn is_privileged() -> bool {
    current_stack() == Stack::Exception || (registers::get_control() & CONTROL_nPRIV_Msk) == 0
}
