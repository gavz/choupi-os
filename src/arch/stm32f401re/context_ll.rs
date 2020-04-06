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

//! Handle stack switches

use context::RemoteCallEnter;
use core::ptr::NonNull;
use registers::Stack;
use syscall::Syscall;
use tools::LinkerSymbol;
use {context, core, registers};

/// Context saved and restored by hardware during an interrupt, especially during a syscall.
///
/// See the ARM Architecture Procedure Call Standard (AAPCS) for details about each register.
#[cfg_attr(feature = "cargo-clippy", allow(missing_docs_in_private_items))]
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Context {
    pub r0: usize,
    pub r1: usize,
    pub r2: usize,
    pub r3: usize,
    pub r12: usize,
    pub lr: usize,
    pub pc: usize,
    pub psr: usize,
}

/// Retrieves the current `PSP` as a `GuestContext`.
///
/// # Panics
///
/// This function panics if not called from inside an exception handler (like `SVC_Handler`):
/// outside of there, the `PSP` could change anytime, and retrieving it would be a meaningless
/// thing to do.
pub fn current_sp() -> NonNull<Context> {
    assert_eq!(
        registers::current_stack(),
        Stack::Exception,
        "context::get_psp can only be called from an exception handler!"
    );
    unsafe {
        let psp = registers::get_psp().get() as usize;
        assert!(context::in_current_context(
            psp,
            core::mem::size_of::<Context>()
        ));
        NonNull::new(psp as *mut Context).unwrap()
    }
}

/// Switch the `PSP` to the `GuestContext` `new_location`.
///
/// This is not unsafe as only userland is affected, but can cause really hard-to-debug errors if
/// wrongly used. However, `GuestContext` can only be created through `unsafe`, so hard-to-debug
/// errors are mostly already "protected" by this `unsafe`.
///
/// # Panics
///
/// This makes sense to call only from an exception handler, hence panics otherwise.
pub unsafe fn switch_sp(new_location: NonNull<Context>) {
    assert_eq!(
        registers::current_stack(),
        Stack::Exception,
        "context::switch_sp can only be called from an exception handler!"
    );
    asm!("msr PSP, $0" :: "r"(new_location.as_ptr()));
}

/// Sets the return value for currently active context
///
/// # Panics
///
/// This makes sense to call only from an exception handler, hence panics otherwise.
pub unsafe fn send_result(res: usize, mut ptr: NonNull<Context>) {
    assert_eq!(
        registers::current_stack(),
        Stack::Exception,
        "context::send_result can only be called from an exception handler!"
    );
    ptr.as_mut().r0 = res;
}

#[allow(improper_ctypes)]
extern "C" {
    static mpu_contexts_start: LinkerSymbol;
    static mpu_contexts_size: LinkerSymbol;
    static stack_lowest: LinkerSymbol;
    static stack_highest: LinkerSymbol;
    static heap_begin: LinkerSymbol;
    static heap_size: LinkerSymbol;
}

/// Begin address of the memory range allocated to context 0's heap by the linker script
///
/// (see also `ctx0_heap_size`)
pub fn ctx0_heap_begin() -> usize {
    unsafe { &heap_begin as *const _ as usize }
}

/// Size of the memory range allocated to context 0's heap by the linker script
///
/// (see also `ctx0_heap_begin`)
pub fn ctx0_heap_size() -> usize {
    unsafe { &heap_size as *const _ as usize }
}

/// Lowest-numbered (in absolute value) address of the stack for context 0
pub fn ctx0_stack_lowest() -> usize {
    unsafe { &stack_lowest as *const _ as usize }
}

/// Highest-numbered (in absolute value) address of the stack for context 0
pub fn ctx0_stack_highest() -> usize {
    unsafe { &stack_highest as *const _ as usize }
}

/// Size of the memory range allocated to contexts by the linker script
///
/// (see also `begin_addr`)
pub fn available_size() -> usize {
    unsafe { &mpu_contexts_size as *const _ as usize }
}

/// Begin address of the memory range allocated to contexts by the linker script
///
/// (see also `available_size`)
pub fn begin_addr() -> usize {
    unsafe { &mpu_contexts_start as *const _ as usize }
}

/// Returns the context to be pushed for a remotecall with given entry point and arguments
pub fn for_remotecall(
    entrypoint: RemoteCallEnter,
    caller: usize,
    arg1: usize,
    arg2: usize,
) -> Context {
    Context {
        r0: entrypoint as usize,
        r1: caller,
        r2: arg1,
        r3: arg2,
        r12: 0x66120712, // r12 is used as a marker for pseudobt command in gdb helper
        lr: end_of_remote_call as usize,
        pc: start_of_remote_call as usize,
        psr: 0x01000000, // Set just thumb bit
    }
}

/// Call a remote call function with given arguments
extern "C" fn start_of_remote_call(
    remote_call_enter: RemoteCallEnter,
    caller: usize,
    arg1: usize,
    arg2: usize,
) -> usize {
    remote_call_enter(caller, arg1, arg2)
}

/// Function automatically called after the remote-called function returns.
///
/// As the remote-called function puts its return value in `r0`, and the first argument (in AAPCS)
/// is r0, semantically this is a function that takes as a single `usize` argument the return value
/// of the called function.
///
/// It just triggers a syscall, in order to deliver the return value to the calling context.
#[naked]
extern "C" fn end_of_remote_call() -> ! {
    unsafe {
        asm!("@ Setup syscall arguments
              mov r1, r0    @ To-be-returned value
              mov r0, $0    @ Syscall number

              @ Clear registers to avoid any leak
              mrs r2, APSR
              bic r2, #0xF8000000
              msr APSR, r2
              mov r2, #0
              mov r3, #0
              mov r4, #0
              mov r5, #0
              mov r6, #0
              mov r7, #0
              mov r8, #0
              mov r9, #0
              mov r10, #0
              mov r11, #0
              mov r12, #0

              @ And trigger the return
              svc 0"
          :: "i"(Syscall::RemoteResult)
          :: "volatile");
        core::intrinsics::unreachable()
    }
}
