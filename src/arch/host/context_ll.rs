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
use {context, core, emulator, registers, RAM};

/// Context saved and restored by hardware during an interrupt, especially during a syscall.
///
/// See the ARM Architecture Procedure Call Standard (AAPCS) for details about each register.
#[cfg_attr(feature = "cargo-clippy", allow(missing_docs_in_private_items))]
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Context {
    pub rip: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
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
        "context_ll::current_sp can only be called from an exception handler!"
    );
    let psp = emulator::current_psp() as usize;
    assert!(context::in_current_context(
        psp,
        core::mem::size_of::<Context>()
    ));
    NonNull::new(psp as *mut Context).unwrap()
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
    emulator::set_psp(new_location.as_ptr() as usize)
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
        "context_ll::send_result can only be called from an exception handler!"
    );
    ptr.as_mut().rdi = res as u64;
}

/// Begin address of the memory range allocated to context 0's heap by the linker script
///
/// (see also `ctx0_heap_size`)
pub fn ctx0_heap_begin() -> usize {
    unsafe { &RAM.get()[0] as *const _ as usize }
}

/// Size of the memory range allocated to context 0's heap by the linker script
///
/// (see also `ctx0_heap_begin`)
pub fn ctx0_heap_size() -> usize {
    0x1000
}

/// Begin address of the memory range allocated to contexts by the linker script
///
/// (see also `available_size`)
pub fn begin_addr() -> usize {
    unsafe { &RAM.get()[0x1000] as *const _ as usize }
}

/// Size of the memory range allocated to contexts by the linker script
///
/// (see also `begin_addr`)
pub fn available_size() -> usize {
    // 0x170000
    unsafe { RAM.get().len() }
}

/// Set for remotecall
pub fn for_remotecall(
    entrypoint: RemoteCallEnter,
    caller: usize,
    arg1: usize,
    arg2: usize,
) -> Context {
    Context {
        rip: start_of_remote_call as u64,
        rdi: entrypoint as u64,
        rsi: caller as u64,
        rdx: arg1 as u64,
        rcx: arg2 as u64,
    }
}

/// Effectively start remote call
#[no_mangle]
pub extern "C" fn effectively_start_remote_call(
    entrypoint: RemoteCallEnter,
    caller: usize,
    arg1: usize,
    arg2: usize,
) -> usize {
    entrypoint(caller, arg1, arg2)
}

#[naked]
extern "C" fn start_of_remote_call() -> ! {
    unsafe {
        // rdi, rsi and rdx are used as inputs
        asm!("# Call the remote function
              movq %rsp, %rax
              andq $$~0xF, %rsp
              addq $$0x8, %rsp
              push %rax
              call effectively_start_remote_call
              pop %rsp

              # And return to the caller
              movq $$6, %rdi # Send a syscall
              movq $$1, %rsi # That is a remote result return
              movq %rax, %rdx # With the return value from called function as an argument
              int3"
        :::: "volatile");
        core::intrinsics::unreachable();
    }
}
