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

//! Handle context switches between userland processes

use alloc::vec::Vec;
use context_ll::{ctx0_heap_begin, ctx0_heap_size, Context};
use core::fmt;
use core::mem::size_of;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use mpu::Mpu;
use registers::Stack;
use spin::Mutex;
use {alloc_ll, context_ll, core, program_begin, program_size, registers};

/// Metadata for each context
static CONTEXTS: Mutex<Option<Vec<ContextMetadata>>> = Mutex::new(None);

/// `ContextID` of the current context
pub static CURRENT_CONTEXT: AtomicContextID = AtomicContextID::zero();

/// Address of the beginning of the range reserved to the heap of the current context
#[link_section = ".shared_ro"]
static CURRENT_HEAP_BOTTOM: AtomicUsize = AtomicUsize::new(0);

/// Size of the range reserved to the heap of the current context
static CURRENT_HEAP_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Address of the beginning of the range reserved to the current context
static CURRENT_CONTEXT_BOTTOM: AtomicUsize = AtomicUsize::new(0);

/// Size of the range reserved to the current context
static CURRENT_CONTEXT_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Top of stack of the current context
static CURRENT_CONTEXT_STACK_HEAP_LIMIT: AtomicUsize = AtomicUsize::new(0);

/// Current context stack.
///
/// The `Option<>` here is left only for lack of a working `const fn Vec::new()`. As a consequence,
/// the `Vec` will be initialized on first call to `push`, and from then on will only be used.
///
/// The `Vec` models a stack of contexts, each calling context being stacked, waiting for the
/// called context to return.
static CONTEXT_STACK: Mutex<Option<Vec<(ContextID, TopOfStack)>>> = Mutex::new(None);

/// "Pointer" to a context as saved by the processor during a syscall.
///
/// As it is saved by the processor, it is non-forgeable.
///
/// Can also be a "pointer" to an empty stack
pub struct TopOfStack {
    /// Highest-numbered address in the stack + 1
    highest: usize,
    /// Lowest-numbered address in the stack
    lowest: usize,
    /// Pointer to the current processor-saved Context if there is one
    context: Option<NonNull<Context>>,
}

impl fmt::Debug for TopOfStack {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(c) = self.context {
            write!(
                f,
                "TopOfStack {{ highest: {:#x}, lowest: {:#x}, context: {:?} }}",
                self.highest,
                self.lowest,
                c.as_ptr()
            )
        } else {
            write!(
                f,
                "TopOfStack {{ highest: {:#x}, lowest: {:#x}, context: None }}",
                self.highest, self.lowest
            )
        }
    }
}

// I'm almost sure this is legitimate and not only written to get things to compile
unsafe impl Send for TopOfStack {}

impl TopOfStack {
    /// Generates a `TopOfStack` without any processor context associated at a given address
    pub unsafe fn empty(lowest: usize, highest: usize) -> TopOfStack {
        TopOfStack {
            lowest,
            highest,
            context: None,
        }
    }

    /// Clones current `TopOfStack`
    unsafe fn please_clone(&self) -> TopOfStack {
        TopOfStack {
            lowest: self.lowest,
            highest: self.highest,
            context: self.context,
        }
    }

    /// Returns a `TopOfStack` with a processor context pushed in
    fn push_context(&mut self, ctxt: Context) {
        let (lowest, mut top) = match *self {
            TopOfStack {
                lowest,
                context: Some(c),
                ..
            } => (lowest, c.as_ptr()),
            TopOfStack {
                lowest, highest, ..
            } => (lowest, highest as *mut Context),
        };
        top = top.wrapping_offset(-1);
        assert!(
            top as usize >= lowest,
            "Stack overflow while remote calling: {:p} < {:#x}",
            top,
            lowest
        );
        unsafe {
            core::ptr::write(top, ctxt);
        }
        *self = TopOfStack {
            highest: self.highest,
            lowest: self.lowest,
            context: Some(NonNull::new(top).unwrap()),
        };
    }

    /// Returns a `TopOfStack` with a processor context popped out
    fn pop_context(self) -> TopOfStack {
        if let TopOfStack {
            highest,
            lowest,
            context: Some(c),
        } = self
        {
            let new_context = c.as_ptr().wrapping_offset(1);
            if new_context as usize + size_of::<Context>() >= highest {
                TopOfStack {
                    highest,
                    lowest,
                    context: None,
                }
            } else {
                TopOfStack {
                    highest,
                    lowest,
                    context: Some(NonNull::new(new_context).unwrap()),
                }
            }
        } else {
            panic!("Trying to pop context from an empty stack")
        }
    }
}

/// Type for a remote call handler function
pub type RemoteCallEnter = fn(usize, usize, usize) -> usize;

/// Metadata for a context
#[derive(Debug)]
pub struct ContextMetadata {
    /// Function to call on a remote call
    pub remote_call_enter: RemoteCallEnter,
    /// Begin of the memory range reserved for the context
    pub begin: usize,
    /// Size of the memory range reserved for the context
    pub size: usize,
    /// Address of the top of the stack
    pub top_of_stack: TopOfStack,
    /// Begin of the memory range reserved for the heap
    pub heap_begin: usize,
    /// Size of the memory range reserved for the heap
    pub heap_size: usize,
}

/// Index inside the `CONTEXTS` array
#[derive(Clone, Copy, Debug)]
pub struct ContextID(usize);

/// Atomic equivalent of a ContextID
#[derive(Debug)]
pub struct AtomicContextID(AtomicUsize);

/// Retrieves the address of the beginning of the range reserved to the heap of the current context
/// (for use with the allocator)
#[no_mangle]
pub unsafe extern "C" fn __current_heap_bottom() -> usize {
    let res = CURRENT_HEAP_BOTTOM.load(Ordering::SeqCst);
    if res == 0 {
        ctx0_heap_begin()
    }
    // in case the variable is not initialized yet
    else {
        res
    }
}

/// Retrieves the size of the range reserved to the heap of the current context (for use with the
/// allocator)
#[no_mangle]
pub unsafe extern "C" fn __current_heap_size() -> usize {
    let res = CURRENT_HEAP_SIZE.load(Ordering::SeqCst);
    if res == 0 {
        ctx0_heap_size()
    }
    // in case the variable is not initialized yet
    else {
        res
    }
}

/// Initializes the [`CONTEXTS`] list and sets up the heaps for each context
///
/// Note: there is no `deinit_contexts` or anything similar provided for the time being. A reboot
/// is required for changing the context list.
///
/// Panics if called multiple times.
///
/// [`CONTEXTS`]: static.CONTEXTS.html
pub unsafe fn init_contexts(meta: Vec<ContextMetadata>) {
    let mut ctxts = CONTEXTS.lock();
    assert!(ctxts.is_none(), "Trying to initialize contexts twice");
    // Initialize all the heaps
    for ctxt in meta.iter().skip(1) {
        // Skip first heap as it has been initialized by startup code
        debug!(
            "(HEAP) Initializing heap at {:#x} with size {:#x}",
            ctxt.heap_begin, ctxt.heap_size
        );
        alloc_ll::initialize_heap_at(ctxt.heap_begin, ctxt.heap_size);
    }
    // Record the metadata associated to context 0
    CURRENT_CONTEXT_BOTTOM.store(meta[0].begin, Ordering::SeqCst);
    CURRENT_CONTEXT_SIZE.store(meta[0].size, Ordering::SeqCst);
    CURRENT_CONTEXT_STACK_HEAP_LIMIT.store(meta[0].top_of_stack.highest, Ordering::SeqCst);
    // And record the context list
    *ctxts = Some(meta);
}

/// Returns a pointer to the processor context unprivileged code is currently in
pub fn current_context() -> TopOfStack {
    TopOfStack {
        highest: CURRENT_CONTEXT_STACK_HEAP_LIMIT.load(Ordering::SeqCst),
        lowest: CURRENT_CONTEXT_BOTTOM.load(Ordering::SeqCst),
        context: Some(context_ll::current_sp()),
    }
}

/// Checks whether [addr, addr+size) is included inside the current context's memory range
pub fn in_current_context(addr: usize, size: usize) -> bool {
    let low = CURRENT_CONTEXT_BOTTOM.load(Ordering::SeqCst);
    let high = low + CURRENT_CONTEXT_SIZE.load(Ordering::SeqCst);
    if low == 0 {
        // CURRENT_CONTEXT_BOTTOM has not yet been initialized, so we're still in main context
        return true;
    }
    low <= addr && addr.saturating_add(size) <= high
}

/// Returns `true` iff the range `[addr, addr+size[` is readable from the current context
pub fn is_readable_from_current_context(addr: usize, size: usize) -> bool {
    // It is in the current context
    in_current_context(addr, size) ||
        // Or it is in the program code
        ((program_begin() as usize) <= addr &&
         addr.saturating_add(size) <= program_begin() as usize + program_size())
}

/// Returns `true` iff the range `[addr, addr+size[` is writable from the current context
pub fn is_writable_from_current_context(addr: usize, size: usize) -> bool {
    in_current_context(addr, size)
}

/// Switch the userland allowed by the MPU to the one of `ctxt`, running from location stored at
/// `location`
pub fn switch_userland(ctxt: ContextID) {
    let (begin, size, stack_heap_limit, new_location) = {
        // Lock ctxts as little as possible
        let ctxts = CONTEXTS.lock();
        let c = &ctxts
            .as_ref()
            .expect("Calling switch_userland before init_contexts")[ctxt.0];
        (c.begin, c.size, c.top_of_stack.highest, unsafe {
            c.top_of_stack.please_clone()
        })
    };
    Mpu::get().switch_userland(begin as *const u8, size);
    CURRENT_CONTEXT_BOTTOM.store(begin, Ordering::SeqCst);
    CURRENT_CONTEXT_SIZE.store(size, Ordering::SeqCst);
    CURRENT_CONTEXT_STACK_HEAP_LIMIT.store(stack_heap_limit, Ordering::SeqCst);
    if let TopOfStack {
        context: Some(location),
        ..
    } = new_location
    {
        unsafe { context_ll::switch_sp(location) }
    } else {
        panic!("Trying to switch userland to an empty stack")
    }
}

/// Sends the result of a syscall to its caller
pub fn send_result(res: usize, location: &mut TopOfStack) {
    if let TopOfStack {
        context: Some(loc), ..
    } = *location
    {
        unsafe { context_ll::send_result(res, loc) }
    } else {
        panic!("Trying to send result to an empty stack context")
    }
}

impl ContextID {
    /// Creates a `ContextID`
    ///
    /// Panics if `init_contexts` has not been called yet or if `id` is outside the allowed range
    ///
    /// Note this function cannot be called by a userland process, as it requires a RW acccess to
    /// `CONTEXTS`. Userland processes should use `from_id_unchecked`.
    pub fn new(id: usize) -> ContextID {
        let ctxts = CONTEXTS.lock();
        assert!(
            id < ctxts
                .as_ref()
                .expect("Trying to create a non-null ContextID before initializing the contexts")
                .len(),
            "Trying to create a ContextID with a length above the maximum allowed"
        );
        ContextID(id)
    }

    /// Creates a `ContextID` without checking for validity
    pub unsafe fn from_id_unchecked(id: usize) -> ContextID {
        ContextID(id)
    }

    /// Returns the 0 context, which is always valid as referring to the OS thread
    pub const fn zero() -> ContextID {
        ContextID(0)
    }

    /// Retrieves the identifier of the current context as an `usize`
    pub fn id(&self) -> usize {
        self.0
    }
}

impl AtomicContextID {
    /// Returns the 0 context, which is always valid as referring to the OS thread
    pub const fn zero() -> AtomicContextID {
        AtomicContextID(AtomicUsize::new(0))
    }

    /// Retrieves the identifier of this context as an `usize`
    pub fn id(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    /// Sets the identifier of this context from a `ContextID`
    pub fn set(&self, o: ContextID) {
        self.0.store(o.0, Ordering::SeqCst);
    }

    /// Retrieves the identifier of this context as a `ContextID`
    pub fn ctxid(&self) -> ContextID {
        unsafe { ContextID::from_id_unchecked(self.id()) }
    }
}

/// Switch current heap to the one of `ctxt`
pub fn switch_to_heap(ctxt: ContextID) {
    if ctxt.id() == 0 {
        CURRENT_HEAP_BOTTOM.store(ctx0_heap_begin(), Ordering::SeqCst);
        CURRENT_HEAP_SIZE.store(ctx0_heap_size(), Ordering::SeqCst);
    } else {
        let ctxts = CONTEXTS.lock();
        let ctxts = ctxts
            .as_ref()
            .expect("Calling switch_to_heap before having set contexts");
        CURRENT_HEAP_BOTTOM.store(ctxts[ctxt.0].heap_begin, Ordering::SeqCst);
        CURRENT_HEAP_SIZE.store(ctxts[ctxt.0].heap_size, Ordering::SeqCst);
    }
}

/// Returns the function called when entering context `ctxt`
pub fn remote_call_enter(ctxt: ContextID) -> RemoteCallEnter {
    CONTEXTS
        .lock()
        .as_ref()
        .expect("Contexts should have been initialized")[ctxt.0]
        .remote_call_enter
}

/// Push the current userland context to the context stack.
///
/// # Panics
///
/// This makes sense to call only from an exception handler, hence panics otherwise.
pub fn push(new_ctxt: ContextID, with: Context) {
    assert_eq!(
        registers::current_stack(),
        Stack::Exception,
        "process::push can only be called from an exception handler!"
    );
    // Record where execution was in previous context
    let mut stack = CONTEXT_STACK.lock();
    let mut ctxts_lock = CONTEXTS.lock();
    let ctxts = ctxts_lock
        .as_mut()
        .expect("Trying to push a context before calling init_contexts");
    if stack.is_none() {
        *stack = Some(Vec::new());
    }
    ctxts[CURRENT_CONTEXT.id()].top_of_stack = current_context();
    stack
        .as_mut()
        .map(|v| v.push((CURRENT_CONTEXT.ctxid(), current_context())));
    CURRENT_CONTEXT.set(new_ctxt);

    // Switch new context to relevant `Context`
    ctxts[new_ctxt.0].top_of_stack.push_context(with);
}

/// Pops the last context on the context stack as the next userland context.
///
/// # Panics
///
/// This makes sense to call only from an exception handler, hence panics otherwise.
pub fn pop() {
    assert_eq!(
        registers::current_stack(),
        Stack::Exception,
        "process::pop can only be called from an exception handler!"
    );
    let next_context;
    {
        let mut stack = CONTEXT_STACK.lock();
        let mut ctxts = CONTEXTS.lock();
        ctxts
            .as_mut()
            .expect("Calling process::pop before the first push!")[CURRENT_CONTEXT.id()]
        .top_of_stack = current_context().pop_context();
        // Think of adding the size of a Context to discard the information pushed by the
        // processor after the return 'svc 0'
        next_context = stack
            .as_mut()
            .expect("Calling process::pop before the first context::push!")
            .pop()
            .expect("Cannot pop from empty context stack! (did init just return?)");
        CURRENT_CONTEXT.set(next_context.0);
    }
    switch_userland(next_context.0);
}

/// Returns the context to be pushed for a remotecall with given entry point and arguments
pub fn for_remotecall(
    entrypoint: RemoteCallEnter,
    caller: usize,
    arg1: usize,
    arg2: usize,
) -> Context {
    context_ll::for_remotecall(entrypoint, caller, arg1, arg2)
}
