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

//! Allocator allocating RAM blocks to contexts

use context::{ContextMetadata, RemoteCallEnter, TopOfStack};
use context_ll::{available_size, begin_addr, ctx0_heap_begin, ctx0_heap_size};
#[cfg(feature = "embedded")]
use context_ll::{ctx0_stack_highest, ctx0_stack_lowest};
use core::intrinsics::write_bytes;

use alloc::vec::Vec;

/// Metadata about a context that can't be auto-filled
pub struct AllocatableContext {
    /// Function to call when the context receives a remote call
    pub entrypoint: RemoteCallEnter,
}

/// Metadata to be used for context 0
///
/// Doesn't include `top_of_stack`, as it will be erased by `process::push()`
#[cfg(feature = "embedded")]
pub fn ctx0_metadata(entrypoint: RemoteCallEnter) -> ContextMetadata {
    ContextMetadata {
        remote_call_enter: entrypoint,
        begin: ::ram_begin() as usize,
        size: ::ram_size().next_power_of_two(),
        top_of_stack: unsafe { TopOfStack::empty(ctx0_stack_lowest(), ctx0_stack_highest()) },
        heap_begin: ctx0_heap_begin(),
        heap_size: ctx0_heap_size(),
    }
}

/// Metadata to be used for context 0
///
/// Doesn't include `top_of_stack`, as it will be erased by `process::push()`
#[cfg(feature = "host")]
pub fn ctx0_metadata(entrypoint: RemoteCallEnter) -> ContextMetadata {
    ContextMetadata {
        remote_call_enter: entrypoint,
        begin: ::ram_begin() as usize,
        size: ::ram_size().next_power_of_two(),
        top_of_stack: unsafe { TopOfStack::empty(0, 0) },
        heap_begin: ctx0_heap_begin(),
        heap_size: ctx0_heap_size(),
    }
}

fn allocate_contexts_of_size(
    c: &[AllocatableContext],
    size: usize,
) -> Option<Vec<ContextMetadata>> {
    let half_size = size >> 1;
    let aligned_begin = (begin_addr() + size - 1) & !(size - 1);
    if (aligned_begin - begin_addr()) + c.len() * size >= available_size() {
        return None;
    }
    Some(
        c.iter()
            .enumerate()
            .map(|(i, ac): (usize, &AllocatableContext)| {
                if i == 0 {
                    ctx0_metadata(ac.entrypoint)
                } else {
                    let begin = aligned_begin + size * (i - 1);
                    // Zero-out each allocated contexts, except the zero'th one (from which we are
                    // currently running)
                    unsafe {
                        write_bytes(begin as *mut u8, 0, size);
                    }
                    ContextMetadata {
                        remote_call_enter: ac.entrypoint,
                        begin: begin,
                        size: size,
                        top_of_stack: unsafe { TopOfStack::empty(begin, begin + half_size) },
                        heap_begin: begin + half_size,
                        heap_size: half_size,
                    }
                }
            })
            .collect(),
    )
}

/// Allocates space for contexts
pub fn allocate_contexts(c: &[AllocatableContext]) -> Vec<ContextMetadata> {
    // Compute biggest size mpu-protectable that can be allocated to all contexts.
    // The size has to be a power of two
    // All contexts also have to be naturally aligned.
    assert!(c.len() > 1);
    let optimal_size = available_size() / (c.len() - 1);
    let size = (1 << (31 - (optimal_size as u32).leading_zeros())) as usize;
    if let Some(res) = allocate_contexts_of_size(c, size) {
        debug!(
            "Allocated contexts of size {:x} with available {:x} and begin {:x}",
            size,
            available_size(),
            begin_addr()
        );
        res
    } else if let Some(res) = allocate_contexts_of_size(c, size >> 1) {
        // The padding required for alignment took up too much space
        debug!(
            "Allocated contexts of size {:x} with available {:x} and begin {:x}",
            size,
            available_size(),
            begin_addr()
        );
        res
    } else {
        panic!("Unable to allocate memory for contexts");
    }
}
