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

#![no_std]
#![feature(allocator_api)]

// extern crate alloc;
extern crate linked_list_allocator as lla;

use core::alloc::{GlobalAlloc, Layout};
use core::mem::size_of;
use core::ptr::NonNull;

extern "C" {
    fn __current_heap_bottom() -> usize;
    fn __current_heap_size() -> usize;
}

#[no_mangle]
pub unsafe extern "C" fn initialize_heap() {
    let bottom = __current_heap_bottom();
    let size = __current_heap_size();
    initialize_heap_at(bottom, size);
}

pub unsafe fn initialize_heap_at(bottom: usize, size: usize) {
    let meta_size = size_of::<lla::Heap>();
    *(bottom as *mut lla::Heap) = lla::Heap::new(bottom + meta_size, size - meta_size);
}

pub struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = __current_heap_bottom() as *mut lla::Heap;
        (*heap)
            .allocate_first_fit(layout)
            .expect("Out of memory!")
            .as_ptr()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let heap = __current_heap_bottom() as *mut lla::Heap;
        let nn_ptr = NonNull::new(ptr).unwrap();
        (*heap).deallocate(nn_ptr, layout);
    }
}

#[global_allocator]
pub static ALLOCATOR: Allocator = Allocator;
