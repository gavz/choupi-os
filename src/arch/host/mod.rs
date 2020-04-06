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

mod constants;
pub use self::constants::*;

#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    missing_docs
)]
#[cfg_attr(
    feature = "cargo-clippy",
    allow(
        expl_impl_clone_on_copy,
        missing_docs_in_private_items,
        pub_enum_variant_names,
        unseparated_literal_suffix
    )
)]
pub mod siginfo;

pub mod alloc_ll;
pub mod context_ll;
pub mod emulator;
pub mod flash_ll;
pub mod mpu_ll;
pub mod privilege;
pub mod registers;
pub mod syscall_ll;
pub mod usart_ll;

/// Static assertion to check `usize` is actually `u64`
#[allow(dead_code)]
fn assert_u64_is_usize() {
    unsafe {
        let _: usize = ::core::mem::transmute(0_u64);
    }
}
