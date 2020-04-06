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

//! # Project
//!
//! Please see `README.md` for installation steps.
//!
//! # Crate
//!
//! This crate is the main access point for all rust code in this project. It provides only
//! C-compatible wrappers for functionalities defined elsewhere.
//!
//! It can be configured using the following configuration flags:
//!  * `debug` for turning on/off potentially helpful serial console-based debugging information
//!  * `stm32f401re` for selecting the stm32f401re architecture-specific constants

#![cfg_attr(feature = "embedded", no_std)]
#![feature(
    asm,
    const_fn,
    core_intrinsics,
    lang_items,
    naked_functions,
    untagged_unions
)]
#![feature(alloc_error_handler)]
#![cfg_attr(feature = "embedded", feature(allocator_api))]
#![cfg_attr(test, feature(plugin))]
#![feature(panic_info_message)]
#![warn(missing_docs)]
#![cfg_attr(
    feature = "cargo-clippy",
    warn(
        filter_map,
        float_arithmetic,
        items_after_statements,
        missing_docs_in_private_items,
        mut_mut,
        mutex_integer,
        non_ascii_literal,
        nonminimal_bool,
        option_map_unwrap_or,
        option_map_unwrap_or_else,
        option_unwrap_used,
        pub_enum_variant_names,
        result_unwrap_used,
        shadow_reuse,
        shadow_same,
        shadow_unrelated,
        similar_names,
        single_match_else,
        string_add,
        string_add_assign,
        unicode_not_nfc,
        unseparated_literal_suffix,
        wrong_pub_self_convention
    )
)]

#[cfg(feature = "embedded")]
extern crate allocator;
#[cfg(feature = "host")]
extern crate core;
#[cfg(feature = "host")]
extern crate ipc_channel;
#[cfg(feature = "embedded")]
extern crate std;
#[cfg(feature = "host")]
#[macro_use]
extern crate lazy_static;
#[cfg(feature = "host")]
extern crate libc;
#[cfg(feature = "host")]
#[macro_use]
extern crate slog;
extern crate alloc;
#[cfg(feature = "host")]
extern crate slog_term;
extern crate spin;

#[cfg(test)]
extern crate speculate;

#[macro_use]
pub mod debug;
pub mod arch;
use arch::*;
#[cfg(feature = "embedded")]
pub mod runtime; // pub for extern lang items

mod argbuf;
pub mod context; // For __current_heap_{bottom, size}
mod contextnum;

#[cfg(feature = "embedded")]
mod contextallocator;
#[cfg(feature = "host")]
mod contextallocator;
mod filename;
mod flash;
mod fs;
mod hashset;
mod mpu;
pub mod syscall; // pub for SVC_Handler
mod tools;

pub mod ffi; // pub for all defined FFI functions
