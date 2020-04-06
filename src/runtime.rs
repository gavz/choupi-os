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

//! Rust compiler support for `no_std` target

use core;
use core::panic::PanicInfo;

extern "C" {
    /// C-defined error handler
    fn Error_Handler();
}

/// Lang item called on a panic.
///
/// This calls back into C's [`Error_Handler`].
///
/// [`Error_Handler`]: fn.Error_Handler.html
// #[lang="panic_fmt"]
#[panic_handler]
#[no_mangle]
pub extern "C" fn rust_begin_panic(info: &PanicInfo) -> !
//(_args: core::fmt::Arguments, _file: &'static str, _line: usize)
{
    let _args = info.message().unwrap();
    let _location = info.location().unwrap();

    debug!("Caught panic at {}:{}!", _location.file(), _location.line());
    debug!("Error message: {}", ::alloc::fmt::format(*_args));
    loop {
        unsafe { Error_Handler() }
    }
}

#[alloc_error_handler]
fn rust_begin_alloc_error(_: core::alloc::Layout) -> ! {
    debug!("Alloc error!");
    loop {
        unsafe { Error_Handler() }
    }
}

/// Lang item used for generating unwind info.
///
/// As there is no unwinding here, this lang item is useless.
#[lang = "eh_personality"]
pub extern "C" fn rust_eh_personality() {}
