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

//! Tools to help debugging through the serial console.
#[cfg(any(debug_assertions, test))]
use core::sync::atomic::{AtomicBool, Ordering};

/// Set to `true` to disable debug output at runtime if `--cfg debug` or `--cfg test` has been
/// given as compile-time argument
#[cfg(any(debug_assertions, test))]
#[link_section = ".shared_ro"]
pub static DISABLE_DEBUG: AtomicBool = AtomicBool::new(false);

/// Writes a `&str` to the serial console.
#[cfg(all(any(debug_assertions, test), feature = "embedded"))]
pub fn output_str(x: &str) {
    use privilege;
    use syscall;

    if !DISABLE_DEBUG.load(Ordering::SeqCst) {
        if !privilege::is_privileged() {
            syscall::usart_output(x);
        } else {
            syscall::privileged_usart_output(x);
        }
    }
}

/// Writes a `&str` via println function
#[cfg(all(any(debug_assertions, test), feature = "host"))]
pub fn output_str(x: &str) {
    use privilege;
    use syscall;

    if !DISABLE_DEBUG.load(Ordering::SeqCst) {
        if !privilege::is_privileged() {
            println!("{}", x);
        } else {
            syscall::privileged_usart_output(x);
        }
    }
}

/// Formats a message to the serial console, `println!`-like, but only if `--cfg debug` is turned
/// on (or currently in test mode).
#[cfg(any(debug_assertions, test))]
#[macro_export]
macro_rules! debug {
    ($msg:expr) => {{
        $crate::debug::output_str(concat!($msg, "\r\n"));
    }};
    ($fmt:expr, $($arg:tt)+) => {{
        $crate::debug::output_str(&::alloc::format!(concat!($fmt, "\r\n"), $($arg)+));
    }};
}

/// Printing debug message.
#[cfg(not(any(debug_assertions, test)))]
#[macro_export]
macro_rules! debug {
    ($msg:expr) => {};
    ($fmt:expr, $($arg:tt)+) => {};
}

/// Makes an error and add an error message to the serial console at evaluation time.
#[macro_export]
macro_rules! err {
    ($x:expr) => {{
        let e = $x;
        debug!("Error at {}:{}: {:?}", file!(), line!(), e);
        Err(e)
    }};
}

/// Forwards an error up (`try!`-like) while adding an error message to the serial console.
#[macro_export]
macro_rules! get {
    ($x:expr) => {{
        match $x {
            Ok(x) => x,
            Err(e) => {
                debug!("  Error at {}:{}: {:?}", file!(), line!(), e);
                Err(e)?
            }
        }
    }};
}
