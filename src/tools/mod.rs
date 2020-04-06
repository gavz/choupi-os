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

//! Tools for manipulating memory-mapped registers

mod tests;

use core::ops::{BitAnd, BitOr, Not};
use core::ptr::{read_volatile, write_volatile};

/// Type of a linker symbol
///
/// It is non-instantiable and nothing can be done with it except take its address, which is
/// exactly what we want from a linker symbol.
#[cfg(not(test))]
#[repr(C)] // Still zero-sized despite repr(C), according to the nomicon
pub struct LinkerSymbol {
    /// Field making sure this struct is non-instantiable.
    _non_instantiable: (),
}

/// Sets bits to 1 in `bits` to 1 in `addr`
pub unsafe fn add_bits_volatile<T>(addr: *mut T, bits: T)
where
    T: BitOr<Output = T>,
{
    write_volatile(addr, read_volatile(addr) | bits);
}

/// Sets bits to 1 in `mask` to their value in `val` in `addr`
///
/// Note that it is assumed that `val & mask == val`.
pub unsafe fn set_bits_volatile<T>(addr: *mut T, mask: T, val: T)
where
    T: BitOr<Output = T>,
    T: BitAnd<Output = T>,
    T: Not<Output = T>,
{
    write_volatile(addr, (read_volatile(addr) & !mask) | val);
}

#[cfg(feature = "host")]
pub struct RunOnDrop {
    run: Box<dyn FnMut()>,
}

#[cfg(feature = "host")]
/// Run on drop
pub fn run_on_drop(run: Box<dyn FnMut()>) -> RunOnDrop {
    RunOnDrop { run }
}

#[cfg(feature = "host")]
impl Drop for RunOnDrop {
    fn drop(&mut self) {
        (self.run)()
    }
}
