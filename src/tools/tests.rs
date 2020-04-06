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

#![cfg(test)]

use super::*;
#[cfg(test)]
use speculate::speculate; // Must be imported into the current scope.

speculate! {
    describe "add_bits_volatile" {
        before {
            let mut base = 0x0F_u8;
        }

        it "adds bits when required" {
            unsafe { add_bits_volatile(&mut base, 0x80); }
            assert_eq!(base, 0x8F);
        }

        it "does nothing when bit is already present" {
            unsafe { add_bits_volatile(&mut base, 0x04); }
            assert_eq!(base, 0x0F);
        }

        it "adds some bits" {
            unsafe { add_bits_volatile(&mut base, 0x75); }
            assert_eq!(base, 0x7F);
        }
    }

    describe "set_bits_volatile" {
        before {
            let mut base = 0x0F_u8;
        }

        it "sets unset bits" {
            unsafe { set_bits_volatile(&mut base, 0xF0, 0x40); }
            assert_eq!(base, 0x4F);
        }

        it "unsets set bits" {
            unsafe { set_bits_volatile(&mut base, 0xF4, 0x00); }
            assert_eq!(base, 0x0B);
        }

        it "both sets and unsets bits" {
            unsafe { set_bits_volatile(&mut base, 0x35, 0x14); }
            assert_eq!(base, 0x1E);
        }
    }
}
