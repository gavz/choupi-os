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

use core::mem::size_of;
use core::slice;
use {argbuf_size, argbuf_start};

unsafe fn get_argbuf_len() -> usize {
    let res = *(argbuf_start() as *mut usize);
    assert!(res < argbuf_size() - size_of::<usize>());
    res
}

unsafe fn set_argbuf_len(val: usize) {
    assert!(val < argbuf_size() - size_of::<usize>());
    *(argbuf_start() as *mut usize) = val;
}

unsafe fn argbuf_buf(len: usize) -> &'static mut [u8] {
    assert!(len < argbuf_size() - size_of::<usize>());
    slice::from_raw_parts_mut(
        argbuf_start().offset(size_of::<usize>() as isize) as *mut u8,
        len,
    )
}

pub fn setup_argbuf() {
    unsafe {
        set_argbuf_len(0);
        for x in argbuf_buf(argbuf_size() - size_of::<usize>() - 1) {
            *x = 0;
        }
    }
}

pub fn get_argbuf(ret: &mut [u8]) {
    unsafe {
        let len = get_argbuf_len();
        assert!(len != 0);
        let argbuf = argbuf_buf(len);
        ret.copy_from_slice(argbuf);
        for x in argbuf.iter_mut() {
            *x = 0;
        }
        set_argbuf_len(0);
    }
}

pub fn set_argbuf(data: &[u8]) {
    unsafe {
        assert!(get_argbuf_len() == 0);
        argbuf_buf(data.len()).copy_from_slice(data);
        set_argbuf_len(data.len());
    }
}
