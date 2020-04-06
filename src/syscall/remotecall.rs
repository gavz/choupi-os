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

//! Module for the syscall allowing to call functions in other contexts

use context;
use syscall::{syscall_saveall, Syscall};

/// Call function in context syscall
pub fn remote_call(c: context::ContextID, arg1: usize, arg2: usize) -> usize {
    unsafe { syscall_saveall(Syscall::RemoteCall, c.id(), arg1, arg2) }
}

/// Implementation of remote call syscall
pub fn syscall_remote_call(cid: usize, arg1: usize, arg2: usize) -> Option<usize> {
    let cid = context::ContextID::new(cid);
    context::push(
        cid,
        context::for_remotecall(
            context::remote_call_enter(cid),
            context::CURRENT_CONTEXT.id(),
            arg1,
            arg2,
        ),
    );
    context::switch_userland(cid);
    None
}

/// Syscall to return a return value to the calling context.
pub fn syscall_remote_result(res: usize, _: usize, _: usize) -> Option<usize> {
    context::pop();
    Some(res)
}
