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

//! Low-level "HAL" emulation for syscalls

use emulator;

/// Generates a syscall of number `num` with arguments `arg[1-3]`, returning the value returned
/// from the syscall. Will call `syscall::syscall_received` as privileged code to handle this call.
pub unsafe fn syscall(num: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    emulator::syscall(num, arg1, arg2, arg3)
}

/// Generates a syscall of number `num` with arguments `arg[1-3]`, returning the value returned
/// from the syscall. Will call `syscall::syscall_received` as privileged code to handle this call.
///
/// In addition to what `syscall` does, `syscall_saveall` also clears all the state stored in
/// registers and regenerates it afterwise, so that data is not leaked through registers.
pub unsafe fn syscall_saveall(num: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    // Here, syscall is handled by emulator and already saves all registers, so there is no need to
    // do it ourselves.
    emulator::syscall(num, arg1, arg2, arg3)
}
