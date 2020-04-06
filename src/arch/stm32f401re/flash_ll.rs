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

//! Raw instructions for performing Flash operations.
//!
//! No safety at all is provided, for a safe interface see `flash.rs`.

use bindings::{
    FLASH_CR_PSIZE_Msk, FLASH_CR_PSIZE_Pos, FLASH_CR_SER_Msk, FLASH_CR_SNB_Msk, FLASH_CR_SNB_Pos,
    FLASH_SR_BSY_Msk, FLASH_SR_PGAERR_Msk, FLASH_SR_PGPERR_Msk, FLASH_SR_PGSERR_Msk,
    FLASH_SR_RDERR_Msk, FLASH_SR_WRPERR_Msk, FLASH_TypeDef, FLASH_CR_LOCK, FLASH_CR_PG,
    FLASH_CR_SER, FLASH_CR_STRT, FLASH_R_BASE, FLASH_SR_BSY,
};
use core::ptr::{read_volatile, write_volatile};
use tools::{add_bits_volatile, set_bits_volatile};

/// Pointer to the FLASH register
const FLASH: *mut FLASH_TypeDef = FLASH_R_BASE as *mut FLASH_TypeDef;

/// Mask grouping all errors that can happen in `FLASH_SR` register
const FLASH_SR_ERR: u32 = FLASH_SR_RDERR_Msk
    | FLASH_SR_PGSERR_Msk
    | FLASH_SR_PGPERR_Msk
    | FLASH_SR_PGAERR_Msk
    | FLASH_SR_WRPERR_Msk;

/// Unlocks the flash so that it becomes possible to write in it
pub unsafe fn unlock() {
    write_volatile(&mut (*FLASH).KEYR, 0x45670123);
    write_volatile(&mut (*FLASH).KEYR, 0xCDEF89AB);
}

/// Locks the flash so that it is no longer possible to write in it until the next `unlock()`
pub unsafe fn lock() {
    add_bits_volatile(&mut (*FLASH).CR, FLASH_CR_LOCK);
}

/// Configures the flash device
///
/// Note: must be called with flash unlocked
pub unsafe fn setup() {
    // 0b10 is x32 parallelism, suitable for 2.7-3.6V
    set_bits_volatile(
        &mut (*FLASH).CR,
        FLASH_CR_PSIZE_Msk,
        0b10 << FLASH_CR_PSIZE_Pos,
    );
}

/// Returns 0 if there was no error, and a non-zero value if the flash reports an error
pub unsafe fn has_error() -> u32 {
    read_volatile(&(*FLASH).SR) & FLASH_SR_ERR
}

/// Clears the previous error number
pub unsafe fn clear_error() {
    add_bits_volatile(&mut (*FLASH).SR, FLASH_SR_ERR);
}

/// Returns `true` if the flash is currently busy writing something
pub unsafe fn currently_busy() -> bool {
    read_volatile(&(*FLASH).SR) & FLASH_SR_BSY_Msk == FLASH_SR_BSY
}

/// Erases a sector, writing all-`0xFF`'s on it
///
/// Note: must be called with flash unlocked
pub unsafe fn erase(sector: u32) {
    set_bits_volatile(
        &mut (*FLASH).CR,
        FLASH_CR_SER_Msk | FLASH_CR_SNB_Msk,
        FLASH_CR_SER | (sector << FLASH_CR_SNB_Pos),
    );
    add_bits_volatile(&mut (*FLASH).CR, FLASH_CR_STRT);
}

/// Writes a 32-bits value to the flash, at address `addr`
///
/// Note: must be called with flash unlocked
pub unsafe fn write(addr: *mut u32, val: u32) {
    add_bits_volatile(&mut (*FLASH).CR, FLASH_CR_PG);
    write_volatile(addr, val);
}
