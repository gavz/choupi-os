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

//! Functions describing the low-level working of the MPU

use bindings::{
    MPU_CTRL_ENABLE_Msk, MPU_CTRL_PRIVDEFENA_Msk, MPU_RASR_AP_Msk, MPU_RASR_AP_Pos,
    MPU_RASR_ENABLE_Msk, MPU_RASR_ENABLE_Pos, MPU_RASR_SIZE_Msk, MPU_RASR_SIZE_Pos,
    MPU_RASR_SRD_Msk, MPU_RASR_SRD_Pos, MPU_RASR_XN_Msk, MPU_RASR_XN_Pos, MPU_RBAR_ADDR_Msk,
    MPU_RNR_REGION_Msk, MPU_Type, SCB_SHCSR_MEMFAULTENA_Msk, SCB_Type, MPU_BASE, SCB_BASE,
};

#[cfg(any(debug_assertions, test))]
use registers;

use tools::{add_bits_volatile, set_bits_volatile};

/// Pointer to the MPU registers
const MPU: *mut MPU_Type = MPU_BASE as _;

/// Pointer to the System Control Block
const SCB: *mut SCB_Type = SCB_BASE as _;

/// Crashes on `MemManage` fault
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn MemManage_Handler() -> ! {
    debug!("Caught MemManage fault");
    debug!("Configurable Fault Status Registers 0x{:08x}", (*SCB).CFSR);
    debug!("MemManage Address Register: 0x{:08x}", (*SCB).MMFAR);
    debug!(
        "MSP=0x{:08x} PSP=0x{:08x} CONTROL=0x{:08x}",
        registers::get_msp(),
        registers::get_psp().get(),
        registers::get_control()
    );
    debug!("Now panicking!");
    panic!();
}

/// Sets up the MPU, with privileged mode all-powerful and unprivileged mode powerless
pub unsafe fn setup() {
    // Enable the MemFault interrupt
    add_bits_volatile(&mut (*SCB).SHCSR, SCB_SHCSR_MEMFAULTENA_Msk);
    // Enable the MPU with Privileged mode all-powerful and Unprivileged mode powerless
    add_bits_volatile(
        &mut (*MPU).CTRL,
        MPU_CTRL_PRIVDEFENA_Msk | MPU_CTRL_ENABLE_Msk,
    );
}

/// Sets permissions for an unprivileged region (along with enabling it).
///
/// All generated regions will turn on the read flag for the user. In order to have the user unable
/// to read a zone, it's enough to just not have any unprivileged region matching this zone.
///
/// For the moment, this turns out to be enough.
pub unsafe fn set_unprivileged_region(
    region: usize,
    start: *const u8,
    size: usize,
    writable: bool,
    executable: bool,
    sub_region_disable: Option<[bool; 8]>,
) {
    // Set Region Number Register
    set_bits_volatile(&mut (*MPU).RNR, MPU_RNR_REGION_Msk, region as u32);
    // Set Region Base Address Register
    set_bits_volatile(&mut (*MPU).RBAR, MPU_RBAR_ADDR_Msk, start as u32);
    // Compute the SRD field
    let srd_field =
        sub_region_disable.map_or(0, |t| t.iter().fold(0, |a, &x| (a << 1) | (x as u32)));
    // Compute the size field
    // Allowed size will be 2^(size_field+1) according to table B3-43 of ARMv7-M reference
    let size_field = 30 - size.leading_zeros();
    // Set Region Attribute and Size Register
    let value = ((1 - (executable as u32)) << MPU_RASR_XN_Pos)
        | ((0b010 | (writable as u32)) << MPU_RASR_AP_Pos)
        | (srd_field << MPU_RASR_SRD_Pos)
        | ((size_field << MPU_RASR_SIZE_Pos) & MPU_RASR_SIZE_Msk)
        | (1 << MPU_RASR_ENABLE_Pos);
    asm!("dsb
          isb" :::: "volatile");
    set_bits_volatile(
        &mut (*MPU).RASR,
        MPU_RASR_XN_Msk
            | MPU_RASR_AP_Msk
            | MPU_RASR_SRD_Msk
            | MPU_RASR_SIZE_Msk
            | MPU_RASR_ENABLE_Msk,
        value,
    );
}
