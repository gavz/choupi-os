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

use context::ContextMetadata;
use mpu::Mpu;
use {emulator, privilege, ram_begin, ram_size, syscall, RAM};

speculate! {
    describe "test_syscall" {
        it "should return 42" {
            emulator::run(|| {
                unsafe {
                    privilege::drop((&mut RAM.get_mut()[0x17FFF] as *mut u8).wrapping_offset(1) as *mut ());

                    assert_eq!(syscall(Syscall::Test, 0, 0, 0), 42);
                    assert!(!privilege::is_privileged());

                    assert_eq!(syscall_saveall(Syscall::Test, 0, 0, 0), 42);
                    assert!(!privilege::is_privileged());
                }
                assert_eq!(test(), 42);
                assert!(!privilege::is_privileged());
            });
        }
    }

    describe "remotecall_syscall" {
        it "should return 42" {
            emulator::run(|| {
                unsafe {
                    let mut mpu = Mpu::get();
                    mpu.setup();
                    mpu.setup_unpriv_regions();
                    mpu.switch_userland(ram_begin(), ram_size().next_power_of_two());
                    drop(mpu);

                    let contexts = vec![
                        ContextMetadata {
                            remote_call_enter: |_, _, _| panic!("disallowed"),
                            begin: 0,
                            size: 0x800000000000000,
                            top_of_stack: context::TopOfStack::empty(0, 0),
                            heap_begin: &RAM.get()[0] as *const _ as usize,
                            heap_size: 0x5000,
                        },
                        ContextMetadata {
                            remote_call_enter: |caller, a, b| {
                                assert!(caller == 0 && a == 12 && b == 23);
                                let value = 42;
                                let addr = &value as *const _ as usize;
                                assert!(&RAM.get()[0x5000] as *const _ as usize <= addr
                                        && addr <= &RAM.get()[0x5800] as *const _ as usize);
                                assert_eq!(
                                    syscall::remote_call(context::ContextID::from_id_unchecked(2),
                                    32, 21),
                                    12
                                    );
                                value
                            },
                            begin: &RAM.get()[0x5000] as *const _ as usize,
                            size: 0x1000,
                            top_of_stack: context::TopOfStack::empty(
                                &RAM.get()[0x5000] as *const _ as usize,
                                &RAM.get()[0x5800] as *const _ as usize
                                ),
                                heap_begin: &RAM.get()[0x5800] as *const _ as usize,
                                heap_size: 0x800,
                        },
                        ContextMetadata {
                            remote_call_enter: |caller, a, b| {
                                assert!(caller == 1 && a == 32 && b == 21);
                                let value = 12;
                                let addr = &value as *const _ as usize;
                                assert!(&RAM.get()[0x6000] as *const _ as usize <= addr
                                        && addr <= &RAM.get()[0x6800] as *const _ as usize);
                                value
                            },
                            begin: &RAM.get()[0x6000] as *const _ as usize,
                            size: 0x1000,
                            top_of_stack: context::TopOfStack::empty(
                                &RAM.get()[0x6000] as *const _ as usize,
                                &RAM.get()[0x6800] as *const _ as usize
                                ),
                                heap_begin: &RAM.get()[0x6800] as *const _ as usize,
                                heap_size: 0x800,
                        },
                        ];

                    context::init_contexts(contexts);
                    privilege::drop((&mut RAM.get_mut()[0x17FFF] as *mut u8).wrapping_offset(1) as *mut ());
                    let value = 0;
                    debug!("current stack: {:p}", &value);
                    assert_eq!(syscall::remote_call(context::ContextID::from_id_unchecked(1), 12, 23),
                    42);
                }
            });
        }
    }

    describe "fs_syscalls" {
        it "handles a simple read-write-reinitialize loop from inside the emulator" {
            use {flash, flash_ll};
            use flash::Flash;
            use fs::*;

            let _only_one_at_a_time = flash_ll::FLASH_TEST_RUNNING.lock();
            emulator::run(|| {
                let flash_sectors = flash_ll::sectors();
                let flash = unsafe { Flash::new(&flash_sectors) }.unwrap();
                flash.sector(flash::SectorID(0)).erase(&flash).unwrap();
                flash.sector(flash::SectorID(7)).erase(&flash).unwrap();
                for i in 1..7 {
                    flash.sector(flash::SectorID(i)).erase(&flash).unwrap();
                }
                drop(flash);

                unsafe {
                    syscall::privileged_fs_init().unwrap();

                    let mut mpu = Mpu::get();
                    mpu.setup();
                    mpu.setup_unpriv_regions();
                    mpu.switch_userland(ram_begin(), ram_size().next_power_of_two());
                    drop(mpu);

                    let contexts = vec![
                        ContextMetadata {
                            remote_call_enter: |_, _, _| panic!("disallowed"),
                            begin: 0,
                            size: 0x800000000000000,
                            top_of_stack: context::TopOfStack::empty(0, 0),
                            heap_begin: &RAM.get()[0] as *const _ as usize,
                            heap_size: 0x5000,
                        },
                    ];

                    context::init_contexts(contexts);
                    privilege::drop((&mut RAM.get_mut()[0x17FFF] as *mut u8).wrapping_offset(1) as *mut ());
                }

                let mut buf = [0; 8];

                let filename = b"\x03\x00\x00\x00\x01";

                assert!(!syscall::fs_exists(filename));
                assert_eq!(syscall::fs_read(filename, &mut buf).unwrap_err(), Error::NoSuchTag);

                syscall::fs_write(filename, b"value").unwrap();

                buf = [0; 8];
                assert!(syscall::fs_exists(filename));
                syscall::fs_read(filename, &mut buf).unwrap();
                assert_eq!(&buf as &[u8], b"value\0\0\0");

                syscall::fs_write(filename, b"value2").unwrap();

                buf = [0; 8];
                assert!(syscall::fs_exists(filename));
                syscall::fs_read(filename, &mut buf).unwrap();
                assert_eq!(&buf as &[u8], b"value2\0\0");

                syscall::fs_erase(filename).unwrap();

                assert_eq!(syscall::fs_read(filename, &mut buf).unwrap_err(), Error::NoSuchTag);
                assert!(!syscall::fs_exists(filename));
            });
        }
    }
}
