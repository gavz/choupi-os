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
#![allow(unused_variables)]

use super::*;
#[cfg(test)]
use speculate::speculate; // Must be imported into the current scope.

use {FLASH, SECTORS};

speculate! {
    describe "overlap" {
        it "should see overlapping ranges" {
            assert!(overlap(1, 3, 1, 3));
            assert!(overlap(1, 3, 3, 2));
            assert!(overlap(2, 3, 2, 1));
            assert!(overlap(5, 1, 5, 1));
            assert!(overlap(4, 5, 6, 1));
            assert!(overlap(2, 5, 3, 0));
            assert!(overlap(4, 0, 2, 6));
        }

        it "should not see non-overlapping ranges" {
            assert!(!overlap(1, 3, 4, 1));
            assert!(!overlap(3, 5, 1, 2));
        }
    }

    describe "flash" {
        before {
            let _only_one_at_a_time = flash_ll::FLASH_TEST_RUNNING.lock();
            let sectors = flash_ll::sectors();
            let flash = unsafe { Flash::new(&sectors) }.unwrap();
        }

        it "should fail when borrowed twice" {
            let twice = unsafe { Flash::new(&[]) };
            assert!(twice.is_err());
            if let Err(x) = twice {
                assert_eq!(x, InitError::FlashInUse);
            }
        }

        it "should unlock when asked to, returning the result of the closure" {
            assert!(flash_ll::locked());
            let res = with_flash_unlocked(&flash, || {
                assert!(!flash_ll::locked());
                1337
            }).unwrap();
            assert!(flash_ll::locked());
            assert_eq!(res, 1337);
        }

        it "should return a sector when asked to" {
            let s = flash.sector(flash::SectorID(2));
            assert_eq!(s.num(), 2);
            assert_eq!(s.start, unsafe { (&mut FLASH.get_mut()[0] as *mut u8).offset(SECTORS[2].0 as isize) });
            assert_eq!(s.len(), SECTORS[2].1);
            assert_eq!(s.locks.lock().iter().next(), None); // No locks should be held
        }

        describe "sector" {
            before {
                let sector = flash.sector(flash::SectorID(6));
                sector.erase(&flash).unwrap();
                sector.with_writer(&flash, 0, 128, |mut b| {
                    for i in 0..128 {
                        b.write(i, i as u8).unwrap()
                    }
                }).unwrap();
            }

            it "should allow overlapping read-locks" {
                sector.lock(false, 1, 5).unwrap();
                sector.lock(false, 3, 8).unwrap();
                sector.lock(false, 0, 3).unwrap();
                sector.lock(false, 124, 2).unwrap();
            }

            it "should allow non-overlapping write-locks" {
                sector.lock(true, 1, 4).unwrap();
                sector.lock(true, 5, 2).unwrap();
                sector.lock(true, 0, 1).unwrap();
            }

            it "should disallow overlapping read- and write-locks" {
                sector.lock(true, 3, 4).unwrap();
                assert_eq!(sector.lock(true, 2, 2), Err(IOError::LockedError));
                assert_eq!(sector.lock(false, 2, 2), Err(IOError::LockedError));
                assert_eq!(sector.lock(false, 4, 1), Err(IOError::LockedError));
                sector.lock(false, 12, 3).unwrap();
                assert_eq!(sector.lock(true, 7, 6), Err(IOError::LockedError));
                assert_eq!(sector.lock(true, 14, 2), Err(IOError::LockedError));
                sector.lock(false, 7, 6).unwrap();
            }

            it "should unlock correctly" {
                sector.lock(true, 3, 5).unwrap();
                assert_eq!(sector.lock(true, 7, 1), Err(IOError::LockedError));
                unsafe { sector.unlock(true, 3, 5); }
                sector.lock(false, 7, 1).unwrap();
                assert_eq!(sector.lock(true, 7, 5), Err(IOError::LockedError));
                unsafe { sector.unlock(false, 7, 1); }
                sector.lock(true, 7, 5).unwrap();
            }

            it "should read data previously written" {
                let b = sector.read(1, 3).unwrap();
                assert_eq!(&*sector.read(2, 4).unwrap(), [2, 3, 4, 5]);
                assert_eq!(&*b, [1, 2, 3]);
                assert_eq!(&*b.read(1, 1).unwrap(), [2]);
            }

            it "should allow rewriting at the same position" {
                sector.with_writer(&flash, 3, 1, |mut b| b.write(0, 6).unwrap()).unwrap();
                assert_eq!(&*sector.read(3, 1).unwrap(), [2]);
            }

            it "should erase" {
                sector.erase(&flash).unwrap();
                assert_eq!(&*sector.read(4, 2).unwrap(), [0xFF, 0xFF]);
            }

            it "should fail writing at a currently-held-for-reading position" {
                {
                    let b = sector.read(4, 2).unwrap();
                    assert_eq!(&*b, [4, 5]);
                    assert_eq!(sector.with_writer(&flash, 4, 1, |mut b| b.write(0, 0)), Err(IOError::LockedError));
                    unsafe { asm!("" ::: "memory" : "volatile"); } // hopefully force pushing writes and pulling b again
                    assert_eq!(&*b, [4, 5]);
                    assert_eq!(sector.erase(&flash), Err(IOError::LockedError));
                    unsafe { asm!("" ::: "memory" : "volatile"); } // hopefully force pushing writes and pulling b again
                    assert_eq!(&*b, [4, 5]);
                }
                sector.erase(&flash).unwrap();
                assert_eq!(&*sector.read(4, 2).unwrap(), [0xFF, 0xFF]);
            }

            it "should fail trying to write to two sectors at the same time" {
                let s2 = flash.sector(SectorID(2));
                sector.with_writer(&flash, 4, 1, |mut _b| {
                    assert_eq!(s2.with_writer(&flash, 2, 1, |mut _b| 0), Err(IOError::LockedError));
                }).unwrap();
            }
        }

        describe "blocks" {
            before {
                let sector = flash.sector(SectorID(7));
                sector.erase(&flash).unwrap();
            }

            it "should point to its parent sector" {
                assert_eq!(sector.read(0, 1).unwrap().sector() as *const _, sector as *const _);
            }

            it "should have the right beginning index" {
                assert_eq!(sector.read(42, 1).unwrap().start(), 42);
            }

            it "should correctly write a block of data at once" {
                sector.with_writer(&flash, 0, 8,
                                   |mut b| {
                                       b.write_block(0, &[0, 1, 2, 3, 4, 5, 6, 7]).unwrap()
                                   }).unwrap();
                assert_eq!(&*sector.read(3, 4).unwrap(), [3, 4, 5, 6]);
            }

            it "should correctly write a small unaligned block of data" {
                sector.with_writer(&flash, 0, 8,
                                   |mut b| {
                                       b.write_block(1, &[42]).unwrap()
                                   }).unwrap();
                assert_eq!(&*sector.read(0, 3).unwrap(), [0xFF, 42, 0xFF]);
            }

            it "should correctly zero out a block of data at once" {
                sector.with_writer(&flash, 0, 8, |mut b| b.zero_block(0, 8).unwrap()).unwrap();
                assert_eq!(&*sector.read(6, 2).unwrap(), [0, 0]);
            }
        }
    }
}
