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
#![allow(unused_variables, unused_mut)]

use super::*;
#[cfg(test)]
use speculate::speculate; // Must be imported into the current scope.

use {flash, flash_ll};

speculate! {
    describe "crc" {
        it "has a correct CRC table" {
            let computed_crc_table = {
                // See comment above CRC_TABLE
                let polynomial = 0xD5; // MSB representation for CRC-8
                let msb = 0b10000000;
                let mut t = msb;
                let mut tmp;
                let mut i = 1;
                let mut idx;
                let mut table: [u8; 256] = [0; 256];
                while i < 256 {
                    tmp = if t & msb != 0 { polynomial } else { 0 };
                    t = (t << 1) ^ tmp;
                    for j in 0..i {
                        idx = (i + j) as u8;
                        table[idx as usize] = table[j as usize] ^ t;
                    }
                    i *= 2;
                }
                table
            };
            let crc1: &[u8] = &CRC_TABLE; // Cast to work around PartialEq not being implemented for n>32
            let crc2: &[u8] = &computed_crc_table;
            assert_eq!(crc1, crc2);
        }

        it "computes correct CRCs" {
            assert_eq!(crc8(0xE1, &[0x00, 0xCA, 0xFE]), 0x26); // Computed using https://ghsi.de/CRC/index.php?Polynom=111010101&Message=E100CAFE
            assert_eq!(crc8(0x12, &[0x34, 0x56, 0x78, 0x90]), 0x3E); // Computed using http://crccalc.com/ (CRC-8/DVB-S2)
        }
    }

    describe "fs" {
        before {
            let _only_one_at_a_time = flash_ll::FLASH_TEST_RUNNING.lock();
            let flash_sectors = flash_ll::sectors();
            let flash = unsafe { Flash::new(&flash_sectors) }.unwrap();
            flash.sector(flash::SectorID(0)).erase(&flash).unwrap();
            flash.sector(flash::SectorID(7)).erase(&flash).unwrap();
            let fs_sectors: Vec<&flash::Sector> = (1..7).map(|i| {
                let sector = flash.sector(flash::SectorID(i));
                sector.erase(&flash).unwrap();
                sector
            }).collect();
            let defragsector = SectorID(0);
            let appletsector = SectorID(7);
            let mut fs = FileSystem::new(&flash, &fs_sectors, defragsector, appletsector).unwrap();
        }

        it "does not have overlapping masks" {
            assert_eq!(VALIDITY_MASK & TAGLEN_MASK, 0);
            assert_eq!(VALIDITY_MASK & LENLEN_MASK, 0);
            assert_eq!(TAGLEN_MASK & LENLEN_MASK, 0);
        }

        it "correctly erases invalid sectors" {
            let sector = flash.sector(flash::SectorID(0));
            sector.with_writer(&flash, 0, 16, |mut b| {
                b.write_block(0, &[0, 1, 2, 3, 0xFF, 0xFF, 6, 7, 0xFF, 0xFF, 0xFF]).unwrap();
            }).unwrap();
            assert_eq!(&*sector.read(0, 10).unwrap(), &[0, 1, 2, 3, 0xFF, 0xFF, 6, 7, 0xFF, 0xFF]);
            erase_invalid_data(&flash, sector, 2).unwrap();
            assert_eq!(&*sector.read(0, 10).unwrap(), &[0, 1, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]);
        }

        it "returns valid metadata" {
            assert_eq!(fs.sector(SectorID(0)) as *const _, fs_sectors[0] as *const _);
            assert_eq!(fs.sector_ids(), (0..6).map(SectorID).collect::<Vec<SectorID>>());
            assert_eq!(fs.next_block(SectorID(0)), 0);
            *fs.set_next_block(SectorID(0)) = 42;
            assert_eq!(fs.next_block(SectorID(0)), 42);
            assert_eq!(fs.valid_size(SectorID(0)), 0);
            *fs.set_valid_size(SectorID(0)) = 24;
            assert_eq!(fs.valid_size(SectorID(0)), 24);
        }

        it "correctly finds available sectors" {
            assert_eq!(fs.available_sector(1, b"").unwrap(), SectorID(1));
            *fs.set_next_block(SectorID(1)) = fs_sectors[1].len();
            assert_eq!(fs.available_sector(1, b"").unwrap(), SectorID(2));
        }

        it "does not see as available a non-defragmentable sector" {
            *fs.set_next_block(SectorID(1)) = fs_sectors[1].len();
            *fs.set_next_block(SectorID(2)) = fs_sectors[2].len();
            *fs.set_next_block(SectorID(3)) = fs_sectors[3].len();
            *fs.set_next_block(SectorID(4)) = fs_sectors[4].len();
            assert_eq!(fs.available_sector(1, b"").unwrap(), SectorID(5));
            *fs.set_next_block(SectorID(5)) = fs_sectors[0].len();
            assert_eq!(fs.available_sector(1, b"").unwrap(), SectorID(5));
            *fs.set_valid_size(SectorID(5)) = fs_sectors[0].len() - 2;
            assert_eq!(fs.available_sector(1, b"").unwrap(), SectorID(5));
            *fs.set_valid_size(SectorID(5)) = fs_sectors[0].len() - 1;
            assert_eq!(fs.available_sector(1, b"").unwrap_err(), Error::OutOfFlash);
        }

        it "sees as available a defragmentable-thanks-to-invalidation sector" {
            *fs.set_next_block(SectorID(1)) = fs_sectors[1].len();
            *fs.set_next_block(SectorID(2)) = fs_sectors[2].len();
            *fs.set_next_block(SectorID(3)) = fs_sectors[3].len();
            *fs.set_next_block(SectorID(4)) = fs_sectors[4].len();
            assert_eq!(fs.available_sector(1, b"").unwrap(), SectorID(5));
            fs.write(b"test", b"1234567890").unwrap(); // Sector takes 1 + 1 + 4 + 10 + 1 = 17 bytes on disk
            *fs.set_next_block(SectorID(5)) = fs_sectors[0].len() - 1;
            *fs.set_valid_size(SectorID(5)) = fs_sectors[0].len() - 1;
            assert_eq!(fs.available_sector(1, b"test").unwrap(), SectorID(5));
            assert_eq!(fs.available_sector(17, b"test").unwrap(), SectorID(5));
            assert_eq!(fs.available_sector(18, b"test"), Err(Error::OutOfFlash));
        }

        it "defragments" {
            // 1 + 1 + 1 + 2 + 1 = 6 bytes on disk per entry
            fs.write(b"a", b"ta").unwrap();
            fs.write(b"b", b"tb").unwrap();
            fs.write(b"c", b"tc").unwrap();
            fs.write(b"c", b"tc").unwrap();
            assert_eq!(fs.next_block(SectorID(0)), 0);
            assert_eq!(fs.next_block(SectorID(1)), 24);
            assert_eq!(fs.valid_size(SectorID(1)), 18);
            fs.defragment(SectorID(1)).unwrap();
            assert_eq!(fs.next_block(SectorID(0)), 0);
            assert_eq!(fs.next_block(SectorID(1)), 18);
            assert_eq!(fs.valid_size(SectorID(1)), 18);
        }

        it "writes to a sector" {
            fs.write_impl(b"test", &[b"foobar"], SectorID(3)).unwrap();
            assert_eq!(&*flash.sector(flash::SectorID(4)).read(2, 4).unwrap(), b"test");
            assert_eq!(&*flash.sector(flash::SectorID(4)).read(6, 6).unwrap(), b"foobar");
            let long_contents: Vec<u8> = (0..500).map(|x| x as u8).collect();
            fs.write_impl(b"test2", &[&long_contents], SectorID(2)).unwrap();
            assert_eq!(&*flash.sector(flash::SectorID(3)).read(5, 5).unwrap(), b"test2");
            assert_eq!(&*flash.sector(flash::SectorID(3)).read(10, 500).unwrap(), &long_contents[..]);
        }

        it "correctly computes a block's length" {
            assert_eq!(fs.block_len(b"test".len(), b"1234567890".len()), 17);
            assert_eq!(fs.block_len(b"test2".len(), 500), 511);
        }

        it "handles a simple read-write-reinitialize loop" {
            assert_eq!(fs.read(b"test").unwrap_err(), Error::NoSuchTag);
            assert!(!fs.has_tag(b"test"));
            fs.write(b"test", b"value").unwrap();
            assert_eq!(&*fs.read(b"test").unwrap(), b"value");
            assert!(fs.has_tag(b"test"));
            fs.write(b"test", b"value2").unwrap();
            assert_eq!(&*fs.read(b"test").unwrap(), b"value2");
            assert!(fs.has_tag(b"test"));
            drop(fs);
            fs = FileSystem::new(&flash, &fs_sectors, defragsector, appletsector).unwrap();
            assert_eq!(&*fs.read(b"test").unwrap(), b"value2");
            assert!(fs.has_tag(b"test"));
        }

        it "handles a simple read-write-erase-reinitialize" {
            assert_eq!(fs.read(b"test").unwrap_err(), Error::NoSuchTag);
            assert!(!fs.has_tag(b"test"));
            fs.write(b"test", b"value").unwrap();
            assert_eq!(&*fs.read(b"test").unwrap(), b"value");
            assert!(fs.has_tag(b"test"));
            fs.erase(b"test").unwrap();
            assert_eq!(fs.read(b"test").unwrap_err(), Error::NoSuchTag);
            assert!(!fs.has_tag(b"test"));
            drop(fs);
            fs = FileSystem::new(&flash, &fs_sectors, defragsector, appletsector).unwrap();
            assert_eq!(fs.read(b"test").unwrap_err(), Error::NoSuchTag);
            assert!(!fs.has_tag(b"test"));
        }

        #[ignore]
        it "allows spamming reads and writes" {
            ::debug::DISABLE_DEBUG.store(true, ::std::sync::atomic::Ordering::SeqCst);
            assert_eq!(fs.read(b"test").unwrap_err(), Error::NoSuchTag);
            for i in 0..100 {
                for j in 0..1000 {
                    let value: Vec<u8> = format!("value-{}-{}", i, j).bytes().collect();
                    fs.write(b"test", &value).unwrap();
                    assert_eq!(&*fs.read(b"test").unwrap(), &value[..]);
                    assert!(fs.has_tag(b"test"));
                }
                drop(fs);
                fs = FileSystem::new(&flash, &fs_sectors, defragsector, appletsector).unwrap();
                let last_value: Vec<u8> = format!("value-{}-{}", i, 999).bytes().collect();
                assert_eq!(&*fs.read(b"test").unwrap(), &last_value[..]);
                assert!(fs.has_tag(b"test"));
            }
        }

        #[ignore]
        it "allows spamming reads and edits" {
            ::debug::DISABLE_DEBUG.store(true, ::std::sync::atomic::Ordering::SeqCst);
            assert_eq!(fs.read(b"test").unwrap_err(), Error::NoSuchTag);
            fs.write(b"test", b"value-???-????").unwrap();
            for i in 0..100 {
                fs.edit_at(b"test", 6, format!("{:03}", i).as_bytes()).unwrap();
                for j in 0..1000 {
                    fs.edit_at(b"test", 10, format!("{:04}", j).as_bytes()).unwrap();
                    assert_eq!(&*fs.read(b"test").unwrap(),
                    format!("value-{:03}-{:04}", i, j).as_bytes());
                    assert!(fs.has_tag(b"test"));
                }
                drop(fs);
                fs = FileSystem::new(&flash, &fs_sectors, defragsector, appletsector).unwrap();
                assert_eq!(&*fs.read(b"test").unwrap(),
                format!("value-{:03}-{:04}", i, 999).as_bytes());
                assert!(fs.has_tag(b"test"));
            }
        }

        describe "parse_hdr" {
            before {
                type Res<'a> = Result<(bool, &'a [u8], &'a [u8], usize), ParseNoBlock>;
            }

            after {
                let header_len = header.len();
                if auto_crc8 {
                    header[header_len - 1] = crc8(header[0] & !VALIDITY_MASK, &header[1..header.len()-1]);
                }
                let sector = flash.sector(flash::SectorID(0));
                sector.with_writer(&flash, 0, header_len, |mut b| b.write_block(0, header).unwrap()).unwrap();
                let res = parse_hdr(sector.read(0, header_len).unwrap());
                match result {
                    Err(e) => assert_eq!(e, res.unwrap_err()),
                    Ok((a, b, c, d)) => {
                        let (ra, rb, rc, rd) = res.unwrap();
                        assert_eq!(a, ra);
                        assert_eq!(b, &*rb);
                        assert_eq!(c, &*rc);
                        assert_eq!(d, rd);
                    },
                }
            }

            it "parses correct header" {
                let mut header = &mut [
                    0b01001000,
                    5,
                    b't', b'e', b's', b't',
                    b'v', b'a', b'l', b'u', b'e',
                    0
                ];
                let auto_crc8 = true;
                let result: Res = Ok((true, b"test", b"value", 12));
            }

            it "parses no longer valid header" {
                let mut header = &mut [
                    0b00001000,
                    5,
                    b't', b'e', b's', b't',
                    b'v', b'a', b'l', b'u', b'e',
                    0
                ];
                let auto_crc8 = true;
                let result: Res = Ok((false, b"test", b"value", 12));
            }

            it "detects checksum errors" {
                let mut header = &mut [
                    0b01001000,
                    5,
                    b't', b'e', b's', b't',
                    b'v', b'a', b'l', b'u', b'e',
                    0
                ];
                let auto_crc8 = false;
                let result: Res = Err(ParseNoBlock::Broken);
            }

            it "detects empty block" {
                let mut header = &mut [0xFF];
                let auto_crc8 = false;
                let result: Res = Err(ParseNoBlock::Empty);
            }

            it "detects erased blocks" {
                let mut header = &mut [0, 0, 0, 0, 0, 0, 0x42];
                let auto_crc8 = false;
                let result: Res = Err(ParseNoBlock::Erased(6));
            }
        }
    }
}
