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

//! Persistent pseudo-hashmap on top of the Flash interface
//!
//! # High-level overview of the file system
//!
//! The file system can be viewed as a persistent hash map on top of the flash.
//! It acts as much as possible without erasing any sector, as an erase is really slow.
//! In order to do so, it doesn't store a hashmap directly on disk, rather it just stores tag-data
//! blocks, and rebuilds the hashmap in RAM on each boot.
//!
//! When modifying the value of a tag, it just adds a new tag block in some free space, and marks
//! the previous block as invalid so that it is not picked up by loader at the next reset.
//!
//! For performance reasons, the blocks are concatenated one after the other, so that scanning can
//! be linear.
//!
//! ## Atomicity and timeline
//!
//! In order to ensure maximal atomicity, a tag is written while being marked as not-yet-valid, and
//! only once it is completely written, it is marked as now-valid.
//!
//! In order to not risk having invalid blocks made valid by an interrupted erase operation, a
//! CRC-8 is appended to each block, checksumming it (except the validity part of the header, which
//! naturally changes when marking a file as invalid) to ensure the file has not been half-erased.
//!
//! ## Defragmentation
//!
//! However, one issue of such an append-only filesystem is that eventually sectors will get full,
//! even when only changing a single low-size value multiple times: old values are never removed.
//!
//! In order to work around this, a "defragmentation" is performed: it is based on copying all the
//! valid blocks of a sector to another sector, then erasing it, and copying all the blocks back to
//! the previous sector.
//! This way, all blocks marked as invalid are erased, and space is recovered.
//!
//! This means there is a need to always have enough free space to be able to defragment any
//! sector.
//! In order to ensure this, a sector is designated as "defragmentation sector", and is reserved
//! for only holding temporary data during defragmentation.
//!
//! # Block layout
//!
//! ## Header (1 byte)
//!
//! ```none
//! +-+-+---------+-+
//! |A|B|    C    |D|
//! +-+-+---------+-+
//! ```
//!
//! `A`: `1` if the block is not valid yet, `0` otherwise
//!
//! `B`: `0` if the block is no longer valid, `1` otherwise
//!
//! `C`: Length of the tag field (`F`), `11111` being reserved for the case when hte block is not
//!      actually written yet (ie. the full header byte is `0xFF`), and `00000` being reserved for
//!      an erased block (ie. a `0x00`-full block), which then ends at the first non-`0x00` octet.
//!
//! `D`: `1` if the data length field (`E`) is a long field (4 bytes), `0` if `E` is a short field
//!      (1 byte)
//!
//! ## Data length field
//!
//! ```none
//! +---------------+
//! |       E       |
//! +---------------+
//! ```
//!
//! `E`: Length of the data field (`G`). If in short form (ie. `D == 0`), it is stored on one byte.
//!      If in long form (ie. `D == 1`), it is stored on four bytes, most significant byte first.
//!
//! ## Data field
//!
//! ```none
//! +---------------+---------------+
//! |       F       |       G       |
//! +---------------+---------------+
//! ```
//!
//! `F`: Tag field, whose length is given by field `C`
//!
//! `G`: Data field, whose length is given by field `E`
//!
//! ## Checksum
//!
//! ```none
//! +---------------+
//! |       H       |
//! +---------------+
//! ```
//!
//! `H`: Checksum (CRC-8) over the following data:
//! ```none
//! +---+---------+-+---------------+---------------+---------------+
//! | 0 |    C    |D|       E       |       F       |       G       |
//! +---+---------+-+---------------+---------------+---------------+
//! ```
//! The `A` and `B` fields are set to zero before checksumming in order to have the checksum
//! consistent independently of the validity state of the block.

mod tests;

use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::hash::{Hash, Hasher};
use core::usize;
use flash::IOError as FlashIOError;
use flash::{Flash, FlashBlock, Sector};
use hashset::HashSet;

/// An error that can happen during a filesystem operation
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    /// There is not enough flash available to both guarantee mutability of the currently set data
    /// and add the requested data
    OutOfFlash,

    /// Trying to read a non-existing tag
    NoSuchTag,

    /// Tag has an invalid length (see [`File`] for more details)
    ///
    /// [`File`]: struct.File.html
    InvalidLengthForTag,

    /// A flash IO error occured during the requested operation
    IO(FlashIOError),
}

impl From<FlashIOError> for Error {
    fn from(e: FlashIOError) -> Error {
        Error::IO(e)
    }
}

/// A file on flash
///
/// File is considered a Borrow of its tag, for set hashing reasons
struct File<'a> {
    /// Tag this file can be referred as ("filename")
    tag: FlashBlock<'a>,

    /// Data contained in the file ("file contents")
    data: FlashBlock<'a>,

    /// Sector number on which the file is
    sector: SectorID,

    /// Total size of the file block
    size: usize,
}

/// Offset in the `sectors` array of a [`FileSystem`] (do not make a mistake between this one and
/// [`flash::SectorID`]!)
///
/// [`FileSystem`]: struct.FileSystem.html
/// [`flash::SectorID`]: ../flash/struct.SectorID.html
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SectorID(pub usize);

/// Persistent pseudo-hashmap on top of the flash
pub struct FileSystem<'a> {
    /// Reference towards the flash
    flash: &'a Flash,

    /// List of sectors to be used by the filesystem
    sectors: &'a [&'a Sector],

    /// Identifier of the sector reserved for defragmenting
    defragsector: SectorID,

    /// Identifier of the sector reserved for applets
    appletsector: SectorID,

    /// Set of the files found
    files: HashSet<File<'a>>,

    /// Pointers to the location of the first bytes to be put for new blocks on each sector
    next_blocks: Vec<usize>,

    /// Size of blocks that are actually useful on each sector
    valid_sizes: Vec<usize>,
}

/// Mask for the `validity` bits in a header block
const VALIDITY_MASK: u8 = 0b11000000;
/// Value for the `validity` bits in a header block when the block is not yet valid
const VALIDITY_NOTYET: u8 = 0b11000000;
/// Value for the `validity` bits in a header block when the block is now valid
const VALIDITY_VALID: u8 = 0b01000000;
/// Value for the `validity` bits in a header block when the block is no longer valid
const VALIDITY_NOLONGER: u8 = 0b00000000;
/// Mask for the `taglen` bits in a header block
const TAGLEN_MASK: u8 = 0b00111110;
/// Shift required for inputting the `taglen` value
const TAGLEN_SHIFT: u8 = 1;
/// Mask for the `lenlen` bits in a header block
const LENLEN_MASK: u8 = 0b00000001;
/// Value for the `lenlen` bits in a header block when the `len` field is 4 bytes long
const LENLEN_LONG: u8 = 0b00000001;
/// Value for the `lenlen` bits in a header block when the `len` field is 1 byte long
const LENLEN_SHORT: u8 = 0b00000000;

/// Number of buckets for the hashmap internally used by [`FileSystem`]
///
/// [`FileSystem`]: struct.FileSystem.html
const FS_FILES_BUCKETS: usize = 32;

/// CRC table for CRC-8.
///
/// This table could have been generated using `const fn`'s if these were more powerful.
/// As they are not, it has been generated using the following code (see [this
/// example](https://github.com/mkopa/rust-crc8/blob/master/src/lib.rs) for reference):
/// ```
/// fn init_crc_table() -> [u8; 256] {
///     let polynomial = 0xD5; // MSB representation for CRC-8
///     let msb = 0b10000000;
///     let mut t = msb;
///     let mut tmp;
///     let mut i = 1;
///     let mut idx;
///     let mut table: [u8; 256] = [0; 256];
///     while i < 256 {
///         tmp = if t & msb != 0 { polynomial } else { 0 };
///         t = (t << 1) ^ tmp;
///         for j in 0..i {
///             idx = (i + j) as u8;
///             table[idx as usize] = table[j as usize] ^ t;
///         }
///         i *= 2;
///     }
///     table
/// }
/// fn main() {
///     let table = init_crc_table();
///     println!("{:?}", &table[..]);
/// }
/// ```
const CRC_TABLE: [u8; 256] = [
    0, 213, 127, 170, 254, 43, 129, 84, 41, 252, 86, 131, 215, 2, 168, 125, 82, 135, 45, 248, 172,
    121, 211, 6, 123, 174, 4, 209, 133, 80, 250, 47, 164, 113, 219, 14, 90, 143, 37, 240, 141, 88,
    242, 39, 115, 166, 12, 217, 246, 35, 137, 92, 8, 221, 119, 162, 223, 10, 160, 117, 33, 244, 94,
    139, 157, 72, 226, 55, 99, 182, 28, 201, 180, 97, 203, 30, 74, 159, 53, 224, 207, 26, 176, 101,
    49, 228, 78, 155, 230, 51, 153, 76, 24, 205, 103, 178, 57, 236, 70, 147, 199, 18, 184, 109, 16,
    197, 111, 186, 238, 59, 145, 68, 107, 190, 20, 193, 149, 64, 234, 63, 66, 151, 61, 232, 188,
    105, 195, 22, 239, 58, 144, 69, 17, 196, 110, 187, 198, 19, 185, 108, 56, 237, 71, 146, 189,
    104, 194, 23, 67, 150, 60, 233, 148, 65, 235, 62, 106, 191, 21, 192, 75, 158, 52, 225, 181, 96,
    202, 31, 98, 183, 29, 200, 156, 73, 227, 54, 25, 204, 102, 179, 231, 50, 152, 77, 48, 229, 79,
    154, 206, 27, 177, 100, 114, 167, 13, 216, 140, 89, 243, 38, 91, 142, 36, 241, 165, 112, 218,
    15, 32, 245, 95, 138, 222, 11, 161, 116, 9, 220, 118, 163, 247, 34, 136, 93, 214, 3, 169, 124,
    40, 253, 87, 130, 255, 42, 128, 85, 1, 212, 126, 171, 132, 81, 251, 46, 122, 175, 5, 208, 173,
    120, 210, 7, 83, 134, 44, 249,
];

/// Computes the CRC-8 of the concatenation of `firstbyte` with `bytes`
///
/// The split between `firstbyte` and `bytes` can be useful as the first byte is a header and its
/// value is set to change at some positions without having to change the computed checksum)
fn crc8(firstbyte: u8, bytes: &[u8]) -> u8 {
    let mut crc = CRC_TABLE[firstbyte as usize];
    for b in bytes {
        crc = CRC_TABLE[(crc ^ b) as usize];
    }
    crc
}

/// An error that can occur during the initial parsing phase
#[derive(Debug, PartialEq, Eq)]
enum ParseNoBlock {
    /// An empty block was found (meaning "end of parsing")
    Empty,

    /// A broken block (ie. wrong checksum) has been found
    Broken,

    /// An erased block (ie. overwritten with 0's) has been found
    ///
    /// The parameter is the size of the erased block
    Erased(usize),
}

/// Parses a filesystem block starting at the beginning of the input-provided [`FlashBlock`].
///
/// It returns a tuple `(valid?, tag, data, size consumed)` on success, where `valid?` is true if
/// the returned block is a valid one, `tag` is the tag of the block, `data` is the data of the
/// block, and `size consumed` is the size of the block on flash.
///
/// See [the flash module documentation](index.html) for more details about the parsed block
/// format.
///
/// # Errors
///
/// It will error out if an empty or erased block was found, or if a broken block was found (ie.
/// invalid checksum, fs block extended past the end of `zone`, etc.)
///
/// [`FlashBlock`]: ../flash/struct.FlashBlock.html
#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
fn parse_hdr(zone: FlashBlock) -> Result<(bool, FlashBlock, FlashBlock, usize), ParseNoBlock> {
    let mut i = 0;

    // Parse header
    let hdr = *get!(zone.get(i).ok_or(ParseNoBlock::Broken));
    if hdr == 0xFF {
        return Err(ParseNoBlock::Empty);
    } else if hdr == 0x00 {
        let mut b = hdr;
        while b == 0x00 {
            i += 1;
            if let Some(&h) = zone.get(i) {
                b = h;
            } else {
                break;
            }
        }
        return Err(ParseNoBlock::Erased(i));
    }
    let valid = (hdr & VALIDITY_MASK) == VALIDITY_VALID;
    let taglen = ((hdr & TAGLEN_MASK) >> TAGLEN_SHIFT) as usize;
    let lenlen = if (hdr & LENLEN_MASK) == LENLEN_LONG {
        4
    } else {
        1
    };
    i += 1;

    // Parse length of data
    if i + lenlen >= zone.len() {
        return err!(ParseNoBlock::Broken);
    }
    let len = if lenlen == 1 {
        zone[i] as usize
    } else {
        // lenlen == 4
        ((zone[i] as usize) << 24)
            | ((zone[i + 1] as usize) << 16)
            | ((zone[i + 2] as usize) << 8)
            | (zone[i + 3] as usize)
    };
    i += lenlen;

    // Check tag, data and checksum lengths
    if i + taglen + len >= zone.len() {
        return err!(ParseNoBlock::Broken);
    }

    // Parse tag and data
    let tag = get!(zone.read(i, taglen).map_err(|_| ParseNoBlock::Broken));
    i += taglen;
    let data = get!(zone.read(i, len).map_err(|_| ParseNoBlock::Broken));
    i += len;

    // Parse and check checksum
    let cksum = *get!(zone.get(i).ok_or(ParseNoBlock::Broken));
    if cksum != crc8(hdr & !VALIDITY_MASK, &zone[1..i]) {
        debug!(
            "excepted: {} | computed: {}",
            cksum,
            crc8(hdr & !VALIDITY_MASK, &zone[1..i])
        );
        return err!(ParseNoBlock::Broken);
    }
    i += 1;

    // And be happy
    Ok((valid, tag, data, i))
}

/// Writes `0x00`'s up to the last non-`0xFF` byte of the sector, starting with `from`
fn erase_invalid_data(f: &Flash, s: &Sector, from: usize) -> Result<(), FlashIOError> {
    // Lock the block in writing immediately, to avoid TOCTOU
    get!(get!(s.with_writer(f, from, s.len() - from, |mut b| {
        let mut end = s.len() - from;
        while end > 0 && b[end - 1] == 0xFF {
            end -= 1;
        }
        b.zero_block(0, end)
    })));
    Ok(())
}

impl<'a> FileSystem<'a> {
    //! Tools to work with `SectorID`'s.
    //!
    //! Only here should `self.sectors`, `self.next_blocks` or `self.valid_sizes` ever be touched.

    /// Returns the sector at the requested SectorID
    ///
    /// # Panics
    ///
    /// Panics if `sid` is not a valid SectorID
    fn sector(&self, SectorID(sid): SectorID) -> &'a Sector {
        self.sectors[sid]
    }
    /// Returns a list of all available SectorID's
    fn sector_ids(&self) -> Vec<SectorID> {
        (0..self.sectors.len()).map(SectorID).collect()
    }
    /// Returns a pair of all (SectorID, Sector) available
    fn sectors_with_ids(&self) -> Vec<(SectorID, &Sector)> {
        self.sectors
            .iter()
            .enumerate()
            .map(|(x, &y)| (SectorID(x), y))
            .collect()
    }
    /// Returns a pointer to the next block for a requested SectorID
    ///
    /// # Panics
    ///
    /// Panics if `sid` is not a valid SectorID
    fn next_block(&self, SectorID(sid): SectorID) -> usize {
        self.next_blocks[sid]
    }
    /// Sets the pointer to the next block for a requested SectorID
    ///
    /// # Panics
    ///
    /// Panics if `sid` is not a valid SectorID
    fn set_next_block(&mut self, SectorID(sid): SectorID) -> &mut usize {
        &mut self.next_blocks[sid]
    }
    /// Returns the valid size for a requested SectorID
    ///
    /// # Panics
    ///
    /// Panics if `sid` is not a valid SectorID
    fn valid_size(&self, SectorID(sid): SectorID) -> usize {
        self.valid_sizes[sid]
    }
    /// Sets the valid size for a requested SectorID
    ///
    /// # Panics
    ///
    /// Panics if `sid` is not a valid SectorID
    fn set_valid_size(&mut self, SectorID(sid): SectorID) -> &mut usize {
        &mut self.valid_sizes[sid]
    }
}

impl<'a> FileSystem<'a> {
    //! Actual implementation of the `FileSystem` functions

    /// Dumps the current state of the filesystem instance onto the serial console
    #[allow(dead_code)]
    #[cfg(debug)]
    pub fn dump(&self) {
        debug!("FileSystem:");

        debug!("  Allocated sectors:");
        for (_id, _sector) in self.sectors_with_ids() {
            debug!("    {:x}:", _id.0);
            debug!("      Physical number: {:x}", _sector.num());
            debug!("      Next block: {:x}", self.next_block(_id));
            debug!("      Valid size: {:x}", self.valid_size(_id));
            if _id == self.defragsector {
                debug!("      This is the defrag sector");
            }
            if _id == self.appletsector {
                debug!("      This is the applet sector");
            }
        }

        debug!("  Files:");
        for _f in self.files.iter() {
            debug!("    {:?}:", &_f.tag);
            debug!("      Value: {:?}", &_f.data);
            debug!("      Sector: {}", _f.sector.0);
            debug!("      On-disk size: {}", _f.size);
        }
    }

    /// Initializes a filesystem with some allocated sector and dedicated defragmentation and
    /// applet sectors.
    ///
    /// This will trigger a parsing of all the allocated sectors.
    ///
    /// See [module-level documentation](index.html) for more details about the parsed format.
    ///
    /// # Panics
    ///
    /// Panics if `defragsector` is not a valid index inside the `sectors` array or if
    /// `appletsector` is not a valid index inside the `sectors` array
    ///
    /// # Errors
    ///
    /// Errors if a flash IO error occurs during the parsing
    pub fn new<'b>(
        flash: &'b Flash,
        sectors: &'b [&'b Sector],
        defragsector: SectorID,
        appletsector: SectorID,
    ) -> Result<FileSystem<'b>, Error> {
        debug!("Initializing fs subsystem");
        let mut files = HashSet::new(FS_FILES_BUCKETS);
        let mut next_block = vec![0; sectors.len()];
        let mut valid_size = vec![0; sectors.len()];
        'nextsector: for (id, &sector) in sectors.iter().enumerate() {
            debug!("  Scanning sector {}", sector.num());
            if SectorID(id) == defragsector {
                debug!("Skipping defrag sector");
                continue;
            }
            while next_block[id] < sector.len() {
                match parse_hdr(get!(
                    sector.read(next_block[id], sector.len() - next_block[id])
                )) {
                    Err(ParseNoBlock::Empty) => {
                        debug!("    Found empty block at {:x}", next_block[id]);
                        break;
                    }
                    Err(ParseNoBlock::Broken) => {
                        debug!("    Found broken block at {:x}, erasing", next_block[id]);
                        get!(erase_invalid_data(flash, sector, next_block[id]));
                        continue 'nextsector;
                    }
                    Err(ParseNoBlock::Erased(size)) => {
                        debug!(
                            "    Found erased block of size {:x} at {:x}",
                            size, next_block[id]
                        );
                        next_block[id] += size;
                    }
                    Ok((true, tag, data, size)) => {
                        debug!("    Found valid block at {:x}", next_block[id]);
                        // If there are multiple valid blocks, this means we
                        // have been interrupted between marking the new block
                        // as valid and marking the previous block as invalid.
                        // In this case, any of the two blocks can be considered
                        // as the right one, given that it's just supposed to be
                        // an atomic operation
                        // So, here we just take whichever comes first in the
                        // order of scanning, and mark the second one as being
                        // invalid
                        if !files.insert(File {
                            tag: tag,
                            data: data,
                            sector: SectorID(id),
                            size: size,
                        }) {
                            // The value was already found, marking this one as
                            // invalid
                            get!(get!(sector.with_writer(
                                flash,
                                next_block[id],
                                1,
                                |mut b| {
                                    let val = b[0] & (VALIDITY_NOLONGER | !VALIDITY_MASK);
                                    b.write(0, val)
                                }
                            )));
                        }
                        next_block[id] += size;
                        valid_size[id] += size;
                    }
                    Ok((false, _, _, size)) => {
                        next_block[id] += size;
                    }
                }
            }
        }

        debug!("Ends of sectors:");
        for (_id, &_e) in next_block.iter().enumerate() {
            debug!("  Sector {:x}: {:x}", _id, _e); // _-prefixed for not(debug) config
        }
        debug!("Initialized fs subsystem");
        let mut res = FileSystem {
            flash: flash,
            sectors: sectors,
            defragsector: defragsector,
            appletsector: appletsector,
            files: files,
            next_blocks: next_block,
            valid_sizes: valid_size,
        };

        res.finish_defragmentation()?;

        Ok(res)
    }

    /// Checks whether a given tag is present on the file system
    pub fn has_tag(&self, tag: &[u8]) -> bool {
        self.files.get(tag).is_some()
    }

    fn is_available(&self, sector: SectorID, size: usize, tag: &[u8]) -> bool {
        // If there is enough space on the sector
        self.next_block(sector) + size <= self.sector(sector).len()
        // And adding the file wouldn't make it go over the defragmentable size
        && {
            let defragsize = self.sector(self.defragsector).len() - 1;
            let next_valid_size =
                self.valid_size(sector)
              + size
              - if let Some(f) = self.files.get(tag) {
                    if f.sector == sector { f.size }
                    else { 0 }
                } else {
                    0
                };
            next_valid_size <= defragsize
        }
    }

    /// Returns an available sector for a given tag and size of the total block
    ///
    /// Tag is required for defragmentability reasons: no sector may exceed in valid size the size
    /// of the defrag sector, and the old tag will be marked as invalid, so knowing the tag to be
    /// written allows to store potentially more data in a sector
    ///
    /// # Errors
    ///
    /// Errors if there is not enough space available on any sector
    fn available_sector(&self, size: usize, tag: &[u8]) -> Result<SectorID, Error> {
        for id in self.sector_ids() {
            // Don't put anything in the defrag or applet sector
            if id == self.defragsector || id == self.appletsector {
                continue;
            }
            // Check there is enough space on the sector
            if self.is_available(id, size, tag) {
                return Ok(id);
            }
        }
        err!(Error::OutOfFlash)
    }

    fn finish_defragmentation(&mut self) -> Result<(), Error> {
        let defragsector = self.defragsector;
        let defragsect = self.sector(defragsector);

        // Figure out which sector is supposed to be defragmented
        let sector_id = SectorID(defragsect.read(defragsect.len() - 1, 1)?[0] as usize);
        if sector_id == SectorID(0xFF) {
            // No defragmentation was running
            return Ok(());
        }

        // Copy all valid blocks to defrag sector
        debug!("Defragmenting sector {}", sector_id.0);
        let sector = self.sector(sector_id);
        let mut ptr = 0;
        while ptr < sector.len() {
            match parse_hdr(get!(sector.read(ptr, sector.len() - ptr))) {
                Err(ParseNoBlock::Empty) => {
                    break;
                }
                Err(ParseNoBlock::Broken) => {
                    return Ok(());
                } // should not happen
                Err(ParseNoBlock::Erased(size)) => {
                    ptr += size;
                }
                Ok((false, _, _, size)) => {
                    ptr += size;
                }
                Ok((true, tag, data, size)) => {
                    get!(self.write_impl(&tag, &[&data], defragsector));
                    ptr += size;
                }
            }
        }

        // Erase sector
        debug!("  Erasing sector");
        get!(self.sector(sector_id).erase(self.flash));
        *self.set_next_block(sector_id) = 0;
        *self.set_valid_size(sector_id) = 0;

        // Copy all blocks back from defrag sector to previous sector
        debug!("  Copying all blocks back to previous sector");
        ptr = 0;
        while ptr < defragsect.len() - 1 {
            match parse_hdr(get!(defragsect.read(ptr, defragsect.len() - 1 - ptr))) {
                Ok((true, tag, data, size)) => {
                    get!(self.write_impl(&tag, &[&data], sector_id));
                    ptr += size;
                }
                Err(ParseNoBlock::Empty) => {
                    break;
                }
                // All these should not happen
                Err(ParseNoBlock::Broken) => {
                    return Ok(());
                }
                Err(ParseNoBlock::Erased(size)) => {
                    ptr += size;
                }
                Ok((false, _, _, size)) => {
                    ptr += size;
                }
            }
        }

        // Erase defrag sector
        debug!("  Erasing defrag sector");
        get!(self.sector(defragsector).erase(self.flash));
        *self.set_next_block(defragsector) = 0;
        *self.set_valid_size(defragsector) = 0;
        debug!("  Done");
        Ok(())
    }

    /// Defragments a sector by using the defragmentation sector
    ///
    /// # Errors
    ///
    /// Errors if there is a flash IO error during the defragmentation
    fn defragment(&mut self, sector_id: SectorID) -> Result<(), Error> {
        let sect = self.sector(self.defragsector);
        get!(get!(sect.with_writer(
            self.flash,
            sect.len() - 1,
            1,
            |mut b| -> Result<(), FlashIOError> {
                get!(b.write(0, sector_id.0 as u8));
                Ok(())
            }
        )));
        self.finish_defragmentation()
    }

    /// Writes a tag-data association on a given sector
    ///
    /// # Errors
    ///
    /// Errors if `tag` has an invalid length (see [module-level documentation](index.html) for
    /// details of valid lengths), if there is not enough free space on the sector, or if a flash
    /// IO error occurs during the defragmentation
    fn write_impl(&mut self, tag: &[u8], data: &[&[u8]], sector_id: SectorID) -> Result<(), Error> {
        if tag.is_empty() || tag.len() >= ((TAGLEN_MASK >> TAGLEN_SHIFT) - 1) as usize {
            return err!(Error::InvalidLengthForTag);
        }

        // Compute metadata for later usage
        let datalen = data.iter().map(|x| x.len()).sum();
        let block_len = self.block_len(tag.len(), datalen);
        let lenlen = if datalen <= 0xFF { 1 } else { 4 };
        let sector_len =
            self.sector(sector_id).len() - if sector_id == self.defragsector { 1 } else { 0 };

        // Check the sector asked for does have enough free space
        // No need to check for defragmentability as this is done by .available_sector(), doing so
        // would prevent using it from the defragment function
        if sector_len - self.next_block(sector_id) < block_len {
            return err!(Error::OutOfFlash);
        }

        // Write the block
        get!(get!(self.sector(sector_id).with_writer(
            self.flash,
            self.next_block(sector_id),
            block_len,
            |mut b| -> Result<(), FlashIOError> {
                // Write the header
                let mut i = 0;
                if lenlen == 1 {
                    get!(b.write(
                        i,
                        VALIDITY_NOTYET | (tag.len() << TAGLEN_SHIFT) as u8 | LENLEN_SHORT
                    ));
                    get!(b.write(i + 1, datalen as u8));
                    i += 2;
                } else {
                    get!(b.write(
                        i,
                        VALIDITY_NOTYET | (tag.len() << TAGLEN_SHIFT) as u8 | LENLEN_LONG
                    ));
                    get!(b.write_block(
                        i + 1,
                        &[
                            (datalen >> 24) as u8,
                            (datalen >> 16) as u8,
                            (datalen >> 8) as u8,
                            datalen as u8
                        ]
                    ));
                    i += 5;
                }

                // Then the tag and the data
                debug!(
                    "About to write tag of length {} to index {} of block with len {}",
                    tag.len(),
                    i,
                    b.len()
                );
                get!(b.write_block(i, tag));
                i += tag.len();
                for d in data {
                    get!(b.write_block(i, d));
                    i += d.len();
                }

                // The footer
                let crc = crc8(b[0] & !VALIDITY_MASK, &b[1..i]);
                get!(b.write(i, crc));

                // And finally, mark the block as valid, now that it's completely written
                let header = b[0];
                get!(b.write(0, header & (VALIDITY_VALID | !VALIDITY_MASK)));

                Ok(())
            }
        )));

        // Remove previous file from hashmap and mark it as invalid
        match self.erase(tag) {
            Ok(()) | Err(Error::NoSuchTag) => (),
            Err(e) => err!(e)?,
        }

        // Update the link to the file in hashmap
        let sector = self.sector(sector_id);
        let new_tag = get!(sector.read(self.next_block(sector_id) + 1 + lenlen, tag.len()));
        let new_data =
            get!(sector.read(self.next_block(sector_id) + 1 + lenlen + tag.len(), datalen));
        self.files.insert(File {
            tag: new_tag,
            data: new_data,
            sector: sector_id,
            size: block_len,
        });

        // Advance next_block pointer
        *self.set_next_block(sector_id) += block_len;
        *self.set_valid_size(sector_id) += block_len;

        Ok(())
    }

    /// Length of a block with a given tag and data
    fn block_len(&self, taglen: usize, datalen: usize) -> usize {
        2 + // Header & checksum
        if datalen > 0xFF { 4 } else { 1 } + // Length of data field
        taglen + datalen
    }

    /// Write a tag-data association to the file system
    ///
    /// Automatically finds a sector with enough free space for holding the block.
    ///
    /// # Errors
    ///
    /// Errors if not enough space can be gathered or if a flash IO error occurs during writing
    pub fn write(&mut self, tag: &[u8], data: &[u8]) -> Result<(), Error> {
        // Find sector on which to put the block
        let mut sector_id = self.available_sector(self.block_len(tag.len(), data.len()), tag);
        if sector_id.is_err() {
            // If none is available yet, defragment what we need to before
            // continuing
            let mut sectors_to_defragment: Vec<SectorID> = self
                .sector_ids()
                .into_iter()
                .filter(|&x| {
                    x != self.defragsector // Don't defragment defrag sector
                          && x != self.appletsector // Nor applet sector
                          && self.next_block(x) != self.valid_size(x)
                })
                .collect();
            // Sort sectors with least-prioritized-for-defrag first
            sectors_to_defragment.sort_by_key(|&id| {
                if self.valid_size(id) == 0 {
                    usize::MAX
                } else {
                    (1 << 15) * self.next_block(id) / self.valid_size(id)
                }
            });
            // Try to find an available sector while defragmenting
            for &x in sectors_to_defragment.iter().rev() {
                get!(self.defragment(x));
                sector_id = self.available_sector(self.block_len(tag.len(), data.len()), tag);
                if sector_id.is_ok() {
                    break;
                }
            }
        }
        // And put it in
        get!(self.write_impl(tag, &[data], get!(sector_id)));
        Ok(())
    }

    /// Writes a tag-data association to the applet sector
    pub fn write_applet(&mut self, tag: &[u8], data: &[u8]) -> Result<(), Error> {
        let appletsector = self.appletsector;
        if self.is_available(appletsector, self.block_len(tag.len(), data.len()), tag) {
            self.write_impl(tag, &[data], appletsector)
        } else {
            get!(self.defragment(appletsector));
            if self.is_available(appletsector, self.block_len(tag.len(), data.len()), tag) {
                self.write_impl(tag, &[data], appletsector)
            } else {
                Err(Error::OutOfFlash)
            }
        }
    }

    /// Replaces the bytes at some offset of the file. Note that if `offset + data.len()` is above
    /// the size of the file, the result will not be extended past the original length without
    /// raising any error.
    pub fn edit_at(&mut self, tag: &[u8], offset: usize, data: &[u8]) -> Result<(), Error> {
        let current_file = self.files.take(tag).ok_or(Error::NoSuchTag)?;
        let current_sector = current_file.sector;
        if self.is_available(
            current_sector,
            self.block_len(tag.len(), current_file.data.len()),
            tag,
        ) {
            get!(self.write_impl(
                tag,
                &[
                    &current_file.data[..offset],
                    data,
                    &current_file.data[offset + data.len()..]
                ],
                current_sector
            ));
            get!(self.erase_file(current_file));
            Ok(())
        } else {
            let defragsector = self.defragsector;
            get!(self.write_impl(
                tag,
                &[
                    &current_file.data[..offset],
                    data,
                    &current_file.data[offset + data.len()..]
                ],
                defragsector
            ));
            get!(self.erase_file(current_file));
            get!(self.defragment(current_sector));
            Ok(())
        }
    }

    /// Retrieves data associated to a tag
    ///
    /// # Errors
    ///
    /// Errors if the tag does not exist in the filesystem
    pub fn read(&self, tag: &[u8]) -> Result<FlashBlock<'a>, Error> {
        self.files
            .get(tag)
            .map_or(Err(Error::NoSuchTag), |v| Ok(v.data.clone()))
    }

    fn erase_file(&mut self, f: File) -> Result<(), Error> {
        *self.set_valid_size(f.sector) -= f.size;
        let hdrpos = f.tag.start() - if f.data.len() <= 0xFF { 1 } else { 4 } - 1;
        get!(get!(f.tag.sector().with_writer(
            self.flash,
            hdrpos,
            1,
            |mut b| -> Result<(), FlashIOError> {
                let val = b[0] & (VALIDITY_NOLONGER | !VALIDITY_MASK);
                b.write(0, val)
            }
        )));
        Ok(())
    }

    /// Removes the file associated to a tag
    pub fn erase(&mut self, tag: &[u8]) -> Result<(), Error> {
        // Remove file from hashmap and mark it as invalid
        let f = self.files.take(tag).ok_or(Error::NoSuchTag)?;
        self.erase_file(f)
    }
}

// Yes this is counter-intuitive, see comment on struct File
impl<'a> Borrow<[u8]> for File<'a> {
    fn borrow(&self) -> &[u8] {
        &self.tag
    }
}

impl<'a> Hash for File<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tag.hash(state);
    }
}

impl<'a> PartialEq for File<'a> {
    fn eq(&self, o: &File<'a>) -> bool {
        &self.tag as &[u8] == &o.tag as &[u8]
    }
}
