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

//! Implementation of the methods of a `BTreeSet` required for the rest of the program.
//!
//! The aim is to have something low-weight on the flash, even though it may not be the fastest
//! running set implementation.

mod tests;

use alloc::vec::Vec;
use core::borrow::Borrow;
use core::hash::{Hash, Hasher};

/// Hash set
#[derive(Debug)]
pub struct HashSet<T: Hash> {
    /// Vector of buckets, each bucket containing a vector of actual data
    data: Vec<Vec<T>>,
}

/// Iterator over a `HashSet`
pub struct Iter<'a, T: 'a>
where
    T: Hash,
{
    /// Reference to the HashSet
    set: &'a HashSet<T>,

    /// Number of the bucket for the next element to return
    bucket: usize,

    /// Index inside the bucket for the next element to return
    ptr: usize,
}

/// Custom hasher
///
/// This does not actually implement the full Hasher interface in a meaningful way, as it is made
/// to be used exclusively from this `HashSet` module: the `finish` function should not be used.
struct CustomHasher {
    /// Current state
    state: usize,
}
impl Hasher for CustomHasher {
    /// Always return 0
    ///
    /// The real return value should be fetched directly from the `state` member, in order to avoid
    /// conversion to/from u64 on this 32-bit platform
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.state = self
                .state
                .overflowing_mul(101)
                .0
                .overflowing_add(b as usize)
                .0;
        }
    }

    // Adding this function gets a ~1/3 performance boost during tests
    fn write_usize(&mut self, i: usize) {
        self.state = self
            .state
            .overflowing_mul(101)
            .0
            .overflowing_add(i as usize)
            .0;
    }
}

/// Hash an object with a [`CustomHasher`](struct.CustomHasher.html)
fn hash<T: Hash + PartialEq + ?Sized>(t: &T) -> usize {
    let mut s = CustomHasher { state: 0 };
    t.hash(&mut s);
    s.state
}

impl<T> HashSet<T>
where
    T: Hash + PartialEq,
{
    /// Creates a new HashSet.
    ///
    /// For code size minimization, the number of buckets given here will not automatically evolve,
    /// even if the hashset becomes overloaded.
    pub fn new(buckets: usize) -> HashSet<T> {
        assert_ne!(buckets, 0, "Cannot initialize a hash set with no buckets");
        HashSet {
            data: (0..buckets).map(|_| Vec::new()).collect(),
        }
    }

    /// Returns an iterator over references to the elements of the set
    pub fn iter(&self) -> Iter<T> {
        Iter {
            set: self,
            bucket: 0,
            ptr: 0,
        }
    }

    /// Returns a reference to the item in the set that is equal to the parameter, if one exists
    pub fn get<Q: Hash + PartialEq + ?Sized>(&self, val: &Q) -> Option<&T>
    where
        T: Borrow<Q>,
    {
        self.data[hash(val) % self.data.len()]
            .iter()
            .find(|&x| x.borrow() == val)
    }

    /// Inserts a value in the set
    ///
    /// Returns false if another value evaluating equal to it already is in the set, in which case
    /// the value will not be updated.
    pub fn insert(&mut self, val: T) -> bool {
        let h = hash(&val) % self.data.len();
        if self.data[h].iter().any(|x| x == &val) {
            false
        } else {
            self.data[h].push(val);
            true
        }
    }

    /// Removes a value from the set
    ///
    /// Returns true if a value was actually removed
    pub fn remove(&mut self, val: &T) -> bool {
        self.take(val).is_some()
    }

    /// Removes a value from the set, and return it by move, if possible
    pub fn take<Q: Hash + PartialEq + ?Sized>(&mut self, val: &Q) -> Option<T>
    where
        T: Borrow<Q>,
    {
        let h = hash(val) % self.data.len();
        if let Some(i) = self.data[h].iter().position(|x| x.borrow() == val) {
            Some(self.data[h].swap_remove(i))
        } else {
            None
        }
    }
}

impl<'a, T> Iterator for Iter<'a, T>
where
    T: Hash,
{
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        if self.bucket >= self.set.data.len() {
            None
        } else if self.ptr >= self.set.data[self.bucket].len() {
            self.ptr = 0;
            self.bucket += 1;
            self.next()
        } else {
            self.ptr += 1;
            Some(&self.set.data[self.bucket][self.ptr - 1])
        }
    }
}
