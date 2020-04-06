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

speculate! {
    describe "custom_hasher" {
        it "should not collide too much" {
            assert!(!(hash(&0) == hash("hello world") && hash(&0) == hash(&vec![42])),
            "Hashes of three pseudo-random values should not collide!");
        }
    }

    #[derive(Debug, Clone)]
    struct PartiallyHashed {
        key: String,
        value: String,
    }

    impl Borrow<str> for PartiallyHashed {
        fn borrow(&self) -> &str {
            &self.key
        }
    }

    impl Hash for PartiallyHashed {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.key.hash(state);
        }
    }

    impl PartialEq for PartiallyHashed {
        fn eq(&self, o: &PartiallyHashed) -> bool {
            self.key == o.key
        }
    }

    describe "hash_set" {
        before {
            let mut testset: HashSet<PartiallyHashed> = HashSet::new(32);
            let a = PartiallyHashed { key: "a".to_string(), value: "a".to_string() };
            let b = PartiallyHashed { key: "b".to_string(), value: "b".to_string() };
            let c = PartiallyHashed { key: "c".to_string(), value: "c".to_string() };
            let d = PartiallyHashed { key: "d".to_string(), value: "d".to_string() };
            assert!(testset.insert(a.clone()));
            assert!(testset.insert(b.clone()));
            assert!(testset.insert(c.clone()));
            assert!(testset.insert(d.clone()));
            let hello1 = PartiallyHashed { key: "hello".to_string(), value: "value1".to_string() };
            let hello2 = PartiallyHashed { key: "hello".to_string(), value: "value2".to_string() };
        }

        #[should_panic]
        it "should fail when initialized without any bucket" {
             let _: HashSet<String> = HashSet::new(0);
        }

        it "should not return a value when not existing" {
            assert_eq!(testset.get("test"), None);
        }

        it "should correctly insert" {
            assert_eq!(testset.get("hello"), None);
            assert_eq!(testset.get("world"), None);
            assert!(testset.insert(hello1.clone()));
            assert_eq!(testset.get("hello"), Some(&hello1));
            assert_eq!(testset.get("world"), None);
            assert!(!testset.insert(hello2.clone()));
            assert_eq!(testset.get("hello"), Some(&hello1));
            assert_eq!(testset.get("world"), None);
        }

        it "should correctly remove items" {
            assert_eq!(testset.get("a"), Some(&a));
            assert!(testset.remove(&a));
            assert_eq!(testset.get("a"), None);
            assert!(!testset.remove(&a));
            assert_eq!(testset.get("a"), None);
        }

        it "should correctly take items" {
            assert_eq!(testset.get("a"), Some(&a));
            assert_eq!(testset.take("a"), Some(a));
            assert_eq!(testset.get("a"), None);
            assert_eq!(testset.take("a"), None);
            assert_eq!(testset.get("a"), None);
        }

        it "should correctly iterate" {
            let mut a_ok = false;
            let mut b_ok = false;
            let mut c_ok = false;
            let mut d_ok = false;
            for x in testset.iter() {
                println!("{:?}", x);
                if x.key == "a" { assert!(!a_ok); a_ok = true; }
                else if x.key == "b" { assert!(!b_ok); b_ok = true; }
                else if x.key == "c" { assert!(!c_ok); c_ok = true; }
                else if x.key == "d" { assert!(!d_ok); d_ok = true; }
                else { panic!("unexpected key"); }
            }
            assert!(a_ok && b_ok && c_ok && d_ok);
        }
    }
}
