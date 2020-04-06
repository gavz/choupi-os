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

use context::ContextID;
use contextnum::ContextNumber;

#[repr(u8)]
enum FileType {
    PkgList = 0x00,
    Cap = 0x01,
    Static = 0x02,
    AppletField = 0x03,
}

pub fn can_read(context: ContextID, tag: &[u8]) -> bool {
    match tag[0] {
        x if x == FileType::PkgList as u8 => true,
        x if x == FileType::Cap as u8 => true,
        x if x == FileType::Static as u8 => true,
        x if x == FileType::AppletField as u8 => tag[1] == context.id() as u8,
        _ => false,
    }
}

pub fn can_write(context: ContextID, tag: &[u8]) -> bool {
    match tag[0] {
        x if x == FileType::PkgList as u8 => {
            (
                /* context.id() == ContextNumber::RuntimeEnvironment as usize // TODO: remove after tests
                || */
                context.id() == ContextNumber::Installer as usize
            ) && tag.len() == 1
        }
        x if x == FileType::Cap as u8 => {
            (
                /* context.id() == ContextNumber::RuntimeEnvironment as usize // TODO: remove after tests
                ||*/
                context.id() == ContextNumber::Installer as usize
            ) && tag.len() == 2
        }
        x if x == FileType::Static as u8 => tag.len() == 3,
        x if x == FileType::AppletField as u8 => tag[1] == context.id() as u8 && tag.len() == 5,
        _ => false,
    }
}

pub fn is_applet(tag: &[u8]) -> bool {
    tag.len() == 2 && tag[0] == FileType::Cap as u8
}

pub fn package_list(tagret: &mut [u8; 32], lenret: &mut u8) {
    tagret[0] = FileType::PkgList as u8;
    *lenret = 1;
}

pub fn cap(pkg: u8, tagret: &mut [u8; 32], lenret: &mut u8) {
    tagret[0] = FileType::Cap as u8;
    tagret[1] = pkg;
    *lenret = 2;
}

pub fn static_field(pkg: u8, static_id: u8, tagret: &mut [u8; 32], lenret: &mut u8) {
    tagret[0] = FileType::Static as u8;
    tagret[1] = pkg;
    tagret[2] = static_id;
    *lenret = 3;
}

pub fn applet_field(
    applet: u8,
    pkg: u8,
    claz: u8,
    field: u8,
    tagret: &mut [u8; 32],
    lenret: &mut u8,
) {
    tagret[0] = FileType::AppletField as u8;
    tagret[1] = applet;
    tagret[2] = pkg;
    tagret[3] = claz;
    tagret[4] = field;
    *lenret = 5;
}
