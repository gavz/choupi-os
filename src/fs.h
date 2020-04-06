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

#ifndef FS_H_INCLUDED
#define FS_H_INCLUDED 1

#include "ffi.h"

namespace fs {

struct Tag {
  uint8_t len;
  uint8_t tag[32];
};

class FsBlock {
private:
  uint8_t *data;
  uint32_t len;

public:
  FsBlock(uint8_t *d, uint32_t l) : data(d), len(l) {}
  ~FsBlock() {
    if (data)
      fs_free(data, len);
  }

  uint8_t const *ptr() const { return data; }
  uint8_t *ptr() { return data; }

  bool valid() const { return data != 0; }
};

class FileSystem {
public:
  FileSystem() { fs_init(); }
  ~FileSystem() { fs_drop(); }

  bool write(Tag const &tag, uint8_t const *data, uint32_t datalen) {
    return !fs_write(&tag.tag[0], tag.len, data, datalen);
  }

  bool exists(Tag const &tag) { return fs_exists(&tag.tag[0], tag.len); }

  FsBlock read(Tag const &tag) {
    uint8_t *data;
    uint32_t len;
    if (fs_read(&tag.tag[0], tag.len, &data, &len)) {
      data = 0;
      len = 0;
    }
    return FsBlock(data, len);
  }
};
} // namespace fs
#endif
