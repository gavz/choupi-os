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

// Compile with:
//  make host-build && \
//  gcc -std=c++11 src/example_host.cpp -Ltarget/debug -ljavacard_os -lutil -ldl
//  -lrt -lpthread -lgcc_s -lc -lm -lrt -lpthread -lutil

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ffi.h"
#include "fs.h"

int main() {
  setvbuf(stdout, 0, _IONBF, 0); // Disable buffering on stdout
  printf("Initializing flash...");
  flash_init();
  printf(" done\n");

  printf("Presetting flash...");
  memcpy(flash_pointer() + 0x4000, "\x48\x06testvalue\0\x23", 13);
  printf(" done\n");

  fs::Tag test{4, "test"}, test2{5, "test2"};

  {
    printf("Initializing FS...");
    fs::FileSystem fs;
    printf(" done\n");

    {
      fs::FsBlock data0 = fs.read(test);
      if (!data0.valid()) {
        printf("/!\\ Unable to read data\n");
        return 1;
      }
      printf(
          "Tag 'test' has '%s' as a value\n",
          data0
              .ptr()); // Knowing data is 0-terminated thanks to previous memcpy
      printf("Freeing read data...");
    }
    printf(" done\n");
    printf("Tag 'test2' %s\n", fs.exists(test2) ? "exists" : "does not exist");
    if (!fs.write(test, (uint8_t const *)"something", 10)) {
      printf("/!\\ Unable to write data\n");
      return 1;
    }
    {
      fs::FsBlock data1 = fs.read(test);
      if (!data1.valid()) {
        printf("/!\\ Unable to read data\n");
        return 1;
      }
      printf("Tag 'test' now has '%s' as a value\n",
             data1.ptr()); // Knowing data is 0-terminated thanks to previous
                           // fs_write
      printf("Freeing read data...");
    }
    printf(" done\n");
    printf("Dropping FS...");
  }
  printf(" done\n");

  {
    printf("Reinitializing FS...");
    fs::FileSystem fs;
    printf(" done\n");
    printf("Tag 'test' %s\n",
           fs.exists(test) ? "now exists" : "still doesn't exist");
    {
      fs::FsBlock data2 = fs.read(test);
      if (!data2.valid()) {
        printf("/!\\ Unable to read data\n");
        return 1;
      }
      printf("Tag 'test' now has '%s' as a value\n", data2.ptr());
      printf("Freeing read data...");
    }
    printf(" done\n");
    printf("Dropping FS...");
  }
  printf(" done\n");
}
