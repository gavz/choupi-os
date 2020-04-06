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

#ifndef FFI_H_INCLUDED
#define FFI_H_INCLUDED 1

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdint.h>

void setup_argbuf();
void set_argbuf(uint8_t const *data, uint32_t len);
void get_argbuf(uint8_t *ret, uint32_t len);
uint32_t remote_call(uint32_t ctx_id, uint32_t arg1, uint32_t arg2);

extern uint32_t flash_error;

uint8_t *flash_pointer();
void flash_write(uint8_t sector, uint32_t index, uint8_t value);
uint8_t flash_read(uint8_t sector, uint32_t index);
void flash_erase(uint8_t sector);
void flash_erase0(uint8_t sector);

uint8_t fs_init();
uint8_t fs_write(uint8_t const *tag, uint8_t taglen, uint8_t const *data,
                 uint32_t datalen);
// Despite returning `uint8_t`, fs_write_applet never returns but reboots the
// card
void fs_write_applet(uint8_t const *tag, uint8_t taglen, uint8_t const *data,
                     uint32_t datalen);
uint8_t fs_erase(uint8_t const *tag, uint8_t taglen);
void fs_erase_applet(uint8_t const *tag, uint8_t taglen);
uint8_t fs_exists(uint8_t const *tag, uint8_t taglen);
uint8_t fs_read_inplace(uint8_t const *tag, uint8_t taglen,
                        uint8_t const **dataret, uint32_t *datalenret);
uint8_t fs_read(uint8_t const *tag, uint8_t taglen, uint8_t *dataret,
                uint32_t datalen);
uint8_t fs_read_1b_at(uint8_t const *tag, uint8_t taglen, uint32_t offset,
                      uint8_t *res);
uint8_t fs_read_2b_at(uint8_t const *tag, uint8_t taglen, uint32_t offset,
                      uint16_t *res);
uint8_t fs_read_4b_at(uint8_t const *tag, uint8_t taglen, uint32_t offset,
                      uint32_t *res);
uint8_t fs_write_1b_at(uint8_t const *tag, uint8_t taglen, uint32_t offset,
                       uint8_t data);
uint8_t fs_write_2b_at(uint8_t const *tag, uint8_t taglen, uint32_t offset,
                       uint16_t data);
uint8_t fs_write_4b_at(uint8_t const *tag, uint8_t taglen, uint32_t offset,
                       uint32_t data);
uint8_t fs_length(uint8_t const *tag, uint8_t taglen, uint32_t *res);
void fs_drop();

// All `tagret` arguments point to the beginning of a 32-byte buffer
void path_package_list(uint8_t (*tagret)[32], uint8_t *lenret);
void path_cap(uint8_t pkg, uint8_t (*tagret)[32], uint8_t *lenret);
void path_static(uint8_t pkg, uint8_t static_id, uint8_t (*tagret)[32],
                 uint8_t *lenret);
void path_applet_field(uint8_t applet, uint8_t pkg, uint8_t claz, uint8_t field,
                       uint8_t (*tagret)[32], uint8_t *lenret);

void run_emulator();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* FFI_H_INCLUDED */
