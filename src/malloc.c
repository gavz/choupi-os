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

#include <stdint.h>
#include <stdlib.h>

void _write(int, char *, int);

void *__real__malloc_r(struct _reent *r, size_t size);
void *__real__free_r(struct _reent *r, void *x);
void *__real__calloc_r(struct _reent *r, size_t a, size_t b);
void *__real__realloc_r(struct _reent *r, void *x, size_t size);

void *rust_allocate(size_t size, size_t align);
void *rust_allocate_zeroed(size_t size, size_t align);
void rust_deallocate(void *ptr, size_t size, size_t align);
void *rust_reallocate(void *ptr, size_t old_size, size_t size, size_t align);

// See newlib's mallocr.c "Vital statistics"
#define ALIGNMENT 8

#define UNUSED(x) (void)x

void *__wrap__malloc_r(struct _reent *r, size_t size) {
  UNUSED(r);
  _write(2, "Using custom malloc!\r\n", 22);
  uint8_t *res = rust_allocate(size + sizeof(size_t), ALIGNMENT);
  *(size_t *)res = size;
  return res + sizeof(size_t);
}

void __wrap__free_r(struct _reent *r, void *x) {
  UNUSED(r);
  _write(2, "Using custom free!\r\n", 20);
  uint8_t *ptr = x - sizeof(size_t);
  size_t size = *(size_t *)ptr;
  rust_deallocate(ptr, size, ALIGNMENT);
}

void *__wrap__calloc_r(struct _reent *r, size_t a, size_t b) {
  UNUSED(r);
  _write(2, "Using custom calloc!\r\n", 22);
  size_t size = a * b;
  uint8_t *res = rust_allocate_zeroed(size + sizeof(size_t), ALIGNMENT);
  *(size_t *)res = size;
  return res + sizeof(size_t);
}

void *__wrap__realloc_r(struct _reent *r, void *x, size_t size) {
  UNUSED(r);
  _write(2, "Using custom realloc!\r\n", 23);
  uint8_t *ptr = x - sizeof(size_t);
  size_t old_size = *(size_t *)ptr;
  uint8_t *res =
      rust_reallocate(ptr, old_size, size + sizeof(size_t), ALIGNMENT);
  *(size_t *)res = size;
  return res;
}
