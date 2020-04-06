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

#include "stm32f4xx.h"
#include <errno.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/unistd.h>

#ifndef STDOUT_USART
#define STDOUT_USART 2
#endif

#ifndef STDERR_USART
#define STDERR_USART 2
#endif

#ifndef STDIN_USART
#define STDIN_USART 2
#endif

#define UNUSED __attribute__((unused))

#undef errno
extern int errno;

/*
 environ
 A pointer to a list of environment variables and their values.
 For a minimal environment, this empty list is adequate:
 */
char *__env[1] = {0};
char **environ = __env;

int _write(int file, char *ptr, int len);

void _exit(UNUSED int status) {
  _write(1, "exit", 4);
  while (1) {
    ;
  }
}

int _close(UNUSED int file) { return -1; }
/*
 execve
 Transfer control to a new process. Minimal implementation (for a system without
 processes):
 */
int _execve(UNUSED char *name, UNUSED char **argv, UNUSED char **env) {
  errno = ENOMEM;
  return -1;
}
/*
 fork
 Create a new process. Minimal implementation (for a system without processes):
 */

int _fork() {
  errno = EAGAIN;
  return -1;
}
/*
 fstat
 Status of an open file. For consistency with other minimal implementations in
 these examples, all files are regarded as character special devices. The
 `sys/stat.h' header file required is distributed in the `include' subdirectory
 for this C library.
 */
int _fstat(UNUSED int file, struct stat *st) {
  st->st_mode = S_IFCHR;
  return 0;
}

/*
 getpid
 Process-ID; this is sometimes used to generate strings unlikely to conflict
 with other processes. Minimal implementation, for a system without processes:
 */

int _getpid() { return 1; }

/*
 isatty
 Query whether output stream is a terminal. For consistency with the other
 minimal implementations,
 */
int _isatty(int file) {
  switch (file) {
  case STDOUT_FILENO:
  case STDERR_FILENO:
  case STDIN_FILENO:
    return 1;
  default:
    // errno = ENOTTY;
    errno = EBADF;
    return 0;
  }
}

/*
 kill
 Send a signal. Minimal implementation:
 */
int _kill(UNUSED int pid, UNUSED int sig) {
  errno = EINVAL;
  return (-1);
}

/*
 link
 Establish a new name for an existing file. Minimal implementation:
 */

int _link(UNUSED char *old, UNUSED char *new) {
  errno = EMLINK;
  return -1;
}

/*
 lseek
 Set position in a file. Minimal implementation:
 */
int _lseek(UNUSED int file, UNUSED int ptr, UNUSED int dir) { return 0; }

/*
 sbrk
 Increase program data space.
 Malloc and related functions depend on this
 */
extern void Error_Handler();
caddr_t _sbrk(int incr) {
  extern char heap_begin, heap_end; // Defined by the linker
  static char *cur_heap_end;
  char *prev_heap_end;

  if (cur_heap_end == 0) {
    cur_heap_end = &heap_begin;
  }
  prev_heap_end = cur_heap_end;

  if (cur_heap_end + incr > &heap_end) {
    _write(STDERR_FILENO, "Heap overflow\r\n", 15);
    Error_Handler();
    errno = ENOMEM;
    return (caddr_t)-1;
  }

  cur_heap_end += incr;
  return (caddr_t)prev_heap_end;
}

/*
 read
 Read a character to a file. `libc' subroutines will use this system routine for
 input from all files, including stdin Returns -1 on error or blocks until the
 number of characters have been read.
 */
// See src/main.c

/*
 stat
 Status of a file (by name). Minimal implementation:
 int    _EXFUN(stat,( const char *__path, struct stat *__sbuf ));
 */

int _stat(UNUSED const char *filepath, struct stat *st) {
  st->st_mode = S_IFCHR;
  return 0;
}

/*
 times
 Timing information for current process. Minimal implementation:
 */

clock_t _times(UNUSED struct tms *buf) { return -1; }

/*
 unlink
 Remove a file's directory entry. Minimal implementation:
 */
int _unlink(UNUSED char *name) {
  errno = ENOENT;
  return -1;
}

/*
 wait
 Wait for a child process. Minimal implementation:
 */
int _wait(UNUSED int *status) {
  errno = ECHILD;
  return -1;
}

/*
 write
 Write a character to a file. `libc' subroutines will use this system routine
 for output to all files, including stdout Returns -1 on error or number of
 bytes sent
 */
// See src/main.c
