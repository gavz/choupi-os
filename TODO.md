General
=======

* Implementing [Rust embedded](https://github.com/rust-embedded/cortex-m)
  framework to easily improve the number of targets

File System
===========

 * Handle transactions, that is writing multiple files in an atomic way.
   This will require a meta-block to make all files valid at the same time.
   An example format could be NotYetValid | StillValid | NumBlocks | B1 | ...
   Then, the writing sequence would be:
    1) Write NumBlocks | B1 | ... (as already valid)
    2) Mark the metablock as valid by putting NotYetValid to 0
    3) Invalidate all the blocks tagged with the tags of B1 etc.
    4) Mark the metablock as invalid by putting StillValid to 0
   The metablock can then be ignored for the rest of the operations.
   If a failure happens before the end of step 2, the metablock will be ignored,
   for it is not yet valid.
   If a failure happens before the end of step 4, on the next reboot filesystem
   auto-repair will resume at step 3, for it knows a transaction was running
   thanks to the valid metablock.
   If a failure happens after step 4, the metablock is no longer and hence is
   ignored, leaving all the blocks inside to be considered valid.

 * Add some wear leveling by not always using the same defrag sector (?) (it is
   erased as often as the sum of all other blocks, so should be the first one to
   physically stop functioning)

 * In `FileSystem::defragment`, optimize by not re-scanning the entire drive,
   but rather using `self.files` to know where the files are located. (~0.7s to
   win out of 2.7s)

 * Handle different pools for short-lived and long-lived objects, in order to
   minimize the number of defragmentations required

 * Checksum only the header? (makes fault injection on the flash easier, maybe?)


Flash
=====

 * Fail after a certain number of erases to a sector, so that attackers cannot
   wear out the flash?

 * Replace `ffi::flash_pointer()` by a set of functions that return the layout
   of the flash memory (is there actually a use case for this out of tests?)


MPU
===

 * Also restrict the possibilities of the kernel for hardening, do not rely on
   `PRIVDEFENA` (this should also prevent stack overflow from the kernel from
   overwriting sensitive data)


Syscalls
========

 * Use a syscall for `Error_Handler` in `main.c`, so that the `gpio_toggle` can
   be turned on again


Allocator
=========

 * Make the allocator hardened (ie. zeroing memory on malloc/free, checksumming
   header, quarantine freelist, etc.)


Testing
=======

 * Put the heap inside `emulator::RAM`

 * Make `emulator.rs`'s "Pop result context" section more robust to changes to
   the `Context` struct

 * Do not write data if `regs.rsp` is not inside the current context, in
   `emulator.rs`'s "Push result context" section

 * Also check privileges for privileged code in `host/mpu_ll.rs`'s `allows_addr`
   (default zone is supposed to be number -1, not number 8)

 * Remove the testing stuff from `ffi::mpu_init`

 * Test in failure situations, by adding a mocker (!crates mockers) for
   `has_error()` and `currently_busy()`?

 * Clean up all the `#[cfg(` in `src/ffi.rs`

 * Test `src/filename.rs`

 * Test `syscall::read_inplace`

 * Also test the main function with sub-region disable

 * Implement rebooting in the emulator, for testing applet install/uninstall


Blocked
=======

 * Remove the `Option<>` from the type of `CONTEXT_STACK` when `Vec::new`
   becomes `const fn`

 * Clear the entire RAM and flash in `Error_Handler` (blocked for debugging for
   the time being)

 * Use a `FromPrimitive`-like trait derived for `Syscall` in `syscall/mod.rs`,
   instead of rewriting it and maintaining it by hand (and same thing for
   `EmulatorCall`)

 * Cleanup `arch/host/context_ll.rs`'s use of `$$6` and `$$1` once rustc allows
   using enum variants in "i" constraints

 * Remove the `fs::dump` function (blocked for easily using it while debugging)
