# Java Card Operating System

## Copyright and license
Copyright (C) 2020

This software is licensed under the MIT license. See [LICENSE](LICENSE) file at
the root folder of the project.

## Authors

  * Guillaume BOUFFARD (<mailto:guillaume.bouffard@ssi.gouv.fr>)
  * Léo GASPARD (<mailto:leo@gaspard.io>)

## Description

The Java Card Operating System (OS) is a part of [CHOUPI
Project](https://github.com/choupi-project). Java Card OS is a secure-oriented
OS for small footprint embedded devices developed in Rust. This OS aims at
running a Java Card Virtual Machine.

More details of this project were published in an article available on [SSTIC
2018](https://www.sstic.org/media/SSTIC2018/SSTIC-actes/hardening_a_java_card_virtual_machine_implementati/SSTIC2018-Article-hardening_a_java_card_virtual_machine_implementation_with_the_mpu-bouffard_gaspard.pdf).
A presentation in French is also [available](https://static.sstic.org/videos2018/SSTIC_2018-06-14_P08.mp4).

## Dependencies

 * The `arm-none-eabi` toolchain. The main Linux distributions provide a package
   for this toolchain. One can manually install via the [ARM developer website](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads).
 * [openocd](http://openocd.org/). OpenOCD is used to interface `rlwrap` and GDB
   to the border. OpenOCD is avalaible on main Linux distribution.
 * [rlwrap](https://github.com/hanslub42/rlwrap). rlwrap is used to send
   commands to the board through OpenOCD. rlwrap is also avalaible on main Linux
   distributions.

## Toolchain setup

 The nightly version of [Rust](https://www.rust-lang.org/) is required. The
 current supported version `rust-1.43-nightly`. To install it you should:

1. Install `rustup`:
   ``` sh
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
   
2. Adding rust to your `PATH` file:
   ``` sh
   source ~/.cargo/env
   ```

3. Install the nightly version of the rust compiler:
   ```sh
   rustup default nightly-2020-03-10
   ```

   To have a *ready-to-build* version of the Java Card OS. The last checked
   version of rust nightly compiler is `1.43.0-nightly`.

4. Install `xargo`:
   ``` sh
   cargo install xargo
   ```

5. Add `rust-src` component:
   ``` sh
   rustup component add rust-src
   ```

6. To build to ARM Cortex M4 board, you should run:
   ``` sh
   rustup target add thumbv7em-none-eabi
   ```

7. Optional step: install clippy, for `make clippy` support:
   ``` sh
   rustup component add clippy
   ```

8. You're ready to compile using `make`! You can also run the tests using
   `make test` (and long-running tests with `make test-ignored`).
   
## Build targets

The Java Card OS has two main targets : computer and embedded board. The
computer version emulates the MPU behavior. The MPU emulation on computer blocks
the usage of a debugger (but debugging works fine on the embedded version :).

* Building OS for computer :

  ``` sh
  make host-build
  ```

* Building for embedded target:

  ``` sh
  make
  ```

Currently, the only target is a Nucleo board which embeds a
[STM32f401](https://www.st.com/en/evaluation-tools/nucleo-f401re.html). The OS
can easily be extended to support new targets.
   
### Documentation

There is documentation provided from source code.

To generate it, just run `make doc` with `rustdoc` installed (which
should be the case if you followed the setup described above).

It will then land in a `doc` folder, whose entry point is
`doc/javacard_os/index.html`.

In order to get the right fonts, if you are using firefox opening computer-local
resources, you should set `security.fileuri.strict_origin_policy` to `false` in
about:config in Firefox.

### Loading on board

Currently, the only target is ST Nucleo STM32f401. To load firmware on board, we
use `rlwrap` though OpenOCD. 

1. start OpenOCD in a terminal:
   ``` sh
   sudo make ocd
   ```

2. in another terminal, run `rlwrap`:
   ``` sh
   sudo make manage
   ```
   
   As indicate, to install the firmware, you should execute:
   
   ``` sh
   reset halt; flash write_image erase loader.hex; flash write_image erase code.hex; reset run
   ```

### Access to debug messages

To see the debug message, in case of the OS is built in debug mode. The
[Makefile](Makefile) may be modified to built the OS in debug mode.

``` sh
make screen
```

### Debugging

#### Debugging the board version

To running the OS on board though a debugger, `arm-none-eabi-gdb` must be
installed.

1. Starting openOCD in a terminal:
   ``` sh
   sudo make ocd
   ```

2. Starting GDB in another terminal :
   ``` sh
   make debug
   ```

3. Enjoy debugging


#### Debugging the computer version

Note that for tests, it may be hard to debug some issues, like when the child in
an emulation has an unexpected behaviour at runtime that is not a `panic!`, as it
would require a debugger, which is not possible given the emulator is already a
pseudo-debugger.

For this reason, sending `SIGILL` to the child process will make the emulator
(ie. parent process) to make it dump core. The core dump can then be used to try
to debug the issue.

## Clippy

For using clippy (additional lints for rust code), you can run `make clippy`
after having installed `clippy` as per setup step 7.
