###############
# System spec #
###############

CC = arm-none-eabi-gcc
LD = arm-none-eabi-ld
AS = arm-none-eabi-as
GDB = arm-none-eabi-gdb
OBJCOPY = arm-none-eabi-objcopy
CARGO = cargo
XARGO = xargo
RUSTC_TARGET = thumbv7em-none-eabi

SIGINFOHDR = /usr/include/signal.h

vpath %.c src
vpath %.c Drivers/STM32F4xx_HAL_Driver/Src/

OUT_BUILD = target/build

#################
# Platform spec #
#################

SRCS = ./Drivers/CMSIS/Device/ST/STM32F4xx/Source/Templates/gcc/startup_stm32f401xe.s
DEFS = -DSTM32F401xE
OCD = /usr/share/openocd/scripts/board/st_nucleo_f4.cfg
LDFLAGS = -Tstm32f401xe.ld
BINDINGHDR = ./Drivers/CMSIS/Device/ST/STM32F4xx/Include/stm32f401xe.h
RSPLATFORM = --features stm32f401re

##########
# Optims #
##########

CFLAGS = -Os
RSFLAGS =

# CARGOFLAGS = --release
# CARGOPROFILE = release

CFLAGS += -ggdb
RSFLAGS += -g3

# "really debug" mode
RSFLAGS = --cfg debug
CARGOFLAGS =
CARGOPROFILE = debug

###################
# Actual Makefile #
###################

RS_SRCS := $(shell find src -name '*.rs') src/arch/stm32f401re/bindings.rs src/arch/host/siginfo.rs Cargo.toml

SRCS += src/main.c
# SRCS += src/ffi.h
SRCS += src/malloc.c

SRCS += src/stm32f4xx_it.c
SRCS += src/system_stm32f4xx.c
SRCS += src/newlib_stubs.c

SRCS += Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal.c
SRCS += Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_rcc.c
SRCS += Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_gpio.c
SRCS += Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_cortex.c
SRCS += Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_uart.c
SRCS += Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_dma.c

OBJS = $(patsubst %.c, $(OUT_BUILD)/%.o, $(patsubst %.s, $(OUT_BUILD)/%.o, $(SRCS)))

CARGOFLAGS += $(RSPLATFORM)
CARGODOCFLAGS += --features host
DOCFLAGS = --cfg debug --no-defaults --passes collapse-docs --passes unindent-comments --passes strip-priv-imports
CLIPPYFLAGS = --cfg debug
CARGOFLAGS += --target $(RUSTC_TARGET)

RSLIBS = -Ltarget/thumbv7em-none-eabi/$(CARGOPROFILE) -ljavacard_os

INCLUDES = -Isrc -IDrivers/STM32F4xx_HAL_Driver/Inc/ -IDrivers/CMSIS/Device/ST/STM32F4xx/Include/ -IDrivers/CMSIS/Include/

CFLAGS += $(DEFS)
CFLAGS += $(INCLUDES)
CFLAGS += -Wall -Wextra -Warray-bounds
CFLAGS += -mlittle-endian -mthumb -mcpu=cortex-m4 -mthumb-interwork -Wl,--gc-sections
CFLAGS += -Wl,-wrap,_malloc_r -Wl,-wrap,_free_r -Wl,-wrap,_calloc_r -Wl,-wrap,_realloc_r
CFLAGS += --specs=nano.specs --specs=nosys.specs

.PHONY: all
all: firmware.elf

firmware.elf: rust $(OBJS) # $(SRCS) Makefile $(wildcard *.ld)
	@echo "[LD] $@"
	$(CC) $(CFLAGS) $(OBJS) $(RSLIBS) $(LDFLAGS) -o $@
	$(OBJCOPY) --only-section=.flashloader -O ihex firmware.elf loader.hex
	$(OBJCOPY) --remove-section=.flashloader -O ihex firmware.elf code.hex
	$(OBJCOPY) --remove-section=.flashloader -O binary firmware.elf firmware.bin

rust: $(RS_SRCS) 
	$(XARGO) rustc $(CARGOFLAGS) -- $(RSFLAGS)

$(OUT_BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	@echo "[CC] $<"
	$(CC) $(CFLAGS) $(RSLIBS) -o $@ -c $<

$(OUT_BUILD)/%.o: %.s
	@mkdir -p $(dir $@)
	@echo "[AS] $<"
	$(AS) -o $@ $<

src/arch/stm32f401re/bindings.rs:
	bindgen --use-core --no-doc-comments -o $@ $(BINDINGHDR) -- $(DEFS) $(INCLUDES)

src/arch/host/siginfo.rs:
	bindgen --use-core --no-doc-comments -o $@ $(SIGINFOHDR)

.PHONY: clean
clean:
	rm -Rf firmware.elf firmware.bin rust.o code.hex loader.hex target

.PHONY: ocd
ocd:
	openocd -f $(OCD)

.PHONY: debug
debug:
	$(GDB) firmware.elf -ex "target extended localhost:3333" -ex "source gdb-helpers.py"

.PHONY: manage
manage:
	@echo "To flash, run the following command in the next-to-come shell:"
	@echo "reset halt; flash write_image erase loader.hex; flash write_image erase code.hex; reset run"
	rlwrap nc localhost 4444

.PHONY: screen
screen:
	screen /dev/ttyACM0 38400

.PHONY: size
size:
	@echo "Size of the functions"
	@echo "====================="
	@echo
	@arm-none-eabi-nm firmware.elf --print-size --size-sort --radix=d --demangle
	@echo
	@echo
	@echo "Size of the sections"
	@echo "===================="
	@echo
	@arm-none-eabi-size -A -d firmware.elf

.PHONY: doc
doc:
	$(XARGO) doc $(CARGOFLAGS)
	rm -f doc
	ln -s target/thumbv7em-none-eabi/doc doc

.PHONY: clippy
clippy:
	$(XARGO) clippy $(CARGOFLAGS) -- $(CLIPPYFLAGS)

.PHONY: test
test: $(RS_SRCS) Makefile
	RUST_TEST_THREADS=1 RUST_BACKTRACE=FULL $(CARGO) test --no-default-features --features host --

.PHONY: test-ignored
test-ignored: $(RS_SRCS) Makefile
	RUST_TEST_THREADS=1 RUST_BACKTRACE=FULL $(CARGO) test --no-default-features --features host -- --ignored

.PHONY: host-build
host-build: $(RS_SRCS) Makefile
	$(CARGO) build --no-default-features --features host,big_ram
