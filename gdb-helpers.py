#!/usr/bin/env python

import gdb

RED = '\033[91m'
BLUE = '\033[94m'
YELLOW = '\033[93m'
NOCOLOR = '\033[0m'

class PseudobtCommand(gdb.Command):
    """ Computes a pseudo-backtrace from an address and a size of the stack to
        scan.

        Usage to debug a MemManage fault:
            pseudobt {address returned by `reg psp` in `make manage`} {number of words to inspect}
    """

    def __init__(self):
        super(PseudobtCommand, self).__init__("pseudobt", gdb.COMMAND_STACK)

    def invoke(self, arg, from_tty):
        (addr, size) = arg.split(' ')
        print("{}Backtrace for {} words from {}{}"
                .format(BLUE, size, addr, NOCOLOR))
        memdump = gdb.execute("x/{}xw {}".format(size, addr), to_string=True)
        cur_addr = int(addr, 16) - 4
        for line in memdump.split('\n'):
            for addr in line.split('\t')[1:]: # skip address base
                cur_addr += 4
                if addr == '0x66120712':
                    # Used in unused registers to mark remote call
                    print("{}@0x{:x}{}: {}*** REMOTE CALL ***{}"
                            .format(BLUE, cur_addr, NOCOLOR, YELLOW, NOCOLOR))
                    continue
                if addr[:4] == '0x08': # looks like code
                    symbol = gdb.execute("info symbol {}".format(addr),
                                         to_string=True).split(' in section')[0]
                    if (symbol[:17] == 'No symbol matches'
                            or symbol[:4] in ['ref.', 'str.']):
                        continue
                    print("{}@0x{:x}{}: {}({}){} {}{}{}"
                            .format(BLUE, cur_addr, NOCOLOR,
                                    RED, addr, NOCOLOR,
                                    YELLOW, symbol, NOCOLOR))

PseudobtCommand()
