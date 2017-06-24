#!/usr/bin/env python
# Sample code for X86 of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *

from binascii import *

SIKRIT_CODE = unhexlify("909090909090909090909090909090905589e583ec60c645daa8c645dbffc645dc88c645ddd0c645deb2c645dff6c645e0f8c645e1eac645e2ffc645e3ffc645e4d2c645e5ffc645e6ffc645e7c2c645e8dcc645e9c2c645ead8c645ebffc645ecf6c645edffc645eefac645efffc645bc55c645bd8bc645beecc645bf51c645c0e8c645c100c645c200c645c300c645c400c645c558c645c62dc645c752c645c81fc645c934c645ca01c645cb2dc645cc52c645cd1fc645ce34c645cf01c645d0e8c645d100c645d200c645d300c645d400c645d590c645d690c645d7c9c645d8c3c645d9ccc645a600c645a75bc645a800c645a900c645aa00c645ab00c645ac00c645ad00c645ae2bc645af17c645b000c645b119c645b23fc645b300c645b400c645b500c645b600c645b703c645b800c645b913c645ba00c645bb05c745fc16000000c745f400000000c745f0000000008b45f083f81673708d55da8b45f001d00fb6000fb6c08945f88d55a68b45f001d00fb6000fb6c08945f4837df4007e0a8345f801836df401ebf08b45fc83e8010fb64405bc0fb6c02945f88b45fc83e8010fb64405bc0fb6c03145f8d17df88b45f889c18d55da8b45f001d08808836dfc018345f001eb8890") # removed c9 (leave) and c3 (ret) at the end

# memory address where emulation starts
ADDRESS = 0x1000000

# Test X86 32 bit
def test_i386(mode, code):
    print("Emulate x86 code")
    try:
        # Initialize emulator
        mu = Uc(UC_ARCH_X86, mode)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, code)

        # initialize stack
        mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x200000)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(code))

        # now print out some registers
        esp = mu.reg_read(UC_X86_REG_ESP)
        rbp = mu.reg_read(UC_X86_REG_RBP)
        print("ESP: 0x%x, RBP: 0x%x" % (esp, rbp))
        bytes_to_read = 0x60 # The size of our stack...
        try:
            buf = mu.mem_read(esp, bytes_to_read)
            print(">>> buffer = 0x%x, size = %u, content = " \
                        %(esp, bytes_to_read), end="")
            for i in buf:
                print("%c" %i, end="")
            print("")
        except UcError as e:
            print(">>> buffer = 0x%x, size = %u, content = <unknown>\n" \
                        %(esp, bytes_to_read))
        print(">>> Emulation done")

    except UcError as e:
        print("ERROR: %s" % e)



if __name__ == '__main__':
    test_i386(UC_MODE_64, SIKRIT_CODE)

