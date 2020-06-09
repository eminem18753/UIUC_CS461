import sys
import hashlib
import binascii

def wha(input):
	mask=0x3FFFFFFF
	outHash=0
	for byteResult in input:
		byteResultInteger=ord(byteResult)
		intermediate_value=((byteResultInteger^0xCC)<<24)|((byteResultInteger^0x33)<<16)|((byteResultInteger^0xAA)<<8)|(byteResultInteger^0x55)
		outHash=(outHash & mask)+(intermediate_value & mask)
	return format(outHash,'#04x')

with open(sys.argv[1]) as f:
	input_string=f.read().strip()

#print(input_string)
#print(wha("I am Groot."))

with open(sys.argv[2],'w') as w:
	w.write(wha(input_string)[2:])

collision_string="TIS HWO LEIAZ ACRRIED CAROSS HTE CIE LFOES FO HTE HOIO IRVER NI NUCLE OTMS ACBIN"
#print(wha(input_string))
#print(wha(collision_string))
