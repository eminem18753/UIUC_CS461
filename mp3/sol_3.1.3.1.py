import sys
import hashlib
import binascii

with open(sys.argv[1]) as f:
	input_string=f.read().strip()

with open(sys.argv[2]) as k:
	perturbed_string=k.read().strip()

input_m=hashlib.sha256()
input_m.update(input_string)
input_result=input_m.hexdigest()

perturbed_m=hashlib.sha256()
perturbed_m.update(perturbed_string)
perturbed_result=perturbed_m.hexdigest()

#print(input_result)
#print(perturbed_result)

input_binary=bin(int(input_result,16))[2:]
input_binary=input_binary.zfill(256)
#print(len(input_binary))

perturbed_binary=bin(int(perturbed_result,16))[2:]
perturbed_binary=perturbed_binary.zfill(256)
#print(len(perturbed_binary))

count=-1
hamming_distance=0
for i in input_binary:
	count=count+1
	if i!=perturbed_binary[count]:
		hamming_distance=hamming_distance+1

with open(sys.argv[3],'w') as o:
	o.write(format(hamming_distance,'x'))
