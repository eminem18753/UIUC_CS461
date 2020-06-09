import sys
import base64
import hmac
import math

from Crypto import Random
from Crypto.Cipher import AES

with open(sys.argv[1]) as f:
	cipher_text=f.read().strip()

with open(sys.argv[2]) as k:
	key=k.read().strip()

with open(sys.argv[3]) as i:
	modulo=i.read().strip()

cipher_integer=int(cipher_text,16)
key_integer=int(key,16)
modulo_integer=int(modulo,16)

result=pow(cipher_integer,key_integer,modulo_integer)
#print(result)

result_hex=format(result,'x')
#print(result_hex)

with open(sys.argv[4],'w') as o:
	o.write(result_hex)

