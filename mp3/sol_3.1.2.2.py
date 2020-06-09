import sys
import base64
import hmac

from Crypto import Random
from Crypto.Cipher import AES

with open(sys.argv[1]) as f:
	cipher_text=f.read().strip()

with open(sys.argv[2]) as k:
	key=k.read().strip()

with open(sys.argv[3]) as i:
	iv=i.read().strip()

key_hex=key.decode("hex")
iv_hex=iv.decode("hex")

decryptor=AES.new(key_hex,AES.MODE_CBC,IV=iv_hex)
plain=decryptor.decrypt(cipher_text.decode("hex"))

with open(sys.argv[4],'w') as o:
	o.write(plain)

