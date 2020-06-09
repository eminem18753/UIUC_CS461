import sys
import urllib2
from collections import deque
BLOCK_SIZE=32
def get_status(u):
	req = urllib2.Request(u)
	try:
		f = urllib2.urlopen(req)
		return f.code
	except urllib2.HTTPError, e:
		return e.code
def blockify(text, block_size=BLOCK_SIZE):
    return [text[i:i+block_size] for i in range(0, len(text), block_size)]
with open(sys.argv[1]) as f:
	cipher_text = f.read().strip()
cipher_integer=format(int(cipher_text,16),'x')
blocks = blockify(cipher_integer)
padding = ['10','0f','0e','0d','0c','0b','0a','09','08','07','06','05','04','03','02','01']
plain_text = []
for index in range(1, len(blocks)):
	modifiedTemp = ['0']*32
	original = map(''.join, zip(*[iter(blocks[-(index + 1)])] * 2))
	modified = map(''.join, zip(*[iter(blocks[-(index + 1)])] * 2))
	forDecryption = map(''.join, zip(*[iter(blocks[-index])] * 2))
	print("Block " + str(len(blocks) - index))
	for byteInTheBlock in range(1, 16+1):
		for guessAttempt in range(0, 256):
			modified[-byteInTheBlock] = format(guessAttempt ^ int(original[-byteInTheBlock], 16) ^ 16,'x').zfill(2)
			url = "http://72.36.89.11:9999/mp3/yufanff2/?" + ''.join(modified) + ''.join(forDecryption)
			if get_status(url) == 404:
				modifiedTemp[-byteInTheBlock] = format(guessAttempt,'x').zfill(2)
				if byteInTheBlock == 16:
					plain_text=[modifiedTemp]+plain_text
					print "Result now:" + ''.join([chr(int(character, 16)) for partial in plain_text for character in partial])
				else:
					for padCount in range(1, byteInTheBlock + 1):			
						modified[-padCount] = format(int(padding[byteInTheBlock - padCount + 1], 16)  ^ int(modifiedTemp[-padCount], 16) ^ int(original[-padCount], 16),'x').zfill(2) 
				break
plain_text = [chr(int(character, 16)) for partial in plain_text for character in partial]
print ''.join(plain_text)
result = ''.join(plain_text)
for x in result:
	if (x < '\x20'):
		result = result.replace(x,'')
print result
with open(sys.argv[2], 'w') as o:
	o.write(result)
