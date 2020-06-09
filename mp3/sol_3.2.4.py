from math import floor
from Crypto.Util.number import GCD
import os
from pbp import decrypt
from Crypto.PublicKey import RSA
import time
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
def product(x):
		result = 1
		for i in range(len(x)):
			#print("i:",x[i])
			#result*=int(i,16)
			result*= x[i]
			#print result
		return result
def productTree(X):
		result = [X]
       #if len(X) == 0: return [1]
		while len(X) > 1:
			X = [product(X[i*2:(i+1)*2]) for i in range((len(X)+1)/2)]
			result.append(X);
		return result
def gcd_all(X):
       p = productTree(X)
       R = p.pop()
       while p:
         X = p.pop()
         R = [R[long(floor(i/2))] % X[i]**2 for i in range(len(X))]
       return [GCD(r/n,n) for r,n in zip(R,X)]
#print product([314,159,265,359,897])
localtime = time.asctime(time.localtime(time.time()))
print localtime
with open("moduli.hex") as r:
	file_cipher=r.read().strip()
with open("3.2.4_ciphertext.enc.asc") as r:
	ciphertext = r.read()
long_to_parse=[]
e = 65537
for i in range(0,10000): 
	temp=""
	for j in range(0,256):
		temp+=file_cipher[i*257+j]
	long_to_parse.append(temp)

n=[]
for i in range(0,10000):
	n.append(long(long_to_parse[i],16))
	#print (long(long_to_parse[i],16))
#print productTree(long_parsed);
new = gcd_all(n)
#print "gcd ok!"
for i in range(0,len(new)):
	if long(new[i]) == 1L:
		continue
	else:
		q = n[i]/long(new[i])
		z = (q-1)*(long(new[i])-1)
		d = modinv(e,z)
		if i>=0:
			#print d
			
			key = RSA.construct((long(n[i]),long(e),long(d)))
			try:
				result = decrypt(key,ciphertext)
				localtime = time.asctime(time.localtime(time.time()))
				print localtime
				print result
				with open("sol_3.2.4.txt",'w') as o:
					o.write(result)			
				break
			except:
				continue
