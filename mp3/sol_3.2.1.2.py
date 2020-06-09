import sys
import urllib
from pymd5 import md5,padding

with open(sys.argv[1]) as f:
	query=f.read().strip()

with open(sys.argv[2]) as c:
	command3=c.read().strip()

#print(query)
#m=md5()
x=md5(state=query[6:6+32].decode("hex"),count=512)
x.update(command3)
h=x.hexdigest()

length=len(query[0:6]+h+query[6+32:])
result=query[0:6]+h+query[6+32:]+urllib.quote(padding((len(query[0:6])+len(query[6+32:])+1)*8))+command3
#print(result)

with open(sys.argv[3],'w') as w:
	w.write(result)
