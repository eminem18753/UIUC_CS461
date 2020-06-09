import sys

with open(sys.argv[1]) as r:
	file_cipher=r.read().strip()

with open(sys.argv[2]) as f:
	file_content=f.read().strip()

with open(sys.argv[3],'w') as o:
	for character in file_cipher:
		if character.isupper():
			count=-1
			for j in file_content:
				count=count+1
				if character==j:
					result=ord('A')+count
			o.write(chr(result))
		else:
			o.write(character)
