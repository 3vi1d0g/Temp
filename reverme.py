import base64
import string
f=open('./xxx.txt','a+')

def mods(x,e,n):
	array = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
	num = 0
	while 1==1:
		array[num] = e % 2
		num=num+1
		e /= 2
		if e == 0:
			break
	num2 = 1
	i = num - 1
	m=ord(x)
	while  i >= 0:
		num2 = num2 * num2 % n
		flag = array[i] == 1
		if flag:
			num2 = num2 * m % n
		i=i-1
	return num2

	
def enc(s,e,n):
	array =list(s)
	array2 = [0,0,0]
	array2[0] = mods(array[0], e, n)
	array2[1] = mods(array[1], e, n)
	array2[2] = mods(array[2], e, n)
	#print hex(array2[0])
	#print hex(array2[1])
	#print hex(array2[2])
	ah=array2[0]/0x100
	al=(array2[0]-ah*0x100)
	bh=array2[1]/0x100
	bl=(array2[1]-bh*0x100)
	ch=array2[2]/0x100
	cl=(array2[2]-ch*0x100)	
	#print hex(al)
	#print hex(ah)
	#print hex(bl)
	#print hex(bh)
	#print hex(cl)
	#print hex(ch)
	#print "###############"
	text=chr(al)+chr(ah)+chr(bl)+chr(bh)+chr(cl)+chr(ch)
	#print text
	#text='\x16\x06\x4B\x71\x91\x44'
	aaa=base64.b64encode(text)
	return aaa

x=''
for a in range(48,125):
	for b in range(48,125):
		for c in range(48,125):
			x=chr(a)+chr(b)+chr(c)
			#x='1'+'2'+'3'
			sd=enc(x,9157,41117)
			f.write(x+">>>>"+sd+'\n')
			#print x+">>>>"+sd+'\n'
		
		