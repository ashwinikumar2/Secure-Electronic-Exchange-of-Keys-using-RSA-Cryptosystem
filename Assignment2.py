import os
import random
import gmpy2
import numpy as np
from gmpy2 import mpfr

def find_inverse(a,n):
	while (a>0 and n%a!=1):
		x=n%a
		n=n//a
		a=x

	return n

def optimized_block_size(n):	#used to find the optimized block size 
	i=0
	while(pow(gmpy2.mpz(29), i)<=n):
		i+=1
	return (i-1)

def derived_ascii(x):			#used to assign number to each of the character used in string
	if(x=='.'):
		return 26
	elif(x==' '):
		return 27
	elif(x=='?'):
		return 28
	return ord(x)-65

def get_char_from_derived_ascii(x):		#used to get character from a number
	if(x<=25):
		return chr(int(x+65))
	elif(x==26):
		return '.'
	elif(x==27):
		return ' '
	elif(x==28):
		return '?'
	return ' '

def common_session_key(p,g):			#used to find common session key 
	e=1
	k1=random.randint(1,p-1)
	k2=random.randint(1,p-1)

	x1=gmpy2.powmod(g,k1,p)
	x2=gmpy2.powmod(g,k2,p)
	x12=gmpy2.powmod(x2,k1,p)
	x21=gmpy2.powmod(x1,k2,p)

	try:								#it may happen that modular inverse do not exist for this value of e so exception handling
		if(x12%2==0):
			e=x12-1
		else:
			e=x12
		d=gmpy2.powmod(e, -1, p-1)
		file = open('User1.txt','w') 
		file.write("User 1 chooses a random key k1 in Zp* = "+str(k1)+"\n")
		file.write("User 1 computes x1= "+str(x1)+"\n") 
		file.write("User 1 and 2 exchange x1= "+str(x1)+" and x2= "+str(x2)+"\n")
		file.write("User 1 computes x1,2= "+str(x12)+"\n")
		file.close()

		file1 = open('User2.txt','w') 
		file1.write("User 2 chooses a random key k2 in Zp* = "+str(k2)+"\n")
		file1.write("User 2 computes x2= "+str(x2)+"\n") 
		file1.write("User 1 and 2 exchange x1= "+str(x1)+" and x2= "+str(x2)+"\n")
		file1.write("User 2 computes x2,1= "+str(x21)+"\n")
		file1.close()
		return e,d
	except ValueError:
		return common_session_key(p,g)	

if __name__=="__main__":
	
	r=int(input("enter r\n"))
	# r=641
	p=2*r+1
	g=int(input("enter g\n"))
	# g=24
	e,d=common_session_key(p,g)
	# plaintext="INDIA IS MY COUNTRY. "
	plaintext=input("enter plaintext\n")
	b=optimized_block_size(p)
	file = open('User1.txt','a') 			#writing to user 1 file
	file.write("Common session key(e)= "+str(e)+str("\n"))
	file.write("Optimized block size(b)= "+str(b)+str("\n"))
	file.close()
	file1 = open('User2.txt','a') 			#writing to user 2 file
	file1.write("Common session key(e)= "+str(e)+str("\n"))
	file1.write("Optimized block size(b)= "+str(b)+str("\n"))
	file1.close()
	net_cipher=''
	net_decipher=''
	for i in range(1,(int)(gmpy2.ceil(len(plaintext)//b))+1):
		
		#SERVER IMPLEMENTATION(User 1)
		j=(i-1)*b
		block_string=""
		t=b-1
		y=b-1
		m=0
		for j in range((i-1)*b,i*b):		#finding value of M
			block_string+=plaintext[j]
			x=derived_ascii(plaintext[j])
			k=x*pow(gmpy2.mpz(29), t)
			m+=k
			t-=1
		c=gmpy2.powmod(m, e,p)			#finding value of C
			#finding the cipher text
		cipher=""
		y=b-1		
		quotient,c1=gmpy2.f_divmod(c,(pow(gmpy2.mpz(29), 1)))
		a0=c1
		cipher+=get_char_from_derived_ascii(a0)
		char_at_end=''
		c_original=c
		if(c<=pow(gmpy2.mpz(29), b)):
			char_at_end='A'
		for j1 in range(1,b+1):
			c-=a0
			c=gmpy2.div(c,29)
			quotient_of_29_,c1=gmpy2.f_divmod(c,(pow(gmpy2.mpz(29), j1)))
			a0=c1
			char=get_char_from_derived_ascii(c1)
			cipher+=char
		net_cipher+=cipher


		#CLIENT IMPLEMENTATION(User 2)
		length_for_decipher=len(cipher)
			#finding value of C
		C=0
		for char_in_cipher in range(len(cipher)):
			char1=cipher[char_in_cipher]
			x=derived_ascii(char1)
			C+=x*(pow(gmpy2.mpz(29), char_in_cipher))

			#finding value of M from recieved cipher text
		M=gmpy2.powmod(C,d,p)
		decipher=''
		
		for j2 in range(1,length_for_decipher):
			quotient_of_29_,ascii_of_char=gmpy2.f_divmod(M,(pow(gmpy2.mpz(29), j2)))
			decipher=get_char_from_derived_ascii(ascii_of_char)+decipher
			M-=ascii_of_char
			M=gmpy2.div(M,29)

		net_decipher+=decipher

	file = open('User1.txt','a') 			#writing to user 1 file
	file.write("Private key(d)= "+str(d)+str("\n"))
	file.write("Cipher text sent from user 1 to user 2= "+str(net_cipher)+str("\n"))
	file.close()
	
	file1 = open('User2.txt','a') 			#writing to user 2 file
	file1.write("Private key(d)= "+str(d)+str("\n"))
	file1.write("Cipher text recieved from user 1= "+str(net_cipher)+str("\n"))
	file1.write("Decrypted text of the recieved cipher text= "+str(net_decipher)+str("\n"))
	file1.close()
	
	# print("decipher= ",net_decipher)