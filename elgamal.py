import sys
import argparse
from random import randint
from Crypto.Util.number import bytes_to_long, inverse, long_to_bytes


def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-e', '--encrypt', required=False, action='store_true', help='Option to encrypt')
	parser.add_argument('-d', '--decrypt', required=False, action='store_true', help='Option to decrypt')
	parser.add_argument('-si', '--sign', required=False, action='store_true', help='Option to sign')
	parser.add_argument('-m', '--message', required=True, action='store', help='Message (to encrypt or decrypt)')
	parser.add_argument('-vv', '--verbose', required=False, action='store_true', help='Allow debugging')
	return parser.parse_args()


def encrypt(Kpub, message, debug=False):
	p, alfa, B = Kpub
	a = randint(0, p) 
	Ke = pow(alfa, a, p)
	K = pow(B,a,p)
	y = (message*K) % p
	sent_values = (Ke, y)
	return sent_values


def decrypt(Kpriv, encrypted_message, debug=False):
	p, alfa, b = Kpriv
	Ke, y = encrypted_message
	K = pow(Ke,b,p)
	x = (y*inverse(K, p)) % p
	return x


def sign(Kpriv, message, debug=False):
	p, alfa, b = Kpriv
	Ke = randint(0, p-2)
	r = pow(alfa, Ke, p)
	s = ( (message-b*r) * inverse(Ke,(p-1)) ) % (p-1)
	signature = (r,s)
	return signature


def verify(Kpub, message, signature, debug=False):
	p, alfa, B = Kpub
	r, s = signature
	t = ( pow(B, r) * pow(r, s)) % p
	verification = (t == (pow(alfa, message, p)))
	return verification


def create_kpub(p, alfa, B):
	p =      int(p)
	alfa =   int(alfa)
	B =      int(B)
	Kpub  = (p, alfa, B)
	return Kpub


def create_kpriv(p, alfa, b):
	p =      int(p)
	alfa =   int(alfa)
	b =      int(b)
	Kpriv = (p, alfa, b) 
	return Kpriv


def main():
	myargs = get_args()
	
	m =      int(myargs.message)
	
	if myargs.encrypt:
		p =      randint(1,100)
		alfa =   randint(1,100)
		B =      randint(1,100)
		Kpub = create_kpub(p, alfa, B)
		encrypted_message = encrypt(Kpub, m)
		print(encrypted_message)
	
	elif myargs.decrypt:
		p =      randint(1,100)
		alfa =   randint(1,100)
		b =      randint(1,100)
		Ke =     randint(1,100)
		Kpriv = create_kpriv(p, alfa, b)
		Ke =    int(Ke)
		encrypted_message = (Ke, m)
		decrypted_message = decrypt(Kpriv, encrypted_message)
		print(decrypted_message)
	
	elif myargs.sign:
		p =      randint(1,100)
		alfa =   randint(1,100)
		b =      randint(1,100)
		Kpriv = create_kpriv(p, alfa, b)
		signature = sign(Kpriv, m)
		print(signature)

	elif myargs.verify:
		p =      randint(1,100)
		alfa =   randint(1,100)
		B =      randint(1,100)
		r =      randint(1,100)
		s =      randint(1,100)
		Kpub = create_kpub(p, alfa, B)
		r =      int(r)
		s =      int(s)
		signature = (r, s)
		verification = verify(Kpub, m, signature)
		print(verification)


if __name__ == "__main__":
    main()
    

