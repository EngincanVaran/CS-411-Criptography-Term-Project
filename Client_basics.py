import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json
API_URL = 'http://cryptlygos.pythonanywhere.com'

# stuID = 25378
stuID = 25050

def create_curve():
	eliptic_curve = Curve.get_curve('secp256k1')
	n_order = eliptic_curve.order
	p_field = eliptic_curve.field
	P_generator = eliptic_curve.generator
	a = eliptic_curve.a
	b = eliptic_curve.b

	return eliptic_curve, n_order, p_field, P_generator, a, b

def generate_key( generator ):
	s_private_key = Random.new().read(int(math.log(n_order,2)))
	s_private_key = int.from_bytes(s_private_key, byteorder='big') % n_order
	# s_private_key = random.randint(2,n_order-1)
	Q_public_key = s_private_key * P_generator

	return s_private_key, Q_public_key

def generate_signature(m, generator, order, private_key):
	k = Random.new().read(int(math.log(order,2)))
	k = int.from_bytes(k, byteorder='big')
	
	R = k * generator
	r = R.x % order
	
	# h=SHA3256(m+r) (modn)
	h = SHA3_256.new( m.encode() + r.to_bytes((r.bit_length()+7)//8, byteorder='big'))
	h = int( h.hexdigest(), 16) % order
	
	# s = (sA·h+k) (modn)
	s = ( (private_key * h)  + k ) % order

	return h,s

# HERE CREATE THE CURVE
eliptic_curve, n_order, p_field, P_generator, a, b = create_curve()

# HERE CREATE A LONG TERM KEY
s_private_key, lkey = generate_key( P_generator )

memoFile = open("long_term_keys.txt", "w")
memoFile.write("Private Key: " +  str(s_private_key) + "\n")
memoFile.write("Public Key Pair: ( " + str(lkey.x) + " , " + str(lkey.y) + " )")

# server's long term key
QSer_long = Point(	0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9, 
					0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c,
					eliptic_curve)

s_private_key = 6557471723369604805641431247986677714366983658769930991094579692778057242958
x = 20609217136271877409751143207719209834560690928280669226414054601339579366790
y = 77795073030484862984657935288014582923087677724743906903802262439770482651858
Qa = Point(x,y,eliptic_curve)

# HERE GENERATE A EPHEMERAL KEY 
e_s_private, ekey = generate_key( P_generator)

try:
	
	# OUR CODE 
	h,s = generate_signature(str(stuID), P_generator, n_order, s_private_key)
	
	#REGISTRATION
	mes = {'ID':stuID, 'h': h, 's': s, 'LKEY.X': lkey.x, 'LKEY.Y': lkey.y}
	response = requests.put('{}/{}'.format(API_URL, "RegStep1"), json = mes)		
	if((response.ok) == False): raise Exception(response.json())
	print(response.json())

	print("Enter verification code which is sent to you: ")	
	code = int(input())

	mes = {'ID':stuID, 'CODE': code}
	response = requests.put('{}/{}'.format(API_URL, "RegStep3"), json = mes)
	if((response.ok) == False): raise Exception(response.json())
	print(response.json())
	'''
	
	#STS PROTOCOL

	mes = {'ID': stuID, 'EKEY.X': ekey.x, 'EKEY.Y': ekey.y}
	response = requests.put('{}/{}'.format(API_URL, "STSStep1&2"), json = mes)
	if((response.ok) == False): raise Exception(response.json())
	res=response.json()
	
	#calculate T,K,U
	Q_b_x = res['SKEY.X']
	Q_b_y = res['SKEY.Y']
	Qb = Point(Q_b_x, Q_b_y, eliptic_curve)

	T = e_s_private * Qb
	U = str(T.x) + str(T.y) + "BeYourselfNoMatterWhatTheySay"
	K = SHA3_256.new( U.encode() )

	#Sign Message
	W1 = str(ekey.x) + str(ekey.y) + str(Qb.x) + str(Qb.y)
	sig_a_h, sig_a_s = generate_signature(W1, P_generator, n_order, s_private_key)
	encrypt_this = "s" + str(sig_a_s) + "h" + str(sig_a_h)

	# Encyption
	key = Random.new().read(16)
	cipher = AES.new(key, AES.MODE_CTR)
	ptext = encrypt_this.encode()
	Y1 = cipher.nonce + cipher.encrypt(ptext)
	
	ctext = int.from_bytes(Y1, byteorder="big")

	###Send encrypted-signed keys and retrive server's signed keys
	mes = {'ID': stuID, 'FINAL MESSAGE': ctext}
	response = requests.put('{}/{}'.format(API_URL, "STSStep4&5"), json = mes)
	if((response.ok) == False): raise Exception(response.json()) 
	ctext= response.json() 
	print(ctext)

	#Decrypt 



	#verify


	#get a message from server for 
	mes = {'ID': stuID}
	response = requests.get('{}/{}'.format(API_URL, "STSStep6"), json=mes)
	ctext= response.json()         
	

	#Decrypt


	#Add 1 to random to create the new message and encrypt it


	
	#send the message and get response of the server
	mes = {'ID': stuID, 'ctext': ct}
	response = requests.put('{}/{}'.format(API_URL, "STSStep7&8"), json = mes)
	ctext= response.json()         
	'''

except Exception as e:
	print(e)
