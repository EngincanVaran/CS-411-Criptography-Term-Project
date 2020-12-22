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

FIRS_TIME_REG = False
# stuID = 25378
stuID = 25050

# HERE CREATE A LONG TERM KEY
if FIRS_TIME_REG:
    print("*** First Time Registration ***")
    s_long_term_key, lkey = generate_key( P_generator )
    try:
        # LONG TERM KEY GENERATION & SIGN 
        h,s = generate_signature(str(stuID), P_generator, n_order, s_long_term_key)
        
        # ! REGISTRATION
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


        print("Private Key:\n\t" +  str(s_long_term_key) + "\n")
        print("Public Key Pair: \n\tx: " + str(lkey.x) + "\n\ty: " + str(lkey.y))

        memoFile = open("long_term_keys.txt", "w")
        memoFile.write("Private Key:\n\t" +  str(s_long_term_key) + "\n\n")
        memoFile.write("Public Key Pair: \n\tx: " + str(lkey.x) + "\n\ty: " + str(lkey.y) )

    except Exception as e:
	    print(e)
    
else:
    print("\n*** Registered Already, Credentials ***\n")
    
    s_long_term_key = 84252512123196180595156784432542782927101824725301391135722006491791948809029
    x = 10431458579174388084927650527176025025798282665280535437266305400962709920768
    y = 49650054737065202286245257604810653015517096203058687975816448989866583413732
    Qa = Point(x,y,eliptic_curve)
    lkey = Qa
    
    print("Private Key:\n\t" +  str(s_long_term_key) + "\n")
    print("Public Key Pair: \n\tx: " + str(lkey.x) + "\n\ty: " + str(lkey.y))

    # memoFile = open("long_term_keys.txt", "w")
    # memoFile.write("Private Key:\n\t" +  str(s_long_term_key) + "\n\n")
    # memoFile.write("Public Key Pair: \n\tx: " + str(lkey.x) + "\n\ty: " + str(lkey.y) )

# server's long term key
QSer_long = Point(	0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9, 
					0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c,
					eliptic_curve)

print("\n\n*** EPHEMERAL KEYS *** \n")
# HERE GENERATE A EPHEMERAL KEY 
ephemeral_key_private, ekey = generate_key( P_generator)

print("Ephemeral Private Key:\n\t" +  str(ephemeral_key_private) + "\n")
print("Ephemeral Public Key Pair: \n\tx: " + str(ekey.x) + "\n\ty: " + str(ekey.y))

try:
    #STS PROTOCOL
    mes = {'ID': stuID, 'EKEY.X': ekey.x, 'EKEY.Y': ekey.y}
    response = requests.put('{}/{}'.format(API_URL, "STSStep1&2"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    res=response.json()
	
    skeyx = res['SKEY.X']
    skeyy = res['SKEY.Y']
    SKEY = Point(skeyx, skeyy, eliptic_curve)

    print("\nServers Ephemeral Public Key Pair: \n\tx: " + str(SKEY.x) + "\n\ty: " + str(SKEY.y))

    #calculate T,K,U
    T = ephemeral_key_private * SKEY
    # print(T)
    U = str(T.x) + str(T.y) + "BeYourselfNoMatterWhatTheySay"
    # print(U)
    K = SHA3_256.new( U.encode() )
    # print(K.digest())

    #Sign Message
    W1 = str(ekey.x) + str(ekey.y) + str(SKEY.x) + str(SKEY.y)
    # print(W1)
    sig_a_h, sig_a_s = generate_signature(W1, P_generator, n_order, s_long_term_key)
    # print(sig_a_h, sig_a_s)
    encrypt_this = "s" + str(sig_a_s) + "h" + str(sig_a_h)
    # print(encrypt_this)

    # Encyption
    key = Random.new().read(16)
    cipher = AES.new(key, AES.MODE_CTR)
    ptext = encrypt_this.encode()
    Y1 = cipher.nonce + cipher.encrypt(ptext)
    # print(Y1)
    ctext = int.from_bytes(Y1, byteorder="big")
    print(ctext)
    
    ### Send encrypted-signed keys and retrive server's signed keys
    mes = {'ID': stuID, 'FINAL MESSAGE': ctext}
    response = requests.put('{}/{}'.format(API_URL, "STSStep4&5"), json = mes)
    if((response.ok) == False): raise Exception(response.json()) 
    ctext= response.json() 
    print(ctext)

except Exception as e:
	print(e)