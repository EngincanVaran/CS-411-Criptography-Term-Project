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
    h = int.from_bytes( h.digest(), byteorder="big") % order
    # h = int( h.hexdigest(), 16) % order

    # s = (sA·h+k) (modn)
    s = ( (private_key * h)  + k ) % order

    return h,s

def verify_signature(m, s, h, generator, order, key):
    # V = sP − hQA
    V = (s * generator) - (h * key)

    # v = V.x (mod n)
    v = V.x % order

    # h′=SHA3256(m+v) (modn)
    h_ = SHA3_256.new( m.encode() + v.to_bytes((v.bit_length()+7)//8, byteorder='big'))
    h_ = int.from_bytes( h_.digest(), byteorder="big") % order
    
    return h == h_


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
    print("\n*** Registered Already, Credentials for " + str(stuID) + " ***")
    
    if stuID == 25050:
        s_long_term_key = 56151490588984619966495949463242848369610960238595967974343184725518461479339
        x = 37382101239388109736295840890608872384706206128270536674835817979241046595268
        y = 8352553717221573606080360260085010079070139262760512897537396375476212675069
        lkey = Point(x,y,eliptic_curve)
    
    elif stuID == 25378:
        s_long_term_key = 47379676928077111776471710624404197341518090666804886937912705780456998790350
        x = 6323928016040579360759554704926176530274646901588974635633308977120840112850
        y = 29162865616210180134342786497921909411008485601327263934582865741789597631745
        lkey = Point(x,y,eliptic_curve)
    
    else:
        print("UNKOWN USER")
        
    
    print("Private Key:\n\t" +  str(s_long_term_key) + "\n")
    print("Public Key Pair: \n\tx: " + str(lkey.x) + "\n\ty: " + str(lkey.y))

# ! server's long term key
QSer_long = Point(	0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9, 
					0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c,
					eliptic_curve)

print("\n*** EPHEMERAL KEYS ***")
# ! HERE GENERATE A EPHEMERAL KEY 
ephemeral_key_private, EKEY = generate_key( P_generator)

print("Ephemeral Private Key:\n\t" +  str(ephemeral_key_private) + "\n")
print("Ephemeral Public Key Pair: \n\tx: " + str(EKEY.x) + "\n\ty: " + str(EKEY.y))

try:
    # ! STS PROTOCOL
    mes = {'ID': stuID, 'EKEY.X': EKEY.x, 'EKEY.Y': EKEY.y}
    response = requests.put('{}/{}'.format(API_URL, "STSStep1&2"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    res=response.json()
	
    skeyx = res['SKEY.X']
    skeyy = res['SKEY.Y']
    SKEY = Point(skeyx, skeyy, eliptic_curve)

    print("\nServers Ephemeral Public Key Pair: \n\tx: " + str(SKEY.x) + "\n\ty: " + str(SKEY.y) + "\n")

    # ! calculate T,K,U
    
    # T = sA * QB
    T = ephemeral_key_private * SKEY

    # U = {T.x||T.y||“BeY ourselfNoMatterWhatTheySay”}
    U = str(T.x) + str(T.y) + "BeYourselfNoMatterWhatTheySay"
    
    # K = SHA3 256(U)
    K = SHA3_256.new( U.encode() )
    key = K.digest()

    # ! Sign Message
    
    # W1 = QA.x||QA.y||QB.x||QB.y
    W1 = str(EKEY.x) + str(EKEY.y) + str(SKEY.x) + str(SKEY.y)
    
    # (SigA.s,SigA.h)=SignsL(W1)
    sig_a_h, sig_a_s = generate_signature(W1, P_generator, n_order, s_long_term_key)
    
    # Y1 = EK (“s”||SigA.s||“h”||SigA.h)
    encrypt_this = "s" + str(sig_a_s) + "h" + str(sig_a_h)

    # Encyption
    cipher = AES.new( key, AES.MODE_CTR)
    ptext = encrypt_this.encode()
    Y1 = cipher.nonce + cipher.encrypt(ptext)
    ctext = int.from_bytes(Y1, byteorder="big")

	### ! Send encrypted-signed keys and retrive server's signed keys
    mes = {'ID': stuID, 'FINAL MESSAGE': ctext}
    response = requests.put('{}/{}'.format(API_URL, "STSStep4&5"), json = mes)
    if((response.ok) == False): raise Exception(response.json()) 
    ctext= response.json() 
    
    # W2 = QB.x||QB.y||QA.x||QA.y.
    W2 = str(SKEY.x) + str(SKEY.y) + str(EKEY.x) + str(EKEY.y)

    ctext = ctext.to_bytes((ctext.bit_length()+7)//8, byteorder='big')
    cipher = AES.new(key, AES.MODE_CTR, nonce=ctext[0:8])
    dtext = cipher.decrypt(ctext[8:]).decode()
    
    server_sig_s = dtext[1:dtext.find("h")]
    server_sig_h = dtext[dtext.find("h")+1:]

    print("Server Signatures extracted...")

    # s-h swap ???
    print("Verified ?",verify_signature(W2, int(server_sig_s), int(server_sig_h), P_generator, n_order, QSer_long))

    mes = {'ID': stuID}
    response = requests.get('{}/{}'.format(API_URL, "STSStep6"), json=mes)
    ctext= response.json() 
    
    ctext = ctext.to_bytes((ctext.bit_length()+7)//8, byteorder='big')
    cipher = AES.new(key, AES.MODE_CTR, nonce=ctext[0:8])
    dtext = cipher.decrypt(ctext[8:]).decode()
    
    message = dtext[:dtext.find(".")+1]
    randomNumber = dtext[dtext.find(".")+2:]

    print("Server sent to us (6):\t", message, randomNumber)
    
    sendingRandomNumber = int(randomNumber) + 1
    encrypt_this = message + " " + str(sendingRandomNumber)
    print("We send to server (7):\t", encrypt_this)

    cipher = AES.new( key, AES.MODE_CTR)
    ptext = encrypt_this.encode()
    ct = cipher.nonce + cipher.encrypt(ptext)
    ct = int.from_bytes(ct, byteorder="big")

    mes = {'ID': stuID, 'ctext': ct}
    response = requests.put('{}/{}'.format(API_URL, "STSStep7&8"), json = mes)
    ctext= response.json()

    ctext = ctext.to_bytes((ctext.bit_length()+7)//8, byteorder='big')
    cipher = AES.new(key, AES.MODE_CTR, nonce=ctext[0:8])
    dtext = cipher.decrypt(ctext[8:]).decode()
    print("Final dtext (8):\t", dtext)

except Exception as e:
	print(e)