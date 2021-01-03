import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256,SHA256,HMAC
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json
import webbrowser

API_URL = 'http://cryptlygos.pythonanywhere.com'
FIRS_TIME_REG = False
RESET_REGISTRATION = False
GENERATE_EPHEMERAL_KEYS = True
# stuID = 25378
stuID = 25050

def create_curve():
    eliptic_curve = Curve.get_curve('secp256k1')
    n_order = eliptic_curve.order
    p_field = eliptic_curve.field
    P_generator = eliptic_curve.generator
    a = eliptic_curve.a
    b = eliptic_curve.b

    return eliptic_curve, n_order, p_field, P_generator, a, b

def generate_key(generator):
    s_private_key = Random.new().read(int(math.log(n_order, 2)))
    s_private_key = int.from_bytes(s_private_key, byteorder='big') % n_order
    Q_public_key = s_private_key * P_generator

    return s_private_key, Q_public_key

def generate_signature(m, generator, order, private_key):
    k = Random.new().read(int(math.log(order, 2)))
    k = int.from_bytes(k, byteorder='big')

    R = k * generator
    r = R.x % order

    # h=SHA3256(m+r) (modn)
    h = SHA3_256.new(
        m.encode() + r.to_bytes((r.bit_length()+7)//8, byteorder='big'))
    h = int.from_bytes(h.digest(), byteorder="big") % order
    # h = int( h.hexdigest(), 16) % order

    # s = (sA·h+k) (modn)
    s = ((private_key * h) + k) % order

    return h, s

def verify_signature(m, s, h, generator, order, key):
    # V = sP − hQA
    V = (s * generator) - (h * key)

    # v = V.x (mod n)
    v = V.x % order

    # h′=SHA3256(m+v) (modn)
    h_ = SHA3_256.new(
        m.encode() + v.to_bytes((v.bit_length()+7)//8, byteorder='big'))
    h_ = int.from_bytes(h_.digest(), byteorder="big") % order

    return h == h_

def delete_long_term_key(student_id):
    # DELETE LONG TERM KEY
    print("\n*** Deleting Long Term Keys ***\n")
    # If you lost your long term key, you can reset it yourself with below code.
    try:
        # First you need to send a request to delete it.
        mes = {'ID': student_id}
        response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json=mes)
        print(response.json())
        code = input()

        # Then server will send a verification code to your email.
        # Send this code to server using below code
        mes = {'ID': student_id, 'CODE': code}
        response = requests.get('{}/{}'.format(API_URL, "RstLong"), json=mes)
        print(response.json())
        print("*** Long Term Keys Resetted ***\n")
    except Exception as e:
        print(e)
    # Now your long term key is deleted. You can register again.
    
def delete_epheremal_keys(student_id):
    h, s = generate_signature(str(stuID), P_generator, n_order, s_long_term_key)
    ###delete ephemeral keys
    print("\n*** Deleting Ephemeral Keys ***\n")
    try:
        mes = {'ID': student_id, 'S': s, 'H': h}
        response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json = mes)
        if response.json() == 200:
            print("*** Ephemeral Keys Deleted ***\n")
        else:
            print(response.json())
    except Exception as e:
        print(e)

def first_time_registration(student_id):
    print("*** First Time Registration ***")
    s_long_term_key, QCli_long = generate_key(P_generator)
    try:
        h, s = generate_signature(
            str(stuID), P_generator, n_order, s_long_term_key)
        # Register Long Term Key
        mes = {
            'ID': stuID, 
            'H': h, 
            'S': s, 
            'LKEY.X': QCli_long.x, 
            'LKEY.Y': QCli_long.y}
        response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json=mes)
        print(response.json())
        code = input()

        mes = {'ID': stuID, 'CODE': code}
        response = requests.put('{}/{}'.format(API_URL, "RegLong"), json=mes)
        print(response.json())
        
        print("Private Key:\n\t" + str(s_long_term_key) + "\n")
        print("Public Key Pair: \n\tx: " + str(QCli_long.x) + "\n\ty: " + str(QCli_long.y))
        
        memoFile = open("long_term_keys.txt", "w")
        memoFile.write("Private Key:\n\t" + str(s_long_term_key) + "\n\n")
        memoFile.write("Public Key Pair: \n\tx: " + str(QCli_long.x) + "\n\ty: " + str(QCli_long.y))

        print("*** First Time Registration Succesfull ***\n")
        return s_long_term_key, QCli_long

    except Exception as e:
        print(e)

print("*** Flows ***\nFirst-Time-Registration:\t", FIRS_TIME_REG)
print("Reset-Registration:\t\t", RESET_REGISTRATION)
print("Generate Ephemeral Keys:\t", GENERATE_EPHEMERAL_KEYS)
print("Student id:\t\t\t", stuID)

cont = input("Check Flows (q to quit): ")
if cont == "q" or cont == "Q":
    print("Quitting...")
    quit()


eliptic_curve, n_order, p_field, P_generator, a, b = create_curve()

# server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9,
                  0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, eliptic_curve)
if FIRS_TIME_REG:
    s_long_term_key, QCli_long = first_time_registration(stuID)

elif RESET_REGISTRATION:
    delete_long_term_key(stuID)
    s_long_term_key, QCli_long = first_time_registration(stuID)

else:
    print("\n*** Registered Already", stuID, "***")
    if stuID == 25050:
        s_long_term_key = 59304411556710662667795837609640185321244532129679788146780235681929946012605
        x = 2262140803121500892571478068356352181515723460475489309925879806711284632250
        y = 3942505368907710690820587320484931574559806401587539034906401150262798522836
        QCli_long = Point(x, y, eliptic_curve)

        # print("Private Key:\n\t" + str(s_long_term_key) + "\n")
        # print("Public Key Pair: \n\tx: " + str(QCli_long.x) + "\n\ty: " + str(QCli_long.y))
    elif stuID == 25378:
        s_long_term_key = 70576181953455683423175309266073377245271976140511725296544045876366493649140

        x = 54126340827016069202248324386975617769699311405281021967329662577891354929676
        y = 35173145737211266849758853035176194716800634647536075102730397609463108780650
        QCli_long = Point(x, y, eliptic_curve)

# ! HERE GENERATE 10 EPHEMERAL KEY
if GENERATE_EPHEMERAL_KEYS:
    print("*** Generating Ephemeral Keys ***\n")
    delete_epheremal_keys(stuID)
    store_eph_keys = {}
    for i in range(10):
        ephemeral_key_private, EKEY = generate_key(P_generator)
        concat = str(EKEY.x) + str(EKEY.y)
        h, s = generate_signature(concat, P_generator, n_order, s_long_term_key)
        # send ephemeral key
        mes = { 'ID': stuID,
                'KEYID': i,
                'QAI.X': EKEY.x,
                'QAI.Y': EKEY.y,
                'Si': s,
                'Hi': h}
        response = requests.put('{}/{}'.format(API_URL, "SendKey"), json=mes)
        print(response.json(), i)
        store_eph_keys[i] = ephemeral_key_private
        # store_eph_keys.append(ephemeral_key_private)
    # print(store_eph_keys)
    memoFile = open("ephemeral_keys.txt", "w")
    for key, value in zip(store_eph_keys.keys(), store_eph_keys.values()):
        memoFile.write( str(key) + "\t"  + str(value) + "\n")
    memoFile.close()
else:
    print("*** Using Pre-Generated Ephemeral Keys ***\n")
    memoFile = open("ephemeral_keys.txt", "r")
    temp = memoFile.readlines()
    store_eph_keys = {}
    for line in temp:
        indexTab = line.find("\t")
        store_eph_keys[int(line[:indexTab])] = int(line[indexTab+1:])

h, s = generate_signature( str(stuID), P_generator, n_order, s_long_term_key)
# Receiving Messages
mes = {'ID_A': stuID, 'S': s, 'H': h}
response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json=mes)

if response.json() == "You dont have new messages. Why dont you reset your short term keys and wait a while?":
    print( response.json())
else:
    # Parse the Response
    IDB = response.json()["IDB"]
    KEYID = int( response.json()["KEYID"] )
    MSG = response.json()["MSG"]
    QBJx = response.json()["QBJ.X"]
    QBJy = response.json()["QBJ.Y"]

    msg_byte = MSG.to_bytes((MSG.bit_length()+7)//8, byteorder='big')
    QBJ = Point(QBJx, QBJy, eliptic_curve)

    T = store_eph_keys[KEYID]*QBJ
    U = str(T.x) + str(T.y) + "NoNeedToRunAndHide"
    K = SHA3_256.new( U.encode() )
    K_ENC = K.digest()
    k_mac = SHA3_256.new( K_ENC )
    K_MAC = k_mac.digest()

    ctext = msg_byte
    cipher = AES.new(K_ENC, AES.MODE_CTR, nonce=ctext[0:8])
    
    dtext = cipher.decrypt(ctext[8:len(ctext)-32])
    mac = ctext[len(ctext)-32:]
    
    h = HMAC.new(K_MAC, digestmod=SHA256)
    h.update(ctext[8:len(ctext)-32])

    try:
        h.verify(mac)
        print("\n\nThe message ", msg_byte , " is authentic.\n\n")
    except ValueError:
        print("Message is not authentic")
        quit()
    
    decmsg = dtext.decode()
    print("Song link:\n\t-->", decmsg)
    webbrowser.open(decmsg)
    print("\n")

    try:
        #send decrypted messages to server
        mes = {'ID_A': stuID, 'DECMSG': decmsg}
        response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
        print(response.json())
    except Exception as e:
        print(e)