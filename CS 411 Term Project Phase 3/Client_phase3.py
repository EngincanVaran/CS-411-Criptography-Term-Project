import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, SHA256, HMAC
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import hashlib, hmac, binascii
import json
API_URL = 'http://cryptlygos.pythonanywhere.com'

GENERATE_EPHEMERAL_KEYS = False
GET_MSG = True
SEND_MSG_2_SERVER = False

stuID_A = 25050
# stuID_A = 25378
stuID_B = 18007

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
    
def delete_epheremal_keys(student_id, long_term_key):
    h, s = generate_signature(str(student_id), P_generator, n_order, long_term_key)
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
            str(student_id), P_generator, n_order, s_long_term_key)
        # Register Long Term Key
        mes = {
            'ID': student_id, 
            'H': h, 
            'S': s, 
            'LKEY.X': QCli_long.x, 
            'LKEY.Y': QCli_long.y}
        response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json=mes)
        print(response.json())
        code = input()

        mes = {'ID': student_id, 'CODE': code}
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

def checkStatus(student_id,private_key):
    h,s = generate_signature( str(student_id), P_generator, n_order, private_key )
    #Check Status
    mes = {'ID_A':student_id, 'H': h, 'S': s}
    response = requests.get('{}/{}'.format(API_URL, "Status"), json = mes)
    print("Status ", response.json())

def getRecieversKey(sender_id, reciever_id, private_key):
    h,s = generate_signature( str(reciever_id), P_generator, n_order, private_key )
    
    ### Get key of the Student B
    mes = {'ID_A': sender_id, 'ID_B':reciever_id, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "ReqKey"), json = mes)
    res = response.json()
    print(res)
    return res

def parseResponse(response):
    A_i = int( response['i'] )
    B_j = int( response['j'] )
    B_QBJx = response['QBJ.x']
    B_QBJy = response['QBJ.y']

    return A_i, B_j, B_QBJx, B_QBJy

def getSessionKey(ephemeral_key, point):
    T = ephemeral_key * point
    U = str(T.x) + str(T.y) + "NoNeedToRunAndHide"
    K = SHA3_256.new( U.encode() )
    K_ENC = K.digest()

    return K_ENC

def encryptMsg(msg, sessionKey):
    cipher = AES.new(sessionKey, AES.MODE_CTR)
    msg = msg.encode()
    ctext = cipher.encrypt(msg)

    # hash
    k_mac = SHA3_256.new( sessionKey )
    K_MAC = k_mac.digest()
    h = HMAC.new(K_MAC, digestmod=SHA256)

    h.update(ctext)

    cMAC = h.digest()

    msg = (cipher.nonce) + (ctext) + ( cMAC )

    msg = int.from_bytes(msg, byteorder="big")

    return msg

def sendMsg(sender_id, reciever_id, msg, A_i, B_j):
    ### Send message to student B
    mes = {'ID_A': stuID_A, 'ID_B':stuID_B, 'I': A_i, 'J': B_j, 'MSG': msg}
    response = requests.put('{}/{}'.format(API_URL, "SendMsg"), json = mes)
    print(response.json())

def getMsg(student_id, private_key):
    h,s = generate_signature( str(student_id), P_generator, n_order, private_key )
    
    ## Get your message
    mes = {'ID_A': student_id, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg_PH3"), json = mes)
    print(response.json())
    res = response.json()

    if(response.ok): ## Decrypt message
        if res != "You dont have any new messages":
            IDB = res["IDB"]
            KEYID = int( res["KEYID"] )
            MSG = res["MSG"]
            QBJx = res["QBJ.X"]
            QBJy = res["QBJ.Y"]
            
            print("\nMsg from:", IDB, "\n")

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
                print("The message ", msg_byte , " is authentic.\n\n")
                decmsg = dtext.decode()
                print(decmsg)
            except ValueError:
                print("The message is not authentic")
            
        else:
            print("Try Again...")

##########################
#### FLOW STARTS HERE ####
##########################

eliptic_curve, n_order, p_field, P_generator, a, b = create_curve()

# KEYS FOR 25050
if stuID_A == 25050:
    A_s_long_term_key = 59304411556710662667795837609640185321244532129679788146780235681929946012605
    A_x = 2262140803121500892571478068356352181515723460475489309925879806711284632250
    A_y = 3942505368907710690820587320484931574559806401587539034906401150262798522836
    A_QCli_long = Point(A_x, A_y, eliptic_curve)

# KEYS FOR 25378
elif stuID_A == 25378:
    A_s_long_term_key = 70576181953455683423175309266073377245271976140511725296544045876366493649140
    A_x = 54126340827016069202248324386975617769699311405281021967329662577891354929676
    A_y = 35173145737211266849758853035176194716800634647536075102730397609463108780650
    A_QCli_long = Point(A_x, A_y, eliptic_curve)

else:
    print("No Such ID was Registered. Try Again...")
    quit()


if GENERATE_EPHEMERAL_KEYS:
    print("*** Generating Ephemeral Keys ***\n")
    delete_epheremal_keys(stuID_A, A_s_long_term_key)
    # delete_epheremal_keys(stuID_B, B_s_long_term_key)
    store_eph_keys = {}
    for i in range(10):
        ephemeral_key_private, EKEY = generate_key(P_generator)
        concat = str(EKEY.x) + str(EKEY.y)
        h, s = generate_signature(concat, P_generator, n_order, A_s_long_term_key)
        # h, s = generate_signature(concat, P_generator, n_order, B_s_long_term_key)
        # send ephemeral key
        mes = { 'ID': stuID_A,
                'KEYID': i,
                'QAI.X': EKEY.x,
                'QAI.Y': EKEY.y,
                'Si': s,
                'Hi': h}
        response = requests.put('{}/{}'.format(API_URL, "SendKey"), json=mes)
        print(response.json(), i)
        store_eph_keys[i] = ephemeral_key_private
    memoFile = open("ephemeral_keys_" + str(stuID_A) + ".txt", "w")
    for key, value in zip(store_eph_keys.keys(), store_eph_keys.values()):
        memoFile.write( str(key) + "\t"  + str(value) + "\n")
    memoFile.close()
else:
    print("\n*** Using Pre-Generated Ephemeral Keys ***\n")
    memoFile = open("ephemeral_keys_" + str(stuID_A) + ".txt", "r")
    # memoFile = open("ephemeral_keys.txt", "r")
    temp = memoFile.readlines()
    store_eph_keys = {}
    for line in temp:
        indexTab = line.find("\t")
        store_eph_keys[int(line[:indexTab])] = int(line[indexTab+1:])

checkStatus(stuID_A, A_s_long_term_key)

if GET_MSG:
    getMsg(stuID_A, A_s_long_term_key)

if SEND_MSG_2_SERVER:
    QUOTES = [
        "The world is full of lonely people afraid to make the first move. Tony Lip",
        "I don’t like sand. It’s all coarse, and rough, and irritating. And it gets everywhere. Anakin Skywalker",
        "Hate is baggage. Life’s too short to be pissed off all the time. It’s just not worth it. Danny Vinyard",
        "Well, sir, it’s this rug I have, it really tied the room together. The Dude",
        "Love is like taking a dump, Butters. Sometimes it works itself out. But sometimes, you need to give it a nice hard slimy push. Eric Theodore Cartman",
    ]

    for quote in QUOTES:
        print("\n\nSending:", quote)
        
        res = getRecieversKey(stuID_A, stuID_B, A_s_long_term_key)
        print("\tGetting e_keys...")

        A_i, B_j, B_QBJx, B_QBJy = parseResponse(res)

        QBJ = Point(B_QBJx, B_QBJy, eliptic_curve)

        K_ENC = getSessionKey(store_eph_keys[A_i], QBJ)
        print("\t\tCalculatin session keys...")
        
        msg2encrypt = quote
        print("\t\t\tEncrypting MSG...")
        msg = encryptMsg(msg2encrypt, K_ENC)
        
        print("\t\t\t\tSending MSG...")
        sendMsg(stuID_A, stuID_B, msg, A_i, B_j)
        break