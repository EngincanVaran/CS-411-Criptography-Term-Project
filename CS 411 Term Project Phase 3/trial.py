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


def create_curve():
    eliptic_curve = Curve.get_curve('secp256k1')
    n_order = eliptic_curve.order
    p_field = eliptic_curve.field
    P_generator = eliptic_curve.generator
    a = eliptic_curve.a
    b = eliptic_curve.b

    return eliptic_curve, n_order, p_field, P_generator, a, b

res = {'IDB': 25050, 'KEYID': 0, 'MSG': 6162304549745641848745414924577321858059463376817452360807075634654189174299160571381675804966499351010120630591589874311505352487447279330948061840540306980999252098976388903625610192824564598320716804581913650865245664346479679679478133778475326389585713498739274738068160, 'QBJ.X': 53234525135579183757713199380466537942546909593967174331177763035359776331051, 'QBJ.Y': 18591241912824458805398898749975528428539860961336830553647437569087212895220}

eliptic_curve, n_order, p_field, P_generator, a, b = create_curve()

memoFile = open("ephemeral_keys_25050.txt", "r")
temp = memoFile.readlines()
store_eph_keys = {}
for line in temp:
    indexTab = line.find("\t")
    store_eph_keys[int(line[:indexTab])] = int(line[indexTab+1:])


IDB = res["IDB"]
KEYID = int( res["KEYID"] )
MSG = res["MSG"]
QBJx = res["QBJ.X"]
QBJy = res["QBJ.Y"]

print("\nMsg from:", IDB, "\n")

msg_byte = MSG.to_bytes((MSG.bit_length()+7)//8, byteorder='big')
QBJ = Point(QBJx, QBJy, eliptic_curve)

T = store_eph_keys[KEYID] * QBJ
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
    print("The message is not authentic.\n")
