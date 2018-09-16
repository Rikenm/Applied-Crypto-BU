from Crypto.Hash import HMAC,SHA256,SHA1,MD5
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.strxor import strxor
from binascii import hexlify, unhexlify
import string
import re

P = b"a two block long private message"
IV = b"an initial value"
C = b"a random looking series of bytes"
M2 = b" private message"       # this will be constant for any collision message

I = strxor(P[0:16],IV)    #using this part to generate first 16 byte of any collision message
I2 = strxor(P[16:32],C[16:32])


def Collision(R):
    message1 = strxor(I,R)                   #getting first half of the new message
    final_message= message1+M2               #using first part of new message and last 16 byte from the old message
    return(hexlify(final_message))          


def main():
    print(Collision(b"some other value").decode("utf-8"))# function call and converting byte string to hex
    

if __name__ == "__main__":
    main()
 


