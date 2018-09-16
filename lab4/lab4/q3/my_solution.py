
from Crypto.Hash import HMAC,SHA256,SHA1,MD5
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.strxor import strxor
from binascii import hexlify, unhexlify
import string
import re


K = b"AES w/ fixed key"


def Encipher(X,key=K):
      assert(len(X) == 16)               # 1 block == 16 bytes
      perm = AES.new(key, AES.MODE_ECB)  # ECB mode is a way to access the cipher directly
      Y = perm.encrypt(X)                # Compute AES in forward direction
      return Y                           # Return output as raw bytes

def Sponge(inputString, outputLen):
    rc=bytes([0])*16
    iterate = int(len(inputString)/6)
    outputLenIterate = int(outputLen/6)
    
    output = b""
    
    for i in range(iterate+outputLenIterate):
        
        if i<iterate:
            
            I = strxor(rc[:6],inputString[i*6:(i+1)*6])  #input string keep on changing but rc is cosntant
            
            
            I = I+rc[6:]
            
          
            
            rc = Encipher(I)
        else:
            
            output+= rc[:6]
           
            I = rc
            
            rc= Encipher(I)
            

    return output


P=b"the length of this message is a multiple of the 6 byte sponge rate"
answer = (Sponge(P,30))
print((hexlify(answer)).decode("utf-8"))






