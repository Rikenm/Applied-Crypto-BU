from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.strxor import strxor
from binascii import hexlify, unhexlify

def bytes_2_hex(my_input):
    numbers = map(int, my_input.split())

    result=""
    for i in numbers:
        if len(format(i,'x'))==1:
         result+="0"+format(i,'0x')
        else:
         result+=format(i,'0x')
    

    return(result) 

def Encipher(key, X):
  assert(len(X) == 16)               # 1 block == 16 bytes
  perm = AES.new(key, AES.MODE_ECB)  # ECB mode is a way to access the cipher directly
  Y = perm.encrypt(X)                # Compute AES in forward direction
  return Y                           # Return output as raw bytes



def cbcmac(K,M):
    message_partition = []
    
    for i in range(0,len(M),16):
        message_partition+= [M[i:i+16]]
    #print(message_partition) 
    
    for i in range(len(message_partition)):
        if i ==0:  # first block is special
            #print((M[i]))
            tagi = Encipher(K,message_partition[i])  #where tagi is intermediate tags
   
        else:
            tagi = Encipher(K,strxor(message_partition[i],tagi))    #where tagi is intermediate tags
    final_tag = tagi

    return (hexlify(final_tag))
                




