
from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor
from binascii import hexlify, unhexlify
import string
import re
key1 = b"sixteen byte key"
tag = b"2508d4f10d74162f44368d8e7c07dcbe"

#------------start of the helper functions-------------
def byte_2_hex(my_input):

 numbers = map(int, my_input.split())

 result=""
 print(numbers)   
 for i in numbers:
    if len(format(i,'x'))==1:
     result+=format(i,'0x')
    else:
     result+=format(i,'0x')
 return(result)  

def hex_2_string(my_input):

    

    hexs = re.findall('..',my_input)
    byte = result = [int(i, 16) for i in hexs]
    numbers = map(int, byte)
    result=""
    for i in numbers:
        result+= chr(i)
    return(result)

def string_2_hex(my_input):
    
    numbers = [ord(a) for a in my_input]
    result=""
    for i in numbers:
        if len(format(i,'x'))==1:
            result+="0"+format(i,'0x')    #hex() does  the same thing 
        else:
            result+=format(i,'0x')
   
    
    return(result)

def byte_2_string(my_input):
    numbers = map(int, my_input.split())

    result=""

    for i in numbers:
        result+= chr(i)
    
    return(result)  
#------------end of the helper functions-------------
def hash_from_cbcmac(M):
    return cbcmac(key1,M)

def cbcmac_32(K,M):
    '''as I was not able to find printable string as collision(3rd checkpoint). I 
    just have hex which are 32 length longs(or 128 bits long) which cannot be converted to ascii as it
    contains non ascii strings. basically a garbage collision I found'''
    
    message_partition = []
    for i in range(0,len(M),32):
        message_partition+= [M[i:i+32]]
    #
    
    for i in range(len(message_partition)):
        if i ==0:  # first block is special
            
            tagi = Encipher(K,message_partition[i])  #where tagi is intermediate tags
   
        else:
            tagi = Encipher(K,strxor(message_partition[i],tagi))    #where tagi is intermediate tags
            
    final_tag = tagi

    return (final_tag)

def cbcmac(K,M):   #normal cbc function
    message_partition = []
    
    for i in range(0,len(M),16):
        message_partition+= [M[i:i+16]]
    
    
    for i in range(len(message_partition)):
        if i ==0:  # first block is special
            #print((M[i]))
            tagi = Encipher(K,message_partition[i])  #where tagi is intermediate tags
   
        else:
            tagi = Encipher(K,strxor(message_partition[i],tagi))    #where tagi is intermediate tags
            
    final_tag = tagi

    return (final_tag)




def decipher(C,key=key1):
    "AES_decipher function"
    
    cipher = AES.new(key,AES.MODE_ECB)
    plaintext = cipher.decrypt(C)
    
    return((plaintext))

def Encipher(key, X):
  #assert(len(X) == 16)               # 1 block == 16 bytes
  perm = AES.new(key, AES.MODE_ECB)  # ECB mode is a way to access the cipher directly
  Y = perm.encrypt(X)                # Compute AES in forward direction
  return Y                           # Return output as raw bytes

def hash_breaker(final_tag):
    message = []
    T = decipher(final_tag)
    return(T)
#--------solving---------problem 3----------

# my idea is to reverse engineer the final_tag and xor my custom messages in between these processes.  
    
final_tag = b"2508d4f10d74162f44368d8e7c07dcbe"  #i need to find collision to this tag

print("We have to find msg which collides with",final_tag,"\n")

intermediate3 = (hash_breaker((final_tag)))    #using decipher function to go back from the final hash to the intermediate value
msg3 = string_2_hex("I need more time")
msg3 = (msg3.encode('utf-8')) #converting my custom message into bytecode that contains hex  (16 character long or 32 hex long)


my_byte2=(strxor(intermediate3,msg3))  #I xor'd "my message" and AES_decipher(final_tag)this 32 hex value is passed to 2nd AES decipher

intermediate2 = (hash_breaker((my_byte2)))  #passing back my_byte2 to AES_Decipher and obtaining intermediate2

msg2 = string_2_hex("I need more time")
msg2 = (msg2.encode('utf-8'))  #converting that same custom message into bytecode that contains hex  (16 character long or 32 hex long)

my_byte1=(strxor(intermediate2,msg2))  

msg1 = (hash_breaker((my_byte1)))  # no intermediate as there was no Xor value
   # msg1  b'\xcf\xed\x00\x97eUI\xc2\xde\xbe9;k\x98\x93C\x0f\rq\x8aI\xf1\x11\xee\xcb\x8aB\x8d\x9a\x9f\xd3L
# msg1 is hex which is 32 in length or 128 bits long

#---------constructing the collision msg------
final_msg = msg1+msg2+msg3
final_msg = (final_msg)

print("Collision found",cbcmac_32(key1,final_msg))   

#final_msg looks weird as it is has character which are not in ascii but final msg is 3 block longs or 48 bytes long
print("Final_msg looks weird as it has character which are not in ascii but final msg is 3 block longs or 48 bytes long and different"
      +" from the provided msg by the professor\n")
print("The final msg is",final_msg,"\n")
print("The len of the final hex msg is",len(final_msg),"or 48 bytes long")
