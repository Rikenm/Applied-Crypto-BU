
from Cryptodome.Hash import HMAC
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA as SHA1
from binascii import unhexlify,hexlify
import sys


def hmacsha1(key, message):
    return HMAC.new(key, message, SHA1).hexdigest() # Note: output is revealed in hex



def verify_then_decrypt(aes_key,hmac_key,alice_blob):

    #hex should always be even length.. 
    if (len(aes_key)%2 !=0) or (len(hmac_key)%2 !=0) or (len(alice_blob)%2 !=0):       
        return "ERROR"

    aes_key = unhexlify(aes_key)
    hmac_key = unhexlify(hmac_key)
    cipher = unhexlify((alice_blob[32:-40]))
    IV = unhexlify(alice_blob[:32])
    mac = alice_blob[-40:]
    
    #print(hexlify(cipher))

    

    
    if hmacsha1(hmac_key,cipher)== mac:
        H = AES.new(aes_key, AES.MODE_CBC,IV)
        x = H.decrypt(cipher)
        last_byte = x[-1]
        #print(x)

       
        for i in range(-1,(-1*(last_byte+1)),-1):
            
               
        
                if last_byte != x[i]:     # will never hit 
                    return("ERROR")
    
    
        return(x[:(-1*(last_byte))].decode())
    
    else:
        return("ERROR")
    
if __name__=="__main__":
    
    print(verify_then_decrypt(sys.argv[1],sys.argv[2],sys.argv[3]))     
        
        
    
        
        
    
    
    
    

