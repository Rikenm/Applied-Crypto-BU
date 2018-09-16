from Cryptodome.Hash import HMAC
from Cryptodome.Hash import SHA as SHA1
from Cryptodome.Util.strxor import strxor
from binascii import hexlify, unhexlify
import sys

def hmacsha1(key, message):
    return HMAC.new(key, message, SHA1).hexdigest() # Note: output is revealed in hex



def leaky_hmac_verify(key, message, claimed_tag):
    # Assume that the tag is well-formed, so it's even possible to be the hex encoding of an HMAC-SHA1 output (which would be 20 bytes long)
    assert(len(claimed_tag) == 40)

    # Test validity of the claimed tag
    valid_tag = hmacsha1(key, message)                         # This is what the tag should be, in hex

    is_valid_tag = (claimed_tag == valid_tag)

    if(is_valid_tag):                                          # The tag is valid, so the "first difference" is after the end of the string
        return [is_valid_tag, 4 * len(valid_tag)]
    else:                                                      # The tag is invalid, and we must find the location of the first difference
        diff = hexlify(strxor(unhexlify(claimed_tag),          # To do so, we take the xor between the (raw) tag and valid_tag
                              unhexlify(valid_tag)))           # and then find the first non-zero bit in this string (which is easier to do when hexlify'd)
        diffstrip = diff.lstrip("0".encode())                       # Remove all of the leading hex-0 characters
        first_diff_location = 4 * (len(diff) - len(diffstrip)) # Each leading hex-0 denotes four bits that are identical between the two strings
        
        #print("diff",diff)
        
        #print("diffstrip",diffstrip)
        
        #print("first_diff_location",first_diff_location)
        
        
        char = chr(diffstrip[0])                              # This character is guaranteed to be a non-zero hex character
        leading_bits = {'1' : 3,                               # This dictionary provides the # of leading zero bits for each non-zero hex character
                        '2' : 2,
                        '3' : 2,
                        '4' : 1,
                        '5' : 1,
                        '6' : 1,
                        '7' : 1,
                        '8' : 0,
                        '9' : 0,
                        'a' : 0,
                        'b' : 0,
                        'c' : 0,
                        'd' : 0,
                        'e' : 0,
                        'f' : 0,}
        first_diff_location += leading_bits[char]
        return [is_valid_tag, first_diff_location]             # Return whether the tag is correct *and* the location of the first difference

def forge(key):

    "main idea: leaky_hmac_verify gives max value when a hex value was replaced properly"

    
    key = unhexlify(key)
    message = b"This message was definitely sent by Alice"
    claimed_tag = "d22546b72f2b71d8a87d922df0108d471cbd58ca"  
    
    #0acd1f0248b85cf5f26ab4102110ae99c8de8187
    answer = leaky_hmac_verify(key, message, claimed_tag)
    
    index = 0
    iterate_this = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']  #my iterator 
    
    max_answer = answer[1]
    
    while(answer[1]!=160):
        
        
        
        
        
        if((max_answer -index) % 4 == 0):  #kerchoffs says except for keys everything is public. hence I used some ideas from leaky_hmac_verify to shortcut this instead of bruteforcing
                                           # I subtracted with index which can be 0,1,2,3. 
                                           # position is always divisble by 4. example 0,4,8 as professor multiplied by 4 in leaky_hmac_verify
            
            for i in iterate_this:
                
                if i=='0':
                    j =(int((max_answer-index)/4))  #finds the position where there was the error
                
                claimed_tag = claimed_tag[:j]+i+claimed_tag[j+1:]  #changing value at the error position with the for loop
                
                answer = leaky_hmac_verify(key, message, claimed_tag)
                
                
                
                if answer[1] == 160:    #found the answer
                    
                    max_i = i    #this is the hex value you would replace the error position with
                    
                    break
                
                
                if max_answer < answer[1]:  #always remember max value returned by leaky_hmac_verify
                    max_answer = answer[1]
                    max_i = i
                    
                
                #print("entering and saving as answer is ",max_answer,i,index,j, max_i)
                
            claimed_tag = claimed_tag[:j]+max_i+claimed_tag[j+1:]   
        
                    #break
                    
                    
                
                
                
                
            
            
            
        index = index+1  #0,1,2,3 incrementing
        
        if index == 4:
            index=0
        
        
            
        
    return(claimed_tag)

if __name__=="__main__":
    
    print(forge(sys.argv[1]),end="")         
            
            
