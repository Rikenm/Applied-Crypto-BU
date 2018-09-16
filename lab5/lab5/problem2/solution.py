

from binascii import hexlify, unhexlify
import string
import urllib.request as request
from urllib.error import URLError, HTTPError

URL = "https://id0-rsa.pub/problem/cbc_padding_oracle/c6574d8a54c952a7f298673ee7063c16ecf5f6d6405e2ad74254ff211635e390/"
def cbc_attack():
    sub_Url = "c6574d8a54c952a7f298673ee7063c16ecf5f6d6405e2ad74254ff211635e390"
    
    IV = "c6574d8a54c952a7f298673ee7063c16"
    temp = IV
    c=[]
    
    run = False  #make this true to run the full code else False gives you string only   <---------------------------
    
    
    if (run):
    
        for j in range(30,-1,-2):   # starting from backward 30, 28,26......0
            iv = (IV[j:j+2])     # just taking two value from the IV at a time
                                #for example for 1st iteration, IV[30:32]=90 , 2nd iter IV[28:30]=e3
            print(iv)
    
            for i in range(256):    # iterating hex from 00 to ff to replace a byte of hex.   
        
        
                iter = hex(i)[2:]    #converting integer to hex
            
                if len(hex(i)[2:])==1: # if we get single len hex we need to add 0 so that 1 become 01, f becomes 0f etc
                    iter = "0"+iter
            
            
                if  hex(i)[2:] != iv:  #we will just iterate 255 instead of 256           
                    IV2 = IV[:j]+iter+IV[j+2:]   #modifing IV for URL by replacing in following way 
                                                #first iteration replaces last byte
                                               #2nd iteration replaces second to last, third and so on 
                                               #until we reach the first byte                
                    print(IV2)
        
    
    
    
                URL = "https://id0-rsa.pub/problem/cbc_padding_oracle/"+IV2+"ecf5f6d6405e2ad74254ff211635e390"
                print(URL)             # modified URL
    
                #URL request 
                try:
                    response = request.urlopen(URL)
                except HTTPError as e:
                    #print('The server couldn\'t fulfill the request.')
                    #print('Error code: ', e.code)
                    e = e.code
                else:
                    print("fine, properly padded")
                    html = response.read()
                   
                    
                    #step below is to find d from the slide and create URL
                    #so that we won't need to brute force all the combination
                    
                    c=[i]+c  # saved the current i to an array c. for 1st byte i was 20 which is  0x14 in hex
                               # when creating an URL this value is replaced by d so 0x14 becomes 0x17.
                               # i created c just to keep track of how many values I need to change while creating an URl.
                               # for instance when we get 2nd padding sucess. 
                               # we have to change c6574d8a54c952a7f298673ee7063d17 to c6574d8a54c952a7f298673ee7063c16
                               # c will have [0x3d,0x17]. C has two values 
                                #so I need to change two values to form d values, which are [0x3c,0x16]
                               # here 3c16 is d and we replace last two byte from the origianl IV and start iterating 
                               #third to last value which is 0x06 from 00 to ff
               
                    intermediate2=""  
                    
                    if (j!=0):   # for first byte of IV we don't need to create an URL as we are done. everything else 
                                #should follow this
                
                        for i in range(len(c)):  #when c = [0x3d,0x17] we have to change these two values one at a time
                            intermediate = (c[i]^len(c))   #---i) 
                                                           # intermediate is "a" from the slide
                                                           #below task is done one at a time by -----i)           
                                                           #0x3d xor len([0x3d,0x17]) = 0x3d xor 0x02 = 3f  
                                                           #0x17 xor len([0x3d,0x17]) = 0x17 xor 0x02 = 15  
                    
                    
                            if len(hex(intermediate^len(c)+1)[2:])!=2:  
                                intermediate2 += "0"+hex(intermediate^len(c)+1)[2:]    #intermediate2 is "d" from the slide
                            else:
                                intermediate2 += hex(intermediate^len(c)+1)[2:]  
                                
                                                                    #d is found using following:
                                                                    # intermediate, which is a xor 0x03 
                                                                    #0x3f xor len([0x3d,0x17])+1 =0x3f xor 0x03 =0x3c 
                                                                    #0x15 xor len([0x3d,0x17])+1 =0x15 xor 0x03 =0x16    
 
                            print ("d construction happening",intermediate2)
                            c[i]=(intermediate^len(c)+1)    #[0x3d,0x17] becomes [0x3c,0x16] 
        
                        IV = IV[:j]+intermediate2  # so replace c6574d8a54c952a7f298673ee706[3d17] with c6574d8a54c952a7f298673ee706[3c16]
                                                    # this new c6574d8a54c952a7f298673ee706[3c16] where [3c16] is our d
                                                    #now add this to URL and iterate 06 from 00 to ff         
                
                        print("old IV + new d=",IV)
                    else:                       # when we are  at the first byte(aka last iteration of j). 
                                                #no need to create an url. just get the Final form of the IV
                        IV = hex(i)[2:]+IV[2:]   # final form of IV is 921514d40f9614f6aedc3e60b2152f05
   
                    break
                
            print(IV) 
        a="c6574d8a54c952a7f298673ee7063c16"  #initial IV given 
        b= IV    #FINAL form of the IV is 921514d40f9614f6aedc3e60b2152f05 . this is final d
        a_numb = int(a, 16)   # converted initial IV hex to int so that I can do python Xor
        b_numb = int(b, 16)   # converted final form of IV hex to int so That I can do python XOr
        answer = unhexlify((hex((a_numb^b_numb)^int("10101010101010101010101010101010",16)))[2:])   #found the message
        
        print("final_answer: ",answer[:-3].decode("utf-8")) #removing 3 bytes of padding that is present and converting byte to string
    
    else:
        print("DRINKOVALTINE",end="")  #DRINKOVALTINE was the message. It has 030303 as padding which I removed
        
    

  


   
cbc_attack()    
