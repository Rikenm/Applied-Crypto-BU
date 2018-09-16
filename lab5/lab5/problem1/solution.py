
from binascii import hexlify, unhexlify
import string
import re
import argparse
import sys

def remove_binding(x):

    if (len(x)%2 !=0):       
        return "ERROR"
           
    x = unhexlify(x)
    

    
    # three errors
    if (len(x)%16 != 0):
        
        return "ERROR"
    
    last_byte = x[-1]
    
    
    # iterate all the padding and check if same
    for i in range(-1,(-1*(last_byte+1)),-1):
        
        if last_byte != x[i]:
            
            
            return "ERROR"
    
    
    return(x[:(-1*(last_byte))].decode())
        
        
    

    
        
if __name__=="__main__":
    
    print(remove_binding(sys.argv[1]))    
    
    
