from Cryptodome.PublicKey import RSA
from fractions import gcd
import sys





#mod inverse
def mult_mod_inverse(a, n):
 c = 1
 while (c % a > 0):
     c += n
 return c // a


def main():
    pem1 = open("mypem.pem").read()
    k1 = RSA.importKey(pem1)
    n = k1.n
    e = k1.e

    n2 = 2
    flag= True
    ''' prime1 = 662700133751480051 '''     #got from primefac library

    '''  I am iterating over numbers until I find the first first prime.'''

    while(flag):  
        prime1 = gcd(n,662700133751480051)   #to run comment this first
        #prime1 = math.gcd(n,n2)  then uncomment this line if you want to run the code
        if prime1 != 1:
            prime2 = n//prime1
            flag = False
        n2= n2+1
        
            
    #print(prime1,prime2) 
    #prime1= 878291059745115859 
    #prime2 = 662700133751480051


    tiotent_function = (prime1-1)*(prime2-1)



    d = mult_mod_inverse(e,tiotent_function)

    final_answer = (hex(d)[2:-1])  

    return(final_answer)

if __name__=="__main__":
    
    print(main()) 

