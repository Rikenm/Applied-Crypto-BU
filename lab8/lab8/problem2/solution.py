from Crypto.PublicKey import RSA
from fractions import gcd
from Crypto.Hash import SHA256



list1 = []

for i in range(1,101):
    
    pem = open("challenge/"+str(i)+".pem").read()
    k1 = RSA.importKey(pem)
    
    n = k1.n
    list1.append(n)

list2 = []
for i in range(len(list1)):
    for j in range(len(list1)):
        
        if (list1[i] is not list1[j]):
            gcd_value = gcd(list1[i],list1[j])
            if (gcd_value != 1):
                
                list2.append((i+1,gcd_value,(list1[i]//gcd_value)))
lsit = []
for i in list2:
    
    string1 = str(i[0])
    if i[1]<i[2]:
        string1 += " "+str(i[1])+" "+str(i[2])
    else:
        string1 += " "+str(i[2])+" "+str(i[1]) 
    lsit.append(string1) 

for i in lsit:
    print(i)
    




    
                    
