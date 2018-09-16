import re
dict_f ={"0":"6","1":"4","2":"c","3":"5","4":"0","5":"7","6":"2","7":"e","8":"1","9":"f","a":"3","b":"d","c":"8","d":"a","e":"9","f":"b"}
dict_inv ={"6":"0","4":"1","c":"2","5":"3","0":"4","7":"5","2":"6","e":"7","1":"8","f":"9","3":"a","d":"b","8":"c","a":"d","9":"e","b":"f"}

def byte_2_hex(my_input):

 numbers = map(int, my_input.split())
 result=""
 for i in numbers:
    if len(format(i,'x'))==1:
     result+=format(i,'0x')
    else:
     result+=format(i,'0x')
 return(result)

def hex_2_byte(my_input):
    
 hexs = re.findall('..',"0"+my_input)
 result = [int(i, 16) for i in hexs]   
 return((result[0]))

#----------------------end of helper functions----------------------

def TOY(v,key):
    
   v = hex_2_byte(v)   #byte form
   key = hex_2_byte(key)
   answer = dict_f[byte_2_hex(str(v^key))] 
   return(answer)

def TOY_Inv(w,key):
          
        dict_value = hex_2_byte(dict_inv[w])
        key = hex_2_byte(key)    #int(f) is not f integer
        answer = dict_value^(key)
        return(byte_2_hex(str(answer)))

def mimtm_2TOY(v,x): 
    v = v[-1].lower()
    x = x[-1].lower()
    
    w_1={}
    w_2={}
    

    list_1 = []
    
    for i in range(16):

        w_1[TOY(v,byte_2_hex(str(i)))] = byte_2_hex(str(i))
        w_2[TOY_Inv(x,byte_2_hex(str(i)))]=  byte_2_hex(str(i))
        
        list_1.append(TOY(v,byte_2_hex(str(i))))
    answer=""
    for i in list_1:
        answer+=w_1[i]+w_2[i]
        
    return (answer)    


def main():
  print(mimtm_2TOY("0xa","0xb"), end="")
    
    
#--------------------------------

if __name__ == "__main__":
    main()

   
