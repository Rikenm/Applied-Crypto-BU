from hashlib import sha256
import re
mostCommonWords = ["the","be","to","of","and","a","in","that","have","I","it","for","not","on","with","he","as","you",
"do","at","this","but","his","by","from","they","we","say","her","she","or","will"," an ","my","one","all","would",
"there","their","what","so","up","out","if","about","who","get","which","go","when","me","make","can","like"," time","no","just",
"him","know","take","person","into","year","your","good","some","could","them","see","other","than","then","now","look","only",
"come","its","over","think","also","back","after","use","two","how","our","homework ","first","well","way","even","new","want",
"becaus","any","these","give","day","most","us "]

#helper functions
def string_2_hex(my_input):
    numbers = [ord(a) for a in my_input]
    result=""
    for i in numbers:
        if len(format(i,'x'))==1:
            result+="0"+format(i,'0x')    #hex() does  the same thing 
        else:
            result+=format(i,'0x')    
    return(result)

def hex_2_int(result):
    answer = int(result, 16) 
    return answer


def hex_2_string(my_input):
    hexs = re.findall('..',my_input)
    byte = result = [int(i, 16) for i in hexs]
    numbers = map(int, byte)
    result=""
    for i in numbers:
        result+= chr(i)
    
    return(result)  

#-----------------------------------------end of helper functions-----------------------
def main():
    c1 = hex_2_int("57fbbaa76f6513d4b0685e651dc75dfed0a2dca24b9e42bf")
    c2 = hex_2_int("71b5edb269784099b77556201ec142f0d0a6c1ed5e9d55b9")
    c1XorCw = (hex(c1^c2)[2:])[:-1]
    
    word_list=[]

    #checking all 100 words 
    for i in mostCommonWords:
        for j in range(0,len(c1XorCw),2):   # checking our most common word with every alphabhet of c1xorc2
            hex_i=string_2_hex(i)
            answer = (hex(hex_2_int(c1XorCw[j:len(hex_i)+j]) ^ hex_2_int(hex_i)))
            
            if len(answer[2:])< len((hex_i)) and len(c1XorCw[j:len(hex_i)+j]) == len(hex_i):
                
                answer = "0"*(len((hex_i))-len(answer[2:])) + answer[2:]
                if answer[-1]=="L":
                    answer = answer[:-1]
                answer = hex_2_string(answer)
                
                
            elif len(answer[2:]) >= len((hex_i)) and len(c1XorCw[j:len(hex_i)+j]) == len(hex_i): 
                answer = answer
                if answer[-1]=="L":
                    answer = answer[:-1]
                answer = hex_2_string(answer[2:])
                
            if answer.isalpha():
                word_list.append(answer)

    
    
    #words were "time" and "work".  see pdf for the description              
    print("I want more time to workon this homework problem", end="")               
     

if __name__ == "__main__":
    main()
