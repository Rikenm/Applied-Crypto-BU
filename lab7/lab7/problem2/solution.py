from aeskeyexp import aes128_lastroundkey
from Cryptodome.Hash import HMAC
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA as SHA1
from Crypto.Util.strxor import strxor
from binascii import unhexlify,hexlify
import sys
import re

Sbox = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 ]

Sinv = [
0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]





def less_leaky_encipher(key, A):
    # I use the variables A, X, Y, and Z here just as in the previous routine
    
    # Let's compute Yvec just as we did before.
    assert(len(A) == 16)
    permutation = AES.new(key, AES.MODE_ECB)
    Z = permutation.encrypt(A)
    lastroundkey = aes128_lastroundkey(key)
    #print("key",lastroundkey)
    Y = strxor(Z, lastroundkey)
    Yvec = [ord(i) for i in Y]
    
    # Now we invert the SubBytes operation, but only store the set of the upper 4 bits of the result
    #Xvec = map(Sinv, Yvec)                       # This is the *list* of full bytes at the start of the 10th round
    Xvec = [Sinv[y] for y in Yvec]
    
    X = frozenset( map(lambda x: x >> 4, Xvec) ) # And now we form the *set* of values with the lower 4 bits truncated
    
    # Return the enciphering of A together with the *set* of cache lines accessed in round 10
    return [Z, X]

def question2(key):
    ''' going overkill'''
    Z1= less_leaky_encipher(key,b'mydataizbadsorrz')
    
    C1=hexlify(Z1[0])
    
    C1 = re.findall('..',C1)
    X1 = list(Z1[1])
    X1 = [(x<<4)+i for x in X1 for i in range(0,16)]
    Y1 = [Sbox[(x)] for x in X1]
    
    

    
    Z2 = less_leaky_encipher(key,b'mydataisbadsorrz')
    C2 = hexlify(Z2[0])
    C2 = re.findall('..',C2)
    X2 = list(Z2[1])
    X2 = [(x<<4)+i for x in X2 for i in range(0,16)]
    Y2 = [Sbox[(x)] for x in X2]
    
    
    
    Z3 = less_leaky_encipher(key,b'cydataisbadsorrz')
    C3 = hexlify(Z3[0])
    C3 = re.findall('..',C3)
    X3 = list(Z3[1])
    X3 = [(x<<4)+i for x in X3 for i in range(0,16)]
    Y3 = [Sbox[(x)] for x in X3]
   
    
    Z4 = less_leaky_encipher(key,b'czdataisbadsorrz')
    C4 = hexlify(Z4[0])
    C4 = re.findall('..',C4)
    X4 = list(Z4[1])
    X4 = [(x<<4)+i for x in X4 for i in range(0,16)]
    Y4 = [Sbox[(x)] for x in X4]
    
    Z5 = less_leaky_encipher(key,b'czdataisbadsorry')
    C5 = hexlify(Z5[0])
    C5 = re.findall('..',C5)
    X5 = list(Z5[1])
    X5 = [(x<<4)+i for x in X5 for i in range(0,16)]
    Y5 = [Sbox[(x)] for x in X5]
    
    Z6 = less_leaky_encipher(key,b'czdataisbadsorr1')
    C6 = hexlify(Z6[0])
    C6 = re.findall('..',C6)
    X6 = list(Z6[1])
    X6 = [(x<<4)+i for x in X6 for i in range(0,16)]
    Y6 = [Sbox[(x)] for x in X6]
    
    
    Z7 = less_leaky_encipher(key,b'czdataisbadsorr2')
    C7 = hexlify(Z7[0])
    C7 = re.findall('..',C7)
    X7 = list(Z7[1])
    X7 = [(x<<4)+i for x in X7 for i in range(0,16)]
    Y7 = [Sbox[(x)] for x in X7]
    
    Z8 = less_leaky_encipher(key,b'czdataisbadsorr3')
    C8 = hexlify(Z8[0])
    C8 = re.findall('..',C8)
    X8 = list(Z8[1])
    X8 = [(x<<4)+i for x in X8 for i in range(0,16)]
    Y8 = [Sbox[(x)] for x in X8]
    
    Z9 = less_leaky_encipher(key,b'czdataisbadsorr4')
    C9 = hexlify(Z9[0])
    C9 = re.findall('..',C9)
    X9 = list(Z9[1])
    X9 = [(x<<4)+i for x in X9 for i in range(0,16)]
    Y9 = [Sbox[(x)] for x in X9]
    
    Z10 = less_leaky_encipher(key,b'czdataisbadsorr5')
    C10 = hexlify(Z10[0])
    C10 = re.findall('..',C10)
    X10 = list(Z10[1])
    X10 = [(x<<4)+i for x in X10 for i in range(0,16)]
    Y10 = [Sbox[(x)] for x in X10]
    
    Z11 = less_leaky_encipher(key,b'czdataisbadsorr6')
    C11 = hexlify(Z11[0])
    C11 = re.findall('..',C11)
    X11 = list(Z11[1])
    X11 = [(x<<4)+i for x in X11 for i in range(0,16)]
    Y11 = [Sbox[(x)] for x in X11]
    
    Z12 = less_leaky_encipher(key,b'czdataisbadsorr7')
    C12 = hexlify(Z12[0])
    C12 = re.findall('..',C12)
    X12 = list(Z12[1])
    X12 = [(x<<4)+i for x in X12 for i in range(0,16)]
    Y12 = [Sbox[(x)] for x in X12]
    
    Z13 = less_leaky_encipher(key,b'czdataisbadsorrh')
    C13 = hexlify(Z13[0])
    C13 = re.findall('..',C13)
    X13 = list(Z13[1])
    X13 = [(x<<4)+i for x in X13 for i in range(0,16)]
    Y13 = [Sbox[(x)] for x in X13]
    
    Z14 = less_leaky_encipher(key,b'czdataisbadsorri')
    C14 = hexlify(Z14[0])
    C14 = re.findall('..',C14)
    X14 = list(Z14[1])
    X14 = [(x<<4)+i for x in X14 for i in range(0,16)]
    Y14 = [Sbox[(x)] for x in X14]
    
    Z15 = less_leaky_encipher(key,b'czdataisbadsorrj')
    C15 = hexlify(Z15[0])
    C15 = re.findall('..',C15)
    X15 = list(Z15[1])
    X15 = [(x<<4)+i for x in X15 for i in range(0,16)]
    Y15 = [Sbox[(x)] for x in X15]
    
    Z16 = less_leaky_encipher(key,b'czdataisbadsorrk')
    C16 = hexlify(Z16[0])
    C16 = re.findall('..',C16)
    X16 = list(Z16[1])
    X16 = [(x<<4)+i for x in X16 for i in range(0,16)]
    Y16 = [Sbox[(x)] for x in X16]
    
    Z17 = less_leaky_encipher(key,b'czdataisbadsorrl')
    C17 = hexlify(Z17[0])
    C17 = re.findall('..',C17)
    X17 = list(Z17[1])
    X17 = [(x<<4)+i for x in X17 for i in range(0,16)]
    Y17 = [Sbox[(x)] for x in X17]
    
    Z18 = less_leaky_encipher(key,b'czdataisbadsorrm')
    C18 = hexlify(Z18[0])
    C18 = re.findall('..',C18)
    X18 = list(Z18[1])
    X18 = [(x<<4)+i for x in X18 for i in range(0,16)]
    Y18 = [Sbox[(x)] for x in X18]
    
    Z19 = less_leaky_encipher(key,b'czdataisbadsorrn')
    C19 = hexlify(Z19[0])
    C19 = re.findall('..',C19)
    X19 = list(Z19[1])
    X19 = [(x<<4)+i for x in X19 for i in range(0,16)]
    Y19 = [Sbox[(x)] for x in X19]
    
    Z20 = less_leaky_encipher(key,b'czdataisbadsorr0')
    C20 = hexlify(Z20[0])
    C20 = re.findall('..',C20)
    X20 = list(Z20[1])
    X20 = [(x<<4)+i for x in X20 for i in range(0,16)]
    Y20 = [Sbox[(x)] for x in X20]
    
    Z21 = less_leaky_encipher(key,b'czdataisbadsorro')
    C21 = hexlify(Z21[0])
    C21 = re.findall('..',C21)
    X21 = list(Z21[1])
    X21 = [(x<<4)+i for x in X21 for i in range(0,16)]
    Y21 = [Sbox[(x)] for x in X21]
    
    Z22 = less_leaky_encipher(key,b'czdataisbadsorrp')
    C22 = hexlify(Z22[0])
    C22 = re.findall('..',C22)
    X22 = list(Z22[1])
    X22 = [(x<<4)+i for x in X22 for i in range(0,16)]
    Y22 = [Sbox[(x)] for x in X22]
    
    Z23 = less_leaky_encipher(key,b'czdataisbadsorrq')
    C23 = hexlify(Z23[0])
    C23 = re.findall('..',C23)
    X23 = list(Z23[1])
    X23 = [(x<<4)+i for x in X23 for i in range(0,16)]
    Y23 = [Sbox[(x)] for x in X23]
    
    Z24 = less_leaky_encipher(key,b'czdataisbadsorrr')
    C24 = hexlify(Z24[0])
    C24 = re.findall('..',C24)
    X24 = list(Z24[1])
    X24 = [(x<<4)+i for x in X24 for i in range(0,16)]
    Y24 = [Sbox[(x)] for x in X24]
    
    Z25 = less_leaky_encipher(key,b'czdataisbadsorrs')
    C25 = hexlify(Z25[0])
    C25 = re.findall('..',C25)
    X25 = list(Z25[1])
    X25 = [(x<<4)+i for x in X25 for i in range(0,16)]
    Y25 = [Sbox[(x)] for x in X25]
    
    Z26 = less_leaky_encipher(key,b'czdataisbadsorrt')
    C26 = hexlify(Z26[0])
    C26 = re.findall('..',C26)
    X26 = list(Z26[1])
    X26 = [(x<<4)+i for x in X26 for i in range(0,16)]
    Y26 = [Sbox[(x)] for x in X26]
    
    Z27 = less_leaky_encipher(key,b'czdataisbadsorru')
    C27 = hexlify(Z27[0])
    C27 = re.findall('..',C27)
    X27 = list(Z27[1])
    X27 = [(x<<4)+i for x in X27 for i in range(0,16)]
    Y27 = [Sbox[(x)] for x in X27]
    
    Z28 = less_leaky_encipher(key,b'czdataisbadsorrv')
    C28 = hexlify(Z28[0])
    C28 = re.findall('..',C28)
    X28 = list(Z28[1])
    X28 = [(x<<4)+i for x in X28 for i in range(0,16)]
    Y28 = [Sbox[(x)] for x in X28]
    
    Z29 = less_leaky_encipher(key,b'czdataisbadsorrw')
    C29 = hexlify(Z29[0])
    C29 = re.findall('..',C29)
    X29 = list(Z29[1])
    X29 = [(x<<4)+i for x in X29 for i in range(0,16)]
    Y29 = [Sbox[(x)] for x in X29]
    
    Z30 = less_leaky_encipher(key,b'czdataisbadsorrx')
    C30 = hexlify(Z30[0])
    C30 = re.findall('..',C30)
    X30 = list(Z30[1])
    X30 = [(x<<4)+i for x in X30 for i in range(0,16)]
    Y30 = [Sbox[(x)] for x in X30]
    
    Z31 = less_leaky_encipher(key,b'czdataisbadsor11')
    C31 = hexlify(Z31[0])
    C31 = re.findall('..',C31)
    X31 = list(Z31[1])
    X31 = [(x<<4)+i for x in X31 for i in range(0,16)]
    Y31 = [Sbox[(x)] for x in X31]
    
    Z32 = less_leaky_encipher(key,b'czdataisbadsor12')
    C32 = hexlify(Z32[0])
    C32 = re.findall('..',C32)
    X32 = list(Z32[1])
    X32 = [(x<<4)+i for x in X32 for i in range(0,16)]
    Y32 = [Sbox[(x)] for x in X32]
    
    Z33 = less_leaky_encipher(key,b'czdataisbadsor13')
    C33 = hexlify(Z33[0])
    C33 = re.findall('..',C33)
    X33 = list(Z33[1])
    X33 = [(x<<4)+i for x in X33 for i in range(0,16)]
    Y33 = [Sbox[(x)] for x in X33]
    
    Z34 = less_leaky_encipher(key,b'czdataisbadsor14')
    C34 = hexlify(Z34[0])
    C34 = re.findall('..',C34)
    X34 = list(Z34[1])
    X34 = [(x<<4)+i for x in X34 for i in range(0,16)]
    Y34 = [Sbox[(x)] for x in X34]
    
    Z35 = less_leaky_encipher(key,b'czdataisbadsor15')
    C35 = hexlify(Z35[0])
    C35 = re.findall('..',C35)
    X35 = list(Z35[1])
    X35 = [(x<<4)+i for x in X35 for i in range(0,16)]
    Y35 = [Sbox[(x)] for x in X35]
    
    Z36 = less_leaky_encipher(key,b'czdataisbadsor16')
    C36 = hexlify(Z36[0])
    C36 = re.findall('..',C36)
    X36 = list(Z36[1])
    X36 = [(x<<4)+i for x in X36 for i in range(0,16)]
    Y36 = [Sbox[(x)] for x in X36]
    
    Z37 = less_leaky_encipher(key,b'czdataisbadsor17')
    C37 = hexlify(Z37[0])
    C37 = re.findall('..',C37)
    X37 = list(Z37[1])
    X37 = [(x<<4)+i for x in X37 for i in range(0,16)]
    Y37 = [Sbox[(x)] for x in X37]
    
    Z38 = less_leaky_encipher(key,b'czdataisbadsor18')
    C38 = hexlify(Z38[0])
    C38 = re.findall('..',C38)
    X38 = list(Z38[1])
    X38 = [(x<<4)+i for x in X38 for i in range(0,16)]
    Y38 = [Sbox[(x)] for x in X38]
    
   
    
    Z39 = less_leaky_encipher(key,b'czdataisbadsor19')
    C39 = hexlify(Z39[0])
    C39 = re.findall('..',C39)
    X39 = list(Z39[1])
    X39 = [(x<<4)+i for x in X39 for i in range(0,16)]
    Y39 = [Sbox[(x)] for x in X39]
    
    Z40 = less_leaky_encipher(key,b'czdataisbadsor20')
    C40 = hexlify(Z40[0])
    C40 = re.findall('..',C40)
    X40 = list(Z40[1])
    X40 = [(x<<4)+i for x in X40 for i in range(0,16)]
    Y40 = [Sbox[(x)] for x in X40]
    
    
    
    
    
    
    
    
    answer=""
    
    for i in range(0,16):
        for y1 in Y1:
            
                c1 = C1[i]
                #print("c1","{0:b}".format((int(c1,16))))
                #print("c1-after","{0:b}".format((int(c1,16))>>4))
                
                keyi = (y1^(int(c1,16)))
                c2 = C2[i]
                c3 = C3[i]
                c4 = C4[i]
                c5 = C5[i]
                c6 = C6[i]
                c7 = C7[i]
                c8 = C8[i]
                c9 = C9[i]
                c10 = C10[i]
                c11 = C11[i]
                c12= C12[i]
                c13 = C13[i]
                c14 = C14[i]
                c15= C15[i]
                c16 = C16[i]
                c17 = C17[i]
                c18= C18[i]
                c19= C19[i]
                c20= C20[i]
                c21= C21[i]
                c22= C22[i]
                c23= C23[i]
                c24= C24[i]
                c25= C25[i]
                c26= C26[i]
                c27= C27[i]
                c28= C28[i]
                c29= C29[i]
                c30= C30[i]
                c31= C31[i]
                c32= C32[i]
                c33= C33[i]
                c34= C34[i]
                c35= C35[i]
                c36= C36[i]
                c37= C37[i]
                c38= C38[i]
                c39= C39[i]
                c40= C40[i]
                
                
                
                if keyi^(int(c2,16)) in Y2:
                    if keyi^(int(c3,16)) in Y3:
                        if keyi^(int(c4,16)) in Y4:
                            if keyi^(int(c5,16)) in Y5:
                                if keyi^(int(c6,16)) in Y6:
                                    if keyi^(int(c7,16)) in Y7:
                                        if keyi^(int(c8,16)) in Y8:
                                            if keyi^(int(c9,16)) in Y9:
                                                if keyi^(int(c10,16)) in Y10:
                                                    if keyi^(int(c11,16)) in Y11:
                                                        if keyi^(int(c12,16)) in Y12:
                                                            if keyi^(int(c13,16)) in Y13:
                                                                if keyi^(int(c14,16)) in Y14:
                                                                    if keyi^(int(c15,16)) in Y15:
                                                                        if keyi^(int(c16,16)) in Y16:
                                                                            if keyi^(int(c17,16)) in Y17:
                                                                                if keyi^(int(c18,16)) in Y18:
                                                                                    if keyi^(int(c19,16)) in Y19:
                                                                                        if keyi^(int(c20,16)) in Y20:
                                                                                            if keyi^(int(c21,16)) in Y21:
                                                                                                if keyi^(int(c22,16)) in Y22:
                                                                                                    if keyi^(int(c23,16)) in Y23:
                                                                                                        if keyi^(int(c24,16)) in Y24:
                                                                                                            if keyi^(int(c25,16)) in Y25:
                                                                                                                if keyi^(int(c26,16)) in Y26:
                                                                                                                    if keyi^(int(c27,16)) in Y27:
                                                                                                                        if keyi^(int(c28,16)) in Y28:
                                                                                                                            if keyi^(int(c29,16)) in Y29:
                                                                                                                                if keyi^(int(c30,16)) in Y30: 
                                                                                                                                    if keyi^(int(c31,16)) in Y31:
                                                                                                                                        if keyi^(int(c32,16)) in Y32:
                                                                                                                                            if keyi^(int(c33,16)) in Y33:
                                                                                                                                                if keyi^(int(c34,16)) in Y34:
                                                                                                                                                    if keyi^(int(c35,16)) in Y35:
                                                                                                                                                        if keyi^(int(c36,16)) in Y36:
                                                                                                                                                            if keyi^(int(c37,16)) in Y37:
                                                                                                                                                                if keyi^(int(c38,16)) in Y38:
                                                                                                                                                                    if keyi^(int(c39,16)) in Y39:
                                                                                                                                                                        if keyi^(int(c40,16)) in Y40:

                                                                                                                                                                            hex_keyi = (hex(keyi)[2:])
                                                                                                                                                                            #print(hex_keyi)
                                                                                                                                                                            if len(hex_keyi)==1: # if we get single len hex we need to add 0 so that 1 become 01, f becomes 0f etc
                                                                                                                                                                                 hex_keyi = "0"+hex_keyi
                                                                                                                                                                            answer = answer + hex_keyi

                                                                            
                                                            
                                
                                
                                
                                
                                
                                
                                
                                
                                
                                
                                
                                
    
                
    return(answer)

if __name__=="__main__":
    
    print (question2(sys.argv[1])) 


    
        
                   




