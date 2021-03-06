### This is a template file for a simple AES function.
##
##  Please implement the provided functions and assure that your code
##  works correctly for the example given below
##
##  Name: Kehan Wang
##  Date: Feb 10, 2015
##
# Rijndael S-box
sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
        0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
        0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
        0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
        0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
        0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
        0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
        0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
        0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
        0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
        0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
        0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
        0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
        0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
        0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
        0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
        0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
        0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
        0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
        0x54, 0xbb, 0x16]

iSbox =[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
        0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
        0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
        0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
        0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
        0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
        0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
        0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
        0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]

rc_table = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a]

def addRoundKey(state, roundKey):
        """Adds (XORs) the round key to the state."""

        # put your code here
        for i in range(len(state)):
            state[i] = state[i] ^ roundKey[i]
        return state

def subBytes(state):
        """Performs SubBytes operation on the state."""
        for i in range(len(state)):
            state[i] = sbox[state[i]]
        return state
      

def shiftRows(state):
        """Performs shiftRows operation on the state."""
        shifted_state = []
        for x in range(len(state)):
            shifted_state.append(0) #initial the shifted array
        for i in range(4):
            for j in range(4):
                shifted_state[i+4*j] = state[(i+4*(j+i)) % 16]
        return shifted_state

def mixColumns(state):
        """Performs mixColumns operation on the state."""
        mixed_state = []
        for x in state:
            mixed_state.append(0) #inital the result array
        for i in range(4):
            mixed_state[i*4] = GMul(2, state[i*4]) ^ GMul(3,state[i*4+1]) ^ state[i*4+2]  ^ state[i*4+3]
            mixed_state[i*4+1] = state[i*4] ^ GMul(2, state[i*4+1]) ^ GMul(3, state[i*4+2]) ^ state[i*4+3]
            mixed_state[i*4+2] = state[i*4] ^ state[i*4+1] ^ GMul(2, state[i*4+2]) ^ GMul(3, state[i*4+3])
            mixed_state[i*4+3] = GMul(3, state[i*4]) ^ state[i*4+1] ^ state[i*4+2] ^ GMul(2, state[i*4+3])
        return mixed_state

def GMul(a, b): #Galois Field (256) Multiplication of two Bytes
#reference : http://en.wikipedia.org/wiki/Finite_field_arithmetic
    p = 0
    for counter in range(8):
        if (b & 1) != 0:
            p = p ^ a
        carry = a & 0x80 % 256
        a =a << 1
        if carry != 0:
            a = a ^ 0x1b #/* x^8 + x^4 + x^3 + x + 1 */
        b =b >> 1
    return p%256


def iSubBytes(state):
        """Performs inverse SubBytes operation on the state."""
        for i in range(len(state)):
            state[i] = iSbox[state[i]]
        return state

def iShiftRows(state):
        """Performs inverse shiftRows operation on the state."""
        shifted_state = []
        for x in range(len(state)):
            shifted_state.append(0) #initial the shifted array
        for i in range(4):
            for j in range(4):
                shifted_state[i+4*j] = state[(i+4*(j-i)) % 16]
        return shifted_state

def iMixColumns(state):
        """Performs inverse mixColumns operation on the state."""
        mixed_state = []
        for x in state:
            mixed_state.append(0) #inital the result array
        for i in range(4):
            mixed_state[i*4] = GMul(14, state[i*4]) ^ GMul(11,state[i*4+1]) ^ GMul(13, state[i*4+2])  ^ GMul(9,state[i*4+3])
            mixed_state[i*4+1] = GMul(9, state[i*4]) ^ GMul(14, state[i*4+1]) ^ GMul(11, state[i*4+2]) ^ GMul(13, state[i*4+3])
            mixed_state[i*4+2] = GMul(13, state[i*4]) ^ GMul(9, state[i*4+1]) ^ GMul(14, state[i*4+2]) ^ GMul(11, state[i*4+3])
            mixed_state[i*4+3] = GMul(11, state[i*4]) ^ GMul(13, state[i*4+1]) ^ GMul(9, state[i*4+2]) ^ GMul(14, state[i*4+3])
        return mixed_state

def bytearray_xor(a, b):
    c = []
    for i in range(len(a)):
        c.append(a[i] ^ b[i])
    return c

def expandKey(key):
        """Expands the key using the appropriate key scheduling """
        roundKeys = [key]  #initial roundkeys
        for round_index in range(1, 11):
            new_key_parts = []
            prev_roundkey = roundKeys[round_index - 1]
            new_key_parts.append (  bytearray_xor(key_g(prev_roundkey[12:16], round_index), prev_roundkey[0:4]))
            #print "1st part of round %d :"%round_index,
            #print_bytearray(new_key_parts[0])
            for i in range(1, 4):
                new_key_parts.append ( bytearray_xor(new_key_parts[i-1] , prev_roundkey[i*4:(i+1)*4]))
                #print "%d part of round %d :" %(i,round_index),
                #print_bytearray(new_key_parts[i])
            roundKeys.append(concatenate_bytearray(new_key_parts))
            #print "round key of %d round generated: "%round_index
            #print_AES_block(roundKeys[round_index])
        return roundKeys

def concatenate_bytearray(bytearray_list):
    #print "##############Concatenate#################"
    rslt = bytearray()
    for i in range(len(bytearray_list)):
        #print_bytearray(bytearray_list[i])
        for j in range(len(bytearray_list[i])):
            rslt.append(bytearray_list[i][j])
            #print "find {0:x}".format(bytearray_list[i][j])
            #print "add to array: ",
            #print_bytearray(rslt)
    #print "############Concatenate end###############"
    return rslt

def print_bytearray(ary): #for debug
    for x in ary:
        print "%02x"%x,
    print 
    
def print_AES_block(blk): #for debug
    for i in range(4):
        for j in range(4):
            print format(blk[i+4*j], '02x'),
        print
    print

def key_g(key, round_index):
    #print "key_g input: ",
    #print_bytearray(key)
    rc = rc_table[round_index]
    rslt = bytearray([sbox[key[1]] ^ rc, sbox[key[2]], sbox[key[3]], sbox[key[0]]])
    #print "key_g result: ",
    #print_bytearray(rslt) 
    return rslt

def AES_encrypt(plaintext,key):
        """Performs an encryption on the plaintext """
        # init state
        state = bytearray(plaintext)
        roundkeys = expandKey(key) #get all the keys
        state = addRoundKey(state, roundkeys[0]) #round 0
        for key in roundkeys[1:-1]:#round 1 to 9
            state = subBytes(state)
            state = shiftRows(state)
            state = mixColumns(state)
            state = addRoundKey(state, key)
            #print_AES_block(state)
        #last round start
        state = subBytes(state)
        #print_AES_block(state)
        state = shiftRows(state)
        #print_AES_block(state)
        state = addRoundKey(state, roundkeys[-1])
        #end last round
        #print_AES_block(state)
        state = bytearray(state)
        ''' Debug
        print_AES_block(state)
        state = addRoundKey(state, key)
        print_AES_block(state)
        state = subBytes(state)
        print_AES_block(state)
        state = shiftRows(state)
        print_AES_block(state)
        state = mixColumns(state)
        print_AES_block(state)
        print GMul(83, 202)
        exit()
        '''    
        # return ciphertext
        return state

def AES_decrypt(ciphertext,key):
        """Performs an decryption on the ciphertext """
        # init state
        state = bytearray(ciphertext)
        roundkeys = expandKey(key)
        #start first round
        state = addRoundKey(state, roundkeys[-1])
        state = iShiftRows(state)
        state = iSubBytes(state)
        #print_AES_block(state)
        #end first round
        for key in reversed(roundkeys[1:-1]):
            state = addRoundKey(state, key)
            state = iMixColumns(state)
            state = iShiftRows(state)
            state = iSubBytes(state)
            #print_AES_block(state)
        #last round
        state = addRoundKey(state, roundkeys[0])
        #print_AES_block(state)
        state = bytearray(state)
        # return ciphertext
        return state


### Testing your code:

# initializing sample inputs (see FIPS 197):
pt  = bytearray.fromhex('32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34')
key = bytearray.fromhex('2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c')
ct  = bytearray.fromhex('39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32')
# print(hex(int.from_bytes(pt,'big')))

my_ct = AES_encrypt(pt,key)
if ct==my_ct:
        print('Good job!')
else:
        print('Still some more error fixing needed')


my_pt = AES_decrypt(ct,key)
if pt==my_pt:
        print('Good job!')
else:
        print('Still some more error fixing needed')
                
#Problem 5(b)
c = bytearray.fromhex('E5 5C D4 A8 EE E5 7D 26 1C 16 CA FE C9 40 A9 44')
key = bytearray.fromhex("00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15")
m = AES_decrypt(c, key)
print "The AES Message is: "
print_AES_block(m)







