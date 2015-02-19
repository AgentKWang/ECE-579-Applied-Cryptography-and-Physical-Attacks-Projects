### This is a template file for efficient modular exponentiation functions
### and a reference implementation of RSA PKCS #1, v2.1 encryption.
##
##  Please implement the provided functions and assure that your code
##  works correctly for the example given below
##
##  Name: Kehan Wang
##  Date: Feb 17, 2015
##

import time
import sys
sys.setrecursionlimit(4*2048)



def my_pow_SqMul(x,e,n):
    ''' Performs modular exponentiation (x^e mod n)
        using the square and multiply algorithm'''
    e_binary = bin(e) #get the binary of the e, returns a list starts with '0b'
    y = 1
    for i in e_binary[2:]: #filter the '0b' prefix and do the algorithm
        y = y * y
        if i == '1':
            y = y * x
        y = y % n
    return y

def my_pow_SlWin(x,e,n,k=4):
    ''' Performs modular exponentiation (x^e mod n)
        using the sliding window algorithm with window size k'''
    e_binary = bin(e) #convert e to binary string
    y = 1
    i = 2 
    while i < len(e_binary):
        if e_binary[i] == '0':
            y *= y
            i += 1
        else:
            #search the longest string
            j = i + k - 1
            if j >= len(e_binary): j = len(e_binary) - 1
            while j>i: #search backward to find the last position of longest string
                if e_binary[j] == '1': break
                else: j -= 1
            longest = int(e_binary[i:j+1], 2) #convert longest string to integer
            for index in range(j-i+1): y*=y #calculate y ^ (2^i-j+1)
            for index in range(longest): y*=x #calculate y * x^longest
            i = j + 1 #set next digit
        y %= n
    return y


def MGF(seed,maskLen):
    '''returns a mask of length maskLen, generated from seed using SHA-256'''
    import hashlib
    
    rslt = ""
    hLen = hashlib.sha256().digest_size
    if maskLen > 2**32*hLen: #size check
        print "mask too long"
        exit()
    for counter in range(0,-(-maskLen//hLen)):
        C = bytearray(seed)
        for i in range(4):
            C.append(counter // 256**(3-i)) #generate C = mgfseed||C
        rslt += hashlib.sha256(C).hexdigest()#T=T||Hash(mgfseed||C)
    rslt = rslt[:maskLen*2]  #cut the string to match required length
    T=bytearray().fromhex(rslt)
    return T


def RSAESencrypt(N,e,m,L=bytearray()):
    '''Performs RSA PKCS #1 v2.1 encryption using the public key <N,e>
        on message m (optinal: label L). Ciphertext c is returned.
        N and e are integers, m, L, and c are byte arrays'''

    import hashlib
    import os

    
    mLen = len(m)
    hLen = hashlib.sha256().digest_size # since we use SHA256

    # put your code here:

    # check lengths
    # generate DB
    # seeding and masking
    # generate EM
    # perform encryption
    c=bytearray()

    return c


def RSAESdecrypt(N,d,c,L=bytearray()):
    '''Performs RSA PKCS #1 v2.1 decryption using the private key <N,d>
        on ciphertext c (optinal: label L). Message m is returned.
        N and d are integers, m, L, and c are byte arrays'''

    import hashlib
    import os


    cLen = len(c)
    hLen = hashlib.sha256().digest_size # since we use SHA256

    # put your code here:
    # check lengths
    # decrypt C
    # separate EM
    # remove masks
    # check DB

    #Note.  Care must be taken to ensure that an opponent cannot
    #distinguish the different error conditions in Step 3.g, whether by
    #error message or timing, or, more generally, learn partial
    #information about the encoded message EM.  Otherwise an opponent may
    #be able to obtain useful information about the decryption of the
    #ciphertext C, leading to a chosen-ciphertext attack such as the one
    #observed by Manger
    m=bytearray()
    
    return m
    
    
p =  997782014483135516947467112733783206034059987091508997470391422588302757009297888172824321316039986332404368187672035334285863264469832007564899663393813987428733469948510589362567714925225591609164647780163771437334778893745924369236957875430167009790722454797434933978389194431730946950351883503681 
q = 79301961686790288135761596161932125982627215111620602465105295605167614622099617732042554017601029601972431354155023876998569040821697397911153196884814759437163993503206804558864234356549520950879755905643095880867184872343043391321834768955404845085269931482274291437512222693097323499756682477811051
#p = 8176662165573700613347344450959887037086515168356394479546398903326976319674343656956828452558146536261756580874692178418735952635936011308339369316896181
#q = 13062362680240858986014063047218740765842583586324085493117801839987719301360641696613806125427125208683501703668298486807198605540347486024024409678675789

N = p*q

b = 3
e = 2**1000-1
m = N

tic = time.clock()
out = pow(b,e,m)
toc = time.clock()
Tpow = toc-tic

tic = time.clock()
out2 = my_pow_SqMul(b,e,m)
toc = time.clock()
Tsqmul=toc-tic

tic = time.clock()
out3 = my_pow_SlWin(b,e,m)
toc = time.clock()
Tslwin=toc-tic


print ('Build-in POW: works (in ', Tpow, 's)') #professor seems forgot this line =)

if(out == out2):
    print('Square and multiply: works (in ',Tsqmul,'s)')
else:
    print('Square and multiply: failed')

if(out == out3):
    print('Sliding Window:      works (in ',Tslwin,'s)')
else:
    print('Sliding Window:      failed')




# Testing RSA encryption and decryption
# don't mess with tese numbers:
p = 8176662165573700613347344450959887037086515168356394479546398903326976319674343656956828452558146536261756580874692178418735952635936011308339369316896181
q = 13062362680240858986014063047218740765842583586324085493117801839987719301360641696613806125427125208683501703668298486807198605540347486024024409678675789
N = p*q
e = 2**16+1
d = 95305639297136535129830247353885048571790931736897092024327830574503233416208940851818667509421055075611745557004095412620624213281032376171998990351263574092801357243118351700307075125243451771395731520183667695423762834718377372357353733379277776224241008883890378073612334038347526558549705139740335907073

# Test MGF:
print('Starting MGF Test: ')
seed = bytearray()
for cnt in range(33):
    seed.append(cnt)

check = MGF(seed,42)
correct = bytearray(b'_\xf0\x98\xa3\xa9\xe7\xa9=\xc6\x04\x99\xf1\xa6\xfb\xf6\x8cW\x9c\x90B\xd6\x9cEs\x1d\xf9\xd7\xa8\x0e\xfb)\xaf\xc0\xc9\n=\x9e\x8a\x11\x18o;')
if len(check)!=42:
    print('error: wrong output length')
elif(check != correct):
    print('failed: wrong output')
else:
    print('passed')

'''
# Test RSA Encryption and decryption:
print('Starting first RSA Test: ',end = '')

m = b'\x02\xff'
c = RSAESencrypt(N,e,m)
mp = RSAESdecrypt(N,d,c)
if (mp!=m):
    print('failed: message not recovered')
else:
    print('passed')
# DB= bytearray(b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$\'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\xff"

print('Starting second RSA Test: ',end = '')
m = correct
c = RSAESencrypt(N,e,m)
mp = RSAESdecrypt(N,d,c)
if (mp!=m):
    print('failed: message not recovered')
else:
    print('passed')
# DB= bytearray(b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$\'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01_\xf0\x98\xa3\xa9\xe7\xa9=\xc6\x04\x99\xf1\xa6\xfb\xf6\x8cW\x9c\x90B\xd6\x9cEs\x1d\xf9\xd7\xa8\x0e\xfb)\xaf\xc0\xc9\n=\x9e\x8a\x11\x18o;")

print('Starting first RSA Failure Test: ',end = '')

m = correct+correct+correct
try:
    c = RSAESencrypt(N,e,m)
except IOError:
    print('passed')
else:
    print('failed')

print('Starting second RSA Failure Test: ',end = '')

c = b"A\xe0\xe5\xe6G)\xbc\x04\xd3'\xe50@/\xddiy\xff\xd0\x8b\xc8U\x10p\xf5v{`\xa7\x19o\xe5\xb3X~\x10\xbf7eN\x9ey\x9f\x1d\xe9\xe8\x89\xbcxX\xee\x95\xf5\xdf\xc7M\x91\xc3\x84C\x15]a\xf9\xcf]\xb4r\x06\xb8QL\x86\x19^NF\xd2\xf6|\xeb\x10G\xc6\x0b\x87\x07\xd1O\xff(\xadk\xe1Cj\xfc\xbc=\xee\x16cc\xb69\xb3\xcb\x92 e+G\x1f\x85&~4p\xc2\x8f]\xf2\xfb\xee\xa6\xe2oJ"
try:
    m = RSAESdecrypt(N,e,c)
except IOError:
    print('passed')
else:
    print('failed')
'''

