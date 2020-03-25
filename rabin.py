import sys

# nrabin is from generation step
nrabin = 4217395290811936631121178575312461530113782099783787847834492818064911012031411796679351964348412926111264326618123885865435027964228145620997254703675969547395322707076629667218264374123406950997090598188586120982230094258297445561651716844354022174433953787954778810911390283264364147274596015993453

# *******************************************************************************
# HASH FUNCTION WITH SPRITZ
# *******************************************************************************
def updateSPZ():
    global aSPZ, iSPZ, jSPZ, wSPZ, sSPZ
    iSPZ = (iSPZ + wSPZ) % 256
    jSPZ = sSPZ[(jSPZ + sSPZ[ iSPZ ]) % 256]
    sSPZ[ iSPZ ], sSPZ[ jSPZ ] = sSPZ[ jSPZ ], sSPZ[ iSPZ ]

def outputSPZ():
    global aSPZ, iSPZ, jSPZ, wSPZ, sSPZ
    updateSPZ()
    return sSPZ[jSPZ]

def shuffleSPZ():
    global aSPZ, iSPZ, jSPZ, wSPZ, sSPZ
    for v in range(256):
        updateSPZ()    
    wSPZ = (wSPZ + 2) % 256
    aSPZ = 0

def absorb_nibbleSPZ(x):
    global aSPZ, iSPZ, jSPZ, wSPZ, sSPZ
    if aSPZ == 240:
        shuffleSPZ()
    sSPZ[aSPZ], sSPZ[240 + x] = sSPZ[240 + x], sSPZ[aSPZ]
    aSPZ = aSPZ + 1

def absorb_byteSPZ(b):
    absorb_nibbleSPZ(b % 16)
    absorb_nibbleSPZ(b / 16)

def squeezeSPZ(out, outlen):
    global aSPZ, iSPZ, jSPZ, wSPZ, sSPZ
    if aSPZ != 0:
        shuffleSPZ()
    for v in range(outlen):
        out.append( outputSPZ() )

def hg(x):
  global aSPZ, iSPZ, jSPZ, wSPZ, sSPZ
  jSPZ = iSPZ = aSPZ = 0
  wSPZ = 1
  sSPZ = range(256)
  for c in x:
     absorb_byteSPZ(ord(c)) 
  res = []
  squeezeSPZ(res, 128)
  out = 0 
  for bx in res:
    out = (out<<8) + bx
  return out % (2**1000)

def h(x):
  global aSPZ, iSPZ, jSPZ, wSPZ, sSPZ
  global nrabin
  jSPZ = iSPZ = aSPZ = 0
  wSPZ = 1
  sSPZ = range(256)
  for c in x:
     absorb_byteSPZ(ord(c)) 
  res = []
  squeezeSPZ(res, 128)
  out = 0 
  for bx in res:
    out = (out<<8) + bx
  return out % (nrabin)

def bin2num(x):
  res = 0
  for c in x:
    res = (res<<8) ^ ord(c)
  return res

def num2bin(x):
  res = ''
  while x > 0:
    res = chr(x % 256) + res
    x /= 256
  return res

def digital2num(x):
  res = 0
  for c in x:
    if ord(c) >= 48 and ord(c) <= 57:
      res = (res*10) + ord(c) - 48
  return res

def hextxt2num(x):
  res = 0
  for c in x:
    if ord(c) < 58 and ord(c) >= 48:
       res = (res<<4) + ord(c) - 48
    elif ord(c) <= ord('f') and ord(c) >= ord('a'):
       res = (res<<4) + ord(c) - 87
  return res

def num2hextxt(x):
  res = ''
  h__ = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
  while x > 0:
    res = h__[x % 16] + res
    x /= 16
  return res

def code2num(x):
  res = 0
  for c in x:
     if ord(c) >= 48 and ord(c) < 58:
       res = (res << 6) + ord(c) - 48
     if ord(c) >= 65 and ord(c) < 91:
       res = (res << 6) + ord(c) - 55
     if ord(c) >= 97 and ord(c) < 123:
       res = (res << 6) + ord(c) - 61
     if c == '#': 
       res = (res << 6) + 62
     if c == '/': 
       res = (res << 6) + 63
  return res

def num2code(x):
  res = ''
  while x > 0:
    y = x % 64
    if y < 10:
       res = chr( y + 48 ) + res
    elif y < 36:
       res = chr( y + 55 ) + res
    elif y < 62:
       res = chr( y + 61 ) + res 
    elif y == 62:
       res = '#' + res 
    elif y == 63:
       res = '/' + res 
    x /= 64
  return res

def gcd(a,b):
  if b > a:
    a,b = b,a
  while b > 0:
    a,b = b,a % b
  return a

def nextPrime(p):
 while p % 4 != 3:
   p = p + 1
 return nextPrime_3(p)
  
def nextPrime_3(p):
  m_ = 3*5*7*11*13*17*19*23*29
  while gcd(p,m_) != 1:
    p = p + 4 
  if (pow(2,p-1,p) != 1):
      return nextPrime_3(p + 4)
  if (pow(3,p-1,p) != 1):
      return nextPrime_3(p + 4)
  if (pow(5,p-1,p) != 1):
      return nextPrime_3(p + 4)
  if (pow(17,p-1,p) != 1):
      return nextPrime_3(p + 4)
  return p
  
# sign: calculate S
def root(m, p, q):
  x = h(m)
  # a & b are from generation step
  a = 5
  b = 6
  if pow(x, (p-1)/2, p) > 1:
    x *= a
  if pow(x, (q-1)/2, q) > 1:
    x *= b
#  print pow(x, (q-1)/2, q)
#  print pow(x, (p-1)/2, p)
  return (pow(p,q-2,q) * p * pow(x,(q+1)/4,q) + pow(q,p-2,p) * q * pow(x,(p+1)/4,p)) % (nrabin) 


def writeNumber(number, fnam):
  f = open(fnam, 'wb')
  n = number
  while n > 0:
    byte = n % 256
    n = n / 256
    f.write(chr(byte))
  f.close()

def readNumber(fnam):
  f = open(fnam, 'rb')
  n = 0
  snum = f.read()
  for i in range(len(snum)):
    n = (n << 8) ^ ord(snum[len(snum)-i-1])   
  f.close()
  return n

def random512():
  md = hashlib.sha512("RANDOM-SEED")
  md.update('large key value for generation of random number')
  md.update( str(random.random()) )
  md.update( str(random.random()) )
  result = 0
  largestr = md.digest()
  for i in range(len(largestr)):
      result = (result << 8) ^ ord(largestr[i])
  return result

def random1024():
  return random512() * random512()

def hF(fnam):
  f = open(fnam,'r')
  return h(f.read())

def sF(fnam):
  p = readNumber("p")
  q = readNumber("q")

  # contains message to sign
  f = open(fnam,'r')
  s = root (f.read(), p, q)
  f.close()
  return s

# find factors a and b from primes p,q
def f_ab(p,q):
  res = [3,3]
  while pow(res[0], (p-1)/2, p) == 1 or pow(res[0], (q-1)/2, q) != 1:
    res[0] = res[0] + 1
  while pow(res[1], (p-1)/2, p) != 1 or pow(res[1], (q-1)/2, q) == 1:
    res[1] = res[1] + 1
  return res

def vF(s, fnam):
  # a & b are from generation step
  a = 5
  b = 6
  h0 = hF(fnam)
  ha = (a*h0) % nrabin
  hb = (b*h0) % nrabin
  hab = (a*b*h0) % nrabin

  sq = (s * s) % nrabin
  return (h0 == sq) or (ha == sq) or (hb == sq) or (hab == sq)
 
print("\n\n rabin signature - copyright Scheerer Software 2018 - all rights reserved\n\n")
print("First parameter is V (Verify) or S (Sign) or G (Generate) \n\n")
print("\n\n verify signature (2 parameters):")
print("   > python rabin.py V <filename> <digital signature> ")

print(" create signature S (2 parameter):")
print("   > python rabin.py S <filename> \n\n")

print(" number of parameters is " + str(len(sys.argv)-1))
print(" ")
print(" ")

if  len(sys.argv) == 4 and sys.argv[1] == "V":
  print("result of verification: " + str(vF(code2num(sys.argv[3]),sys.argv[2])))

if len(sys.argv) == 3 and sys.argv[1] == "S":
  print(" digital signature:\n " + num2code(sF(sys.argv[2])))
     
if len(sys.argv) == 3 and sys.argv[1] == "G":
  print " generate primes ... "
  p = nextPrime( hg(sys.argv[2]) % (2**501 + 1) )  
  q = nextPrime( hg(sys.argv[2] + '0') % (2**501 + 1) )  
  writeNumber(p, 'p')                     
  writeNumber(q, 'q')     
  print "nrabin = ", (p * q) 
  print "\ncrabin = \n", num2code(p * q) 
  print "factor a = ", f_ab(p,q)[0]             
  print "factor b = ", f_ab(p,q)[1]
                     