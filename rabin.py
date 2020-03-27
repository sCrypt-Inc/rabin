import hashlib, sys

nrabin = 0x15525796ddab817a3c54c4bea4ef564f090c5909b36818c1c13b9e674cf524aa3387a408f9b63c0d88d11a76471f9f2c3f29c47a637aa60bf5e120d1f5a65221

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

# x: bytes
# return: int
def h(x):
  return int(hashlib.sha256(x).hexdigest(), 16)

# m: bytes
def root(m, p, q):
  i = 0
  while True:
    x = h(m) % nrabin
    sig =   pow(p,q-2,q) * p * pow(x,(q+1)//4,q) 
    sig = ( pow(q,p-2,p) * q * pow(x,(p+1)//4,p) + sig ) % (nrabin) 
    if (sig * sig) % nrabin == x:
      break
    m = m + bytes.fromhex("00")
    i = i + 1
  print("paddingnum: " + str(i))
  return sig

def writeNumber(number, fnam):
  with open(fnam + '.txt', 'w') as f:
    f.write('%d' % number)

def readNumber(fnam):
  with open(fnam + '.txt', 'r') as f:
    return int(f.read())

def hF(m, paddingnum):
  return h(m + bytes.fromhex("00") * paddingnum) % nrabin

def sF(hexmsg):
  p = readNumber("p")
  q = readNumber("q")
  return root(bytes.fromhex(hexmsg), p, q)


def vF(hexmsg, paddingnum, s):
  return hF(bytes.fromhex(hexmsg), paddingnum) == (s * s) % nrabin
 
print("\n\n rabin signature - copyright Scheerer Software 2018 - all rights reserved\n\n")
print("First parameter is V (Verify) or S (Sign)\n\n")
print("\n\n verify signature (2 parameters):")
print("   > python rabin.py V <hexmessage> <paddingnum> <digital signature> ")

print(" create signature S (2 parameter):")
print("   > python rabin.py S <hexmessage> \n\n")

print(" number of parameters is " + str(len(sys.argv)-1))
print(" ")
print(" ")

if len(sys.argv) == 5 and sys.argv[1] == "V":
  print("result of verification: " + str(vF(sys.argv[2], int(sys.argv[3]), int(sys.argv[4], 16))))

if len(sys.argv) == 3 and sys.argv[1] == "S":
  print((" digital signature:\n " + hex(sF(sys.argv[2]))))
     
if len(sys.argv) == 3 and sys.argv[1] == "G":
  print(" generate primes ... ")
  p = nextPrime( h(bytes.fromhex(sys.argv[2])) % (2**501 + 1) )  
  q = nextPrime( h(bytes.fromhex(sys.argv[2] + '00')) % (2**501 + 1) )  
  writeNumber(p, 'p')                     
  writeNumber(q, 'q')     
  print("nrabin = ", hex(p * q))
