import random, hashlib, sys

nrabin = 1116705369667683094806847219508144970451437099933488450284517797141150201629195047119398549706064070681325529749675621392780646572135106869032095184212513


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
    x //= 16
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

# x: bytes
# return: int
def h(x):
  return int(hashlib.sha256(x).hexdigest(), 16)
  # dx1 = hashlib.sha512(x).digest()
  # dx2 = hashlib.sha512(dx1+x).digest()
  # dx3 = hashlib.sha512(x+dx2).digest()
  # dx4 = hashlib.sha512(x+dx3).digest()
  # dx5 = hashlib.sha512(x+dx4).digest()
  # res = 0
  # for cx in (dx1+dx2+dx3+dx4+dx5):
  #   res = (res<<8) ^ ord(cx)
  # return res

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
  print("result of verification: " + str(vF(sys.argv[2], int(sys.argv[3]), hextxt2num(sys.argv[4]))))

if len(sys.argv) == 3 and sys.argv[1] == "S":
  print((" digital signature:\n " + num2hextxt(sF(sys.argv[2]))))
     
if len(sys.argv) == 3 and sys.argv[1] == "G":
  print(" generate primes ... ")
  p = nextPrime( h(bytes.fromhex(sys.argv[2])) % (2**501 + 1) )  
  q = nextPrime( h(bytes.fromhex(sys.argv[2] + '00')) % (2**501 + 1) )  
  writeNumber(p, 'p')                     
  writeNumber(q, 'q')     
  print("nrabin = ", (p * q))
