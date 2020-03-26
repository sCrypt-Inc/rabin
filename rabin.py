import random, hashlib, sys

nrabin = 19357582850646234094870243936597881526816985728422822188584707758040190772124753795991976921183046753452348096483832662365979754187531420465198820567318721654423603010043133474548809492401416756882260459015012465339112151702054910778727561990594846430780059397082161240247533519862291928917720568887309L


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
  
def h(x):
  dx1 = hashlib.sha512(x).digest()
  dx2 = hashlib.sha512(dx1+x).digest()
  dx3 = hashlib.sha512(x+dx2).digest()
  dx4 = hashlib.sha512(x+dx3).digest()
  dx5 = hashlib.sha512(x+dx4).digest()
  res = 0
  for cx in (dx1+dx2+dx3+dx4+dx5):
    res = (res<<8) ^ ord(cx)
  return res


def root(m, p, q):
  i = 0
  while True:
    x = h(m) % nrabin
    sig =   pow(p,q-2,q) * p * pow(x,(q+1)/4,q) 
    sig = ( pow(q,p-2,p) * q * pow(x,(p+1)/4,p) + sig ) % (nrabin) 
    if (sig * sig) % nrabin == x:
      break
    m = m + ' '
    i = i + 1
  print "padding: " + str(i)
  return sig

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

def hF(fname, padding):
  f = open(fname,'r')
  return h(f.read() + " " * padding) % nrabin

def sF(fnam):
  p = readNumber("p")
  q = readNumber("q")

  f = open(fnam,'r')
  s = root (f.read(), p, q)
  f.close()
  return s

def vF(fname, padding, s):
  return hF(fname, padding) == (s * s) % nrabin
 
print "\n\n rabin signature - copyright Scheerer Software 2018 - all rights reserved\n\n"
print "First parameter is V (Verify) or S (Sign)\n\n"
print "\n\n verify signature (2 parameters):"
print "   > python rabin.py V <filename> <padding> <digital signature> "

print " create signature S (2 parameter):"
print "   > python rabin.py S <filename> \n\n"

print " number of parameters is " + str(len(sys.argv)-1)
print " "
print " "

if len(sys.argv) == 5 and sys.argv[1] == "V":
  print "result of verification: " + str(vF(sys.argv[2], int(sys.argv[3]), hextxt2num(sys.argv[4])))

if len(sys.argv) == 3 and sys.argv[1] == "S":
  print(" digital signature:\n " + num2hextxt(sF(sys.argv[2])))
     
if len(sys.argv) == 3 and sys.argv[1] == "G":
  print " generate primes ... "
  p = nextPrime( h(sys.argv[2]) % (2**501 + 1) )  
  q = nextPrime( h(sys.argv[2] + '0') % (2**501 + 1) )  
  writeNumber(p, 'p')                     
  writeNumber(q, 'q')     
  print "nrabin = ", (p * q)