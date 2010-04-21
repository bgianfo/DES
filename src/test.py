import sys
if sys.version_info[0] >= 3:
  bin = "{0:#0b}".format
from functools import reduce

def a(chars):
  "Convert a string to its bits representation as a string of 0's and 1's"
  return bin(reduce(lambda x, y : (x<<8)+y, (ord(c) for c in chars), 1))[3:]


x = a("0123456")
print( x )
