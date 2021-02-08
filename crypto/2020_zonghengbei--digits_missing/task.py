from gmpy2 import *
from Crypto.Util.number import *
from random import getrandbits
import uuid

flag = 'flag{' + str(uuid.uuid4()) + '}'
flag = flag.encode().strip(b'flag{').strip(b'}').split(b'-')
padding = long_to_bytes(getrandbits(512))

m = bytes_to_long(flag[0] + padding + b''.join([_ for _ in flag[1:]]))

def leak(a, b, c):
    e1, e2 = a >> 32, a & 2 ** 32 - 1
    m1, m2 = b >> 256, b & 2 ** 256 - 1
    p, q = getPrime(512), getPrime(512)
    e = getPrime(32)
    n = p * q
    d = invert(e, (p - 1) * (q - 1))
    c1 = pow(b, e, n)
    c2 = pow((m1 + m2), (e1 + e2), n)
    c3 = pow(a, a, n)
    c4 = pow(c, 0x10001, n)

    return (p, q, d % (p-1), d % (q-1), c1, c2, c3, c4)

def enc(m):
    p = getPrime(512)
    q = getPrime(512)
    e = 5
    n = p * q
    c = pow(m, e, n)
    return (c, n)

l = leak(bytes_to_long(flag[0]), bytes_to_long(padding), bytes_to_long(flag[1] + flag[2]))
c, n = enc(m)
print(l)
print(n)
print(c)
