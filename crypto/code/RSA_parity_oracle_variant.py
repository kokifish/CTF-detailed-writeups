# python3
from Crypto.Util.number import *
mm = bytes_to_long(b'12345678')
l = len(bin(mm)) - 2

def genkey():
    while 1:
        p = getPrime(128)
        q = getPrime(128)
        e = getPrime(32)
        n = p * q
        phi = (p - 1) * (q - 1)
        if GCD(e, phi) > 1:
            continue
        d = inverse(e, phi)
        return e, d, n

e, d, n = genkey()
cc = pow(mm, e, n)
f = str(pow(cc, d, n) % 2)      # oracle 一开始泄露的第一bit

for i in range(1, l):
    e, d, n = genkey()
    cc = pow(mm, e, n)          # oracle给出的密文
    ss = inverse(2**i, n)
    cs = (cc * pow(ss, e, n)) % n   # 把处理过后的密文cs发给oracle
    lb = pow(cs, d, n) % 2          # oracle返回新泄露的最后1bit
    bb = (lb - (int(f, 2) * ss % n)) % 2    # 恢复第 i bit
    f = str(bb) + f
    assert(((mm >> i) % 2) == bb)
print(long_to_bytes(int(f, 2)))