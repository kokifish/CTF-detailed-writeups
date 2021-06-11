from Crypto.Util.number import *
from math import sqrt, gcd
import random

BITS = 512
f = open("flag.txt", "rb")
flag = f.read()
f.close()

def get_prime(nbit):
    while True:
        p = getPrime(nbit)
        if p % 3 == 2:
            return p


def gen(nbit):
    p = get_prime(nbit)
    q = get_prime(nbit)
    if q > p:
        p, q = q, p
    n = p * q
    bound = int(sqrt(2 * n)) // 12
    while True:
        x = random.randint(1, round(sqrt(bound)))
        y = random.randint(1, bound) // x
        zbound = int(((p - q) * round(n ** 0.25) * y) // (3 * (p + q)))
        z = zbound - ((p + 1) * (q + 1) * y + zbound) % x
        e = ((p + 1) * (q + 1) * y + z) // x
        if gcd(e, (p + 1) * (q + 1)) == 1:
            break
    gifts = [int(bin(p)[2:][:22], 2), int(bin(p)[2:][256:276], 2)]
    return n, e, gifts


def add(p1, p2):
    if p1 == (0, 0):
        return p2
    if p2 == (0, 0):
        return p1
    if p1[0] == p2[0] and (p1[1] != p2[1] or p1[1] == 0):
        return (0, 0)
    if p1[0] == p2[0]:
        tmp = (3 * p1[0] * p1[0]) * inverse(2 * p1[1], n) % n
    else:
        tmp = (p2[1] - p1[1]) * inverse(p2[0] - p1[0], n) % n
    x = (tmp * tmp - p1[0] - p2[0]) % n
    y = (tmp * (p1[0] - x) - p1[1]) % n
    return (int(x), int(y))


def mul(n, p):
    r = (0, 0)
    tmp = p
    while 0 < n:
        if n & 1 == 1:
            r = add(r, tmp)
        n, tmp = n >> 1, add(tmp, tmp)
    return r


n, e, hint = gen(BITS)
pt = (bytes_to_long(flag[:len(flag) // 2]), bytes_to_long(flag[len(flag) // 2:]))
c = mul(e, pt)
f = open("output.txt", "w")
f.write(f"n = {n}\n")
f.write(f"e = {e}\n")
f.write(f"h1 = {hint[0]}\n")
f.write(f"h2 = {hint[1]}\n")
f.write(f"c = {c}\n")
f.close()
