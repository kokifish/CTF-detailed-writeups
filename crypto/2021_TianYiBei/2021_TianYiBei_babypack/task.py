from random import getrandbits, randint
from Crypto.Util.number import getPrime
from functools import reduce
# from secret import flag
flag = b'flag{1234567890}'
import sys
# import signal
#
# signal.alarm(90)

N = 512
def egcd(a, b):
    if 0 == b:
        return 1, 0, a
    x, y, q = egcd(b, a % b)
    x, y = y, (x - a // b * y)
    return x, y, q

def chinese_remainder(pairs):
    mod_list, remainder_list = [p[0] for p in pairs], [p[1] for p in pairs]
    mod_product = reduce(lambda x, y: x * y, mod_list)
    mi_list = [mod_product//x for x in mod_list]
    mi_inverse = [egcd(mi_list[i], mod_list[i])[0] for i in range(len(mi_list))]
    x = 0
    for i in range(len(remainder_list)):
        x += mi_list[i] * mi_inverse[i] * remainder_list[i]
        x %= mod_product
    return x

def keygen():
    U = [getrandbits(N)for i in range(N)]
    V = []
    for i in range(N):
        v = U[i] - pow(2, N-i-1)
        V.append(v)

    s1 = sum(U)
    while True:
        p = getPrime(s1.bit_length() + 1)
        if p > s1:
            break
    s1 = 0
    s2 = 0
    for i in V:
        if i < 0:
            s2 += i
        else:
            s1 += i

    tmp = max(s1, -s2)
    while True:
        q = getPrime(tmp.bit_length() + 1)
        if q > tmp:
            break

    A = []
    for i, j in zip(U, V):
        A.append(chinese_remainder([(p, i), (q, j)]))
    return A, U, V, p, q

def check(m, n):
    mbin = bin(m)[2:]
    nbin = bin(n)[2:]
    count = 0
    for i, j in zip(mbin, nbin):
        if i == j:
            count += 1
    return count

def encrypt(msg, pub):
    s = 0
    for i, j in zip(msg, pub):
        s += i * j
    return s


A, U, V, p, q = keygen()


n = p * q
print("your pubkey:")
print(A)
print(U[0] + V[0])
print(U[0] * V[0])
Menu = '''
1.hint
2.get flag'''
for i in range(500):
    print(Menu)
    op = int(input(">").strip())
    if op == 1:
        m = int(input(">").strip())
        print(check(m, n))
    elif op == 2:
        msg = [randint(0, 1) for i in range(N)]
        ct = encrypt(msg, A)
        print("secret:")
        print(ct)
        secret = int(input(">").strip())
        ans = int("".join(list(map(str, msg))), 2)
        if ans == secret:
            print(flag)
        else:
            print("wrong")
            sys.exit(0)
    else:
        sys.exit(0)


