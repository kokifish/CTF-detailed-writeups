from pwn import *
from z3 import *

from ctypes import c_uint32 as uint32
from struct import pack, unpack

from hashlib import sha256
import itertools, string
import random


def g_z3(v1, v2, x):
    value = v1 + v2 + x
    value = ((value << 3) | LShR(value, 5))
    return value


def f_z3(value):
    v1, v2 = value
    v2 = g_z3(v1, v2, 1)
    v1 = g_z3(v1, v2, 0)
    value = v1, v2
    return value


def encrypt_z3(msg, key_1, key_2):
    left_1, left_2, right_1, right_2 = msg
    right_1 = right_1 ^ key_1[3]
    right_2 = right_2 ^ key_2[3]
    for i in range(3):
        f_1, f_2 = f_z3((key_1[i] ^ right_1, key_2[i] ^ right_2))
        tmp_1, tmp_2 = f_1 ^ left_1, f_2 ^ left_2
        left_1, left_2 = right_1, right_2
        right_1, right_2 = simplify(tmp_1), simplify(tmp_2)
    left_1, left_2 = right_1 ^ left_1, right_2 ^ left_2
    return left_1, left_2, right_1, right_2


def g(v1, v2, x):
    value = (v1 + v2 + x) % 256
    value = ((value << 3) | value >> 5) & 0xff
    return value


def f(value):
    v1, v2 = value
    v2 = g(v1, v2, 1)
    v1 = g(v1, v2, 0)
    value = v1, v2
    return value


def encrypt(msg, key_1, key_2):
    left_1, left_2, right_1, right_2 = msg
    right_1 = right_1 ^ key_1[3]
    right_2 = right_2 ^ key_2[3]
    for i in range(3):
        f_1, f_2 = f((key_1[i] ^ right_1, key_2[i] ^ right_2))
        tmp_1, tmp_2 = f_1 ^ left_1, f_2 ^ left_2
        left_1, left_2 = right_1, right_2
        right_1, right_2 = tmp_1, tmp_2
    left_1, left_2 = right_1 ^ left_1, right_2 ^ left_2
    return left_1, left_2, right_1, right_2


def decrypt(cipher, key_1, key_2):
    left_1, left_2, right_1, right_2 = cipher
    left_1 = left_1 ^ right_1
    left_2 = left_2 ^ right_2
    for i in range(2, -1, -1):
        f_1, f_2 = f((key_1[i] ^ left_1, key_2[i] ^ left_2))
        tmp_1, tmp_2 = f_1 ^ right_1, f_2 ^ right_2
        right_1, right_2 = left_1, left_2
        left_1, left_2 = tmp_1, tmp_2
    right_1, right_2 = right_1 ^ key_1[3], right_2 ^ key_2[3]
    return left_1, left_2, right_1, right_2


class Gao:
    def __init__(self) -> None:
        self.conn = remote('127.0.0.1', 10005)
        self.sol = Solver()
        self.k1s = [BitVec(f'k1_{i}', 8) for i in range(4)]
        self.k2s = [BitVec(f'k2_{i}', 8) for i in range(4)]

    def gao_proof(self):
        # sha256(XXXX+ls80Gvx0HNZnbZsz) == 01f7c263ac523016fc728c8326ec15428f8da9384d6e1e302577b39d1dd15fa6
        s = self.conn.recvline().strip().decode()
        m2 = s[12:28]
        c2 = s[-64:]
        for m in itertools.product(string.ascii_letters + string.digits, repeat=4):
            m = ''.join(m)
            mm = m + m2
            if (sha256(mm.encode()).hexdigest() == c2):
                self.conn.sendline(m)
                break

    def gao(self):
        # self.gao_proof()
        c = self.conn.recvuntil(b'Encrypted flag is:')
        c = self.conn.recvuntil(b'Here is your chance:')
        print(c)
        c = c[:-21]
        print(c)
        mm = [random.randrange(0, 256) for x in range(144)]
        self.conn.sendline(bytes(mm))
        cc = self.conn.recvall()
        print(cc)
        for i in range(0, 144, 4):
            myc = encrypt_z3(mm[i:i + 4], self.k1s, self.k2s)
            for j in range(4):
                self.sol.add(myc[j] == cc[i + j])
        print('OK')
        if (self.sol.check() == sat):
            m = self.sol.model()
            self.k1s = [m[x].as_long() for x in self.k1s]
            self.k2s = [m[x].as_long() for x in self.k2s]
        else:
            print('GG simida')

        print(bytes(encrypt(mm[:4], self.k1s, self.k2s)))
        print(bytes(decrypt(cc[:4], self.k1s, self.k2s)))
        print(bytes(mm[:4]))

        m = []
        for i in range(0, len(c), 4):
            m.extend(decrypt(c[i:i + 4], self.k1s, self.k2s))
        print(bytes(m))


if __name__ == '__main__':
    random.seed(0)
    g_ = Gao()
    g_.gao()