import z3
import random
import signal
import socket
import string
from hashlib import sha256
from os import urandom


TABLE2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*-?'


def proof_of_work(str, hashh):
    l = len(TABLE2)
    for i in range(l):
        for j in range(l):
            for k in range(l):
                for ll in range(l):
                    tmp = (TABLE2[i] + TABLE2[j] + TABLE2[k] + TABLE2[ll]).encode()
                    if sha256(tmp + str).hexdigest().encode() == hashh:
                        print(tmp)
                        client.send(tmp + b'\n')
                        return


def _prod(L):
    p = 1
    for x in L:
        p *= x
    return p


def _sum(L):
    s = 0
    for x in L:
        s ^= x
    return s


def n2l(x, l):
    return list(map(int, '{{0:0{}b}}'.format(l).format(x)))


class Generator1:
    def __init__(self, key: list):
        assert len(key) == 64
        self.NFSR = key[: 48]
        self.LFSR = key[48:]
        self.TAP = [0, 1, 12, 15]
        self.TAP2 = [[2], [5], [9], [15], [22], [26], [39], [26, 30], [5, 9], [15, 22, 26], [15, 22, 39],
                     [9, 22, 26, 39]]
        self.h_IN = [2, 4, 7, 15, 27]
        self.h_OUT = [[1], [3], [0, 3], [0, 1, 2], [0, 2, 3], [0, 2, 4], [0, 1, 2, 4]]

    def g(self):
        x = self.NFSR
        return _sum(_prod(x[i] for i in j) for j in self.TAP2)

    def h(self):
        x = [self.LFSR[i] for i in self.h_IN[:-1]] + [self.NFSR[self.h_IN[-1]]]
        return _sum(_prod(x[i] for i in j) for j in self.h_OUT)

    def f(self):
        return _sum([self.NFSR[0], self.h()])

    def clock(self):
        o = self.f()
        self.NFSR = self.NFSR[1:] + [self.LFSR[0] ^ self.g()]
        self.LFSR = self.LFSR[1:] + [_sum(self.LFSR[i] for i in self.TAP)]
        self.NFSR = [z3.simplify(i) for i in self.NFSR]
        self.LFSR = [z3.simplify(i) for i in self.LFSR]
        return o


class Generator2:
    def __init__(self, key):
        assert len(key) == 64
        self.NFSR = key[: 16]
        self.LFSR = key[16:]
        self.TAP = [0, 35]
        self.f_IN = [0, 10, 20, 30, 40, 47]
        self.f_OUT = [[0, 1, 2, 3], [0, 1, 2, 4, 5], [0, 1, 2, 5], [0, 1, 2], [0, 1, 3, 4, 5], [0, 1, 3, 5], [0, 1, 3],
                      [0, 1, 4], [0, 1, 5], [0, 2, 3, 4, 5], [
                          0, 2, 3], [0, 3, 5], [1, 2, 3, 4, 5], [1, 2, 3, 4], [1, 2, 3, 5], [1, 2], [1, 3, 5], [1, 3],
                      [1, 4], [1], [2, 4, 5], [2, 4], [2], [3, 4], [4, 5], [4], [5]]
        self.TAP2 = [[0, 3, 7], [1, 11, 13, 15], [2, 9]]
        self.h_IN = [0, 2, 4, 6, 8, 13, 14]
        self.h_OUT = [[0, 1, 2, 3, 4, 5], [0, 1, 2, 4, 6], [1, 3, 4]]

    def f(self):
        x = [self.LFSR[i] for i in self.f_IN]
        return _sum(_prod(x[i] for i in j) for j in self.f_OUT)

    def h(self):
        x = [self.NFSR[i] for i in self.h_IN]
        return _sum(_prod(x[i] for i in j) for j in self.h_OUT)

    def g(self):
        x = self.NFSR
        return _sum(_prod(x[i] for i in j) for j in self.TAP2)

    def clock(self):
        self.LFSR = self.LFSR[1:] + [_sum(self.LFSR[i] for i in self.TAP)]
        self.NFSR = self.NFSR[1:] + [self.LFSR[1] ^ self.g()]
        self.NFSR = [z3.simplify(i) for i in self.NFSR]
        self.LFSR = [z3.simplify(i) for i in self.LFSR]
        return self.f() ^ self.h()


class Generator3:
    def __init__(self, key: list):
        assert len(key) == 64
        self.LFSR = key
        self.TAP = [0, 55]
        self.f_IN = [0, 8, 16, 24, 32, 40, 63]
        self.f_OUT = [[1], [6], [0, 1, 2, 3, 4, 5], [0, 1, 2, 4, 6]]

    def f(self):
        x = [self.LFSR[i] for i in self.f_IN]
        return _sum(_prod(x[i] for i in j) for j in self.f_OUT)

    def clock(self):
        self.LFSR = self.LFSR[1:] + [_sum(self.LFSR[i] for i in self.TAP)]
        self.LFSR = [z3.simplify(i) for i in self.LFSR]
        return self.f()


class zer0lfsr:
    def __init__(self, msk, t: int):
        if t == 1:
            self.g = Generator1(msk)   # Generator的构造函数的参数是int的一个list
        elif t == 2:
            self.g = Generator2(msk)
        else:
            self.g = Generator3(msk)
        self.t = t

    def next(self):
        for i in range(self.t):
            o = self.g.clock()
        return o


host = '127.0.0.1'
port = 31337
bufsize = 1024
addr = (host, port)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(addr)

# proof of work
msg = client.recv(2048)
s = msg[14:30]
hash = msg[-65:-1]
msg = client.recv(2048)
proof_of_work(s, hash)

genList = [1,3]
for _ in range(2):
    msg = client.recv(2048)
    print(msg)
    client.send(str(genList[_]).encode() + b'\n')
    # msk = z3.BitVec('msk', 64)
    msk = [z3.BitVec('msk%d'%i, 1) for i in range(64)]
    lfsr = zer0lfsr(msk, genList[_])
    s = z3.Solver()

    keystream = ''
    for i in range(5):
        tmp = client.recv(2048)
        print(tmp)
        keystream += tmp[8:-7].decode('latin-1')
    # print(keystream[8:-7])
    # print(len(keystream))     1000
    # record_order = ''
    for j in range(12):
        word = ord(keystream[j])
        for k in range(8):
            cur = (word & 128) >> 7
            # record_order += bin(cur)[2:]
            s.add(z3.simplify(cur == lfsr.next()))
            word <<= 1
    # print(record_order)
    print(s.check())
    s_model = s.model()
    # print(s_model)

    msg = client.recv(2048)
    print(msg)

    # msk hash
    final_msk = 0
    print([s_model.evaluate(msk[i]).as_long() for i in range(64)])
    for i in range(64):
        final_msk = (final_msk << 1) + s_model.evaluate(msk[i]).as_long()
    print(bin(final_msk)[2:])
    print(final_msk)

    # msk_hash = sha256(str(final_msk).encode()).hexdigest()
    # print(msk_hash)
    client.send(str(final_msk).encode() + b'\n')

    msg = client.recv(2048)
    print(msg)

msg = client.recv(2048)
print(msg)

