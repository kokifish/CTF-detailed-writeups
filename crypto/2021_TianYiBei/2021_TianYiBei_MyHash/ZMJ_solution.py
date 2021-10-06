from pwn import *
# from z3 import *

from ctypes import c_uint32 as uint32
from struct import pack, unpack

from hashlib import sha256
import itertools, string


def TEA_encryption(vs, ks):
    delta = 0x9E3779B9
    v0, v1 = map(uint32, unpack('>2I', vs))
    k0, k1, k2, k3 = map(uint32, unpack('>4I', ks))
    sm, delta = uint32(0), uint32(delta)

    for i in range(32):
        sm.value += delta.value
        v0.value += ((v1.value << 4) + k0.value) ^ (v1.value + sm.value) ^ ((v1.value >> 5) + k1.value)
        v1.value += ((v0.value << 4) + k2.value) ^ (v0.value + sm.value) ^ ((v0.value >> 5) + k3.value)

    return pack('>2I', v0.value, v1.value)


def TEA_decryption(vs, ks):
    delta = 0x9E3779B9
    v0, v1 = map(uint32, unpack('>2I', vs))
    k0, k1, k2, k3 = map(uint32, unpack('>4I', ks))
    sm, delta = uint32(delta * 32), uint32(delta)

    for i in range(32):
        v1.value -= ((v0.value << 4) + k2.value) ^ (v0.value + sm.value) ^ ((v0.value >> 5) + k3.value)
        v0.value -= ((v1.value << 4) + k0.value) ^ (v1.value + sm.value) ^ ((v1.value >> 5) + k1.value)
        sm.value -= delta.value

    return pack('>2I', v0.value, v1.value)


class Gao:
    def __init__(self) -> None:
        # self.conn = remote('8.134.37.86', 23252)
        self.conn = remote('127.0.0.1', 10006)
        # self.sol = Solver()
        # self.v0 = BitVec('v0', 32)
        # self.v1 = BitVec('v1', 32)

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

        self.conn.sendlineafter(b'Choice:\n', '0')
        ks = [0, 0, 0, 0]
        msg = pack('>4I', *ks)
        self.conn.sendlineafter(b'I can hash for you', msg)
        cs = self.conn.recv(8)
        # cs = unpack('>2I', cs)
        m = TEA_decryption(cs, msg)
        self.conn.sendlineafter(b'Choice:\n', '1')
        adminpass = b'Iamthesuperadmin'
        c = TEA_encryption(m, adminpass)
        self.conn.sendlineafter(b'Are you admin?', c)
        self.conn.interactive()


if __name__ == '__main__':
    g = Gao()
    g.gao()