from sage.all import *
from hashlib import sha256

def key_gen(n):
    k = 4 * round(sqrt(n) + 1) + 1
    sk = k * identity_matrix(n) + random_matrix(Integers(9), n, n).change_ring(ZZ) - 4 * ones_matrix(n, n)
    pk = sk.hermite_form()
    return pk, sk

def round_vector(v):
    return vector(ZZ, [round(i) for i in v])

def signature(sk, v):
    return round_vector(v * sk**-1) * sk - v # return a short error vector as the signature

def verify(pk, v, sig):
    n, _ = pk.dimensions()
    A = block_matrix([[pk], [matrix(v + sig)]])
    if A.hermite_form() != block_matrix([[pk], [zero_matrix(1, n)]]): # check that v + sig is a lattice point
        return False
    if sig.norm(Infinity) > 4 * sqrt(2 * n) + 1: # check that sig is short enough
        return False
    return True

def hash_msg(s, n):
    h = sha256()
    h.update(s.encode())
    u = h.digest()
    u = int.from_bytes(u + u, 'big')
    return vector((u >> i) & ((1 << 256) - 1) for i in range(0, 256, (255 + n) // n))

def hash_and_sign(sk, s):
    n, _ = sk.dimensions()
    return signature(sk, hash_msg(s, n))

def hash_and_verify(pk, s, sig):
    n, _ = pk.dimensions()
    return verify(pk, hash_msg(s, n), sig)