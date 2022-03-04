from sage.all import *
from scheme import *

def rand_vector(n, l):
    return vector(ZZ, [randint(0, l - 1) for _ in range(n)])

n = 128
pk, sk = key_gen(n)
save(pk, 'pk')

sigs = []
for i in range(32768):
    v = rand_vector(128, 2**128)
    e = signature(sk, v)
    assert verify(pk, v, e)
    sigs.append((v, e))

save(sigs, 'signatures')