#!/usr/bin/env sage
import struct
from random import SystemRandom

p = 10000000000000001119
R.<x> = GF(p)[]
y=x
f = y + y^7
C = HyperellipticCurve(f, 0)
J = C.jacobian()

es = [SystemRandom().randrange(p**3) for _ in range(3)]
Ds = [J(C(x, min(f(x).sqrt(0,1)) ) ) for x in (11,22,33)]
q = []

def clk():
	global Ds,es
	Ds = [e*D for e,D in zip(es, Ds)]
	return Ds

def generate():
    
    u,v = sum(clk())
    rs = [u[i] for i in range(3)] + [v[i] for i in range(3)]
    assert 0 not in rs and 1 not in rs
    q = struct.pack('<'+'Q'*len(rs), *rs)
    return q


flag = "flag{xxxxxxx}"
text = 'a'*20+flag
t = ''
keys = generate()
leng = len(keys)
i = 0
for x in text:
    t += chr(ord(keys[i%leng])^^ord(x))
    i+=1
print t.encode('hex')
#for x,y in zip(RNG(),flag):





