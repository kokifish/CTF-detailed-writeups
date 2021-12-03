# 原writeup https://ctftime.org/writeup/25448

from binascii import unhexlify, hexlify
from itertools import permutations

p = 10000000000000001119
k = GF(p)
kc = k.algebraic_closure()

R.<x> = GF(p)[]
y=x
f = y + y^7
C = HyperellipticCurve(f, 0)
J = C.jacobian()

msg_prefix = b"aaaaaaaaaaaaaaaaaaaaflag"

content = unhexlify('66def695b20eeae3141ea80240e9bc7138c8fc5aef20532282944ebbbad76a6e17446e92de5512091fe81255eb34a0e22a86a090e25dbbe3141aff0542f5')

bs = []
for c, m in zip(content, msg_prefix):
    # Do the XOR, obtain k
    b = c^^m
    print(b)
    bs.append(b)

u0 = int.from_bytes(bytes(bs[:8]), byteorder="little")
u1 = int.from_bytes(bytes(bs[8:16]), byteorder="little")
u2 = int.from_bytes(bytes(bs[16:24]), byteorder="little")
print(hex(u0), hex(u1), hex(u2))

ps = x^3 + u2 * x^2 + u1 * x + u0  # TODO: this ordering might be the other way around.
aps_roots = ps.roots(ring=kc, multiplicities=False)
x0, x1, x2 = aps_roots

A = Matrix(((x0^2, x0, kc(1)), (x1^2, x1, kc(1)), (x2^2, x2, kc(1))))
Y = vector((x0^7 + x0, x1^7 + x1, x2^7 + x2))
Ys = vector((-Y[0].sqrt(), -Y[1].sqrt(), -Y[2].sqrt())) # TODO: Maybe the other sqrt?

v = A.solve_right(Ys)
print(v)
v0 = int(str(v[0])).to_bytes(8, byteorder="little")
v1 = int(str(v[1])).to_bytes(8, byteorder="little")
v2 = int(str(v[2])).to_bytes(8, byteorder="little")

for a0, a1, a2 in permutations((v0, v1, v2)):
    q = bytes(bs) + a0 + a1 + a2
    leng = len(q)
    t = ''
    i = 0
    for x in content:
        t += chr(q[i%leng]^^x)
        i+=1
    print(t)

