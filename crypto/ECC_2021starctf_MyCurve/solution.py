# Sagemath 9.2
from Crypto.Util.number import long_to_bytes

F = GF(2**100)
R.<x,y> = F[]

def _map(p):
    x,y = F.fetch_int(p[0]), F.fetch_int(p[1])
    u = 3*(x+y)/(x*y+x+y)
    v = 3*(x/(x*y+x+y)+2)
    return (u,v)

G = (698546134536218110797266045394, 1234575357354908313123830206394)
P = (403494114976379491717836688842, 915160228101530700618267188624)
# d1 = 1
# d2 = 1
# a1 = 1
# a2 = d1 ** 2 + d2 = 2
# a3 = 0
# a4 = 0
# a6 = d1**4 * (d1**4 + d1**2 + d2**2) = 3
E = EllipticCurve(GF(2**100), [1, 2, 0, 0, 3])
base = E(_map(G))
res = E(_map(P))
flag = discrete_log(res, base, base.order(), operation="+")
print(long_to_bytes(flag))