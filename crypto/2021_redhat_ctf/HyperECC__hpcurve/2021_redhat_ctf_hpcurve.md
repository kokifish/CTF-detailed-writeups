# 2021年红帽杯—— Crypto —— hpcurve

## 题目
```
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
```

这道题相当于是hxp CTF 2020 hyper 的原题，题目本质上是给了超椭圆曲线的加密方案，但是密钥泄露了$u(x)$。然后只需要求出$v(x)$即可。根据$u(x)$我们可以知道$u(x)$的三个根，然后又因为点$(x_i, v(x_i))$在曲线$C$上。因此可以列出三个方程
$$(ax^2+bx+c)^2 = x^7 +x$$，解出参数$a,b,c$得到$v(x)$，然后就可以求出flag。

* 实际上题目难点在于要对超椭圆曲线有一个比基础的认识，不然根本没有办法下手做题。

题解：
见``solution.py``文件