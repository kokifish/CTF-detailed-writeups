# 2022年 SUSCTF—— Crypto —— SpecialCurve3

题目见`SpecialCurve3.py`

题目中所提到的SpecialCurve其实就是通过圆锥曲线构造的加法群。曲线方程为$$C(\mathbb{F}_p):y^2=ax^2-bx \\ a,b\in \mathbb{F}_p$$ 其中当$a>0$时曲线为双曲线，$a=0$时曲线为抛物线，$a<0$时曲线为椭圆。这个曲线恒过$(0,0)$点。

突破口：其中当$a >=0$时，$a$有模$p$的二次剩余，此时可以通过同构映射映射到有限域$GF(p)$这个乘法群中。当$a<0$时$a$不是模$p$的二次剩余，但是通过分析发现曲线的阶为$p+1$，且$p+1$光滑(能分解为较小的素数的乘积)。

难点：题目的难点在于如何构造这个同构映射，如果找到第二篇参考资料就很好解决，但是如果找不到，那就要自己手动去推一下（还是有点难度的）

* problem1：双曲线，通过同构映射$$M:C(\mathbb{F}_p)(x,y)\longrightarrow \phi_a(t) = \frac{t+\theta_1}{t+\theta_2} \\ t = \frac{y}{x} \\ \theta_1^2 \equiv \theta_2^2 \equiv a\ (mod\ p)$$ 把曲线上的点映射到有限域的乘法群中。因为$p$的取值不大，因此可以直接用`discrete_log`函数求解离散对数。

* problem2：抛物线。两种解法：
  * 通过曲线的加法公式，我们可以得知$$(nG)_y = 2n\times G_y\ mod\ p$$ 因此求个逆就行。
  * 构造同构映射$$M:C(\mathbb{F}_p)(x,y)\longrightarrow \phi_a(t) = \frac{1}{t-\theta} \\ t = \frac{y}{x} \\ \theta^2 \equiv a\ (mod\ p)$$ 即$a$的二次剩余$\theta$有重根，把曲线上的点映射到有限域的加法群中，然后求个逆然后相乘即可。

* problem3：双曲线。这里暂时构造同构映射。但是我们发现了曲线的阶为$p+1$，且$p+1$光滑(能分解为较小的素数的乘积)。因此直接使用Polig-Hellman算法进行求解。但是因为是自定义的曲线，因此需要自定义曲线的求逆运算、加法运算和单位元。
  * **注：** 这里面Sagemath没有实现自定义的曲线的运算，需要自己在源代码中修改，修改方法见`crypto/Sagemath_Usage.md`

```python
import hashlib
import random
from hashlib import md5
from Crypto.Util.number import bytes_to_long, long_to_bytes

# problem 1
p,a,b=(,,)
G=(,)
Q=(,)
Fp = GF(p)
G = (Fp(G[0]), Fp(G[1]))
Q = (Fp(Q[0]), Fp(Q[1]))
tG = G[1] / G[0]
tQ = Q[1] / Q[0]
a = Fp(a)
theta1 = a^((p+1)//4)
theta2 = -a^((p+1)//4)
phiG = (tG+theta1)/(tG+theta2)
phiQ = (tQ+theta1)/(tQ+theta2)
e1 = phiQ.log(phiG)
print(e)

#problem 2
p,a,b=(,,)
G=(,)
Q=(,)
Fp = GF(p)
G = (Fp(G[0]), Fp(G[1]))
Q = (Fp(Q[0]), Fp(Q[1]))
tG = G[1] / G[0]
tQ = Q[1] / Q[0]
phiG = 1/tG
phiQ = 1/tQ
e2 = phiQ / phiG
print(e2)

# problem 3
class SpecialCurve:
    def __init__(self, p, a, b):
        self.p = p
        self.a = a
        self.b = b

#     def __str__(self):
#         return f'SpecialCurve({self.p},{self.a},{self.b})'

    def __call__(self, x, y):
        return SpecialCurvePoint(self.p, self.a, self.b, x, y)

#     def __contains__(self, other):
#         x, y = other.x, other.y
#         return (self.a * x ** 2 - self.b * x - y ** 2) % self.p == 0

class SpecialCurvePoint:

    def __init__(self, p, a, b, x, y):
        self.p = p
        self.a = a
        self.b = b
        self.x = x % p
        self.y = y % p

    def __str__(self):
        return "(%d, %d)" % (self.x, self.y)

    def __repr__(self):
        return str(self)

    def __add__(self, P1):
        x1, y1 = self.x, self.y
        x2, y2 = P1.x, P1.y
        if x1 == 0:
            return P1
        elif x2 == 0:
            return self
        elif x1 == x2 and (y1+y2) % self.p == 0:
            return SpecialCurvePoint(self.p, self.a, self.b, 0, 0)
        if self == P1:
            t = (2*self.a*x1-self.b)*inverse_mod(2*y1, self.p) % self.p
        else:
            t = (y2-y1)*inverse_mod(x2-x1, self.p) % self.p
        x3 = self.b*inverse_mod(self.a-t**2, self.p) % self.p
        y3 = x3*t % self.p
        return SpecialCurvePoint(self.p, self.a, self.b, x3, y3)
    
    def __sub__(self, P1):
        x1, y1 = self.x, self.y
        x2, y2 = P1.x, -P1.y
        if x1 == 0:
            return P1
        elif x2 == 0:
            return self
        elif x1 == x2 and (y1+y2) % self.p == 0:
            return SpecialCurvePoint(self.p, self.a, self.b, 0, 0)
        if self == P1:
            t = (2*self.a*x1-self.b)*inverse_mod(2*y1, self.p) % self.p
        else:
            t = (y2-y1)*inverse_mod(x2-x1, self.p) % self.p
        x3 = self.b*inverse_mod(self.a-t**2, self.p) % self.p
        y3 = x3*t % self.p
        return SpecialCurvePoint(self.p, self.a, self.b, x3, y3)

    def __mul__(self, k):
        assert k >= 0
        Q = SpecialCurvePoint(self.p, self.a, self.b, 0, 0)
        P = SpecialCurvePoint(self.p, self.a, self.b, self.x, self.y)
        cnt = 0
        now = 1
        while k > 0:
            if k % 2:
                k -= 1
                Q = P + Q
                cnt += now
            else:
                k //= 2
                P = P + P
                now *= 2

        return Q

    def order(self):
        return self.p + 1

    def is_zero(self):
        return self.x == 0 and self.other == 0

    def __eq__(self, other):
        return self.a == other.a and self.b == other.b and self.p == other.p \
            and self.x == other.x and self.y == other.y
    def __hash__(self):
        return int(md5(("%d-%d-%d-%d-%d" % (self.p, self.a, self.b, self.x, self.y)).encode()).hexdigest(), 16)

def myinvert(P):
    return SpecialCurvePoint(P.p, P.a, P.b, P.x, -P.y % P.p)

def myadd(P1, P2):
    return P1 + P2

curve=SpecialCurve(,,)
G=curve(,)
Q=curve(,)
E = curve(0, 0)
# order = p + 1
print(G* (curve.p+1))
order = curve.p + 1

e3 = discrete_log(Q, G, curve.p+1,  operation='other', op=myadd, inverse=myinvert, identity=E)
print(e3)
enc=
flag=long_to_bytes(bytes_to_long(hashlib.sha512(b'%d-%d-%d'%(e1,e2,e3)).digest())^^enc)
print(flag)
```

**参考资料：**
* https://mp.weixin.qq.com/s?__biz=Mzg3NTEzOTA5Nw==&mid=2247484344&idx=1&sn=bce7e092b79c937f5ec2d57c505c98ee&chksm=cec75acef9b0d3d8547055726e2497e1e166096a58166d54cd8eef355981b5607aabb76ba120&mpshare=1&scene=23&srcid=0301W0QoDAT1Oj3r6tq0CFrr&sharer_sharetime=1646127847203&sharer_shareid=eafb5e05153aa88f1f9e7cb0b5edf2fd#rd
* https://www.jiamisoft.com/blog/4068-yuanzhuiquxianjiamisuanfa.html
* https://team-su.github.io/passages/2022-2-28-SUSCTF/