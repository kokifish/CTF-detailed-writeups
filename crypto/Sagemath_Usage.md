# This document is for usual and useful Sagemath tools
> version: Sagemath 9.2
> 这里所有的代码都是Sagemath 9.2的代码


### 基础数论
#### 1. 有限域的定义
```python
p =      # a prime 
Fp = GF(p)
```

#### 2. 有限域乘法群
```python
p =      # a prime 
base = Mod(,p)
v = Mod(,p)
x = discrete_log(u, base)   # 求离散对数
```

### 曲线运算

#### 1. 椭圆曲线的运算
```python
P1x = 
P1y = 
P1 = (P1x,P1y)
E1p = EllipticCurve(GF(p1), [0, 0, 0, A1, B1])
P1p = E1p(P1)       # 椭圆曲线上的点
```

#### 2. 椭圆曲线离散对数
代码见：文件`/opt/sagemath-9.3/local/lib/python3.7/site-packages/sage/groups/generic.py`
比较常用的算法:

```python
# ALGORITHM: Pohlig-Hellman and Baby step giant step.
x=discrete_log(a,base,ord,operation)

#求离散对数的Pollard-Rho算法
x=discrete_log_rho(a,base,ord,operation)

#求离散对数的Pollard-kangaroo算法(也称为lambda算法)
x=discrete_log_lambda(a,base,bounds,operation)

#小步大步法
x=bsgs(base,a,bounds,operation)
```

主要介绍后面几个参数：
- `def bsgs(a, b, bounds, operation='*', identity=None, inverse=None, op=None)` 
- `def discrete_log(a, base, ord=None, bounds=None, operation='*', identity=None, inverse=None, op=None):`
- `bound` 表示界 `(bg, ed)`，就是找出的离散对数在界之间
- `ord` 表示基点`base`的阶
- `operation` 表示运算，取值有[`+,*,other`]，`+`表示的是取加法群，`*`表示的是取乘法群，选这两个运算符会自动搜索传入的点的参数的群，然后决定后面的三个运算。如果是其它，那么就需要传入`identity` `inverse` `op`三个参数。
- `identity` 表示单位元(**一个点**)
- `inverse` 表示一个负点的函数（**一个函数**）
- `op` 表示曲线群的运算（**一个函数**）

**bug**：`bsgs` 函数和`discrete_log`函数实际上有处理其它运算的能力，但是代码中没有实现，因此
1. 需要把文件`/opt/sagemath-9.3/local/lib/python3.7/site-packages/sage/groups/generic.py` 的大约476行改为`c = op(inverse(b), multiple(a, lb, operation=operation, identity=identity, inverse=inverse, op=op))`。 
2. 需要在文件`/opt/sagemath-9.3/local/lib/python3.7/site-packages/sage/groups/generic.py` 的大约836行添加
   ```python
   elif identity is not None and inverse is not None and op is not None:
        c = bsgs(base * (ord // pi), (a - base * l[i]) * (ord // pi ** (j + 1)), (0, pi), operation=operation, identity=identity, inverse=inverse, op=op)
        l[i] += c * (pi ** j) 
    ```


#### 3. 自定义曲线
有时候我们想在自定义的曲线中求解离散对数问题，这时候需要定义一个类，然后实现相应的一些算法，然后就可以使用`bsgs`或者`discrete_log`函数去求解离散对数了。这里以**圆锥曲线群**为例。类中的函数缺一不可，如果还有报错，那么根据需要对所需的函数进行实现。

```python
import hashlib

class ConicCurve:
    def __init__(self, p, a, b):
        self.p = p
        self.a = a
        self.b = b

#     def __str__(self):
#         return f'ConicCurve({self.p},{self.a},{self.b})'

    def __call__(self, x, y):
        return ConicCurvePoint(self.p, self.a, self.b, x, y)

#     def __contains__(self, other):
#         x, y = other.x, other.y
#         return (self.a * x ** 2 - self.b * x - y ** 2) % self.p == 0

class ConicCurvePoint:

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
            return ConicCurvePoint(self.p, self.a, self.b, 0, 0)
        if self == P1:
            t = (2*self.a*x1-self.b)*inverse_mod(2*y1, self.p) % self.p
        else:
            t = (y2-y1)*inverse_mod(x2-x1, self.p) % self.p
        x3 = self.b*inverse_mod(self.a-t**2, self.p) % self.p
        y3 = x3*t % self.p
        return ConicCurvePoint(self.p, self.a, self.b, x3, y3)
    
    def __sub__(self, P1):
        return self + ConicCurvePoint(P1.p, P1.a, P1.b, P1.x, -P1.y % P1.p)

    def __mul__(self, k):
        assert k >= 0
        Q = ConicCurvePoint(self.p, self.a, self.b, 0, 0)
        P = ConicCurvePoint(self.p, self.a, self.b, self.x, self.y)
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
        return int(hashlib.md5(("%d-%d-%d-%d-%d" % (self.p, self.a, self.b, self.x, self.y)).encode()).hexdigest(), 16)

def ConicCurveInvert(P):
    return ConicCurvePoint(P.p, P.a, P.b, P.x, -P.y % P.p)

def ConicCurveAdd(P1, P2):
    return P1 + P2

curve=ConicCurve(,,)
G=curve(,)
Q=curve(,)
E = curve(0, 0)

order = curve.p + 1

x = discrete_log(Q, G, curve.p+1,  operation='other', op=ConicCurveAdd, inverse=ConicCurveInvert, identity=E)
print(x)

```






### 格基规约算法
```python
# Sagemath 9.2
A = Matrix(ZZ,3,3,range(1,10))
bkz_result = A.BKZ(block_size = 20)     # BKZ
lll_result = A.LLL()                    # LLL
```