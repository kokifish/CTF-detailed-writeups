# This document is for usual and useful Sagemath tools
> version: Sagemath 9.2
> 这里所有的代码都是Sagemath 9.2的代码


### 功能性函数
```python
a = 12345
a.is_integer()        # 判断是否为整数
``` 


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

#### 3. 连分数
```python
e = randint(*,*)
n = randint(*,*)
for yx in continued_fraction(e/n).convergents():
    k = yx.numerator()      # 分子 或 yx.numer()
    d = yx.denominator()    # 分母 或 yx.denom()
```

#### 4. 多项式环
```python
P.<x,y>=PolynomialRing(ZZ)
P.<x>=PolynomialRing(ZZ)    # 定义多项式环

N = P.random_element(degree=100)    # 随机生成一个多项式环P的元素

R.<z> = P.quotient(N)       # 多项式环R的商环，模多项式为N，如果N是不可约多项式，那么R就是一个有限域，此时环R的系数需要为素域上的元素
 
f = x^3+2*x^2+3*x+4         
f.coefficients()            # 多项式系数
f.monic()                   # 变成首一多项式
```

#### 5. 最大公约数 GCD
**神坑：使用sagemath自带的gcd的时候一定要确认两个参数是int类型（最好类型转换一下），不然本来能出结果的变成出不了结果**
```python
def mygcd(a, b):
    while b != 0:
        a, b = b, a%b
    return a

gcd(a,b)                    # Sagemath自带gcd，但是有些情况下需要自己实现
```

#### 6. 扩展欧几里得算法
```python
def myxgcd(a, b):
    prevx, x = 1, 0; prevy, y = 0, 1
    while b:
        q = a//b
        x, prevx = prevx - q*x, x
        y, prevy = prevy - q*y, y
        a, b = b, a % b
    return prevx, prevy, a

xgcd(a,b)                   # Sagemath自带xgcd，速率比自己实现的快几十倍
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

#### 正交格

- 定义：$\mathcal{L}^{\perp} = \{\vec{v}\in \mathbb{Z}^m | \vec{u}\in \mathcal{L}, \langle \vec{u},\vec{v} \rangle = 0 \}$。 一定程度上可以理解成零空间

- 方案一：参考 [Equivalent key attack against a public-key cryptosystem based on subset sum problem](https://ietresearch.onlinelibrary.wiley.com/doi/pdf/10.1049/iet-ifs.2018.0041)
```python
def orthogonal_lattice(L):
    def distance(vec):
        ans = 0
        for i in range(len(vec)):
            ans += vec[i]*vec[i]
        return round(sqrt(ans))

    kk,nn = L.dimensions()
    g = ceil(2^((nn-0.5)+((nn-kk)*(nn-kk-1)/4))) * sum([distance(row) for row in L])

    B = Matrix(ZZ, nn+kk, nn)
    for i in range(nn+kk):
        for j in range(nn):
            if (i < kk):
                B[i,j] = L[i,j] * g
            else:
                B[i,j] = 1 if i-kk == j else 0
    B_ = B.transpose().LLL()
    return B_.submatrix(0,kk,nn-kk,-1)
```

- 方案二：（不知道为什么可以）
```python
def orthogonal_lattice(L):
    return L.transpose().left_kernel(basis="LLL").basis_matrix()
```

### 矩阵运算
```python
A = Matrix(ZZ,3,3,range(1,10))      # 按先行后列初始化
A = Matrix(ZZ,3,3)                  # 初始化为全0
A = Matrix(ZZ,3,3[[1,1,1],[2,2,2],[3,3,3]]) # 二维数组初始化
A.dimensions()                      # 矩阵的维度 (row, col) 
A.norm(p 或 Infinity)               # 矩阵的范式(范数)，即 $(\sum |x_i|^p)^{\frac{1}{p}}$

B = vector(ZZ,3, range(1,3))
A.solve_right(B)        # 求Ax = B 的解
A.solve_left(B)         # 求xA = B 的解 
A.right_kernel()        # 求Ax = 0 的解空间，类型是自由模
A.left_kernel()         # 求xA = 0 的解空间，类型是自由模
assert A.left_kernel() == A.transpose().right_kernel()  # Ture 
FM.basis_matrix()       # 显示自由模的基矩阵，一般在right_kernel()函数后使用
```