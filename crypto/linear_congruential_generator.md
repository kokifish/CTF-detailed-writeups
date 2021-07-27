**声明:本文转载自**
https://www.codercto.com/a/35743.html 
**目的是为了更方便地进行学习，版权归原作者或者来源机构所有。**

### 0x01 线性同余生成器(LCG)
#### 1. 线性同余方法
线性同余方法（LCG）是个产生伪随机数的方法。

它是根据递归公式：

其中A,B,M是产生器设定的常数。

LCG的周期最大为 M，但大部分情况都会少于M。要令LCG达到最大周期，应符合以下条件：

B,M互质；
M的所有质因数都能整除A-1；
若M是4的倍数，A-1也是；
A,B,N[0]都比M小；
A,B是正整数。
#### 2. Python代码实现
由上面的原理我们可以看到，其中最重要的是定义了三个整数，乘数A、增量B和模数M，因此我们在此用简单的几行 Python 代码实现一下:
```python
class prng_lcg:
    m = 672257317069504227  # "乘数"
    c = 7382843889490547368  # "增量"
    n = 9223372036854775783  # "模数"

    def __init__(self, seed):
        self.state = seed  # the "seed"

    def next(self):
        self.state = (self.state * self.m + self.c) % self.n
        return self.state


def test():
    gen = prng_lcg(123)  # seed = 123
    print gen.next()  # 第一个生成值
    print gen.next()  # 第二个生成值
    print gen.next()  # 第三个生成值
```

#### 3.LCG的优缺点
LCG目前是分流行，得益于其在数学表达实现上十分优雅、非常容易理解并且容易设计实现、计算速度可以非常快。但是它也存在一些缺点，比如它在加密安全性方面十分弱。接下来将从以下几种情况对其进行攻击。

### 0x02 攻击LCG
#### 1. 对于A、B、M以及N0已知的情况
假设我们观察到有一个LCG系统产生了以下三组连续的值，并且我们知道内部的参数如下:

```python
# 三组连续的值
s0 = 2300417199649672133
s1 = 2071270403368304644
s2 = 5907618127072939765
# 内部的参数
m = 672257317069504227   # the "multiplier"
c = 7382843889490547368  # the "increment"
n = 9223372036854775783  # the "modulus"
```

在已知了这些参数之后我们可以很快的推算出未来的数值或者之前的某个数值，所以还是存在安全问题的。
```python
In [1]: m = 672257317069504227

In [2]: c = 7382843889490547368

In [3]: n = 9223372036854775783

In [4]: s0 = 2300417199649672133

In [5]: s1 = (s0*m + c) % n

In [6]: s2 = (s1*m + c) % n

In [7]: s3 = (s2*m + c) % n

In [8]: s4 = (s3*m + c) % n

In [9]: s1
Out[9]: 2071270403368304644L

In [10]: s2
Out[10]: 5907618127072939765L

In [11]: s3
Out[11]: 5457707446309988294L
```
### 2.增量未知
我们不清楚增量，但是我们知道以下信息:
```python
m = 81853448938945944
c = # unknown
n = 9223372036854775783
# 初值和第一个计算值
s0 = 4501678582054734753
s1 = 4371244338968431602
```

我们稍稍改写下公式就可以将目标c计算出来
```python
s1 = s0*m + c   (mod n)

c  = s1 - s0*m  (mod n)
```
此种类型Python攻击代码如下所示:
```python
def crack_unknown_increment(states, modulus, multiplier):
    increment = (states[1] - states[0]*multiplier) % modulus
    return modulus, multiplier, increment

print crack_unknown_increment([4501678582054734753, 4371244338968431602], 9223372036854775783, 81853448938945944)
```
#### 3.增量和乘数都未知
我们虽然不知道增量和乘数但是我们知道以下数值
```python
m = # unknown
c = # unknown
n = 9223372036854775783
# LCG生成的初值和后面生成的两个值
s0 = 6473702802409947663
s1 = 6562621845583276653
s2 = 4483807506768649573
```
解决办法很简单，想想怎么解线性方程组就好了

```python
s_1 = s0*m + c  (mod n)
s_2 = s1*m + c  (mod n)

s_2 - s_1 = s1*m - s0*m  (mod n)
s_2 - s_1 = m*(s1 - s0)  (mod n)
m = (s_2 - s_1)/(s_1 - s_0)  (mod n)
```
此种类型Python攻击代码如下所示:
```python
def crack_unknown_multiplier(states, modulus):
    multiplier = (states[2] - states[1]) * modinv(states[1] - states[0], modulus) % modulus
    return crack_unknown_increment(states, modulus, multiplier)

print crack_unknown_multiplier([6473702802409947663, 6562621845583276653, 4483807506768649573], 9223372036854775783)
```
这个算法中应用到了求模，所以我们就需要逆推。

```python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

def modinv(b, n):
    g, x, _ = egcd(b, n)
    if g == 1:
        return x % n
```

#### 4.增量，乘数和模数均未知
现在内部状态基本是都不知道了，但是我们知道初值和随后LCG产生的连续的几个值。

```python
m = # unknown
c = # unknown
n = # unknown
s0 = 2818206783446335158
s1 = 3026581076925130250
s2 = 136214319011561377
s3 = 359019108775045580
s4 = 2386075359657550866
s5 = 1705259547463444505
s6 = 2102452637059633432
```
这次用线性方程式不好解决的了，因为对于每一个方程，我们是不知道前一个模数，因此我们将形成的每个方程都会引入新的未知量：

```python
s1 = s0*m + c  (mod n)
s2 = s1*m + c  (mod n)
s3 = s2*m + c  (mod n)
s1 - (s0*m + c) = k_1 * n
s2 - (s1*m + c) = k_2 * n
s3 - (s2*m + c) = k_3 * n
```
这就相当于六个未知数和三个方程。所以线性方程组是不可能行得通的了，但是数论里面有一条很有用:如果有几个随机数分别乘以n，那么这几个数的欧几里德算法(gcd)就很可能等于n。

```python
In [944]: n = 123456789

In [945]: reduce(gcd, [randint(1, 1000000)*n, randint(1, 1000000)*n, randint(1, 1000000)*n])
Out[945]: 123456789
```
某些取模运算是会等于0的

``X = 0 (mod n)``
然后，根据定义，这相当于：

``X = k*n``
所以这种``X != 0``但是``X = 0 (mod n)``的情况就很有趣。我们只需要取几个这样的值进行gcd运算，我们就可以解出n的值。这种是在模数未知的情况下十分常用的方法。

我们在此引入一个序列 – T(n) = S(n+1) - S(n):
```python
t0 = s1 - s0
t1 = s2 - s1 = (s1*m + c) - (s0*m + c) = m*(s1 - s0) = m*t0 (mod n)
t2 = s3 - s2 = (s2*m + c) - (s1*m + c) = m*(s2 - s1) = m*t1 (mod n)
t3 = s4 - s3 = (s3*m + c) - (s2*m + c) = m*(s3 - s2) = m*t2 (mod n)
```
之后我们就可以得到我们想要的效果了:

``t2*t0 - t1*t1 = (m*m*t0 * t0) - (m*t0 * m*t0) = 0 (mod n)``
然后我们就可以生成几个这样模是0的值，进而利用我们上文讲述的技巧，此种类型Python攻击代码如下所示:

```python
def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)

print crack_unknown_modulus([2818206783446335158, 3026581076925130250,
    136214319011561377, 359019108775045580, 2386075359657550866, 1705259547463444505])
```

### 0x03 总结
此处我们简述了对LCG的攻击方式，这种方式刚在P.W.N CTF中出现过，具体的题目以及解答可以参考我的下一篇文章–《P.W.N. CTF》中的LCG and the X题目解析。



本文来源：码农网
本文链接：https://www.codercto.com/a/35743.html