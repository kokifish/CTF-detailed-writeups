# 2021年东华杯大学生网络安全邀请赛暨第七届上海市大学生网络安全大赛—— Crypto —— CryptoSystem_ec
题目见`task_ec.py`

* 题目描述：首先题目给出一个同态加密方案，然后给出一个用rsa加密后的hint。要求破解这个同态加密方案。

* 题解：首先根据hint分解rsa，然后得到同态加密的hint，hint为同态加密中大数$N=pq$中的p，既相当于帮我们分解了大数$N$。

然后这个同态加密方案是Paillier加密方案的一个变种。因为该方案中的$r$是模$N^2$的数而Paillier方案是一个模$N$的数。

因此我们需要用到公式$a^{\phi{N} = 1+kN}$这个性质。然后两个离散对数就都可以写成$(1+kN)$的形式，从而可以把离散对数求解出来，然后通过这个性质就可以解密了。

* 所以其实这个密码方案的安全性上还是基于大数分解。

```python

from Crypto.Util.number import *
def Encrypt(public,pk,m):
    N,g = public
    r = random.randrange(N*N)
    A = pow(g,r,N*N)
    B = (pow(pk,r,N*N) * (1 + m * N)) % (N * N)
    return A,B

p =
assert N % p == 0

q = N // p

def L(c, lam, N):
    return (pow(c, lam, N**2) - 1) // N

m2 = []
for i in range(len(c_list)):
    A, B = c_list[i]
    y = y_list[i]
    lam = (p-1) * (q-1) // GCD(p-1, q-1)lcc = L(y, lam, N)
    lgg = L(g, lam, N)
    mu = inverse(lgg, N)
    xx = lcc * mu % N
    # print(xx == x % N)
    k = L(A, lam, N)
    h2 = L(B, lam, N)
    m2.append((h2 - k*xx) * inverse(lam, N) % N)

m22 = [123, 456, 789, 123, 456, 789]
m = [x - y for x, y in zip(m2, m22)]
for x in m:
    print(long_to_bytes(x))
```

参考writeup：W4terDr0p 

