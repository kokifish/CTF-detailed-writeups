# 2021年RCTF—— Crypto —— Uncommon_Factors_II

## 题目
见当前目录的`uncommon2.sage`文件

题目给出了$2^7$对RSA的$N$的值，但是没有设计加密解密和密钥。因此可以理解为是一道数学题。题目中p是312bit的素数，q是200bit的素数，然后p的高208bit是固定的，是由flag组成。

这道题是能被LLL算法破解的近似最大公约数问题。(Approximate GCD)。
题目可以看成，给定固定的$p$,计算$x_i = q_ip + r_i$。其中$q_i,r_i$都是变量。其中一种攻击方法SDA（ Simultaneous Diophantine approximation）要求$r_i$不能大于$pq_i$，从而保证满足 $$\frac{x_i}{x_0} \approx \frac{q_i}{q_0}$$

从而有$q_02^{\rho+1} \approx q_0r_1-q_1r_0 \approx \cdots \approx q_0r_t-q_1r_t$，其中是$r_i$最多有$\rho$bit。可以列出基矩阵$B$然后使用LLL算法进行求解。LLL算法其中一些向量中的第一个元素为$q_02^{\rho+1}$。从而求出了$q_0$，进而求出$p$。

题解：
```python
# sagemath 9.2

import random
import numpy as np

f = open('lN.bin','rb')

ns = []
for i in range(2**7):
    msg = f.read(64)
    n = int.from_bytes(msg, 'big')
    ns.append(n)
    
print(len(bin(ns[10])[2:]))

# for l in range(100,312):
lamb = 304
N = 2**7-1

m = Matrix(ZZ, N + 1, N + 1)
for i in range(N + 1):
    m[i, i] = -ZZ(ns[0])
#     m[i, 0] = ZZ(ns[i])
    m[0,i] = ZZ(ns[i])
m[0, 0] = ZZ(2**(lamb+1))

ml = m.LLL()
ttt = ml.rows()    

for i in range(N):
        a = ttt[i][0]
        while not (a&1) and a!=0:
            a >>= 1
        if is_prime(a):
            print(i, a)

# 10 12196246221116293539829081328604201616947934540493681923337
# 11 12196246221116293539829081328604201616947934540493681923337
# ...

a = 12196246221116293539829081328604201616947934540493681923337
p = ns[0] // a
p >>= 104
p %= 2**129
# len(bin(p)[2:])
(p).to_bytes(22,'big')
# b'\x00\x00\x00\x00\x00\x00Simpl3_LLL_TrIck'
```

从而得到flag为`flag{Simpl3_LLL_TrIck}`

参考资料：
* https://martinralbrecht.wordpress.com/2020/03/21/the-approximate-gcd-problem/
* https://eprint.iacr.org/2016/215.pdf