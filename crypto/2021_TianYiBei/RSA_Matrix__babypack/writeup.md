# 2021年“天翼杯”—— Crypto —— babypack

题目见`task.py`.

题目生成了一个两个512比特的整数列表U，V。其中有$$V[i] = U[i] - 2^{512-i}$$ 取素数$p,q$，并令$n=pq$,且有$p > sum(U)\ q > sum(V的正数和负数和的最大值)$。然后通过中国剩余定理生成列表A，其中有$$a_i\equiv u_i\ mod\ p\\ a_i\equiv v_i\ mod\ q$$ 然后公钥为$A, U[0], V[0]$。

加密函数为
```python
def encrypt(msg, pub):
    s = 0
    for i, j in zip(msg, pub):
        s += i * j
    return s
```

经推导，若知道$p,q$则能很容易进行解密，推导过程不难，关键在于$sum(U) < p$， 这样就有$sum(A) % p = sum(U)$。
```python
def decrypt(c, p, q):
    mp = c % p
    mq = c % q
    msg = abs(mq-mp)
    return msg
```

**难点：** 题目的难点在于怎么把$p,q$恢复出来。这里没有想到，看了别人的wp之后发现因为题目有hint能给出部分的$n$。然后根据题目要求可以恢复出约666个比特，大概知道n是1024bit左右，因此使用 Factoring with High Bits Known(已知高比特分解) 【虽然是在RSA中使用的，但是关键在于求解$x+p_{fake}\equiv 0\ mod\ Factor(N)$】

其中x就是我们想要求的$n$，然后根据给出的公钥有$$n \mid (a[0]-u[0])(a[0]-v[0])$$因此有$N = (a[0]-u[0])(a[0]-v[0])$，然后使用Factoring with High Bits Known(已知高比特分解) 把$n$求出来。求出来之后有$$p = gcd(n, a[0]-u[0]) \\ q = gcd(n, a[0]- v[0])$$。进而得到$p,q$代入解密函数就可以解密，从而向服务器拿到flag。

参考代码：见`solution.py`和`Factor_with_high_known_bit.sage`。其中`task_server.py`是本地测试用的。

参考wp：
* https://mp.weixin.qq.com/s/IowuiwBIfaV4AldqrXjmCQ
* https://zhuanlan.zhihu.com/p/413319231