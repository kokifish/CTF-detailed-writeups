# 2021年RCTF—— Crypto —— Uncommon_Factors_I

## 题目
见当前目录的`uncommon.sage`文件

题目给出了$2^22$对RSA的$N$的值，但是没有设计加密解密和密钥。因此可以理解为是一道数学题。题目中p是200bit的素数，q是312bit的素数，然后p的高152bit是固定的，是由flag组成。

这里不能使用Approximate GCD的方法求解，因为$r_i$过大。根据dalao的提示，这道题使用的是Batch GCD。本质上就是给出许多个($t$个)$N_1,\cdots,N_t$。然后Batch GCD算法可以快速给出每个数关于其它所有数的共享最大公约数，即对于$N_0$，如果其共享gcd不为1，则表示$\exists i, gcd(N_0,N_i)\neq 0$。

然后Batch GCD算法求解GCD比每两个数分别两两求解gcd的速度要快得多。因此这道题目可以使用这种方法来求解。因为题目中给出了$2^22$个$N$，然后$p$的取值只有$2^48$个，非常大概率存在相同的$p$出现。因此可以使用这种方法求解。

因为题目中给出了256Mb的数据，这里就不给出了。


题解：

Batch GCD的代码github上有，我使用的是这个：
https://github.com/therealmik/batchgcd

把`lN.bin`文件转化为十六进制的形式后输入到代码中。
```bash
> ./fastgcd input.module
    preprocessing input from input.module
    preprocessing 4194304 elements took 4.881s
    multiplying numbers...
    reading input.mpz...4194304 elements, 301956105 bytes (0.510s
    ...
```
大概用了400秒左右出结果，结果在当前目录的`gcds`文件里面，记录的是共享GCD不为1的结果。
```
# gcds 文件
7f2ec3455a5f6763645f5472333333333333338a2068398023
7f2ec3455a5f6763645f5472333333333333336044cf07eca9
7f2ec3455a5f6763645f547233333333333333f963ef8d63a3
7f2ec3455a5f6763645f5472333333333333333a3df554fba1
7f2ec3455a5f6763645f5472333333333333336044cf07eca9
7f2ec3455a5f6763645f547233333333333333f963ef8d63a3
7f2ec3455a5f6763645f5472333333333333337c74d2c9536d
7f2ec3455a5f6763645f5472333333333333337c74d2c9536d
7f2ec3455a5f6763645f5472333333333333333a3df554fba1
7f2ec3455a5f6763645f5472333333333333338a2068398023
```
然后提取中间的128bit就是flag了
```python
a = 0x7f2ec3455a5f6763645f5472333333333333338a2068398023
a >>= 48
b = a % (2**128)
b.to_bytes(22, 'big')
b'\x00\x00\x00\x00\x00\x00EZ_gcd_Tr3333333'
```

从而得到flag为`flag{EZ_gcd_Tr3333333}`

参考资料：
* https://github.com/therealmik/batchgcd
* https://protonmail.com/blog/batch-gcd/
* https://facthacks.cr.yp.to/batchgcd.html
* https://windowsontheory.org/2012/05/15/979/