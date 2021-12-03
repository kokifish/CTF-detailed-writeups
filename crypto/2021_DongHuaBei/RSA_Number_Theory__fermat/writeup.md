# 2021年东华杯大学生网络安全邀请赛暨第七届上海市大学生网络安全大赛—— Crypto —— fermat's reverse
题目见`task.py`，数据见`cipher.txt`

* 题目描述：题目给出$(1010p+1011)^q\ mod\ n$，分解$n$。

* 题解：依题意记$c \equiv (1010p+1011)^q\ mod\ n$。则有$c \equiv 1011^q\ mod\ p \equiv 1011^n \ mod\ p$ 因此有$$ p | (1011^n - c)$$，然后gcd得到p


```python
n=

hint=

pow(1011,n,n) > hint

import gmpy2
gmpy2.gcd(pow(1011, n, n) - hint, n)

p = gmpy2.gcd(pow(1011, n, n) - hint, n)
q = n // p
c=

phi = (p-1)*(q-1)
d = gmpy2.invert(65537, phi)
m = pow(c, d, n)
from Crypto.Util.number import long_to_bytes
long_to_bytes(m)
# b'flag{1d2f28834ecbd1983b62d30f4723476e}'
```