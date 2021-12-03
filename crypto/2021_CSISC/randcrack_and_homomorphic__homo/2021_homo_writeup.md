## homo

题目：见`task.py`和`poly.py`文件

* 说明：`poly.py`文件给出了多项式的定义，相当于是一个文件类。`task.py`文件给出了编码，同态加密和解密。

题目分为两个阶段：
1. 第一个阶段是`game()`函数定义的，本质上就是破解python自带的`random`类中的随机数。参考`random_number_Mersenne_Twister_2021NahamconCTF_Dice_Roll`中的writeup。里面使用的随机数预测器是自己手动写的，然后貌似还可以使用python自带的`randcrack`库进行破解。

2. 第二个阶段就是输入一个自定义的密文，然后有一个Oracle(服务器)会返回解密的结果，只要给出的这个密文不是ct[0],ct[0]和0。
    * 解法1：因为是同态加密，因此只要给出2*ct[0],2*ct[0]就可以把2m恢复出来，其中m表示的是明文。然后知道2m就相当于知道了m。
    * 解法2：按照别人的writeup的说法以及同态加密的实现过程，算法实际上是加了一点噪音，因此我们给Oracle的密文只需要给出ct[0]+1和ct[0]+1，这样就能直接得到m。这是因为加少许噪音不影响解密结果。


解题程序
```python
from randcrack import RandCrack
from Crypto.Util.number import long_to_bytes
from pwn import *

# context.log_level = 'debug'

p = process(["python", "task.py"])
pk0 = p.recvline()
pk1 = p.recvline()
ct0 = p.recvline()
ct1 = p.recvline()
ct0 = eval(ct0)
ct1 = eval(ct1)
ct0[-1] -= 1
ct1[-1] -= 1
p.sendline("1")
rc = RandCrack()
for i in range(312):
    p.sendlineafter(":", "0")
    p.recvuntil("number is ")
    num = int(p.recvline().strip())
    rc.submit(num & ((1<<32)-1))
    rc.submit(num >> 32)
for i in range(200):
    p.sendlineafter(":", str(rc.predict_getrandbits(64)))
p.sendline("2")
p.sendlineafter("c0:",repr(ct0)[1:-1])
p.sendlineafter("c1:",repr(ct1)[1:-1])
p.recvline()
res = p.recvline()
res = eval(res)
flag = long_to_bytes(int(''.join(map(str, res)),2))
print(flag)
```