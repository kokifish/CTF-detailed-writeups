# 2021第三届美团CTF—— Crypto —— easy_RSA

## 题目 

首先题目给出了一个`padding_attack`文件，里面使用的是RSA短填充攻击。解出明文为：`everything_is_easy_in_this_question`

然后该明文是压缩文件的密码，解密后得到一个`one_time_cipher`文件，里面是使用相同密钥的异或加密。

* 个人的破解方案为两个密文之间相互异或就可以把密钥去除，然后如果两个密文间有一个明文是**空格字符**，那么就可以把另一个密文恢复出来，如果有多个密文与密文字符c异或都是英文字符，那么c很有可能就是空格字符。然后再根据明文信息逐步恢复出所有的明文。**这个方案非常的不科学，不是正常解法，最后能求解出结果只能说是暴力硬解出来的。**

* 另一个方法参考 https://ctf.njupt.edu.cn/618.html#easy_RSA
这个方法先是把密钥和明文的范围进行缩小。先对加密的密钥定义一个table1，然后再对明文m定义一个table2，如果暴力模拟密钥的每个字符，如果这个字符能使所有的明文m都落在table2中，那么就表示当前密钥字符是可取的。这样一来就能大幅度缩小明文和密钥的范围。最终可以很轻易把密钥恢复出来。然后最后发现密钥就是flag。
`flag{it_1s_P@dd1n_@nd_p@d}"`

代码：
```python
from Crypto.Util.number import *
from string import *
print(printable.encode())
TABLE1=ascii_letters+digits+"{}_@#\"| "
TABLE2=b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,{} '
# data = open("one_time_cipher").read().split(',\n')
data = [0x280316470206017f5f163a3460100b111b2c254e103715600f13,             0x091b0f471d05153811122c70340c0111053a394e0b39500f0a18,
     0x4638080a1e49243e55531a3e23161d411a362e4044111f374409, 0x0e0d15470206017f59122935601405421d3a244e10371560140f,
     0x031a08080e1a540d62327f242517101d4e2b2807177f13280511, 0x0a090f001e491d2c111d3024601405431a36231b083e022c1d,
     0x16000406080c543854077f24280144451c2a254e093a0333051a, 0x02050701120a01334553393f32441d5e1b716027107f19334417,
     0x131f15470800192f5d167f352e0716481e2b29010a7139600c12, 0x1609411e141c543c501d7f232f0812544e2b2807177f00320b1f,
     0x0a090c470a1c1d3c5a1f2670210a0011093a344e103715600712, 0x141e04040f49153142043a22601711520d3a331d0826]

data = [long_to_bytes(i) for i in data]
# print(data)
key = []
for i in range(26):
    tmp_key = b""
    for j in TABLE1.encode(): # 密钥key的table
        yes = True
        for k in range(len(data)):
            if len(data[k])<(i+1): break
            tmp_m = j^data[k][i]
            if long_to_bytes(tmp_m) not in (TABLE2.decode()).encode(): # 明文m的table
                yes = False
                break
        if yes:
            tmp_key += long_to_bytes(j)
    print(tmp_key)
    key.append(tmp_key)
```

* 第三种解法使用多字节XOR加密方式的破解工具``cribdrag``破解密文,但是暂时我还不会使用这个工具。