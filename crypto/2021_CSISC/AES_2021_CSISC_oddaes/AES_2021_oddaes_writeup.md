## oddaes

* 参考文献：http://eprint.iacr.org/2009/575

题目所求的是AES的差分故障分析（Differential Fault Analysis）。
* 原理：若在AES的第八轮的某个字节中添加错误信息，则AES算法的密钥可以在多项式时间内恢复出来。算法的本质有时间可以去研究，但在做题的时候只要知道怎么使用即可。


题目：
```python
from aes import AES
# from flag import key,flag
key = b'1234567890abcdef'
flag = b'CISCN{996ce17f6abc9fe126b57aa5f1d8c92c}'
import os,hashlib,random
print(hashlib.md5(key).hexdigest())

assert (flag[:5] == b'CISCN')
assert (flag[6:-1]==hashlib.md5(key).hexdigest().encode())
plain = os.urandom(16)
print (AES(key).encrypt_block(plain))
cipher,k = AES(key).encrypt_block_(plain,random.randint(0,255))
print (cipher)
piece1 = [k[0],k[1],k[4],k[7],k[10],k[11],k[13],k[14]]
print (hashlib.md5(bytes(piece1)).hexdigest())
piece2 = [k[2],k[3],k[5],k[6],k[8],k[9],k[12],k[15]]
print (hashlib.md5(bytes(piece2)).hexdigest())

```

题目中给出了添加了错误信息的AES的加密结果和没有添加错误信息的加密结果。然后再给出了最后一轮密钥的哈希值。可以很明显看出可以直接使用差分故障分析是最直观的。

参考代码：https://github.com/Daeinar/dfa-aes
见``dfa-aes-master.zip``文件，readme里面写得非常清楚。

* 用法：程序非常简单，只有一个`dfa.exe`可执行文件。必须传入3个参数，第一个是破解时使用的核数，第二个是错误添加的位置0-15。若为-1则回遍历0-15，第三个是输入文件。文件中每行包括两个16进制的长度为32的字符串，表示两个加密结果，一个是正常的，另一个是添加了错误的。然后文件就会执行DFA算法给出AES算法可能的密钥，并存放在`keys-s.csv`文件中。

example:``dfa.exe 32 -1 input-1.csv``

然后运行程序
```python
import os,hashlib
from aes import AES
import binascii

plain = os.urandom(16)

with open('keys-0.csv','r') as f:
    content = f.readlines()

for line in content:
    candidate = binascii.unhexlify(line.strip())
    cipher, k = AES(candidate).encrypt_block_(plain, 0)
    piece1 = [k[0], k[1], k[4], k[7], k[10], k[11], k[13], k[14]]
    if hashlib.md5(bytes(piece1)).hexdigest() == '417e875092e51d5612b8e81f99773236':
        print(hashlib.md5(candidate).hexdigest())
        # 973f5ae78bc933a8fc7f7ab98d53d16f
        break
```
`flag = CISCN{973f5ae78bc933a8fc7f7ab98d53d16f}`

参考writeup：不知道是那个dalao给出的`CISCN Crypto`专门为Crypto方向写的writeup。