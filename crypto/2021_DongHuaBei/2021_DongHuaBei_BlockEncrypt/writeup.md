# 2021年东华杯大学生网络安全邀请赛暨第七届上海市大学生网络安全大赛—— Crypto —— BlockEncrypt
题目见`task.py`还有一个`my_encrypt.cpython-39.pyc`编译后的文件

* 题目描述：题目给出flag的密文，然后我们可以输入任意的明文然后服务器给出密文。

首先因为`pyc`文件是python3.9版本，使用`pycdc`进行反编译得到了一个类似AES的加密系统，但是反编译不完善，有些细节没有出来。（在做题的时候卡在这里不知道怎么做了）

赛后看了一下dalao的wp，发现明文的某一位输入对应密文的相同位置的输出，这里猜测是padding出了问题。因此我们只需要暴力模拟明文的某一位输入，直到与密文相匹配，然后进行下一位明文的暴力模拟。

* 题解：
```python
from pwn import *
from Crypto.Util.number import long_to_bytes,bytes_to_long
import gmpy2
import itertools
from hashlib import sha256

conn = connect('127.0.0.1', 10004)

msg = conn.recvline()
print(msg)

b = msg[16:32].decode()
ans = msg[37:-1].decode()

for a in itertools.product(string.ascii_letters+string.digits, repeat=4):
    a = ''.join(a)
    payload = a + b
    if (sha256(payload.encode()).hexdigest() == ans):
        print(a)
        conn.sendline(a.encode())
        break

msg = conn.recvuntil(b'3.Exit:\n')
print(msg)

conn.sendline(b'1')
# msg = conn.recvline()
enc_flag = conn.recvuntil(b'3.Exit:\n')[26:-67]
print(enc_flag)

alphabat = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-,.?}{'

try_flag = b'flag{'
judge = 1
l = 5
tmp_cipher = b''

while True:
    l += 1

    for i in range(len(alphabat)):
        tf = try_flag + chr(alphabat[i]).encode() + b'000'

        conn.sendline(b'2')
        msg = conn.recvuntil(b'Cipher.\n')
        conn.sendline(tf)
        conn.recvuntil(b'CipherText:')
        cipher = conn.recvuntil(b'3.Exit:\n')[:-67]
        # print(msg)
        if cipher[l-1] == enc_flag[l-1]:
            try_flag = try_flag + chr(alphabat[i]).encode()
            tmp_cipher = cipher
            break
    print(l, try_flag)
    print(tmp_cipher)
    if tmp_cipher == enc_flag or l >= len(enc_flag):
        break
print('flag:', try_flag)
```


* !!!出题人说这个是非预期解emmmmm，那正解是什么。。。。。。