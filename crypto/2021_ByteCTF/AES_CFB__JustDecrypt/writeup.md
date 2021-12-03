# 2021年ByteCTF—— Crypto —— JustDecrypt

题目见`JustDecrypt.py`

题目仅仅使用CFB模式的AES的解密运算，然后要求我们构造出一个密文使得其输出指定的明文。

题解，首先需要了解AES在CFB模式下的运行：
* CFB模式需要一个整数参数$s$，使$1\leq s\leq b$。在下面的CFB模式规范中，每个明文段($P_j$)和密文段($C_j$)由$s$位组成。$s$的值有时被合并到模式的名称中，例如，1位CFB模式、8位CFB模式、64位CFB模式或128位CFB模式。运算形式如下： $$ \begin{array}{l}I_0 = IV, \\ I_i=((I_{i-1}\ll s) + C_i)\ mod\ 2^b, \\ C_i = MSB_s(E_K(I_{i-1}))\oplus P_i, \\ P_i = MSB_s(E_K(I_{i-1}))\oplus C_i \end{array}$$

题目的分段是默认分段，以8位为一个段。而且题目还会随机删除解密后密文的最后的部分解密后的明文。因此我们需要在我们伪造的明文后加上一段256长度的固定byte串使得令解密不要把伪造的信息删除。然后根据8位一个段，每次伪造8位的明文，因此进行49次伪造就能伪造出目标明文。

* 官方解题代码：

```python
import re
import itertools
import string
import codecs
from hashlib import sha256
from pwn import remote, context
from os import urandom

# context.log_level = 'debug'

BLOCK_SIZE = 16


def PoW(hash_value, part):
    alphabet = string.ascii_letters + string.digits
    for x in itertools.product(alphabet, repeat=4):
        nonce = ''.join(x)
        if sha256((nonce + part).encode()).hexdigest() == hash_value:
            return nonce


def pad(s):
    num = BLOCK_SIZE - (len(s) % BLOCK_SIZE)
    return s + bytes([num] * num)


def xor(a, b):
    assert len(a) == len(b)
    return bytes([i ^ j for i, j in zip(a, b)])


def send_encrypted_data(sh: remote, data: bytes):
    sh.recvuntil(b'Please enter your cipher in hex > ')
    sh.sendline(codecs.encode(data, 'hex'))
    sh.recvuntil(b'Your plaintext in hex: \n')
    pt = codecs.decode(sh.recvline().strip(), 'hex')
    return pt


def main():
    sh = remote('127.0.0.1', 30000)

    line = sh.recvuntil(b'Bytedancer can get secret.\n')
    print(line)
    # re_res = re.search(r'sha256\(XXXX\+([0-9a-zA-Z]{28})\) == ([0-9a-z]{64})', line.decode())
    # part = re_res.group(1)
    # hash_value = re_res.group(2)
    # nonce = PoW(hash_value, part)
    # sh.sendline(nonce.encode())
    # print('PoW finish.')

    new_plain = pad(b"Hello, I'm a Bytedancer. Please give me the flag!")

    suffix = urandom(256)

    cipher = b'\x00' * 64
    t_cipher = suffix + cipher + suffix
    res = send_encrypted_data(sh, t_cipher)
    # pt = b'\x00'
    # cipher = bytes([res[256]]) + b'\x00' * 63
    pt = bytes([res[256]])
    cipher = b'\x00' * 64


    for i in range(0, 49):
        # cipher = cipher[:i] + bytes([cipher[i] ^ pt[i] ^ new_plain[i]]) + cipher[i + 1:]
        print(pt[i])
        cipher = cipher[:i] + bytes([pt[i] ^ new_plain[i]]) + cipher[i + 1:]
        t_cipher = cipher + suffix
        pt = send_encrypted_data(sh, t_cipher)
        print(pt)

    cipher = cipher[:63] + b'\x00' + cipher[63 + 1:]
    t_cipher = cipher + suffix
    pt = send_encrypted_data(sh, t_cipher)
    print(pt)

    cipher = cipher[:63] + bytes([pt[63] ^ new_plain[63]]) + cipher[63 + 1:]
    t_cipher = cipher
    pt = send_encrypted_data(sh, t_cipher)
    print(pt)

    sh.interactive()


if __name__ == '__main__':
    main()
```

* 参考资料：
    * https://bytectf.feishu.cn/docs/doccnq7Z5hqRBMvrmpRQMAGEK4e#
    * https://blog.csdn.net/m0_57291352/article/details/120935264
    * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation