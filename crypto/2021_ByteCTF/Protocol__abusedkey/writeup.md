# 2021年ByteCTF—— Crypto —— abusedkey

题目见`abusedkey.md`

* 一般来说发现又臭又长的题目一般都是纸老虎，本质上是阅读理解题，根据题目写Client就行。首先模拟协议二的client，然后得到hint，按照题目的描述，hint应该就是协议一中server的公钥和client的私钥。然后直接进行模拟协议一交互得到flag。

* 官方解题代码：
```python
import hashlib

import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from ellipticcurve.curve import secp256k1
from ellipticcurve.math import Math
from ellipticcurve.point import Point
from ellipticcurve.utils.integer import RandomInteger

curve = secp256k1
d_C_hex = hint
P_C_hex = 'b5b1b07d251b299844d968be56284ef32dffd0baa6a0353baf10c90298dfd117' \
          'ea62978d102a76c3d6747e283091ac5f2b4c3ba5fc7a906fe023ee3bc61b50fe'

P_S_hex = hint

pi_C = 'FFFF'

url_msg11 = 
url_msg13 = 
url_msg21 = 
url_msg23 = 
url_msg25 = 

def correctness_ake():
    d_C = int(d_C_hex, 16)
    P_S = Point(int(P_S_hex[:64], 16), int(P_S_hex[-64:], 16), 0)

    sid_1 = get_random_bytes(32).hex()
    msg12 = requests.get(url_msg11, data=sid_1).text
    T_S = Point(int(msg12[:64], 16), int(msg12[64:], 16), 0)

    t_C = RandomInteger.between(1, curve.N - 1)
    T_C = Math.multiply(curve.G, n=t_C, A=curve.A, P=curve.P, N=curve.N)
    T_C_hex = '%064x%064x' % (T_C.x, T_C.y)
    msg14 = requests.get(url_msg13, data=(sid_1 + T_C_hex)).text

    former_C = Math.multiply(T_S, n=(d_C + t_C), A=curve.A, P=curve.P, N=curve.N)
    latter_C = Math.multiply(P_S, n=t_C, A=curve.A, P=curve.P, N=curve.N)
    KCS_C = Math.add(former_C, latter_C, curve.A, curve.P)

    KCS_C_x_bytes = KCS_C.x.to_bytes(32, 'big')
    sk1_C_bytes = hashlib.sha256(KCS_C_x_bytes).digest()
    output = bytes.fromhex(msg14)
    iv, mac = output[:12], output[-16:]
    cipher = AES.new(sk1_C_bytes, AES.MODE_GCM, iv)
    flag = cipher.decrypt_and_verify(output[12:-16], mac).decode()
    print(flag)

def correctness_pake():
    sid_2 = get_random_bytes(32).hex()

    msg22 = requests.get(url_msg21, data=sid_2).text
    Q_S_hex = msg22

    r_C = RandomInteger.between(1, curve.N - 1)
    R_C = Math.multiply(curve.G, n=r_C, A=curve.A, P=curve.P, N=curve.N)
    h_C = int.from_bytes(hashlib.sha256(bytes.fromhex(pi_C)).digest(), 'big') % curve.N
    Q_C = Math.multiply(R_C, n=h_C, A=curve.A, P=curve.P, N=curve.N)
    Q_C_hex = '%064x%064x' % (Q_C.x, Q_C.y)
    msg23 = Q_C_hex + Q_S_hex

    msg24 = requests.get(url_msg23, data=msg23).text
    Y_C_hex = msg24[:128]
    msg26 = requests.get(url_msg25, data=(sid_2 + Y_C_hex)).text

    Y_S_x_hex = msg24[-128:-64]
    Y_S_y_hex = msg24[-64:]
    Y_S = Point(int(Y_S_x_hex, 16), int(Y_S_y_hex, 16), 0)
    ZCS_C = Math.multiply(Y_S, n=r_C, A=curve.A, P=curve.P, N=curve.N)
    ZCS_C_x_bytes = ZCS_C.x.to_bytes(32, 'big')
    sk2_C_bytes = hashlib.sha256(ZCS_C_x_bytes).digest()

    output = bytes.fromhex(msg26)
    iv, mac = output[:12], output[-16:]
    cipher = AES.new(sk2_C_bytes, AES.MODE_GCM, iv)
    hint = cipher.decrypt_and_verify(output[12:-16], mac).decode()
    print(hint)

if __name__ == '__main__':
    correctness_ake()
    correctness_pake()
```

* 参考资料：
    * https://bytectf.feishu.cn/docs/doccnq7Z5hqRBMvrmpRQMAGEK4e#