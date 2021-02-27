# 2021年*CTF2021 —— Crypto —— MyEnc

## 题目
题目中给出了一个服务器的IP，然后给出handout.py代表服务器的逻辑。
```py
# handout.py
from Crypto.Util.number import getPrime,bytes_to_long
import time,urandom
from flag import flag
iv=bytes_to_long(urandom(256))
assert len(flag)==15
keystream=bin(int(flag.encode('hex'),16))[2:].rjust(8*len(flag),'0')
p=getPrime(1024)
q=getPrime(1024)
n=p*q
print "n:",n
cnt=0
while True:
    try:
        print 'give me a number:'
        m=int(raw_input())
    except:
        break
    ct=iv
    for i in range(1,8):
        if keystream[cnt]=='1':
            ct+=pow(m^q,i**i**i,n)
            ct%=n
        cnt=(cnt+1)%len(keystream)
    print "done:",ct
```

## 解题
***这道题没有想出来，我就看别人的writeup来复现，同时也积累一下经验***

服务器的逻辑就一个RSA加密，给定了模数N。然后客户端每给出一个数m，服务器就会返回$$ iv+\sum_{i=1}^7k[(cnt+i-1)mod\ 120](m\hat \ q)^{i^{i^i}}\ mod\ N \tag{1}$$这个值。其中$k[(cnt+i-1)mod\ 120]$表示的是flag所生成的01比特串作为的密钥流$k$的第$(cnt+i-1)mod\ 120$位，这里$k$的长度为120bit。$iv$代表一个常数。然后每次输入一个数后，cnt就加7，然后等待下一个m的输入。(*这里的自己的归纳，避免慢慢看代码*)

题目的目的是要把密钥流k找出，实际上这道题的RSA只是一个工具。flag与RSA算法本身并无关系。

但是要求密钥流k，最好的方法是把$q$和$iv$恢复出来。我做的时候没有经验，不知道怎么恢复。实际上是这样，通过输入3个0，获取三组数据$q_0,q_1,q_2$。然后$gcd(N,gcd(q_0-q_1,q_0-q_2)) = q$。推导过程如下：
$$
q_0-q_1 = \sum_{i=1}^7(k_{0,i}-k_{1,i})q^{i^{i^i}}\ mod\ N \newline
q_0-q_2 = \sum_{i=1}^7(k_{0,i}-k_{2,i})q^{i^{i^i}}\ mod\ N
$$可以看出，$q_0-q_1$与$q_0-q_2$必定有一个公因子q，而其最大公约数可能你是q的倍数，因此还需要求它与N的最大公约数。

此时恢复出了q，我们向服务器输入q，这样q与q进行异或得到了0，服务器返回的结果就只有$iv$了。此时我们就得到了$iv$。

接下来不断输入0，获取一组服务器。接下来我们可以每7个比特进行穷搜索，因为现在$q$与$iv$已知，只剩下k未知，只要遍历7位k，就然后比较遍历的结果是否与服务器返回的结果一致，若一致，则得到的就是对应的密钥流。这里要注意我们前面已经输入了4次m，因此穷搜索时候是在k的第29bit开始。然后循环穷搜索18次就可以把k恢复出来。

这里仿照题目自己写了一个服务器名为``MyEnc.py``文件。

```py
# MyEnc.py

from Crypto.Util.number import getPrime, bytes_to_long
import os
from socket import *
flag = 'flag{123456789}'

# 生成iv, q, p, n, keystream
iv = bytes_to_long(os.urandom(256))
assert len(flag) == 15
keystream = bin(int(flag.encode('hex'), 16))[2:].rjust(8 * len(flag), '0')
p = getPrime(1024)
q = getPrime(1024)
n = p * q

phi = (p-1) * (q-1)
i_list = [0]        # 提前计算幂次，减少运算的时间
for i in range(1, 8):
    i_list.append((i**i**i) % phi)

print("n:", n)
print('q:',q)
print('iv', iv)

serverSocket = socket(AF_INET,SOCK_STREAM)
serverSocket.bind(('127.0.0.1', 9001))
serverSocket.listen(10)
clientSocket, clientInfo = serverSocket.accept()

clientSocket.send(str(n).encode('utf-8'))
cnt = 0
while True:
    try:
        m = int(clientSocket.recvfrom(2048)[0])
        print('give me a number:', m)

    except:
        break
    ct = iv
    for i in range(1, 8):
        if keystream[cnt] == '1':
            ct += pow(m ^ q, i_list[i], n)
            ct %= n
        cnt = (cnt + 1) % len(keystream)
    print("done:", ct)
    clientSocket.send(str(ct))
```
自身设定的flag为``flag{123456789}``。

然后写了一个客户端名为``MyEnc_solution.py``文件，里面包含了交互的逻辑与分析的过程，并最后给出结果。

```python
# MyEnc_solution.py

from gmpy2 import *
from socket import *

def brute_flag(res, q, n, q_list, iv):
    dic = ["0", "1"]
    for x1 in dic:
        for x2 in dic:
            for x3 in dic:
                for x4 in dic:
                    for x5 in dic:
                        for x6 in dic:
                            for x7 in dic:
                                xx = x1 + x2 + x3 + x4 + x5 + x6 + x7
                                ct = 0
                                for i in range(7):
                                    if xx[i] == '1':
                                        ct = (ct + q_list[i])%n
                                if ct == res:
                                    # print("find ct: " + str(xx))
                                    return xx


if __name__=='__main__':

    host = '127.0.0.1'
    port = 9001
    bufsize = 2048
    addr = (host, port)
    client = socket(AF_INET, SOCK_STREAM)
    client.connect(addr)

    n = int(client.recvfrom(bufsize)[0])
    client.send('0')
    print 'n:', n

    q0 = int(client.recvfrom(bufsize)[0])
    client.send('0')
    q1 = int(client.recvfrom(bufsize)[0])
    client.send('0')
    q2 = int(client.recvfrom(bufsize)[0])

    a = (n + q0 - q1) % n
    b = (n + q2 - q1) % n
    q = gcd(a, b)
    q = gcd(q, n)
    print(q)

    # solve iv input q and get iv
    client.send(str(q))
    iv = int(client.recvfrom(bufsize)[0])
    print 'iv:', iv

    N = 120
    cnt = 0
    a = [0 for i in range(N+7)]
    b = [0 for i in range(N)]
    for i in range(20):
        print i
        client.send('0')
        tmp = (int(client.recvfrom(bufsize)[0]) + n - iv) % n
        b[i] = tmp
    client.close()

    # 计算q_list避免重复计算pow(q, i**i**i, n)
    p = n/q
    phi = (p-1)*(q-1)
    i_list = [0]
    for i in range(1, 8):
        i_list.append((i ** i ** i) % phi)
    q_list = []
    for i in range(1,8):
        q_list.append(pow(q, i_list[i], n))

    # 从第29位开始每7bit进行穷搜索来找密钥流，结果存在列表a中
    cnt += 4 * 7
    cum_cnt = 0
    for i in range(N):
        tmp = brute_flag(b[i], q, n, q_list, iv)
        print 'ct:', tmp
        tmp = list(tmp)
        for j in range(7):
            a[cnt+j] = tmp[j]
        cnt += 7
        cum_cnt += 7
        if cnt > N:         # 边界判断
            a[0:cnt - N + 1] = a[N: cnt + 1]
            cnt -= N
        if cum_cnt > 120:   # 退出条件
            break

    print a[0:N]
    a = a[0:N]
    # binary to str
    b = ''.join(a)
    if int(b,2) > 2**32:
        flag = hex(int(b, 2))[2:-1].decode('hex')
    else:
        flag = hex(int(b, 2))[2:].decode('hex')
    print flag

```
客户端最终运行结果：
```
...
ct: 1000110
ct: 0001011
ct: 0011101
['0', '1', '1', '0', '0', '1', '1', '0', '0', '1', '1', '0', '1', '1', '0', '0', '0', '1', '1', '0', '0', '0', '0', '1', '0', '1', '1', '0', '0', '1', '1', '1', '0', '1', '1', '1', '1', '0', '1', '1', '0', '0', '1', '1', '0', '0', '0', '1', '0', '0', '1', '1', '0', '0', '1', '0', '0', '0', '1', '1', '0', '0', '1', '1', '0', '0', '1', '1', '0', '1', '0', '0', '0', '0', '1', '1', '0', '1', '0', '1', '0', '0', '1', '1', '0', '1', '1', '0', '0', '0', '1', '1', '0', '1', '1', '1', '0', '0', '1', '1', '1', '0', '0', '0', '0', '0', '1', '1', '1', '0', '0', '1', '0', '1', '1', '1', '1', '1', '0', '1']
flag{123456789}

Process finished with exit code 0
```

* **参考：https://github.com/sixstars/starctf2021/tree/main/crypto-MyEnc**