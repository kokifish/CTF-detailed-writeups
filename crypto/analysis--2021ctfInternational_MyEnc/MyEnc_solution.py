# coding=utf-8
from Crypto.Util.number import getPrime, bytes_to_long
import numpy as np
from gmpy2 import *
from socket import *


def Mgcd(x, y):
    while y:
        x, y = y, x % y
    return x


def Minvert(mat, N, size):    # list, int, int
    result = []
    for i in range(size):
        result.append([long(0) for j in range(8)])
        result[i][i] = long(1)

    for i in range(size):
        top = int(mat[i][i])
        top_invert = invert(top, N)
        mat[i] = [k * top_invert % N for k in mat[i]]
        result[i] = [k * top_invert % N for k in result[i]]
        for j in range(size):
            if i !=j:
                tmp = mat[j][i]
                tmp2 = [k * tmp % N for k in mat[i]]
                res2 = [k * tmp % N for k in result[i]]
                mat[j] = [(mat[j][k] + N - tmp2[k]) % N for k in range(size)]
                result[j] = [(result[j][k] + N - res2[k]) % N for k in range(size)]
    # print 'mat:'
    # print np.array(mat)
    # print 'result:'
    # print np.array(result)
    return result


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
    b = ''.join(a)
    # binary to str
    if int(b,2) > 2**32:
        flag = hex(int(b, 2))[2:-1].decode('hex')
    else:
        flag = hex(int(b, 2))[2:].decode('hex')
    print flag