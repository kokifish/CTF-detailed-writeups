import numpy as np
# from secret import flag
import os

flag = os.urandom(40)

def getQ(n):
    return np.linalg.qr(np.random.random([n,n]))[0]     # 随机生成矩阵然后qr分解，获取q矩阵

def pad(x,N=50,k=256):
    return np.hstack([x,np.random.random(N-len(x))*k])  # 把矩阵补全为N列

n=len(flag)
N=50
A=np.hstack([getQ(N)[:, :n] @ np.diag(np.logspace(n,1,n)) @ getQ(n), getQ(N)[:, n:] @ np.diag(np.linspace(N-n,1,N-n)) @ getQ(N-n)])
# 取Q的前n列 * 一个对角矩阵，对角线元素为10^(n-i) * Q(n)  并上 取Q的后n列 * 一个对角矩阵，对角线元素为N-n-i * Q(N-n)
x=pad(list(flag))       # 往flag后面添加少许错误
b=A@x
print(A)
# np.savetxt('A.txt',A)
# np.savetxt('b.txt',b)