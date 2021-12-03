# 2021年TCTF_final—— Crypto —— ezRSA

## 题目
见当前目录的`task.sage`文件

矩阵的运算都是在有限域GF(71)上的。
题目本质上就是随机生成一个$11\times 11$公钥矩阵pk和私钥矩阵s。对s进行矩阵的LU分解。然后加密的过程是$$c = U(M+pk)$$其中U是LU分解中的上三角矩阵，M是明文矩阵，pk是密钥矩阵。而且明文只有25个数，其矩阵上的分布如下：
```
A = [[1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1],
[0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0],
[0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0],
[0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0],
[0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0],
[1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1],
[0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0],
[0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0],
[0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0],
[0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0],
[1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]]
```

题解：
* 我个人的解法。从倒数第一行开始恢复出明文和U矩阵。每到倒数第i行，就构造矩阵方程$$\left[\begin{matrix}
a_{1,1} & a_{1,2} & \cdots & a_{1,i} \\
a_{2,1} & a_{2,2} & \cdots & a_{2,i} \\
\vdots & \vdots & \ddots & \vdots  \\
a_{i,1} & a_{i,2} & \cdots & a_{i,i} 
\end{matrix}\right]
\left[\begin{matrix}
u_{n-i+1, n-i+1} \\ \vdots \\ u_{n-i+1, n}
\end{matrix}\right]
= 
\left[\begin{matrix}
c_1 \\ \vdots \\ c_i
\end{matrix}\right]
$$

其中$a_{i,j}$表示从明文矩阵$(M+pk)$中的第n-i+1行取一个数，如果矩阵A的位置为0，则直接使用$pk$矩阵的位置，如果不是则暴力枚举明文。然后$a$的第2到第i列是前面恢复出来的数，能直接使用，只有第1列需要枚举。然后向量$c$是知道的，因此可以解方程组把$u$解出来。当$u$解出来之后就可以把密文的第$n-i+1$列的明文恢复出来。

* 别人的解法：  Flag加密后每行最多3个基本就2个 其他都是0，那就可以直接开始 感觉每行71个，71 * 2就可以爆 最多也就71 * 3。
因为LU分解后 U矩阵就是一个上三角 ，可以从后面往前开始爆，用在爆破的每一行前面n个是0去爆，看他能不能成功解密，如果不能就跳过，接着继续去拿之前的，发现第二行会有多解，但是每个是1 1对应的，于是直接开爆，第一行三个 第二行相当于只有1个，71的4次

* 参考https://l.xdsec.org/archives/385.html

```python
p = 71
alphabet = '=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$!?_{}<>'

Enc=[
[31,45,41,12,36,43,45,51,25,2 ,64],
[68,24,32,35,52,13,64,10,14,2 ,40],
[34,34,64,32,67,25,21,57,31,6 ,56],
[7 ,17,12,33,54,66,28,25,40,23,26],
[14,65,70,35,67,55,47,36,36,42,57],
[68,28,33,0 ,45,52,59,29,52,41,46],
[60,35,0 ,21,24,44,49,51,1 ,6 ,35],
[20,21,44,57,23,35,30,28,16,23,0 ],
[24,64,54,53,35,42,40,17,3 ,0 ,36],
[32,53,39,47,39,56,52,15,39,8 ,9 ],
[7 ,57,43,5 ,38,59,2 ,25,2 ,67,12]]

pk=[
[53,28,20,41,32,17,13,46,34,37,24],
[0 , 9,54,25,36,1 ,21,24,56,51,24],
[61,41,10,56,57,28,49,4,44,70,34],
[47,58,36,53,68,66,34,69,22,25,39],
[4 ,70,21,36,53,26,59,51,3,44,28],
[41,23,39,37,1 ,28,63,64,37,35,51],
[43,31,16,36,45,5 ,35,52,7,45,41],
[26,3 ,54,58,50,37,27,49,3,46,11],
[14,48,18,46,59,64,62,31,42,41,65],
[17,50,68,10,24,40,58,46,48,14,58],
[46,24,48,32,16,1 ,27,18,27,17,20]]

from sage.all import *
p = 71
Enc = Matrix(GF(p),Enc)
R = Matrix(GF(p),pk)

def cross(m):
    return alphabet.index(m)

def prepare(msg):
    A = zero_matrix(GF(p), 11, 11)
    for k in range(len(msg)):
        i, j = 5*k // 11, 5*k % 11
        A[i, j] = cross(msg[k])
    return A

#print(prepare('1'*24) )# U最后一行就最后以为在线

ULAST = R[10,2]
MUl = Enc[10,2]
print(MUl/ULAST)
ULAST = R[10,3]
MUl = Enc[10,3]
print(MUl/ULAST)

U = zero_matrix(GF(p), 11, 11)
U[10,10] = MUl/ULAST
A = zero_matrix(GF(p), 11, 11)
A[10,0] = Enc[10,0]/U[10,10]-R[10,0]
A[10,5] = Enc[10,5]/U[10,10]-R[10,5]

def inv_cross(c):
    return alphabet[c]

def inv_prepare(cip):
    msg = ''
    for k in range(24-1,-1,-1):
        i, j = 5*k // 11, 5*k % 11
        msg = inv_cross(int(cip[i,j])) + msg
    return msg
#print(Enc[10,0])
#print((U*(A+R))[10,0])
#print('\n')
'''
for i in range(71):
    for j in range(71):
        try:
            A[9,1],A[9,6] = i,j
            tmpU = (A+R).solve_left(Enc)
            if tmpU[9,0] == 0 and tmpU[9,1] == 0 and tmpU[9,2] == 0 : 
                print(i,j)
            else:
                #print(i,j)
                continue
        except:
            continue'''
A[9,1],A[9,6] = 64,38
print(inv_prepare(A))
'''
for i in range(71):
    for j in range(71):
        try:
            A[8,2],A[8,7] = i,j
            tmpU = (A+R).solve_left(Enc)
            if tmpU[8,0] == 0 and tmpU[8,1] == 0 and tmpU[8,2] == 0 : 
                print(i,j)
            else:
                #print(i,j)
                continue
        except:
            continue'''
A[8,2],A[8,7] = 61,25
print(inv_prepare(A))

'''
for i in range(71):
    for j in range(71):
        try:
            A[7,3],A[7,8] = i,j
            tmpU = (A+R).solve_left(Enc)
            if tmpU[7,0] == 0 and tmpU[7,1] == 0 and tmpU[7,2] == 0 : 
                print(i,j)
            else:
                #print(i,j)
                continue
        except:
            continue'''
A[7,3],A[7,8] = 48,17
print(inv_prepare(A))
'''
for i in range(71):
    for j in range(71):
        try:
            A[6,4],A[6,9] = i,j
            tmpU = (A+R).solve_left(Enc)
            if tmpU[6,0] == 0 and tmpU[6,1] == 0 and tmpU[6,2] == 0 : 
                print(i,j)
            else:
                #print(i,j)
                continue
        except:
            continue'''
A[6,4],A[6,9] = 25,18
print(inv_prepare(A))
'''
for i in range(71):
    for j in range(71):
        for k in range(71):
            try:
                A[5,0],A[5,5],A[5,10] = i,j,k
                tmpU = (A+R).solve_left(Enc)
                if tmpU[5,0] == 0 and tmpU[5,1] == 0 and tmpU[5,2] == 0 : 
                    print(i,j,k)
                else:
                    #print(i,j)
                    continue
            except:
                continue'''
A[5,0],A[5,5],A[5,10] = 16,4,12
print(inv_prepare(A))

'''
for i in range(71):
    for j in range(71):
            try:
                A[4,1],A[4,6] = i,j
                tmpU = (A+R).solve_left(Enc)
                if tmpU[4,0] == 0 and tmpU[4,1] == 0 and tmpU[4,2] == 0 : 
                    print(i,j)
                else:
                    #print(i,j)
                    continue
            except:
                continue'''
A[4,1],A[4,6] = 14,37
print(inv_prepare(A))
'''
for i in range(71):
    for j in range(71):
            try:
                A[3,2],A[3,7] = i,j
                tmpU = (A+R).solve_left(Enc)
                if tmpU[3,0] == 0 and tmpU[3,1] == 0 and tmpU[3,2] == 0 : 
                    print(i,j)
                else:
                    #print(i,j)
                    continue
            except:
                continue'''
A[3,2],A[3,7] = 55,3
print(inv_prepare(A))
'''
for i in range(71):
    for j in range(71):
            try:
                A[2,3],A[2,8] = i,j
                tmpU = (A+R).solve_left(Enc)
                if tmpU[2,0] == 0 and tmpU[2,1] == 0 : 
                    print(i,j)
                else:
                    #print(i,j)
                    continue
            except:
                continue'''
A[2,3],A[2,8] = 0,12
print(inv_prepare(A))

TMP = []
for i in range(71):
    for j in range(71):
            try:
                A[1,4],A[1,9] = i,j
                tmpU = (A+R).solve_left(Enc)
                if tmpU[1,0] == 0  : 
                    #print(i,j)
                    TMP.append((i,j))
                else:
                    #print(i,j)
                    continue
            except:
                continue
alphabet = '=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$!?_{}<>'
MD = '95cb911a467482cc0f879861532e9ec7680b0846b48a9de25fb13b01c583d9f8'
from hashlib import*
for i in range(71):
    for j in range(71):
        for k in range(71):
            for s in range(len(TMP)):
                m,n = TMP[s]
                A[0,0],A[0,5],A[0,10],A[1,4],A[1,9] = i,j,k,m,n
                sss = inv_prepare(A)
                if sha256(sss.encode()).hexdigest() == '95cb911a467482cc0f879861532e9ec7680b0846b48a9de25fb13b01c583d9f8':
                    print(sss)

```