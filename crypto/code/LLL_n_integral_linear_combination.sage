# python
# given n, a_1, a_2,..., a_n, find an integral linear combiation to 0.
 
import random
import numpy as np
 
mod = 2**256

K = 2**200
N = 50

a = [random.randint(2**100, 2**128) for i in range(N+1)]

m = Matrix(ZZ, N + 1, N + 2)
for i in range(N + 1):
    ge = ZZ(pow(a[i], N - i, mod))
    m[i, i] = 1
    m[i, N + 1] = ZZ(ge * K)
m[i, N + 1] = ZZ(K * mod)

ml = m.LLL()
ttt = ml.rows()[0]      # 第一行表示线性组合的系数
print(np.array(ttt))


lllm = (m.transpose()*ml.transpose()[:51])  # 每一列表示一个新的LLL基的向量，第一列最后一个元素表示a_1到a_n的线性组合，理论上是0，或者是一个非常接近0的数
print(np.array( lllm ))
print(lllm[51][0])
