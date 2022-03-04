# Sagemath 9.2  非常直接的LWE问题

import numpy as np
# d = 0.25
def gravity(n,d=0.25):
    A=np.zeros([n,n])
    for i in range(n):
        for j in range(n):
            A[i,j]=d/n*(d**2+((i-j)/n)**2)**(-1.5)
    return A

K = 10^20
b = np.loadtxt('b.txt')
n = len(b)
AA=gravity(n)*K
W = Matrix(ZZ,AA)    # n * n
e = vector(ZZ,vector(b)*K)    # n

def babai(A, w):
    A = A.LLL(delta=0.75)
    G = A.gram_schmidt()[0]
    t = w
    for i in reversed(range(A.nrows())):
        c = ((t * G[i]) / (G[i] * G[i])).round()
        t -= A[i] * c
    return w - t

V = babai(W, e)
print(W.solve_right(V))
