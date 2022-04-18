import numpy as np
# from secret import flag

import os

def gravity(n,d=0.25):
    A=np.zeros([n,n])
    for i in range(n):
        for j in range(n):
            A[i,j]=d/n*(d**2+((i-j)/n)**2)**(-1.5)
    return A

flag = os.urandom(85)

n=len(flag)
A=gravity(n)
x=np.array(list(flag))
b=A@x
# np.savetxt('b.txt',b)
print(x)