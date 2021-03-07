#python3.7.6
#Author:Am473ur
#调用函数 sDLP(g,h,p) 返回 g^x≡h (mod p) 的一个解
#Shanks's Babystep-Giantstep Algorithm
from gmpy2 import invert,iroot
from Crypto.Util.number import getPrime

class node:
    def _init_(self):
        self.vue=0
        self.num=0
def cmp(a):
      return a.vue
def init_list(first,g,n,p):
      List=[]
      temp=node()
      temp.vue,temp.num=first,0
      List.append(temp)
      for i in range(1,n+1):
            temp=node()
            temp.num = i
            temp.vue = List[i-1].vue * g % p
            List.append(temp)
      List.sort(key=cmp)
      return List
def sDLP(a,b,p):
    ans=p
    n=iroot(p,2)[0]+1
    L1=init_list(1,a,n,p)
    aa=pow(invert(a,p),n,p)
    L2=init_list(b,aa,n,p)
    i = 0
    j = 0
    while True :
        if (i>=n or j>=n): break
        while (L1[i].vue < L2[j].vue and i<n): i += 1
        while (L1[i].vue > L2[j].vue and j<n): j += 1
        if L1[i].vue == L2[j].vue :
            x=L1[i].num+L2[j].num*n
            return int(x)
p = 552022109
g = 520158203
h = 525148510
print(sDLP(g,h,p))


#python3.7.6
#Author:Am473ur
# m 和 a 为两个列表，表示同余方程组 x mod m = a (m1,a1;m2,a2;...)
from functools import reduce
from gmpy2 import invert

def CRT(m,a):
      Num=len(m)
      M=reduce(lambda x,y: x*y, m)
      Mi=[M//i for i in m]
      t=[invert(Mi[i], m[i]) for i in range(Num)]
      x=0
      for i in range(Num):
            x+=a[i]*t[i]*Mi[i]
      return x%M


#python3.7.6
#Author:Am473ur
#通过调用 Factor(n) 进行质因数分解，返回值是因数列表。
from Crypto.Util.number import isPrime
from math import gcd

def f(x):
    return x**2 + 1

def pollard_rho(N):
    xn = 2
    x2n = 2
    d = 1
    while d == 1:
        xn = f(xn) % N
        x2n = f(f(x2n)) % N
        abs_val = abs(xn - x2n)
        d = gcd(abs_val, N)
    return d

def Factor(n):
    ans=[]
    while True:
        temp=pollard_rho(n)
        ans.append(temp)
        n=n//temp
        if n==1:return ans
        if isPrime(n):
            ans.append(n)
            return ans
'''
n=12345678754345678765456789876587654567899876
print(Factor(n))
output:[4, 3109, 3553454208763, 279372423577347576184497407]
'''


#python3.7.6
#Author:Am473ur
from Crypto.Util.number import long_to_bytes
from functools import reduce
from gmpy2 import gcd,invert
from ShanksDLP import sDLP
from PollardRhoFactor import Factor
import time
#g^x = h (mod p)

def CRT(m,a):
      Num=len(m)
      M=reduce(lambda x,y: x*y, m)
      Mi=[M//i for i in m]
      t=[invert(Mi[i], m[i]) for i in range(Num)]
      x=0
      for i in range(Num):
            x+=a[i]*t[i]*Mi[i]
      return x%M
def BruteForceDLP(A,B,P):
      for i in range(P):
            if pow(A,i,P)==B:
                  return int(i)
def PohligHellman(g,h,p):
      qe=Factor(p-1)
      assert reduce(lambda x,y: x*y, qe) == p-1
      print(qe)
      Lg=[pow(g,(p-1)//i,p) for i in qe]
      Lh=[pow(h,(p-1)//i,p) for i in qe]
      length=len(qe)
      La=[]
      for i in range(length):
            if p<1000000000000:#p较小Shanks's算法可以接受就使用Shanks's解决
                  La.append(sDLP(Lg[i],Lh[i],p))
            else:#p-1的最大质因子较小的话暴力枚举法也有很好的表现
                  La.append(BruteForceDLP(Lg[i],Lh[i],p))
            #print(Lg[i],Lh[i],La[i])
      X=CRT(qe,La)
      if pow(g,X,p)==h:
            print("x is Right ! x = ",X)
      else:print("Wrang Answer")

print("g^x = h (mod p)")
p=int(input("p= "))
g=int(input("g= "))
h=int(input("h= "))
start_time=time.time()
PohligHellman(g,h,p)
print("it takes ",time.time()-start_time," seconds",)

#————————————————
#版权声明：本文为CSDN博主「Am473ur」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
#原文链接：https://blog.csdn.net/qq_41956187/article/details/104981499