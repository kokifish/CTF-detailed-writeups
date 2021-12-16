from Crypto.Util.number import *
from flag import flag
import random

def add(P1,P2):
    x1,y1=P1
    x2,y2=P2
    x3=(x1*x2-y1*y2)%n
    y3=(x1*y2+x2*y1)%n
    return (x3,y3)

def mul(P,k):
    assert k>=0
    Q=(1,0)
    while k>0:
        if k%2:
            k-=1
            Q=add(P,Q)
        else:
            k//=2
            P=add(P,P)
    return Q

def getMyPrime():
    while True:
        q=getPrime(88)
        p=2*q+1
        if isPrime(p):
            return p

e=getPrime(256)
n=getMyPrime()*getMyPrime()*getMyPrime()
print('n=%d'%n)

G=(1,1)
HINT=mul(G,e)
print('HINT=%s'%str(HINT))

x=bytes_to_long(flag[7:39])
y=bytes_to_long(flag[39:-1])
M=(x,y)
C=mul(M,e)
print('C=%s'%str(C))
'''
n=92916331959725072239888159454032910975918656644816711315436128106147081837990823
HINT=(1225348982571480649501200428324593233958863708041772597837722864848672736148168, 1225348982571480649501200428324593233958863708041772597837722864848672736148168)
C=(44449540438169324776115009805536158060439126505148790545560105884100348391877176, 73284708680726118305136396988078557189299357177640330968917927635171441710392723)
'''