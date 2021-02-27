from Crypto.Util.number import *
from libnum import *
from secret import flag,special,p,q,n


def little_trick(msg):
    p1 = getPrime(1024)
    q1 = getPrime(1024)
    n1 = p1 * q1
    d1=random.randint(1,2**256)
    e1=inverse(d1,(p1-1)*(q1-1))
    print(n1)
    print(e1)
    print(pow(msg,e1,n1))


def real_trick():
    assert (special > (ord("*")*100) and gcd(special,(p-1)*(q-1))!=1 )
    print(n)
    print(pow(libnum.s2n(flag),special,n))


if __name__ == '__main__':
    little_trick(p-1)
    real_trick()