from Crypto.Util.number import *
f = open('flag.txt', 'rb')
m = bytes_to_long(f.read())
f.close()
e = 65537
p = getPrime(1024)
q = getPrime(1024)
n = p * q
c = pow(m, e, n)
hint = pow(1010 * p + 1011, q, n)
f = open('cipher.txt', 'w')
f.write(f'n={n}\n')
f.write(f'c={c}\n')
f.write(f'hint={hint}\n')
f.close()
