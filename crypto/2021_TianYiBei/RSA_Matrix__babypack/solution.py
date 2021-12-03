from random import getrandbits, randint
from Crypto.Util.number import getPrime
from pwn import *
from gmpy2 import gcd, is_prime

conn = remote('127.0.0.1', 10007)
conn.recvuntil(b'your pubkey:')
A = [int(i) for i in conn.recvuntil(b']')[1:-1].split(b',')]
UpV = int(conn.recvline()[:-1])
UmV = int(conn.recvline()[:-1])



bgb = 1044
m = 2**bgb
count = 1
msg = conn.recvuntil(b'get flag')
conn.sendline(b'1')
conn.recvuntil(b'>')
conn.sendline(str(m).encode())
lst = int(conn.recvline()[:-1])
print(lst)

rst_n = m
offset = 1
begin = 0
while count < 498:
    conn.recvuntil(b'get flag')
    conn.sendline(b'1')
    conn.recvuntil(b'>')
    send_m = m + 2**(bgb-2*offset+1) + 2**(bgb - 2*offset)
    conn.sendline(str(send_m).encode())
    msg = int(conn.recvline()[:-1])
    if msg - lst == 2:
        rst_n += 2**(bgb-2*offset+1) + 2**(bgb - 2*offset)
        count += 1
        offset += 1
        begin = 1
    elif msg - lst == -2:
        count += 1
        offset += 1
        # begin = 1
    else:
        count += 1
        # if begin == 0:
        #     offset += 1
        #     continue
        conn.recvuntil(b'get flag')
        conn.sendline(b'1')
        conn.recvuntil(b'>')
        send_m = m + 2 ** (bgb - 2 * offset + 1)
        conn.sendline(str(send_m).encode())
        msg = int(conn.recvline()[:-1])
        if count >= 498:
            break
        if msg - lst == 1:
            rst_n += 2 ** (bgb - 2 * offset + 1)
        else:
            rst_n += 2 ** (bgb - 2 * offset)
        offset += 1
        count += 1

conn.recvuntil(b'get flag')
print(offset)

# print(bin(rst_n))

u0 = (UpV + int((UpV*UpV - 4*UmV)**0.5))//2
v0 = (UpV - int((UpV*UpV - 4*UmV)**0.5))//2

mod = (A[0] - u0)*(A[0] - v0)
print('n=', mod)
print('pbar =', rst_n)

# 把mod和rst_n的结果复制进Factor_with_high_known_bit.sage文件并运行得到n
n = int(input(">").strip()) 

p = gcd(n, A[0] - u0)
q = gcd(n, A[0] - v0)
p,q = p // gcd(p,q), q //gcd(p,q)

print(is_prime(p), is_prime(q), p*q == n, n // p//q)
print(p)
print(q)
n = p*q

conn.sendline(b'2')
# msg = conn.recvline()
# print(msg)
ct = int(conn.recv(2048))
# ct = int(conn.recvline()[:-1])
print(ct)

mp = ct % p
mq = ct % q

conn.sendline(str(abs(mq-mp)).encode())

flag = conn.recv(2048)
print(flag)