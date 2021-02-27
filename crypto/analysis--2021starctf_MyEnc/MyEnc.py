from Crypto.Util.number import getPrime, bytes_to_long
import os
from socket import *
flag = 'flag{123456789}'

iv = bytes_to_long(os.urandom(256))
assert len(flag) == 15
keystream = bin(int(flag.encode('hex'), 16))[2:].rjust(8 * len(flag), '0')
p = getPrime(1024)
q = getPrime(1024)
n = p * q

phi = (p-1) * (q-1)
i_list = [0]
for i in range(1, 8):
    i_list.append((i**i**i) % phi)

print("n:", n)
print('q:',q)
print('iv', iv)

serverSocket = socket(AF_INET,SOCK_STREAM)
serverSocket.bind(('127.0.0.1', 9001))
serverSocket.listen(10)
clientSocket, clientInfo = serverSocket.accept()

clientSocket.send(str(n).encode('utf-8'))
cnt = 0
while True:
    try:
        m = int(clientSocket.recvfrom(2048)[0])
        print('give me a number:', m)

        # m = int(input())
    except:
        break
    ct = iv
    for i in range(1, 8):
        if keystream[cnt] == '1':
            ct += pow(m ^ q, i_list[i], n)
            ct %= n
        cnt = (cnt + 1) % len(keystream)
    print("done:", ct)
    clientSocket.send(str(ct))
