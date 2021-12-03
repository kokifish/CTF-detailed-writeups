from random import getrandbits, randint
from Crypto.Util.number import getPrime
from functools import reduce

import sys
import socketserver


N = 512
flag = b'flag{1234567890}'


def egcd(a, b):
    if 0 == b:
        return 1, 0, a
    x, y, q = egcd(b, a % b)
    x, y = y, (x - a // b * y)
    return x, y, q

def chinese_remainder(pairs):
    mod_list, remainder_list = [p[0] for p in pairs], [p[1] for p in pairs]
    mod_product = reduce(lambda x, y: x * y, mod_list)
    mi_list = [mod_product//x for x in mod_list]
    mi_inverse = [egcd(mi_list[i], mod_list[i])[0] for i in range(len(mi_list))]
    x = 0
    for i in range(len(remainder_list)):
        x += mi_list[i] * mi_inverse[i] * remainder_list[i]
        x %= mod_product
    return x

def keygen():
    U = [getrandbits(N)for i in range(N)]
    V = []
    for i in range(N):
        v = U[i] - pow(2, N-i-1)
        V.append(v)

    s1 = sum(U)
    while True:
        p = getPrime(s1.bit_length() + 1)
        if p > s1:
            break
    print(s1.bit_length() + 1)

    s1 = 0
    s2 = 0
    for i in V:
        if i < 0:
            s2 += i
        else:
            s1 += i

    tmp = max(s1, -s2)
    while True:
        q = getPrime(tmp.bit_length() + 1)
        if q > tmp:
            break
    print(tmp.bit_length() + 1)

    A = []
    for i, j in zip(U, V):
        A.append(chinese_remainder([(p, i), (q, j)]))
    return A, U, V, p, q

def check(m, n):
    mbin = bin(m)[2:]
    nbin = bin(n)[2:]
    # print(mbin[:200])
    # print(nbin[:200])
    count = 0
    for i, j in zip(mbin, nbin):
        if i == j:
            count += 1
    return count

def encrypt(msg, pub):
    s = 0
    for i, j in zip(msg, pub):
        s += i * j
    return s


class Task(socketserver.BaseRequestHandler):

    def handle(self):

        A, U, V, p, q = keygen()
        n = p * q
        print(p)
        print(q)
        self.request.sendall(b'your pubkey:')
        self.request.sendall(repr(A).encode())
        self.request.sendall(str((U[0] + V[0])).encode()+b'\n')
        self.request.sendall(str((U[0] * V[0])).encode()+b'\n')
        # print(A)
        # print(U[0] + V[0])
        # print(U[0] * V[0])
        Menu = b'''
        1.hint
        2.get flag'''
        for i in range(500):
            # print(Menu)
            self.request.sendall(Menu)
            # op = int(input(">").strip())
            op = int(self.request.recv(160).strip())
            print(op)
            if op == 1:
                # m = int(input(">").strip())
                # print("11111")
                self.request.sendall(b'>')
                m = int(self.request.recv(1024).strip())
                # print(m)
                # print(check(m, n))
                self.request.sendall(str(check(m, n)).encode())
            elif op == 2:
                msg = [randint(0, 1) for i in range(N)]
                ct = encrypt(msg, A)
                print("secret:")
                print(ct)
                # self.request.sendall(b'secret:')
                self.request.sendall(str(ct).encode())

                # secret = int(input(">").strip())
                secret = int(self.request.recv(160).strip())
                ans = int("".join(list(map(str, msg))), 2)
                print(bin(ans)[2:])
                if ans == secret:
                    print(flag)
                    self.request.sendall(flag)
                else:
                    print("wrong")
                    # sys.exit(0)
                    self.request.close()
                    break
            else:
                # sys.exit(0)
                self.request.close()
                break
        self.request.close()


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '127.0.0.1', 10007
    # server = ForkingServer((HOST, PORT), Task)
    server = ThreadedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
