#!/usr/bin/env python3

import random
import signal
import socketserver
import string
from Crypto.Util.number import *
from hashlib import sha256
from os import urandom
from secret import flag

class ezhash:
    def __init__(self):
        self.p = 328145541634163431929233386535821861121
        self.i = 96858741233065729363697642301435517926
        assert pow(self.i, 2, self.p) == self.p - 1
        self.l = 5
        self.g = [
            [[1, -2 * self.i], [-2 * self.i, 1]],
            [[1, -2], [2, 1]],
            [[1 - 2 * self.i, 0], [0, 1 + 2 * self.i]],
            [[1 + 2 * self.i, 0], [0, 1 - 2 * self.i]],
            [[1, 2], [-2, 1]],
            [[1, 2 * self.i], [2 * self.i, 1]]
        ]

        self.pi = [
            [1, 0, 5, 4, 3, 2],
            [0, 5, 4, 3, 2, 1],
            [2, 1, 0, 5, 4, 3],
            [4, 3, 2, 1, 0, 5],
            [3, 2, 1, 0, 5, 4]
        ]

        self.x = [[getRandomRange(1, self.p) for _ in range(2)] for _ in range(2)]

    def base(self, n):
        seq = []
        while n:
            seq.append(n % self.l)
            n //= self.l
        return seq

    def digest(self, msg):
        seq = self.base(int(msg.hex(), 16))
        g_last = self.g[1]
        r = [[1, 0], [0, 1]]
        for _ in range(len(seq)):
            g_cur = self.g[self.pi[seq[_]][self.g.index(g_last)]]
            (a, b), (c, d) = r[0], r[1]
            (e, f), (g, h) = g_cur[0], g_cur[1]
            r[0][0] = (a * e + b * g) % self.p
            r[0][1] = (a * f + b * h) % self.p
            r[1][0] = (c * e + d * g) % self.p
            r[1][1] = (c * f + d * h) % self.p
            g_last = g_cur
        return r

    def check(self, msg):
        d = self.digest(msg)
        s = [inverse(d[0][0], self.p) * self.x[0][0] % self.p, \
        inverse(d[0][1], self.p) * self.x[0][1] % self.p, \
        inverse(d[1][0], self.p) * self.x[1][0] % self.p, \
        inverse(d[1][1], self.p) * self.x[1][1] % self.p]
        if len(list(set(s))) == 1:
            return True
        else:
            return False

class Task(socketserver.BaseRequestHandler):
    def __init__(self, *args, **kargs):
        super().__init__(*args, **kargs)

    def proof_of_work(self):
        random.seed(urandom(8))
        proof = ''.join([random.choice(string.ascii_letters + string.digits + '!#$%&*-?') for _ in range(20)])
        digest = sha256(proof.encode()).hexdigest()
        self.dosend('sha256(XXXX + {}) == {}'.format(proof[4: ], digest))
        self.dosend('Give me XXXX:')
        x = self.request.recv(10)
        x = (x.strip()).decode('utf-8')
        if len(x) != 4 or sha256((x + proof[4: ]).encode()).hexdigest() != digest:
            return False
        return True

    def dosend(self, msg):
        try:
            self.request.sendall(msg.encode('latin-1') + b'\n')
        except:
            pass

    def timeout_handler(self, signum, frame):
        raise TimeoutError

    def handle(self):
        try:
            signal.signal(signal.SIGALRM, self.timeout_handler)
            signal.alarm(30)
            if not self.proof_of_work():
                self.dosend('You must pass the PoW!')
                return
            signal.alarm(10)
            h = ezhash()
            self.dosend('x: ' + str(h.x))
            msg = self.request.recv(1024).strip()
            msg = bytes.fromhex(msg.decode('utf-8'))
            if h.check(msg):
                self.dosend(flag)
            else:
                self.dosend('Good luck!')
        except TimeoutError:
            self.dosend('Timeout!')
            self.request.close()
        except:
            self.dosend('Wtf?')
            self.request.close()


class ThreadedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 13337
    server = ThreadedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()