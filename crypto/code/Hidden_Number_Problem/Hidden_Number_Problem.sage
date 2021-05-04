# Sage

import socket
import ast
import telnetlib

#HOST, PORT = 'localhost', 9999
HOST, PORT = '60.205.223.220', 9999

s = socket.socket()
s.connect((HOST, PORT))
f = s.makefile('rw', 0)

def recv_until(f, delim='\n'):
    buf = ''
    while not buf.endswith(delim):
        buf += f.read(1)
    return buf

p = 1461501637330902918203684832716283019655932542983
k = 10

def solve_hnp(t, u):
    # http://www.isg.rhul.ac.uk/~sdg/igor-slides.pdf
    M = Matrix(RationalField(), 23, 23)
    for i in xrange(22):
        M[i, i] = p
        M[22, i] = t[i]

    M[22, 22] = 1 / (2 ** (k + 1))

    def babai(A, w):
        A = A.LLL(delta=0.75)
        G = A.gram_schmidt()[0]
        t = w
        for i in reversed(range(A.nrows())):
            c = ((t * G[i]) / (G[i] * G[i])).round()
            t -= A[i] * c
        return w - t

    closest = babai(M, vector(u + [0]))
    return (closest[-1] * (2 ** (k + 1))) % p

for i in xrange(5):
    t = ast.literal_eval(f.readline().strip())
    u = ast.literal_eval(f.readline().strip())
    alpha = solve_hnp(t, u)
    recv_until(f, 'number: ')
    s.send(str(alpha) + '\n')

t = telnetlib.Telnet()
t.sock = s
t.interact()

