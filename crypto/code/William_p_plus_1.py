import threading
from gmpy2 import iroot
from functools import reduce
from Crypto.Util.number import *
import time
import math

factor_state = False


def pow_with_sqrt(a, c, b, n, mod):  # (a+c*sqrt(b))^n
    states = [(a % mod, c % mod)]
    for i in range(int(math.log(n, 2))):
        new_state = ((pow(states[i][0], 2, mod) + b * pow(states[i][1], 2, mod)) %
                     mod, (2 * states[i][0] * states[i][1]) % mod)
        states.append(new_state)
    n_bin = bin(n)[2:][::-1]
    res_x = 1
    res_y = 0
    for i in range(len(n_bin)):
        if n_bin[i] == '1':
            res_x, res_y = (res_x * states[i][0] + res_y * states[i][1] *
                            b) % mod, (res_x * states[i][1] + res_y * states[i][0]) % mod
    return res_x, res_y


def william_factor(n, index):
    start = time.clock()
    global factor_state
    A = getRandomRange(3, n)
    #m = 2
    #next_pos = 1
    m = 3000
    next_pos = reduce(lambda x, y : x * y, [i + 1 for i in range(m - 1)])
    B = A**2 - 4
    #res_x1, res_y1 = A, -1
    #res_x2, res_y2 = A, 1
    res_x1, res_y1 = pow_with_sqrt(A, -1, B, next_pos, n)
    res_x2, res_y2 = pow_with_sqrt(A, 1, B, next_pos, n)
    while True:
        if factor_state == True:
            return
        print((index, m))
        next_pos *= m #next_pos = m!
        C = inverse(pow(2, next_pos, n), n)
        res_x1, res_y1 = pow_with_sqrt(res_x1, res_y1, B, m, n)
        res_x2, res_y2 = pow_with_sqrt(res_x2, res_y2, B, m, n)
        res_x, res_y = (res_x1 + res_x2) % n, (res_y1 + res_y2) % n
        assert(iroot(B, 2)[1] == False and res_y != n)
        if iroot(B, 2)[1] == True:
            res_x = (res_x + res_y * iroot(B, 2)[0]) % n
        # Vi = C((A-sqrt(B))^(m!)+(A+sqrt(B))^(m!))
        Vi = (C * res_x) % n
        p = GCD(Vi - 2, n)
        assert(p != n) #p=n说明lucas序列下标过大
        if p != 1:
            factor_state = True
            print('p =', p)
            end = time.clock()
            print('cost {}s'.format(end - start))
            return
        m += 1


def main():
    n = 7941371739956577280160664419383740967516918938781306610817149744988379280561359039016508679365806108722198157199058807892703837558280678711420411242914059658055366348123106473335186505617418956630780649894945233345985279471106888635177256011468979083320605103256178446993230320443790240285158260236926519042413378204298514714890725325831769281505530787739922007367026883959544239568886349070557272869042275528961483412544495589811933856131557221673534170105409
    #n = 112729
    threads = []
    for i in range(3):
        t = threading.Thread(target=william_factor, args=(n, i))
        threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == '__main__':
    main()