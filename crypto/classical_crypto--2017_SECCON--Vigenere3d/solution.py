import sys


def _l(idx, s):
    return s[idx:] + s[:idx]


def main(p, k1, k2):
    s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"
    t = [[_l((i+j) % len(s), s) for j in range(len(s))] for i in range(len(s))]
    i1 = 0
    i2 = 0
    c = ""
    for a in p:
        c += t[s.find(a)][s.find(k1[i1])][s.find(k2[i2])]
        i1 = (i1 + 1) % len(k1)
        i2 = (i2 + 1) % len(k2)
    return c


s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_{}"


def FFF(x, y):
    return s.find(x) - s.find(y)


ukey = [-3, 10, 15, 28, 25, 36, -3, -3, 36, 25, 28, 15, 10, -3]
cip = 'POR4dnyTLHBfwbxAAZhe}}ocZR3Cxcftw9'
l = len(s)
expukey = []
for i in range(len(cip)//len(ukey)):
    expukey += ukey
expukey += ukey[:(len(cip) % len(ukey))]
plaintext = [s[(s.find(cip[i]) - expukey[i] + l) % l] for i in range(len(cip))]
print("".join(plaintext))