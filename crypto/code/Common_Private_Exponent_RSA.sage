# Sagemath 9.2
from Crypto.Util.number import long_to_bytes, bytes_to_long

r = 20

e_list = []
n_list = []
c_list = []

m = Matrix(ZZ, r + 1, r + 1)
for i in range(1, r + 1):
    m[i, i] = -ZZ(n_list[i-1])
    m[0,i] = ZZ(e_list[i-1])
m[0,0] = ZZ(2**512)

ml = m.LLL()
ttt = ml.rows()
d = ttt[0][0] // 2**512

m = pow(c_list[0], d, n_list[0])