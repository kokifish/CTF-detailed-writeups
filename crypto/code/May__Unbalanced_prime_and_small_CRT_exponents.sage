# Sagemath9.2
N=
e=

beta  = 0.233
delta = 0.226
n_size = 1024
# Y = 2**(int(n_size * beta))
# X = 2**(int(n_size * (delta+beta))-5)
Y = int(N^beta)
X = int(N^(delta+beta))
# X = 2^460
# Y = 2^240
R.<x,y> = PolynomialRing(IntegerRing())
dl_list = [0, 1.732, 2, 3, 4, 5.744562, 7, 9, 11, 13, 15]

fe = x*(N-y)-N


def generate_Lattice(m):
    tao = (1-3*beta-delta)/(2*beta)
    tao = ((1-beta)^2-delta)/(2*beta*(1-beta))
    t = ceil(tao * m)
    t = 3
    B_polynomial = []
    usedMonomial = []        # 用来记录单项式被用了
    B = [[0 for j in range((t+m+2)^2)] for i in range((t+m+2)^2)]
    
    c = 0
    for i in range(m+1):
        for j in range(m-i+1):

            g = e^(m-i)*x^j*fe^i
            B_polynomial.append(g)
            mono = g.monomials()
            coefs = g.coefficients()
            mono.reverse()
            coefs.reverse()
            for ele in range(len(mono)):
                if mono[ele] not in usedMonomial:
                    usedMonomial.append(mono[ele])
#                 print(c, usedMonomial.index(mono[ele]))
                B[c][usedMonomial.index(mono[ele])] = coefs[ele]*mono[ele](X,Y) 
            c += 1                 
    
    for i in range(m+1):
        for j in range(1, t+1):
            h = e^(m-i)*y^j*fe^i
            B_polynomial.append(h)
            mono = h.monomials()
            coefs = h.coefficients()
            mono.reverse()
            coefs.reverse()
            for ele in range(len(mono)):
                if mono[ele] not in usedMonomial:
                    usedMonomial.append(mono[ele])
                B[c][usedMonomial.index(mono[ele])] = coefs[ele]*mono[ele](X,Y) 
            c += 1
    B = B[:c]
    for i in range(len(B)):
        B[i] = B[i][:len(usedMonomial)]
    
    print(usedMonomial)
    return Matrix(ZZ, B), usedMonomial, B_polynomial


m = 5
dl = dl_list[m]
C, mono, B_polynomial = generate_Lattice(m)

ml = C.LLL()
ttt = ml.rows() 
print(ttt[0])

tmp = distance(ttt[1])
print(tmp < (e^m)/dl) # 有时候界稍微超一点点也能出结果

# construct f
cs = C.solve_left(vector(ttt[0]))
# cs = ttt[0]
assert len(B_polynomial)==len(cs)

f = 0
for i in range(len(mono)):
    f = f + cs[i]*B_polynomial[i]
#     f = f + cs[i]*mono[i] / mono[i](X, Y)
    
cs = C.solve_left(vector(ttt[1]))
# cs = ttt[1]
g = 0
for i in range(len(mono)):
    g = g + cs[i]*B_polynomial[i]
#     g = g + cs[i]*mono[i] / mono[i](X, Y)

f = R(f)
g = R(g)
rr = f.resultant(g, x)
PR.<y> = PolynomialRing(IntegerRing())
rr = PR(rr)
print(rr.roots())   # 其中的结果是较小的那个素数
