# 2021年广东省强网杯团体赛—— Crypto —— DLP
题目见`task.sage`

* 题解
给出两条在Zmod上的椭圆曲线求离散对数。
首先对每一条曲线进行分解得到两条曲线，原理见`[CTF]_Crypto.md`椭圆曲线部分。
* 第一条曲线分解得到的p1,p2，对于p1可以使用DH求解，p2使用SmartAttack
* 第一条曲线分解得到的p1,p3，对于p1可以使用DH求解，p3使用MOV攻击，用DH也能出结果，就是时间比较久。

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break
#     print(P.curve())
#     print(P_Qps)

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)


p =
p2 = 
p1 = 

# first

A1 = 
B1 = 
P1x = 
P1y = 
Q1 = 
P1 = (P1x,P1y)

E1p = EllipticCurve(GF(p), [0,0,0,A1,B1])
P11 = E1p(P1)
Q11 = E1p(Q1)
d11 = discrete_log(Q11,P11,P11.order(),operation='+')

E1q = EllipticCurve(GF(p1), [0,0,0,A1,B1])
P12 = E1q(P1)
Q12 = E1q(Q1)
d12 = SmartAttack(P12,Q12,p1)

d1 = crt([d11,d12],[P11.order(), P12.order()])

# second
A2 = 
B2 = 
P2x = 
P2y = 
Q2 = 
P2 = (P2x, P2y)

E2p = EllipticCurve(GF(p), [0,0,0,A2,B2])
P21 = E2p(P2)
Q21 = E2p(Q2)
d21 = discrete_log(Q21,P21,P21.order(),operation='+')

E2q = EllipticCurve(GF(p2), [0,0,0,A2,B2])
P22 = E2q(P2)
R22 = E2q(Q2)

F1 = GF(p2)
k = 2 
F2 = GF(p2^k)
phi = Hom(F1, F2)(F1.gen().minpoly().roots(F2)[0][0])
E2q2 = EllipticCurve(F2, [0, 0, 0, A2,B2])

P2q2 = E2q2(phi(P22.xy()[0]), phi(P22.xy()[1]))
R2q2 = E2q2(phi(R22.xy()[0]), phi(R22.xy()[1]))

n = E2q.order()
cn1 = p2+1
coeff = ZZ(cn1 / n)

Q = coeff * E2q2.random_point()
alpha = P2q2.weil_pairing(Q, n)
beta = R2q2.weil_pairing(Q, n)
d22 = beta.log(alpha)

d2 = crt([d21,d22],[P21.order(), P22.order()])

print(long_to_bytes(d1) + long_to_bytes(d2))
```