# 2021年*CTF2021 —— Crypto —— MyCurve

## 题目
题目中给出了一个``curve.sage``文件。
```py
# curve.sage
from Crypto.Util.number import bytes_to_long
from flag import flag
assert flag[:5]=='*CTF{' and flag[-1]=='}'
flag=flag[5:-1]
def add(P,Q):
	if Q==0:
		return P
	x1,y1=P
	x2,y2=Q
	return (d1*(x1+x2)+d2*(x1+y1)*(x2+y2)+(x1+x1^2)*(x2*(y1+y2+1)+y1*y2))/(d1+(x1+x1^2)*(x2+y2)),(d1*(y1+y2)+d2*(x1+y1)*(x2+y2)+(y1+y1^2)*(y2*(x1+x2+1)+x1*x2))/(d1+(y1+y1^2)*(x2+y2))

def mul(k,P):
	Q=(0,0)
	while k>0:
		if is_even(k):
			k/=2
			P=add(P,P)
		else:
			k-=1
			Q=add(P,Q)
	return Q

F=GF(2**100)
R.<x,y>=F[]
d1=F.fetch_int(1)
d2=F.fetch_int(1)
x,y=(698546134536218110797266045394L, 1234575357354908313123830206394L)
G=(F.fetch_int(x),F.fetch_int(y))
P=mul(bytes_to_long(flag),G)
print (G[0].integer_representation(),G[1].integer_representation())
print (P[0].integer_representation(),P[1].integer_representation())
#(698546134536218110797266045394L, 1234575357354908313123830206394L)
#(403494114976379491717836688842L, 915160228101530700618267188624L)

```

## 解题
***这道题完全不会做，经验不足，题解是复现别人的writeup***
* **参考writeup** ：https://blog.csdn.net/cccchhhh6819/article/details/112766888

```py
F=GF(2**100)
d1=F.fetch_int(1)   # 把整数转换成多项式
```

这道题很大程度上要靠经验来发现是什么曲线，不过理论上如果搜索引擎用得好，应该也是可以搜得到的。
然后通过观察代码(靠经验或者搜索引擎)发现这个加密的曲线是二元域上的爱德华兹曲线，曲线方程的通用形式为$$d_1(x+y)+d_2(x^2+y^2)=(x+x^2)(y+y^2)$$曲线的细节见
https://www.hyperelliptic.org/EFD/g12o/auto-edwards.html
https://www.hyperelliptic.org/EFD/g12o/data/edwards/coordinates

然后把此曲线映射到一般的椭圆曲线上。
$$d_1(x+y)+d_2(x^2+y^2)=(x+x^2)(y+y^2)$$通过爱德华兹曲线与Weierstrass曲线的双射关系，即假设Weierstrass曲线为$$v^2+uv=u^3+a_2u^2+a_6$$有$$u=d_1(d_1^2+d_1+d_2)(x+y)/(xy+d_1(x+y))\newline v=d_1(d_1^2+d_1+d_2)(x/(xy+d_1(x+y))d_1+1)$$ 得到 $$v^2+uv=u^3+(d_1^2+d_2)u^2+(d_1^4(d_1^2+d_1^2+d_2^2))$$从而得到标准椭圆曲线上的参数。接下来把代码中的点$P，G$转换成椭圆曲线的形式，然后使用sagemath中的椭圆曲线设置与离散对数函数可以直接求解得出结果。

然后给出解密的代码，在**solution.py**文件中
```python
# Sagemath 9.2
from Crypto.Util.number import long_to_bytes

F = GF(2**100)
R.<x,y> = F[]

def _map(p):
    x,y = F.fetch_int(p[0]), F.fetch_int(p[1])
    u = 3*(x+y)/(x*y+x+y)
    v = 3*(x/(x*y+x+y)+2)
    return (u,v)

G = (698546134536218110797266045394, 1234575357354908313123830206394)
P = (403494114976379491717836688842, 915160228101530700618267188624)
# d1 = 1
# d2 = 1
# a1 = 1
# a2 = d1 ** 2 + d2 = 2
# a3 = 0
# a4 = 0
# a6 = d1**4 * (d1**4 + d1**2 + d2**2) = 3
E = EllipticCurve(GF(2**100), [1, 2, 0, 0, 3])
base = E(_map(G))
res = E(_map(P))
flag = discrete_log(res, base, base.order(), operation="+")
print(long_to_bytes(flag))
```

得到flag为``*CTF{p01Y_Edw@rds}``