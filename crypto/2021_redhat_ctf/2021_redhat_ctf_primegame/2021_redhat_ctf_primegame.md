# 2021年红帽杯—— Crypto —— PrimeGame

## 题目
```python
#!/usr/bin/env python3

from decimal import *
import math
import random
import struct
# from flag import flag
flag = b'123456781234567812345678123456781234567812345678'

assert (len(flag) == 48)
msg1 = flag[:24]
msg2 = flag[24:]
primes = [2]
for i in range(3, 90):
    f = True
    for j in primes:
        if i * i < j:
            break
        if i % j == 0:
            f = False
            break
    if f:
        primes.append(i)

print(primes)

getcontext().prec = 100
keys = []
for i in range(len(msg1)):
    keys.append(Decimal(primes[i]).ln())

sum_ = Decimal(0.0)
for i, c in enumerate(msg1):
    sum_ += c * Decimal(keys[i])

print(sum_ *2**256)
ct = math.floor(sum_ * 2 ** 256)
print(ct)

sum_ = Decimal(0.0)
for i, c in enumerate(msg2):
    sum_ += c * Decimal(keys[i])

ct = math.floor(sum_ * 2 ** 256)
print(ct)

```

题解：
变种背包问题，本质上是求多个变量的正线性组合。即要求：$$a_{23}x_{23}+a_{22}x_{22}+...+a_0x_0 = ct$$的一个线性组合，其中$x_i$已知，求$a_i$且这些$a_i$都是整数。

使用格方法可以进行求解，详细见``[CTF]_Crypto.md``中的哈希函数中``FNV``部分。

代码见``solution.py``文件

```
# Sagemath9.2

import numpy as np
import math
from decimal import Decimal, getcontext

# getcontext().prec = Integer(100)

# K = 2**200
K = 1
N = 25

# 2^6
bkeys = [Decimal('5136701451903443767182969869203844514175402727141756582791863520346877246475001.93013811751272310162560'), Decimal('8141479178666875996166302061369806439577976397088200938470758996866233568944938.6479599781320291584768'), Decimal('11927051416223311319041251533367841081339107701051489627512248058766432830154652.2534990064279057752512'), Decimal('14420544104141574230884098298841919046188484995540791682423345574452840253918863.4702048678409902502144'), Decimal('17770067418214885392491145898013388539136023699307159772044599107855896582735641.5580437186534699344320'), Decimal('19008054072856518322225907807003576696532751567477385491461350195922748096920349.9149325592659953800576'), Decimal('20996076311251993920140754420840339295838079447122440314575964391774759042432576.0827138064316294271360'), Decimal('21820335425886251248077381476063776621405039026059892937924055731404540976853859.1531619835809049192192'), Decimal('23236187267453240114504740700147637246382115973736252546912610286244000012037243.8115473242044255884096'), Decimal('24953998030991136293749733350588168413450068644908495562709048678956403902594396.6547097209240053529024'), Decimal('25448227380578946034450231486494784324575481865594338215759920650299754851664090.2396521860443519153984'), Decimal('26759406666849508045682935910927559705543497044747194453023162751616497004414801.1342656452729666714816'), Decimal('27520145160769916173455917116790195366796545401671256569831506645377693338575260.0962398282218269571520'), Decimal('27873102043890750627130516962623541293795577562733036014408493734003838175320735.1471560042354484451584'), Decimal('28532264619139202351193801993949519018853687156667167328740275300464219451212589.5841371159624164395328'), Decimal('29422617315342218829008547446725961710404435863246186469006316964661364958923556.5631825083181376310976'), Decimal('30217381092686671815655848959032260695688221629273111831744112130552816269879184.6735751160363826113920'), Decimal('30464427092717242422523259131918572815877487445444651673742808546194311046838378.5854524374553191699392'), Decimal('31159689152000225480750679318309880235691385698886839501753379932509039319392342.0116100638969766112576'), Decimal('31589414957598721450989634907522128483932593871132133681577718647148203233823383.3925458944647764180224'), Decimal('31795280798626577857223724977481842557523230884345257955959529867504529140289633.3499816868158156021696'), Decimal('32380639721642301623510587284816586739672452539010842918822916837718732458654412.8754868992418965529088'), Decimal('32746674302941452920176364222801704089799917926661183431364825315345097016885408.9056846474370514003264'), Decimal('33263909316984764686313141214821696121254933397863907483685400261258537894503536.3368362117369889953280')]
bkeys.append(Decimal('27263070403058005554557651258268598578114093606308600662122275234967812058277754752')
            )

print(len(bkeys))

m = Matrix(ZZ, N, N + 1)
for i in range(N):
    #     print(bkeys[i])
    ge = ZZ(math.floor(bkeys[i]))
    #     print(ge)
    m[i, i] = 1
    m[i, N] = ZZ(ge * K)

ml = m.LLL()
ttt = ml.rows()[0]  # 第一行表示线性组合的系数
print(np.array(ml))
```