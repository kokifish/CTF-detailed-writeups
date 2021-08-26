# 2021第三届美团CTF—— Crypto —— random

## 题目 

题目没有代码，只有一个`nc`命令。因此只能与服务器进行交互。

1. 首先给出
```
e*d+n = 3563329754048976946603729466426236052000141166700839903323255268203185709020494450173369806214666850943076188175778667508946270492708397447950521732324059148390232744011000065982865974194986726739638097566303135573072114448615095262066554751858952042395375417151593676621825939069783767865138657768553767717034970
e*d-n = 3563121718917234588723786463275555826875232380691165919033718924958406353810813480184744219046717838078497090403751007254545187720107602959381881715875898243474504999760208133192572812110967142474619366650504948619637909653723376917174456091396220576841259798792078769198369072982063716206690589554604992470787752
```
要求计算pow(m,d,n)，其中
```python 
m=b"you_can_get_more_message"
```

* 解： 解法很简单，暴力分解出$p,q$，然后暴力枚举k的值来猜测$\phi$。最后暴力枚举得到$e=65553$。（因为暴力枚举的e有多个结果，然后做题的时候e选错了，导致一直都做不出来）

2. 第一问给出答案后给了一堆lcg(线性同余生成器)产生的数。破解lcg就可以了。

参考代码：
```python
from functools import reduce
from gmpy2 import invert,gcd
from Crypto.Util.number import *

states = [3732074616716238200873760199583586585380050413464247806581164994328669362805685831589304096519259751316788496505512, 8890204100026432347745955525310288219105398478787537287650267015873395979318988753693294398552098138526129849364748, 3443072315415198209807083608377973177101709911155814986883368551162572889369288798755476092593196361644768257296318, 4505278089908633319897964655164810526240982406502790229247008099600376661475710376587203809096899113787029887577355, 9059646273291099175955371969413555591934318289156802314967132195752692549263532407952697867959054045527470269661073, 3085024063381648326788677294168591675423302286026271441848856369032582049512915465082428729187341510738008226870900, 8296028984288559154928442622341616376293205834716507766500770482261973424044111061163369828951815135486853862929166, 2258750259954363171426415561145579135511127336142626306021868972064434742092392644953647611210700787749996466767026, 4382123130034944542655156575000710851078842295367353943199512878514639434770161602326115915913531417058547954936492, 10982933598223427852005472748543379913601896398647811680964579161339128908976511173382896549104296031483243900943925]

def crack_unknown_increment(states, modulus, multiplier):
    increment = (states[1] - states[0]*multiplier) % modulus
    return modulus, multiplier, increment

def crack_unknown_multiplier(states, modulus):
    multiplier = (states[2] - states[1]) * invert(states[1] - states[0], modulus) % modulus # 注意这里求逆元
    return crack_unknown_increment(states, modulus, multiplier)

def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)
modulus, multiplier, increment = crack_unknown_modulus(states)
seed = (states[0]-increment)*invert(multiplier, modulus)%modulus
print(long_to_bytes(seed))
```