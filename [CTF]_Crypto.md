# Crypto

> 学习密码学需要了解一定的数论知识，特别是初等数论以及群、环、域、格。

密码学（Cryptography）一般可分为**古典密码学**和**现代密码学**。

其中，**古典密码学**，作为一种实用性艺术存在，其编码和破译通常依赖于设计者和敌手的创造力与技巧，并没有对密码学原件进行清晰的定义。古典密码学主要包含以下几个方面：

- 单表替换加密（Monoalphabetic Cipher）
- 多表替换加密（Polyalphabetic Cipher）
- 奇怪怪的加密方式

而**现代密码学**则起源于 20 世纪中后期出现的大量相关理论，1949 年香农（C. E. Shannon）发表了题为《保密系统的通信理论》的经典论文标志着现代密码学的开始。现代密码学主要包含以下几个方面：

- 对称加密（Symmetric Cryptography），以 DES，AES，RC4 为代表。
- 非对称加密（Asymmetric Cryptography），以 RSA，ElGamal，椭圆曲线加密为代表。
- 哈希函数（Hash Function），以 MD5，SHA-1，SHA-512 等为代表。
- 数字签名（Digital Signature），以 RSA 签名，ElGamal 签名，DSA 签名为代表。

其中，对称加密体制主要分为两种方式：
- 分组密码（Block Cipher），又称为块密码。
- 序列密码（Stream Cipher），又称为流密码。

# 古典密码

> 各种各样的古典密码(提供思路)
http://www.practicalcryptography.com/

#### 替换密码
http://quipqiup.com/

#### XOR 密码(异或密码)
https://www.dcode.fr/xor-cipher

#### 维吉尼亚密码
* 解密工具
    * https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx 

#### 密码破解工具集

https://www.dcode.fr/tools-list#cryptography


#### latex数学符号
给出一堆latex数学符号，然后要求解flag。一般来说，把数学符号转换为latex公式的形式，然后取每个公式的首个字符就是flag。

* https://blog.csdn.net/anscor/article/details/80878285 latex数学符号
* http://detexify.kirelabs.org/classify.html latex手写公式识别

#### Playfair
###### 原理 
Playfair 密码（Playfair cipher or Playfair square）是一种替换密码，1854 年由英国人查尔斯 · 惠斯通（Charles Wheatstone）发明，基本算法如下：

1. 选取一串英文字母，除去重复出现的字母，将剩下的字母逐个逐个加入 5 × 5 的矩阵内，剩下的空间由未加入的英文字母依 a-z 的顺序加入。注意，将 q 去除，或将 i 和 j 视作同一字。
2. 将要加密的明文分成两个一组。若组内的字母相同，将 X（或 Q）加到该组的第一个字母后，重新分组。若剩下一个字，也加入 X 。
3. 在每组中，找出两个字母在矩阵中的地方。
    * 若两个字母不同行也不同列，在矩阵中找出另外两个字母（第一个字母对应行优先），使这四个字母成为一个长方形的四个角。
    * 若两个字母同行，取这两个字母右方的字母（若字母在最右方则取最左方的字母）。
    * 若两个字母同列，取这两个字母下方的字母（若字母在最下方则取最上方的字母）。
    新找到的两个字母就是原本的两个字母加密的结果。

以 playfair example 为密匙，得

```
P L A Y F
I R E X M
B C D G H
K N O Q S
T U V W Z
```
要加密的讯息为 ```Hide the gold in the tree stump```

```HI DE TH EG OL DI NT HE TR EX ES TU MP```
就会得到

```BM OD ZB XD NA BE KU DM UI XM MO UV IF```
>工具 
CAP4

#### Polybius
###### 原理 
Polybius 密码又称为棋盘密码，其一般是将给定的明文加密为两两组合的数字，其常用密码表
```
1	2	3	4	5
1	A	B	C	D	E
2	F	G	H	I/J	K
3	L	M	N	O	P
4	Q	R	S	T	U
5	V	W	X	Y	Z
```
举个例子，明文 HELLO，加密后就是 ```23 15 31 31 34```。

#### 培根密码
特点：
* 只有两种字符
* 每一段的长度为 5
* 加密内容会有特殊的字体之分，亦或者大小写之分。

#### 栅栏密码
原理：栅栏密码把要加密的明文分成 N 个一组，然后把每组的第 1 个字连起来，形成一段无规律的话。
本质上就是置换密码

#### 曲路密码
原理曲路密码（Curve Cipher）是一种置换密码，需要事先双方约定密钥（也就是曲路路径）
![曲路密码](crypto/images/Curve_Cipher.PNG)

#### 列移位加密
本质上也是置换密码

#### 01248密码(云影密码)
该密码又称为云影密码，使用 0，1，2，4，8 四个数字，其中 0 用来表示间隔，其他数字以加法可以表示出 如：28=10，124=7，18=9，再用 1->26 表示 A->Z。

#### JSFuck
JSFuck 可以只用 6 个字符 []()!+ 来编写 JavaScript 程序。
> 工具 
JSFuck 在线加密网站 http://www.jsfuck.com/

#### BrainFuck
Brainfuck，是一种极小化的计算机语言
> 工具
https://www.splitbrain.org/services/ook

#### WINGDING
WINGDING是一个将文本符号转换为Wingding符号的工具，Wingding符号是"Unicode"符号，可以进行复制粘贴。(这里其实更像misc)，因为本质上是编码的转换而不是密码。
例子：
```
♐●♋♑❀♏📁🖮🖲📂♍♏⌛🖰♐🖮📂🖰📂🖰🖰♍📁🗏🖮🖰♌📂♍📁♋🗏♌♎♍🖲♏❝
解码：flag{e0791ce68f718188c0378b1c0a3bdc9e}
```
> 工具
https://lingojam.com/WingDing


#### 猪圈密码
![猪圈密码](crypto/images/pip_sty.PNG)
#### 舞动的小人密码
这些密码本质上是以一些符号代替英文字母，只要把英文字母替换上去就可解密，实质上可以使用词频分析

#### 键盘密码
所谓键盘密码，就是采用手机键盘或者电脑键盘进行加密。
##### 手机键盘密码
手机键盘加密方式，是每个数字键上有 3-4 个字母，用两位数字来表示字母
##### 电脑键盘棋盘
电脑键盘棋盘加密，利用了电脑的棋盘方阵
##### 电脑键盘坐标
电脑键盘坐标加密，利用键盘上面的字母行和数字行来加密
##### 电脑键盘 QWE
电脑键盘 QWE 加密法，就是用字母表替换键盘上面的排列顺序
##### 键盘布局加密
简单地说就是根据给定的字符在键盘上的样子来进行加密。
> 例：密文：```4esxcft5 rdcvgt 6tfc78uhg 098ukmnb```。试着在键盘上按照字母顺序描绘一下，可得到 ```0ops``` 字样

### 解题技巧
1. 如果遇到一段无脑的密文然后没有任何的提示，那么考虑替换密码，代换密码，哈希函数，直接上破解网站进行破解。
2. 一般如果是古典密码，一般都会给出一定的提示告诉我们使用的是哪一种古典密码。
3. 遇到给定的.py文件的题目，首先需要分析其主要运用的加密逻辑，与古典密码进行比较，若是一种新提出的方案，一般都会给出足够的信息作为突破口。
4. 在搜索关键词的时候，相同使用`common`而不是`same`


# 现代密码

## 对称密码

### 流密码

#### 伪随机数生成器PRNG

##### 随机性的严格性 
* 随机性：随机数应该不存在统计学偏差，是完全杂乱的数列。
* 不可预测性：不能从过去的序列推测出下一个出现的数。
* 不可重现性：除非数列保存下来，否则不能重现相同的数列。




#### BBS生成器 (Blum-Blum-Shub)

> 具体算法见：《密码学原理与实践》(第三版) 8.3节，这里作简要的叙述

设$p,q$是满足$p\equiv q\equiv 3\ mod\ 4$ 的$k$比特素数。$n=pq$。设$s_0$是模$n$的二次剩余。对于$0\leq i\leq l-1$，有$$s_{i+1} = s_i^2\ mod\ n$$，定义$f(s_0) = (z_1,z_2,...,z_l)$，其中$z_i = s_i\ mod\ 2,\ \ 1\leq i\leq l$。这样一来$f$就是一个$(k,l)$的BBS生成器。



#### 码安全伪随机数生成器

* 例题：woodman - Google CTF
```python
class SecurePrng(object):
    def __init__(self):
        # generate seed with 64 bits of entropy
        self.p = 4646704883L
        self.x = random.randint(0, self.p)
        self.y = random.randint(0, self.p)

    def next(self):
        self.x = (2 * self.x + 3) % self.p
        self.y = (3 * self.y + 9) % self.p
        return (self.x ^ self.y)
```
目标是要求出前100个随机数。
前面几个随机数很容易就可以知道，假设是sol1和sol2，因此可以写出相应的表达式，然后由于相乘的系数只为2和3，因此实际上求模的时候最多只会减去3个p，因此可以通过枚举减去的p的数量来猜测x0和y0的值。这里只要找出了两个明文就可以把x0和y0恢复出来。

> 首先需要模拟x和y模p是减去p的个数kx，ky

> 对于每一个候选比特串tx，都枚举0和1表示当前的第i bit，记为bi；把枚举出的bi添加到候选比特串的第i位中。然后把tx和sol1进行异或求出另一个比特串ty，再把tx和ty代入随机数生成的函数中(模p就使用减去kx和ky表示)，并把结果进行异或得到guess2，把guess2的低i位与sol2的低i位进行比较，如果相等，那么就把tx加入新一轮的候选，第i轮结束后，使用新一轮的候选覆盖第i轮的候选作为第i+1轮候选。

> 以此类推，直到所有bit都选择完毕，这样一来用最后剩下的候选进行测试，


#### 线性同余生成器 LCG(linear congruential generator)

* https://en.wikipedia.org/wiki/Linear_congruential_generator

简介：The generator is defined by recurrence relation: $$ X_{n+1}=(aX_n+c)\ mod\ m$$其中$X$是伪随机值(pseudorandom values)，并且
* $m,\ 0 < m$ the "modulus"模数
* $a,\ 0 < a < m$ the "multiplier"乘数
* $c,\ 0\leq c < m$ the "increment"加数
* $X_0,\ 0\leq X_0 < m$ the "seed" 种子。

求解方案参考reference：https://www.codercto.com/a/35743.html
主要流程参见`crypto/linear_congruential_generator.md`


##### 截断线性同余生成器 TLCG(truncated linear congruential generator)
- **TLCG**：在$X_{n+1}=(aX_n+c)\ mod\ m$的基础上，令$k = \lfloor log\ m\rfloor + 1$，然后令$$X_i = 2^{k-s}y_i + z_i,\ \ where 0\leq z_i < 2^{k-s}$$ 然后每次返回$y_i$.
- **攻击方法**：构造一组多项式，然后通过类似Hidden Number Problem的方法进行求解，然后解线性方程组。因为用到了LLL算法，因此有一定的条件限制。

- 参考资料：
  - [Contini S., Shparlinski I. E., "On Stern's Attack Against Secret Truncated Linear Congruential Generators"](https://link.springer.com/content/pdf/10.1007/11506157_5.pdf)
  - [crypto-attack Truncated LCG parameter recovery](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/truncated_parameter_recovery.py)
  - [Frieze, A. et al., "Reconstructing Truncated Integer Variables Satisfying Linear Congruences"]
  - [crypto-attack Truncated LCG state recovery](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/truncated_state_recovery.py)



#### 反馈移位寄存器
![反馈移位寄存器](crypto/images/Feedback_shift_register.jpg)
* $a_0, a_1, ... , a_{n-1}$位初态
* F 为反馈函数或者反馈逻辑。如果 F 为线性函数，那么我们称其为线性反馈移位寄存器（LFSR），否则我们称其为非线性反馈移位寄存器（NFSR）。
* $a_{i+n} = F(a_i, a_{i+1},...,a_{i+n-1})$

##### 线性反馈移位寄存器 - LFSR

##### B-M 算法 (一种求解线性反馈移位寄存器的算法)

##### python中的一个库`z3`
`z3`这个库主要用来**解方程组**，它微软开发的一套约束求解器，可以简单的理解它是解方程。其优势在于可以求解有位运算的方程组。如果方程有多组解，z3只会给出其中的一组解。

* 参考题目
    * TCTF 2019 Quals - zer0lfsr https://fireshellsecurity.team/0ctf-zer0lfsr/
    * TCTF 2021 - zer0lfsr-

基本用法： 参考 https://www.jianshu.com/p/64d87659673a
`z3.simplify()`函数可以简化z3表达式从而加快运算速度，但是有可能导致精度丢失。

* **如果题目中给出多元多次方程，可以找出额外的约束条件，从而可以用z3求解。**

使用`z3`求解出约束的多项式之后，需要把结果转换成`python`中的类型，比如int,float,bool等类型，解决方法如下
(参考：https://www.jb51.cc/python/186627.html 和 https://jingyan.baidu.com/article/48a420579c65f3e8242504b8.html)
> 对于布尔值,可以使用函数is_true和is_false.数值可以是整数,合理或代数.我们可以使用函数is_int_value,is_rational_value和is_algebraic_value来测试每种情况.整数情况是最简单的,我们可以使用方法as_long()将Z3整数值转换为Python long.对于有理值,我们可以使用方法numerator()和分母()来获取表示分子和分母的Z3整数.方法numerator_as_long()和denominator_as_long()是self.numerator().as_long()和self.denominator().as_long()的快捷方式.最后,代数数字用于表示非理性数字. AlgebraicNumRef类有一个称为约(self,precision)的方法.它返回一个Z3有理数,它以精度为1/10 ^的精度逼近代数

```python
x,y,z = BitVecs('x y z', 8)
s = Solver()
s.add(x^y&z== 12)   # 用add方法添加约束
s.add(y&x>>3 == 3)
s.add(z^y==4)

s.check()   # 求解
s.model()
[z = 19, y = 23, x = 31]
```
更进一步的理解：https://blog.csdn.net/s1054436218/article/details/78651075


#### 非线性反馈移位寄存器
* 非线性组合生成器，对多个 LFSR 的输出使用一个非线性组合函数
* 非线性滤波生成器，对一个 LFSR 的内容使用一个非线性组合函数
* 钟控生成器，使用一个（或多个）LFSR 的输出来控制另一个（或多个）LFSR 的时钟
代表 Geffe

#### `python`中的`random`库的预测
python中的random库使用的是**Mersenne Twister 算法作为核心生成器**。

参考文献：
1. https://docs.python.org/zh-cn/3/library/random.html
2. https://en.wikipedia.org/wiki/Mersenne_Twister

维基百科上提供了梅森旋转算法的伪代码，有兴趣的读者可以自己实现一版。然后在攻击的predictor中的`mt19937predictor.py`文件中也有相应的生成算法的代码。

参考：`crypto/random_number_Mersenne_Twister_2021NahamconCTF_Dice_Roll`中的writeup。
破解代码见`crypto/code/mersenne-twister-predictor-master.zip`。

#### `python`中的随机数生成
在普通的工程上使用`random`函数库即可，但是如果要设计密码方案，则需要用到强随机数生成器。一般来说使用
* `os.urandom()`：函数调用计算机底层的模块生成随机数，并且它会从许多不可预测的来源中提取其熵源，有较强的随机性。
* `secrets`：一个较为通用的强伪随机数生成器。

> 一般来说需要仔细观察LFSR，然后看看是否有特殊的情况，然后看看能否用这种特殊的情况来进行破解。然后看看是否为LFSR，如果是的话看看能不能构造BM算法的求解方式，或者看看有没有这种情况。然后其中要考虑暴力破解的可能。然后有时候也能想一下是否能用`z3`去求解。



#### RC4 TODO

RC4属于对称密码算法中的序列密码(stream cipher,**流密码**)，它是**可变密钥长度**，**面向字节操作的序列密码**。它是一种基于非线性数据表变换的序列密码，它以一个足够大的数据表为基础，对表进行非线性变换，产生非线性的序列密钥。

- 参考资料 
  - [RC4](https://blog.csdn.net/weixin_42369053/article/details/117028245)
  - [crypto-attack Fluhrer-Mantin-Shamir attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rc4/fms.py) 使用Fluhrer-Mantin-Shamir attack恢复RC4的部分密钥，需要有`encrypt_oracle`



### 块密码
所谓块加密就是每次加密一块明文，常见的加密算法有：
- IDEA 加密
- DES 加密
- AES 加密
- ARX 加密
- TEA 加密
- Simon and Speck 加密

还有许多对称加密方案，这里只列出常见的几种，每一种方法网上资料都比较多，这里就不一一列举。

在分组密码设计时，一般回使用**混淆(S盒，乘法)与扩散(线性变换，置换，移位)** 两大策略。

#### DES (Data Encryption Standard)

DES is developed in 1970s until 2000s after it was broken (in 22 hours and 15 minutes by distributed.net and the Electronic Frontier Foundation in January 1999). **Triple DES** is hence recommended by the NIST for future use.

DES是一个**16轮**的Feistel型结构密码，它的**分组长度为64比特**，用一个**56比特的密钥**来加密一个64比特的明文串，输出一个64比特的密文串。

* DES的原理见《密码学原理与实践 第三版》3.5章，下面仅给出DES的轮函数：
![DES主要流程](crypto/images/DES_main_process.png)
![DES的F函数](crypto/images/F_function_of_DES.PNG)

* 参考Sagemath9.2代码
```python
# Sagemath9.2
from sage.crypto.block_cipher.des import DES
des = DES()
P = 0x01A1D6D039776742
K = 0x7CA110454A1A6E57
K2 = 0x133457799bbcdff1
K3 = 0x1f08260d1ac2465e
C1 = des.encrypt(plaintext=P, key=K)
C2 = des.encrypt(plaintext=C1, key=K2)
C3 = des.encrypt(plaintext=C2, key=K3)
print(C3.hex())
#9c0102317f7a6991

#Now decrypt back:
D3 = des.decrypt(ciphertext=C3, key=K3)
D2 = des.decrypt(ciphertext=D3, key=K2)
D1 = des.decrypt(ciphertext=D2, key=K)
print(D1.hex())
#1a1d6d039776742
```

##### 1. 线性S盒
DES的S盒如果是纯线性的，那么只要知道一组明密文对，那么就可以列出在$GF(2)$上的线性方程组，从而把密钥求解出来。可以使用`python`的`z3`库列举线性方程组，然后使用Sagemath进行求解，因为`z3`求解线性方程组比较慢。

* 具体流程
```python
from z3 import *

key_z3 = [BitVec(f'k_{i}', 1) for i in range(64)]
print(len(key_z3))
s = Solver()
msg = # 64 bit message
myc = encrypt_z3(msg, key_z3)
cc =  # 64 bit ciphertext
for i in range(64):
    print([z3.simplify(myc[i])],',')
```
方程组列举完成后，使用Sagemath进行求解

```python
# Sagemath 9.2
M = Matrix(GF(2), M)
v = vector(GF(2), v)
x = M.solve_right(v)
print(x)    # x is the key in bits
```

> 如果S盒是线性的，那么这种攻击方法也可以推广到AES中。


#### AES (Advanced Encryption Standard)

AES is a block cipher encryption standard approved by NIST in 2002 and developed by Vincent Rijmen and Joan Daemen.
**Block-size:** 128 bits
**Key-size:** 128, 192 and 256 bits with 10, 12 and 14 rounds respectively

主要流程：![AES流程](crypto/images/AES.PNG)

* 预计算：轮密钥生成，S盒的计算
* 每一轮主要包含四个运算，分别是（这里说的与图的不太一致，但是运算是一致的）
    1. 轮密钥加（AddRoundKey）
    2. 字节替换（SubBytes / S盒）
    3. 行移位（ShiftRows）
    4. 列混合（MixColumns）
* 最后一轮运算的时候不需要进行列混合
* 最后一轮运算结束后，还需要进行一次轮密钥加运算


> 常见python实现(这种实现AES是一个黑盒，只能用作加密和解密，无法深入进行分析)：
``` python 
# python3
from Crypto.Cipher import AES
import os
key = b'1234567890123456' #秘钥
text = b'1234567890123456' #需要加密的内容
iv = os.urandom(16)   # 初始向量
model = AES.MODE_CBC #定义模式
aes = AES.new(key, AES.MODE_CBC, iv=iv) #创建一个aes对象

en_text = aes.encrypt(text) #加密明文
print(en_text)

aes2 = AES.new(key, AES.MODE_CBC, iv=iv)
de_text = aes2.decrypt(en_text) #解密明文
print(de_text)
```

> 常见sagemath实现(这里的实现涉及到aes的每一步，这里每一步的运算是一个黑盒，如果题目中有自己定义的S盒，行移位，列混合运算，就需要更具体的分析)。Sagemath的AES的实现主要用到了``RijndaelGF``这个类。

> Rijndael-GF是AES密码的代数实现，它寻求提供整个AES密码及其单个组件的完全广义代数表示。

* Sagemath9.2基于``Rijndael-GF``实现的AES见``crypto/code/AES_sage.sage``

##### AES相关攻击
* 差分错误分析(Differential Fault Analysis)在AES的第八轮添加1个byte的错误信息，则可以恢复出AES的密钥，见``crypto/2021_CSISC/AES_2021_oddaes``。


#### TEA加密
TEA算法由剑桥大学计算机实验室的David Wheeler和Roger Needham于1994年发明。它是一种分组密码算法，其明文密文块为64比特，密钥长度为128比特。TEA算法利用不断增加的Delta(黄金分割率)值作为变化，使得每轮的加密是不同，该加密算法的迭代次数可以改变，建议的迭代次数为32轮。

参考资料：
* https://blog.csdn.net/gsls200808/article/details/48243019
* https://github.com/iweizime/StepChanger/wiki/%E8%85%BE%E8%AE%AFTEA%E5%8A%A0%E5%AF%86%E7%AE%97%E6%B3%95

最明显的是`delta=0x9e3779b9`这个特殊的设定吗，**遇到加密或解密文件里面有特殊的字符时，直接搜索这串字符有很大概率能找到相应的加密解密算法**。
```python
def TEA_encryption(vs, ks):
    delta = 0x9E3779B9
    v0, v1 = map(uint32, unpack('>2I', vs))
    k0, k1, k2, k3 = map(uint32, unpack('>4I', ks))
    sm, delta = uint32(0), uint32(delta)

    for i in range(32):
        sm.value += delta.value
        v0.value += ((v1.value << 4) + k0.value) ^ (v1.value + sm.value) ^ ((v1.value >> 5) + k1.value)
        v1.value += ((v0.value << 4) + k2.value) ^ (v0.value + sm.value) ^ ((v0.value >> 5) + k3.value)

    return pack('>2I', v0.value, v1.value)


def TEA_decryption(vs, ks):
    delta = 0x9E3779B9
    v0, v1 = map(uint32, unpack('>2I', vs))
    k0, k1, k2, k3 = map(uint32, unpack('>4I', ks))
    sm, delta = uint32(delta * 32), uint32(delta)

    for i in range(32):
        v1.value -= ((v0.value << 4) + k2.value) ^ (v0.value + sm.value) ^ ((v0.value >> 5) + k3.value)
        v0.value -= ((v1.value << 4) + k0.value) ^ (v1.value + sm.value) ^ ((v1.value >> 5) + k1.value)
        sm.value -= delta.value

    return pack('>2I', v0.value, v1.value)
```

#### prince 加密
同样是一个分组密码加密方案，使用的是块加密的模式。标志性字符串：
```
ALPHA = BitArray("0xc0ac29b7c97c50dd")
BETA = BitArray("0x3f84d5b5b5470917")
```

此加密算法存在integral attack。 攻击代码： https://github.com/de-ci-phe-red-LABS/PRINCE-under-Differential-Fault-Attack-Now-in-3D

算法介绍参考：https://en.wikipedia.org/wiki/Prince_(cipher)


#### 分组模式
分组加密会将明文消息划分为固定大小的块，每块明文分别在密钥控制下加密为密文。当然并不是每个消息都是相应块大小的整数倍，所以我们可能需要进行填充。常见的分组模式：
- **ECB**：密码本模式（Electronic codebook）
    - 这种模式是将整个明文分成若干段相同的小段，然后对每一小段进行加密。
- **CBC**：密码分组链接（Cipher-block chaining）
    - 这种模式是先将明文切分成若干小段，然后每一小段与初始块或者上一段的密文段进行异或运算后，再与密钥进行加密。
- **PCBC**：密码分组链接（Cipher-block chaining）
- **CFB**：密文反馈模式（Cipher feedback）
    - 此模式将会以一种流密码的形式进行，详细见下面描述：
    - CFB模式需要一个整数参数$s$，使$1\leq s\leq b$。在下面的CFB模式规范中，每个明文段($P_j$)和密文段($C_j$)由$s$位组成。$s$的值有时被合并到模式的名称中，例如，1位CFB模式、8位CFB模式、64位CFB模式或128位CFB模式。运算形式如下： $$ \begin{array}{l}I_0 = IV. \\ I_i=((I_{i-1}\ll s) + C_i)\ mod\ 2^b, \\ C_i = MSB_s(E_K(I_{i-1}))\oplus P_i, \\ P_i = MSB_s(E_K(I_{i-1}))\oplus C_i \end{array}$$
    - `pycryptodome`中默认是$s=8$，是其中的`segment_size`参数。

- **OFB**：输出反馈模式（Output feedback）
- **CTR**：计数器模式（Counter mode）
- **GCM**：（Galois/Counter mode ）
  - **G**指代GMAC( Galois message authentication code mode, 伽罗瓦消息验证码 )；**C**指代CTR；所以GCM可以提供对消息的加密和完整性校验。
  - 针对GCM的攻击
    - [Joux A., "Authentication Failures in NIST version of GCM"](https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/joux_comments.pdf)
    - [crypto-attack Forbidden attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/gcm/forbidden_attack.py)

**注：ECB模式的AES是不安全的。建议仔细进行确认，网上有些填充模式说得不对。**

* 参考： https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

* 有时候会把分组模式作为题目，此时把AES看成黑箱，然后根据最后的结果、最初的结果和允许执行的中间过程构造出题目想要的结果。

#### 填充方法
目前有不少的填充规则。常见的填充规则：
- **pkcs5**：填充字节数与填充字节数相同的值
- **pkcs7**：(OneAndZeroes Padding)Pad with 0x80 followed by zero bytes
- **Pad with zeroes except make the last byte equal to the number of padding bytes** 用零填充，并使最后一个字节等于填充字节的数目
- **null**：Pad with zero characters（零填充）
- **Pad with spaces**：空格填充


#### 块加密攻击方法
##### BitFlipping
这是一种块加密的常用攻击方法，目的是构造相应的`iv`或者密文，使得通过黑盒解密得到的明文是我们想构造出的明文。适合于所有的块加密，只要出现密文或`iv`和某些东西异或得到明文，那么我们就可以通过修改密文或者`iv`使得在不破解黑盒(AES或其它块加密)的情况下修改明文，使得明文变成我们想要的结果。

**适用分组模式**：CBC，CTR等。
例子：
![CBC_BitFlipping](crypto/images/CBC_BitFlipping.png)


##### The Padding Oracle Attack
程序中有Padding相关的判断条件返回的时候，我们可以构造出相应的密文给oracle，（可能是构造padding让oracle作判断）。oracle然后根据构造的明文padding返回对应的结构。

**攻击原理：** 本质上是BitFlipping的一种。根据CBC或者其它填充模式，通过改变iv或者改变某些密文，使得我们需要的位置构造成我们需要的信息（比如使得明文等于padding，或者使得明文等于串字符串。）

参考资料：[The Padding Oracle Attack](https://robertheaton.com/2013/07/29/padding-oracle-attack/)



##### CRIME Attack 
全称：Compression Ratio Info-Leak Mass Exploitation
适用于AES—CTR模式，并且给出了Encrypt oracle，并且oracle中有对明文的压缩函数。这个时候才能使用。我们可以对明文进行单byte填充来猜测明文某个byte的值，然后如果猜中了那么加密的结果会比没有猜中的结果要短。

一般在HTTPS或者TLS/SSL中会对明文进行压缩，并使用AES-CRT模式，此时如果给出encrypt oracle则可以用这种攻击。

* 参考资料
  * [crime attack](https://shainer.github.io/crypto/2017/01/02/crime-attack.html)
  * [crypto-attack](https://github.com/jvdsn/crypto-attacks/blob/c26872bdac2e2d95c5be00e6e593c891c849f446/attacks/ctr/crime.py)

##### Separator Oracle Attack
适用于AES—CTR模式，
攻击原理：分隔符预言攻击是一种自适应选择密文攻击。 攻击者将修改后的密文发送到预言机。 分隔符是一个特殊字符，例如 `;` 或`|`。如果未使用密文/明文中正确数量的分隔符，则分隔符 oracle 将引发 SeparatorException，或者返回false。

* 参考资料
  * [Separator Oracle Attack](https://github.com/mprechtl/separator-oracle)
  * [crypto-attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ctr/separator_oracle.py)



##### 差分攻击
差分攻击一般应用于块加密函数中非线性函数（比如说s盒或某些轮函数）设计缺陷导致差分信息较为明显，从而构造相应的输入对密码系统进行攻击。一般来说是选择明文攻击。

差分攻击适用许多块加密系统如DES, Blowfish, FEAL, and RC5

* AES的差分攻击可见密码学课本
* 对FEAL的攻击见http://www.theamazingking.com/crypto-feal.php

对于没有线性变换（行移位，列混合等）的密码方案攻击会相对简单。

攻击流程：
1. 首先寻找非线性函数中最明显的差分信息。代码：
    ```python
    def find_differential():
        for i in range(0x10000):
            diffs = {}
            for j in range(0x100):
                input1 = random.randint(0, 0xffff)
                input2 = input1 ^ i
                output1 = f(input1)
                output2 = f(input2)
                diff = output1 ^ output2
                if diff in diffs.keys():
                    diffs[diff] += 1
                else:
                    diffs[diff] = 1
            for k in diffs.keys():
                if diffs[k] >= 60:
                    print(hex(i)[2:], hex(k)[2:], diffs[k])
    ```
    这里的f就表示非线性函数，代码找出的是输出差分大于等于1/4的所有输入差分。
2. 在没有线性变换的情况下，以FEAL-4加密为例，其加密过程如下：
    ![](crypto/images/crypto-feal2.jfif)
    在FEAL-4加密的过程中，轮函数在差分输入为0x8080的情况下输出差分一定为0x400。即对于轮函数$f$，给定两个输入$in_1$，$in_2$其中 $in_1 = in_2 \oplus 0x8080$，则必有$f(in_1) = f(in_2) \oplus 0x400$。
3. 每一轮加密只是一边的输入异或轮密钥后再经过轮函数f得到输出。攻击从最后一轮密钥开始进行攻击。其中有一点很重要的是**非线性函数的输入的差分不确定的情况下和输出的差分一般是均匀分布。** 因此在攻击是时候已知轮函数f输出，在轮密钥交小的情况暴力破解轮密钥模拟输入，如果轮函数f的模拟的输入的结果的差分和已知输出的差分一致，则当前轮密钥就是一个候选密钥。
4. 得到上一轮的候选密钥就可以构造当前这一轮的轮函数f的输出，然后再暴力枚举轮密钥进行当前密钥的破解。以这样就能得到第二轮之后的轮密钥。
5. 第一轮的轮密钥可能情况比较的多，而且也不一定需要用到差分性质，需要根据实际情况进行攻击。

例题见`crypto\2021_TianYiBei\2021_TianYiBei_MyCipher`








## 非对称密码

![](crypto/images/RSA_theory.PNG)

## RSA
***TITLE:***

0. 实用工具
1. 分解大整数N
2. 基本攻击
3. 小解密指数攻击
4. 小公钥指数攻击(Coppersmith's Theorem)
5. 选择明密文攻击
6. 侧信道攻击
7. 基于具体RSA实现的攻击
8. 实用工具

***RSA Reference***：
1.  Boneh D . **Twenty Years of Attacks on the RSA Cryptosystem**[J]. Notices of the Ams, 2002, 46.
2. D. Boneh and G. Durfee. **New results on cryptanalysis of low private exponent RSA**[J]. Preprint, 1998.
3. Howgrave-Graham N , Seifert J P . **Extending Wiener's Attack in the Presence of Many Decrypting Exponents**[M] Secure Networking — CQRE [Secure] ’ 99. Springer Berlin Heidelberg, 1999.
4. Cao Z , Sha Q , Fan X . **Adleman-Manders-Miller Root Extraction Method Revisited**[J]. 2011.
5. Nagaraj S V . Cryptanalysis of RSA and its variants[M]. Computing Reviews, 2010, 51(7) http://index-of.es/Varios-2/Cryptanalysis%20of%20RSA%20and%20It's%20Variants.pdf

* 第5个参考文献集成了大部分的RSA的攻击，都可以当作工具使用。

#### 零、实用工具
* RSA工具集-openssl,rsatool,RsaCtfTool
参考：https://www.jianshu.com/p/c945b0f0de0a
    * openssl可以实现：秘钥证书管理、对称加密和非对称加密。一般来说Windows有自带的，Ubuntu中apt可以方便地下载。
    * 根据给定的两个素数（p，q）或模数和私有指数（n，d）来计算RSA（p，q，n，d，e）和RSA-CRT（dP，dQ，qInv）参数。 https://github.com/ius/rsatool
    * RsaCtfTool:RSA多重攻击工具，从弱公钥解密数据并尝试恢复私钥针对给定的公钥自动选择最佳攻击。 https://github.com/Ganapati/RsaCtfTool

* **Sagemath9.2**: Sage是免费的、开源的数学软件，支持代数、几何、数论、密码学、数值计算和相关领域的研究和教学。Sage的开发模式和Sage本身的技术都非常强调开放性、社区性、合作性和协作性：我们在制造汽车，而不是重新发明轮子。Sage的总体目标是为Maple、Mathematica、Magma和MATLAB创建一个可行的、免费的、开源的替代品。
    * 入门中文文档：https://www.osgeo.cn/sagemath/tutorial/index.html
    * Reference：https://doc.sagemath.org/html/en/reference/index.html
    * 官方网站：https://www.sagemath.org/
    * 简单使用：Windows上Sagemath安装完成后，运行``SageMath 9.2 Notebook``文件，然后会打开Jupyter Notebook，在里面进行编程即可。
    * SageMath常用函数：https://blog.csdn.net/weixin_44338712/article/details/105320810
    * 常用函数及文档：
      * `discrete_log`:在`Modules`文档中 https://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html#sage.groups.generic.discrete_log
    * 常见使用文档：见`crypto/Sagemath_Usage.md`

* Crypto常用的python库
    * gmpy2 (pip 一般不能直接安装，要在网上下载.whl文件然后用pip进行安装)
    * Crypto (安装命令``pip install pycryptodome``)

* [crypto-attack](https://github.com/jvdsn/crypto-attacks/tree/master)
  * 一个常用的整理好了的各种各样的攻击，里面有着非常详细的sagemath代码


#### 一、分解大整数N
目前最快的分解大整数$N$的方法是广义数域筛法(General Number Field Sieve)。对于n-bit的整数，时间为$O(exp((c+o(1))n^{\frac{1}{3}}log^{\frac{2}{3}}n))$

另一种分解大整数的方法：已知私钥$d$，和公钥$e$，则可快速对$N$进行分解。反之亦然，即已知$N$的分解$N=pq$，则可以快速恢复出$d$。

* 常见大整数$N$分解工具：
    * yafu (p,q相差过大或过小yafu可分解成功)，一般来说在300bit以下的$N$都能在1小时内分解
    * http://www.factordb.com   (**可能出题人会把分解的结果放在这里，然后就能直接查到**)
    * cado-nfs 一般来说600bit以下的$N$都能在1天以内分解

##### 1.1 已知 $(N, e, d)$ 求 $(p, q)$ V1
* 攻击条件，$e$或$d$足够小
* 攻击原理：$ed-1=k\varphi(N)$。因为$e$或$d$比较小，然后$\varphi(N)$与$N$比较接近，因此爆破$k$，从而找到$\varphi(N)$。**但是实际上求解$\varphi(N)$是非常困难的，只有少数特殊情况能求解**。然后由$$N=pq \newline \varphi(N)=(p-1)(q-1)$$得$$N-\varphi(N)+1=p+q$$接下来构造方程$$x^2-(N-\varphi(N)+1)x+N=(x-p)(x-q)=0 \tag{1.1}$$只需要解方程$(1.1)$就可以把$p$和$q$解出来。

* 代码参考 https://blog.csdn.net/ayang1986/article/details/112714749
* ***具体python2代码见``crypto/code/Known_ed_factor_N_V1.py``*** 
**注意：代码中那种爆破$k$求解出$\varphi(N)$的方法实际上需要$e$或$d$非常的小，而且足够小了也不一定能用上。因此这里最好仅仅是作为一种已知$\varphi(N)$求解$p,q$的方案。**

##### 1.2 已知 $(N, e, d)$ 求 $(p, q)$ V2
* 没有攻击条件的限制
* 分解原理：
![](crypto/images/RSA_Factor_N.PNG)

参考书籍：**密码学原理与实践(第三版)** 作者：**冯登国**
* 关键定理：
**定理1.2.1：** 假定$p$为一个奇素数，$a$为一个正整数,$x$为一个数，且$gcd(x,p)=1$。那么同余方程$y^2\equiv x(mod\ p^a)$当$(\frac{a}{p})=-1$时没有解，当$(\frac{a}{p})=1$时有两个解$(mod\ p^a)$。
**定理1.2.2：** 假定$n>1$时一个奇数，且有如下分解$$n=\prod_{i=1}^{l}p_i^{a_i}$$其中$p_i$为不同的素数，且$a_i$为正整数。进一步假定$gcd(x,n)=1$。那么同于方程$y^2\equiv x(mod\ n)$当$(\frac{a}{p_i})=1$对于所有的$i\in\{1,...,l\}$成立时有$2^l$个模$n$的解，其它情况无解。

由定理1.2.2可知，$N=pq$对于方程$x^2\equiv 1\ mod\ N$有4个解。展开可得$$x\equiv\pm1\ mod\ p \newline x\equiv\pm1\ mod\ q$$其中$\pm1\ mod\ N$为平凡平方根。另外两个根称为非平凡平方根。而对于非平凡平方根，是由$$x\equiv1\ mod\ p \newline x\equiv-1\ mod\ q$$和$$x\equiv-1\ mod\ p \newline x\equiv1\ mod\ q$$所生成的。因此如果我们找到了$1\ mod\ N$的非平凡平方根$x$，那么我们就可以通过计算$gcd(x+1,N)$和$gcd(x-1,N)$来分解$N$。因为非平凡平方根满足$x\equiv\pm1\ mod\ p$。然后通过下方代码是算法能够以$\frac{1}{2}$的概率分解$N$。具体证明过程见参考书籍中的P159~P161。或者参考：https://www.cnblogs.com/jcchan/p/8430904.html

* 代码参考 https://blog.csdn.net/ayang1986/article/details/112714749
* ***具体python2代码见``crypto/code/Known_ed_factor_N_V2.py``***
* 快速的做法
    ```python
    RSA.construct(x.n, x.e, x.d)    # 可以通过这个函数来分解n得到p和q
    ```

##### 1.3 Pollard $p-1$
* 攻击前提：$p-1$或者$q-1$只有小的素因子，假设其素因子都不大于$B$。
* 攻击原理：这种情况下必然有  $$(p-1)|B!$$  因此有$2^{p-1} | 2^{B!}$。 令$a=2$， 因为$a^{p-1}\equiv 1\ mod\ p$， 因此有$a^{B!}\equiv 1\ mod\ n$。则有$$2^{B!}-1 = kp,$$因此只要计算$gcd(2^{B!}-1, n) = p$。

##### 1.4 William $p+1$
攻击条件与1.3节的相同这里直接给出代码。
* 代码参考 https://0xdktb.top/2020/02/28/Summary-of-Crypto-in-CTF-RSA/
* ***具体python2代码见``crypto/code/William_p_plus_1.py``*** 

**理论上1.3和1.4节的整数的分解使用大数分解工具都能进行分解。**

##### 1.5 Batch GCD
在得知 **成千上万对rsa的公钥$N$** 的时候，有可能会出现某些私钥$p,q$相同的情况，这个时候就可以使用gcd来求出私钥$N$。但是直接对两两的$N$求最大公约数会非常的耗时。因此使用Batch GCD的方法可以快速求出每个$N$关于其它所有$N$的公约数，即可以求出      $$\exists i, gcd(N_0,N_i)\neq 0$$ 参考：
* https://github.com/therealmik/batchgcd
* https://protonmail.com/blog/batch-gcd/
* https://facthacks.cr.yp.to/batchgcd.html
* https://windowsontheory.org/2012/05/15/979/

例题见`crypto\2021_RCTF\2021_RCTF_Uncommon_Factors_I`


##### 1.6 已知$(N,p,q,m,c)$ 求 $d$
本质上是求解离散对数问题。使用Pohlig-Hellman方法求出$dp$和$dq$，然后变成2.5节中的已知$dp,dq$用中国剩余定理求出$d$。

这里其中一个难点在于当$p,q$比较大的时候，$p-1$和$q-1$将会有比较大的素因子$p_i$，此时要求$g^{d\ mod\ p_i}\ mod\ p$一般来说会用Pollard rho这些$O(\sqrt{p_i})$的算法。但是此时会求不出来。

这里可以使用离散对数的数域筛(Number Field Sieve)算法，见离散对数数域筛算法。

参考题目：https://zhuanlan.zhihu.com/p/428567414


##### 1.7 Complex multiplication (elliptic curve) factorization
* **攻击条件**：$N=pq$满足，$4p-1=Ds^2$，其中$D$是非平方剩余。且$D\equiv 3\ (mod\ 8)$，当$D=3$时有更简单的解法。
* **攻击原理**：通过把系数摸$p$，映射 $\mathbb{Z}_n \longrightarrow^{(mod\ p)} \mathbb{F}_p$ 诱导出同态映射 $E(\mathbb{Z}_n) \longrightarrow E(\mathbb{F}_p)$
* **攻击步骤**：简单版
  1.  选择曲线$E(\mathbb{Z}_n)$
  2.  选择随机点$P\in E(\mathbb{Z}_n)$
  3.  计算点$mP = (\frac{\phi_m(P)}{\psi_m(P)^2}, \frac{\omega_m(P)}{\psi_m^3(P)})$,其中$\phi_m(P),\psi_m(P),\omega_m(P)\in \mathbb{Z}_n$
  4.  计算$gcd(\psi_m(P), N)$

Cheng的$4p-1$方法构造了一条anomalous曲线，并在计算点$mP$的时候用了complex multiplication (CM) method。具体见参考资料。

* 参考资料
  * [Sedlacek V. et al., "I want to break square-free: The 4p - 1 factorization method and its RSA backdoor viability"](https://www.researchgate.net/publication/335162606)
  * [crypto-attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/complex_multiplication.py)





#### 二、基本攻击
##### 2.1. N不互素
给定两个N1，N2，若不互素，则其gcd(N1,N2)就是其中一个p或q。因此直接被破解。

##### 2.2 共模攻击(Common Modules)
当两个用户使用相同的模数 N、不同的私钥时，加密同一明文消息M，此时可以使用此攻击。
设两个用户的公钥分别为$e_1$和$e_2$，且两者互质。明文消息为$m$，密文分别为
$$
c_1 = m^{e_1}\ mod \ N \newline 
c_2 = m^{e_2}\ mod \ N
$$
截获$c_1和c_2$后，计算$re_1+se_2=1\ mod \ n$中的$r$和$s$，则$m^{re_1+se_2}\ mod\ n\equiv m\ mod\ n$

##### 2.3 盲化攻击(Blinding)
Bob有私钥<N,d>，公钥<N,e>。敌手Alice想要Bob对M进行签名，但是Bob不会对M签名。于是Alice计算$M'=r^eM\ mod\ N$。然后Bob就会对M'进行签名得到S'，则有$$S'=r^{ed}M^d\ mod\ N = rM^d\ mod\ N$$因此$$S=S'/r\ mod\ N=M^d\ mod\ N$$。

##### 2.4 已知$dp\equiv d\ mod\ (p-1)$
已知$$d_p\equiv d\ mod\ (p-1)\newline ed\equiv 1\ mod\ (p-1)(q-1)$$有$$d_p=k(p-1)+d \newline ed=k'(p-1)(q-1)+1$$则有$$ed_p-1=(p-1)(ek+k'(q-1))$$因为$$0\leq ed_p-1\leq ep$$因此$$0\leq (p-1)(ek+k'(q-1))\leq ep \newline 0\leq (ek+k'(q-1))\leq e+1$$因此遍历$i\in[0,e]$若发现$N$能被$(ed_p-1)/i+1$整除，则$p=(ed_p-1)/i+1$。

参考例子：
```python
e= 65537
n = 
c = 
dp = 
for i in range(1,e+1):
    if (dp*e-1)%i == 0:
        if n%(((dp*e-1)/i)+1)==0:
            p=((dp*e-1)/i)+1
            q=n/(((dp*e-1)/i)+1)
            phi = (p-1)*(q-1)
            d = gmpy2.invert(e,phi)%phi
            m = pow(c,d,n)
            print(long_to_bytes(m))
```

##### 2.5 已知$N,e,dp,dq,p,q$的RSA快速解密

* 在RSA中$dp,dq$被称为 “private CRT-exponents”，在搜论文的时候可以用这个关键词进行搜索，或者搜“RSA-CRT”。

在参数很大的时候比如$N$是2048或4096比特的时候计算$m\equiv c^d\ mod\ N$计算量非常的大。因此给定$$dp\equiv d\ mod\ p$$和$$dq\equiv d\ mod\ q$$以及$p,q$，可以更快地进行解密。

* 原理：已知$$c\equiv m\ mod\ N \\ m\equiv c^d\ mod\ N\\ dp\equiv d\ mod\ (p-1)\\ dq\equiv d\ mod\ (q-1)$$
    1. 由中国剩余定理可知$$m_1\equiv c^d\ mod\ p\\ m_2\equiv c^d\ mod\ q$$
    2. 记$c^d=kp+m_1$，则有$$(m_2-m_1)p^{-1}\equiv k\ mod\ q$$把本步的两个公式合并得到$$m\equiv c^d \equiv ((m_2-m_1)p^{-1}\ mod\ q)p+m_1 \ mod\ N$$
    3. 由1中式可得$$m_1\equiv c^d\equiv c^{dp}\ mod\ p\\ m_2\equiv c^d\equiv c^{dq}\ mod\ q$$ 此时$m_1,m_2,p,q$都是已知的，因此可以计算出$m$
* 参考代码
    ```python
    InvQ = gmpy2.invert(q, p)
    mp = pow(enc, dp, p)
    mq = pow(enc, dq, q)
    m = (((mp - mq) * InvQ) % p) * q + mq
    print(long_to_bytes(m))
    ```
    实际上打比赛的过程中，如果知道了$p,q$直接计算$\phi(N)$就行，没必要用这种方法。


##### 2.6 小公钥指数攻击 （非Coppersmith）
***本质上是当公钥指数较小$e\leq 5$，把问题变成求解$f(x)\equiv 0\ mod\ N$的问题，其中$f(x)=\sum_{i=0}^{e} a_ix^i，a_i\in Z_N$。主要应用场景在e很小，方程的根比较小的情况。***
###### 2.6.1 Hastad的广播攻击
假设$e=3$，并且加密者使用了三个不同的模数$n_1,n_2,n_3$给三个不同的用户发送了加密后的消息$m$: $$c_1=m^3\ mod\ n_1 \newline 
c_2=m^3\ mod\ n_2 \newline 
c_3=m^3\ mod\ n_3$$
其中$n_1,n_2,n_3$不互素，$m < n_i$。
* 攻击方法：首先通过中国剩余定理得到$m^3\equiv C\ mod\ n_1n_2n_3$。因此只要对$C$开三次根就可以得到$m$的值。开根可以使用``SageMath``中的``iroot``函数。
    * 代码参考：https://github.com/yifeng-lee/RSA-In-CTF/blob/master/exp2.sage
    * ***具体Sagemath9.2代码见``crypto/code/Hastad_Broadcast_Attact.sage``***
* **拓展：** 具有线性填充的广播攻击也能通过Coppersmith's Theorem被攻破。(Coppersmith's Theorem见RSA第四部分)
* 因此广播攻击的避免方式可以使用随机填充(padding)


###### 2.6.2 Franklin-Reiter 相关信息攻击 Related message attack
(**Franklin-Reiter**)当 Alice 使用同一公钥对两个具有某种线性关系的消息 M1 与 M2 进行加密，并将加密后的消息 C1，C2 发送给了 Bob 时，我们就可能可以获得对应的消息 M1 与 M2。这里我们假设模数为 N，两者之间的线性关系为$M_1\equiv f(M_2)\ mod\ N，f=ax+b$。则此时可以比较容易地恢复出$M$。
* 方法：当$e=3$时，$C_1=M_1^e\ mod\ N$，则有$M_2$是$g_1(x) = f(x)^e - C_1\equiv 0\ mod\ N$的根，而且$M_2$也是$g_2(x)=x^e - C_2\equiv 0\ mod\ N$的根。如果$g_1,g_2$的最大公因子是线性的，那么$M_2 = gcd(g_1,g_2)$。
* 当$e>3$时，$g_1,g_2$不一定是线性的，此时无法用此方法求解。


###### 2.6.3 消息长度较短
* **攻击条件：** $e < 5, m^e \approx N$

    根据$m ^ e = kN + c$构造出$f = m^e - c\ (mod\ N)$，然后暴力枚举$k$，当$k < 2^{32}$时约半个小时能求解。 （Coppersmith是无法求解的,因为$m$仍然太大了）


##### 2.7 费马
* **攻击条件：** 当$p$和$q$非常接近的时候，大约$|p-q| < 10^9$。
* 直接对$N$开根号，然后暴力搜索$p$


##### 2.8 已知元素的阶
已知$a^s \equiv 1\ mod\ N$。遍历所有的$s$的因数$r$，则存在一个$r$，使得$a^{s/r}$一定是$p$或$q$的倍数。




#### 三、小解密指数攻击
##### 3.1 Wiener’s attack
* **Theorem 2 (M. WIener)：** 让$ N=pq, q<p<2q $，并且有$d<\frac{1}{3}N^{\frac{1}{4}}$。给定公钥<N,e>，则有一个有效的方法恢复出私钥d。

* 证明：此定理是基于连分数的近似。易得 $$|\frac{e}{\varphi(N)}-\frac{k}{d}|=\frac{1}{d\varphi(N)}$$ $$\varphi(N)=N-p-q+1 $$ $$
k < d <\frac{1}{3}N^{\frac{1}{4}}
$$ 因此有 $$
|\frac{e}{N}-\frac{k}{d}|\leq\frac{1}{2d^2}
$$ 根据![](crypto/images/Th2.2_Continued_Fraction.PNG)

可知$\frac{e}{N}$的**连分数的收敛式**中有一项为$\frac{k}{d}$。**连分数的收敛式(Convergent)** 的定义：记为$c_i$。令$n$表示连分数最多展开$n$层。即
$$
a=a_0+\frac{1}{a_1+\frac{1}{\ddots +\frac{1}{a_n}}}简写为a=[a_0;a_1,a_2,...,a_n]
$$
则连分数的收敛式$c_i$满足
$$\forall x\in[0,n],\ c_i=[a_0;a_1,...,a_i]$$ 
因此只需要对$\frac{e}{N}$进行连分数展开，找出满足 $$ed-1=0\ mod\ k \tag{3.1}$$ 的收敛式 $\frac{k}{d}$，即 $\exists i'\in[0,n],c_{i'}=\frac{k}{d}$ ，则 $$\phi(n)=\frac{ed-1}{k}$$ 可能会出现当$d$比较小的时候$(3.1)$式成立，因此需要进行特殊的判别。

* 避免此类攻击的方法
    * 选择比较大的公钥$e$，$e>1.5N$。[这样以来k就会变大]
    * 使用中国剩余定理设定两个私钥$d_p, d_q$，一个mod p一个 mod q,这样解密速度会变快，并且通过中国剩余定理恢复出来的d会很大。

Boneh and Durfee [D. Boneh and G. Durfee.New results on cryptanalysis of low private exponent RSA. Preprint, 1998.]等人提出当$d<N^{0.292}$时敌手也能快速恢复出私钥d。

* 3.1节代码参考 https://www.cnblogs.com/Guhongying/p/10145815.html

* ***具体python2代码见``crypto/code/Wieners_Attack.py``*** 在代码中给出$e,n$可恢复出私钥指数$d$。

* 一半来说，如果题目中出现$\frac{1}{3}N^{0.25}$，即使不是使用Wiener算法求解RSA，也可以用到**Theorem 2.2**中的连分数分解定理，从而求出某些值。例子见``crypto/2021_CSISC/RSA_ECC_2021_CSISC_move``。

##### 3.2 Extending Wiener's Attack

原理：对于同一个$N$，有$i, i>1$个公钥指数$e_i$，所有$e_i$所对应的私钥指数$d_i$都比较的小。此时可以使用Extending Wiener's Attack进行求解。下面给出当$i$比较小时$d_i$所取的范围。我们令$d_i< N^{\alpha}$，则$i$与$\alpha$的关系为(一般情况比较的复杂，这里只列举$i$比较小的情况)：
$i$|$\alpha$
:-:|:-:
2|$< 5/14-\epsilon'$
3|$< 2/5-\epsilon'$
4|$< 15/34-\epsilon'$

具体思路：令$$g = gcd(p-1,q-1)$$易得$$deg=k(p-1)(q-1)+g$$令$$s=1-p-q$$记方程$W_i$为$$e_id_ig-k_iN=g+k_is \tag{Wi}$$。对于两个公钥指数的情况，有$$e_1d_1-k_1\varphi(N)=1 \newline e_2d_2-k_2\varphi(N)=1$$上式乘$k_2$减去下式乘$k_1$得$$e_1d_1k_2-e_2d_2k_1=k_2-k_1 \tag{G(1,2)}$$计算可得$W_1W_2$同样也是一个等式。由式$$k_1k_2=k_1k_2 \newline W_1*k_2 \newline G_{(1,2)} \newline W_1*W_2 $$四个等式可以构造如下等式$$A*L_2=B_2$$其中$$A=(k_1k_2,d_1gk_2,d_2gk_1,d_1d_2g^2)$$
![](crypto/images/Extended_Wieners_Attack_L.PNG)
其中$L_2$矩阵都是已知的项构成的，我们可以把$L_2$看作一个格，然后$B_2$是其最短向量，使用**LLL定理**（见4.1节）可以求出其最短向量。而且若$B_2$为最短向量，则需要满足$||B_2||\leq \sqrt{n}det(L)^{\frac{1}{n}}$，即$$2N^{1+2\alpha}\leq 2N^{(\frac{13}{2}+\alpha)\frac{1}{4}}$$解得$\alpha\leq \frac{5}{14}$从而可以代入$M_2$中。(**编程实现的过程中可稍微缩小$\alpha$使得LLL算法必定有解**)求出最短向量$B_2$后，计算$B_2*L_2^{-1}$得到$A$。然后用a的前两项计算$$\frac{a[1]}{a[0]}e_1 = \frac{e_1d_1g}{k_1} = \varphi(N)$$从而把$\varphi(N)$恢复出来。

* 代码参考：https://blog.csdn.net/jcbx_/article/details/109306542
* ***具体Sagemath9.2代码见``crypto/code/Extended_Wieners_Attack.py``*** 在代码中提供$\alpha,e_1,e_2,n$可恢复出$\varphi(N)$


##### 3.3 一种RSA的广义攻击

* **参考文献：Bunder M , Nitaj A , Susilo W , et al. A generalized attack on RSA type cryptosystems[J]. Theoretical Computer Science, 2017:74-81.**

* 攻击条件：$q < p < 2q$，$ex-(p^2-1)(q^2-1)y=z$，其中正整数$x,y$互素。且有 $$xy < 2N - 4\sqrt{2} N^{0.75}\ and\ |z| < (p-q)N^{0.25}y$$ 可使用连分数与Coppersmith定理对$N$进行分解。

* 例子见参考文献
```python
# sagemath 9.2 
# 调试的时候small_roots函数的边界比较难调
from tqdm import tqdm

N = ZZ(204645825996541)
e = ZZ(26384989321053458213237)

def solve_pell (N, e):
    X = e/(N^2+1-9/4*N)
    cf = continued_fraction (X)
    PR.<xx> = PolynomialRing(Zmod(N))
    p_low = floor(N^(1/4) / (2 ^ 1))
    for i in tqdm(range (len(cf))):
        denom = cf . denominator ( i )
        numer = cf . numerator ( i )
        y, x = numer, denom
        if (y != 0):
            p_bar = 1/2 * ((abs((N+1)^2 - e*x/y))^(1/2) + (abs((N-1)^2 - e*x/y))^(1/2))
            p_bar = floor(p_bar)
            f = xx + p_bar

            sol = f.small_roots(X=p_low, beta=0.48, epsilon=0.03)
            if (len(sol) != 0):
                p = ZZ(f(sol[0]))
                print(p)

print(N.nbits())
print(e.nbits())
solve_pell(N, e)
```

##### 3.4 公有解密指数攻击(Common Private exponent)

* **参考文献：Ravva S K . Lattice Based Attack on Common Private Exponent RSA[J]. International Journal of Computer Science Issues, 2012, 9(2):28-31. http://ijcsi.org/papers/IJCSI-9-2-1-311-314.pdf**

* 攻击条件： 给出$r$对RSA的公钥$\{(e_1,N_1),...,(e_r,N_r)\}$，而且这$r$对RSA的私钥$d$是相同的。并且满足以下两个条件：
    1. $N_1 < N_2 < ... < N_r < 2N_1$
    2. $N_i$是稳定的，既若$\phi(N_i) = N_i - s_i$，则$|s_i| < 3N_i^{0.5}$
    3. $d < N_r^{\sigma_r}$ 其中 $\sigma_r < \frac{1}{2} - \frac{1}{2(r+1)} - log_{N_r}\sigma_r$

* 攻击原理：有方程 $$e_id = 1 + k_i\phi(N_i),$$ 则有 $$e_id - N_ik_i = 1 - k_is_i$$ 进而构造$r+1$个方程 $$x_rB_r=V_r$$ 其中 $$x_r =(d,k_1,k_2,...,k_r) \\ $$$$B_r = \left[\begin{matrix} 
M & e_1 & e_2 & \cdots & e_r \\
0 & -N_1 & 0 & \cdots & 0 \\
0 & 0 & -N_2 & \cdots & 0 \\
\vdots & \vdots & \vdots & \ddots & \vdots \\
0 & 0 & 0 & \cdots& -N_r
\end{matrix}\right] \\ V_r = (dM, 1-k_1s_1 ,..., 1-k_rs_r)$$ 其中$M = \lfloor N_r^{0.5} \rfloor$.

* 参数确定：首先可以根据给出的公钥确定$r$的取值，一般来说如果随机生成的话去20就足够了。

* 攻击例子见参考文献

* 参考代码: `crypto/code/Common_Private_Exponent_RSA.sage`







#### 四、Coppersmith's Theore

1996年，Coppersmith 提出了一种针对于模多项式（单变量，二元变量）找所有小整数根的多项式时间的方法。然后后面许多工作都围绕着这方面来进行（多元变量，界的提升等）。因此说到Coppersmith，指的就是找出**模多项式（单变量，二元变量）的所有小整数根**。



* **Theorem 3 (Coppersmith)：** $N$是整数，$f\in Z[x]$是度数为$d$的首一多项式。令$X=N^{\frac{1}{d}-\epsilon}$（$X$是实数）。则给定$N,f$，敌手可以快速找出所有的整数$\{x_0|\ \ |x_0|<X\ 且\ f(x_0)\equiv 0\ mod\ N\}$。运行时间为运行**LLL**算法所花费的时间，记为$O(w), w=min(1/\epsilon,log_2 N)$。 **需要认清本质上是一种格的算法，很多解法都是可以通过构造格来进行实现的。**
<!-- * **Coppersmith方法**主要通过找到与$f\ mod\ N$有 **(1.相同根 2.系数为整数域 3.系数更小)** 性质的多项式$g$，从而找出$g$的根(因为容易找出整数域上的多项式根)
    * $f到g$的转换方式：预定义一个整数m，定义$$g_{u,v}(x)=N^{m-v}x^uf(x)^v$$。因此$x_0$是$g_{u,v}(x)\ mod\ N^m$的一个根，其中$u\geq 且0\leq x_0\leq m$与此同时有$f(x_0)\equiv 0\ mod\ N$
    * 因此我们可以找到一组$g_{u,v}$的线性组合$h(x)$，满足$h(xX)$有小于$N^m$的范式(根)，其中$X$是$x_0$中满足$X<N^{\frac{1}{d}}$的上界。只要m足够大，那么一定能找到这样的$h(x)$。**此时表示我们找到了这样的$h(x)$，它在整数中有同样的根$x_0$**。

**$h(x)$的寻找方法**
* 定义$h(x)=\sum a_ix^i \in Z[x]$，则$\|h(x)\| = \sum a_i$
* **Lemma 4 (Howgrave-Graham)：** Let $h(x)\in Z[x]$ be a polynomial of degree $dg$ and let $X$ be a positive integer. Suppose $\|h(xX)\| < N/\sqrt{dg}$. If $|x_0| < X$ satisfies $h(x_0)=0\ mod\ N$, then $h(x_0)=0$ holds over the integer.（$h(x_0)=0$在整数上成立）
    * 首先我们把多项式$g_{u,v}(xX)$作为向量，并记格$L$是由它所生成的。固定一个m，我们就可以写出格$L$的表达式，形如下图。其中带``*``号的表示非0系数，空的位置代表0。下图是当$m=3,dg=2$时所构造出的格$L$。
    ![格L](crypto/images/lattice_L.PNG)
    * 通过**LLL定理**，可以找出格L中的一个向量$v\in L$，满足$\|v\|\leq 2^{w/4}det(L)^{1/w}$，w表示格的维数。接下来需要证明：$2^{w/4}det(L)^{1/w} < N^m/\sqrt{w}，其中w=dg(m+1)$。当m足够大的时候，上式可以被满足。因此通过LLL定理找出的向量$v$就是所求的$h(x)$。
    * 参数的确定:当由$X=N^{\frac{1}{dg}-\epsilon}$时，有$m=O(k/dg)，k=min(\frac{1}{\epsilon},log\ N)$

**LLL定理：** Let L be a lattice spanned by $<u_1,...,u_w>$. When $<u_1,...,u_w>$ are given as input, then the LLL algorithm outputs a point $v\in L$ satisfying $$\|v\|\leq 2^{w/4}det(L)^{1/w}$$ LLL的运行时间是输入长度$w$的四次方。 -->
* **Coppersmith定理所使用的攻击方法一般都被写在了``Magma``的``SmallRoots``函数中，以及``SageMath``的``small_root``函数中。**
* 详细实现过程参考：https://github.com/mimoo/RSA-and-LLL-attacks
* 参考文献： 
  * Wong D. Survey: Lattice Reduction Attacks on RSA. 
  * [Don Coppersmith. Small Solutions to Polynomial Equations, and Low Exponent RSA Vulnerabilities](https://link.springer.com/content/pdf/10.1007/s001459900030.pdf)
  * [Using LLL-Reduction for Solving RSA and Factorization Problems 相对简单的攻击](https://www.cits.ruhr-uni-bochum.de/imperia/md/content/may/paper/lll.pdf)

* [crypto-attack](https://github.com/jvdsn/crypto-attacks/tree/master/shared/small_roots) 这里面封装了各种Coppersmith方法的通用方法，比如在构建好多项式$h,g$后需要构造格，LLL算法，恢复多项式，用（Groebner基、resultant、variety(三角分解)）求根等。在`attacks/factorization`目录下的每个攻击几乎都用到了这些通用的方法。

* 无论是单变元还是多变元的Coppersmith方法，其本质都是构造多项式，构造矩阵，LLL，然后求根。关键在于界应该要怎么取，参数应该怎么调。因为本质上都是LLL算法的界，通过LLL算法的界和构造的矩阵反推出各个变元的界，从而判断当前的方法是否适用。


- **一些Coppersmith方法**
  - Coron Method 
    - [Finding Small Roots of Bivariate Integer Polynomial Equations Revisited](https://link.springer.com/content/pdf/10.1007/978-3-540-24676-3_29.pdf)
    - [crypto-attack](https://github.com/jvdsn/crypto-attacks/blob/master/shared/small_roots/coron.py)
  - Coron Method (Direct)
    - [Finding Small Roots of Bivariate Integer Polynomial Equations: a Direct Approach](https://link.springer.com/content/pdf/10.1007/978-3-540-74143-5_21.pdf)
    - [crypto-attack](https://github.com/jvdsn/crypto-attacks/blob/master/shared/small_roots/coron_direct.py)
  - Ernst Method 见4.3.4节
  - Herrmann-May method (unravelled linearization) 经典的Boneh and Durfee, 可见4.4.2节
  - Herrmann-May method (modular multivariate) 见4.2.4节 
  - Howgrave-Graham method 见4.2.3节 
  - Jochemsz-May method (Common Prime GCD with small $d$)
    - [A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants](https://link.springer.com/content/pdf/10.1007/11935230_18.pdf)
    - [crypto-attack Jochemsz-May method (modular roots)](https://github.com/jvdsn/crypto-attacks/blob/master/shared/small_roots/jochemsz_may_modular.py)
    - [crypto-attack Jochemsz-May method (integer roots)](https://github.com/jvdsn/crypto-attacks/blob/master/shared/small_roots/jochemsz_may_integer.py)
  - Nitaj-Fouotsa method
    - [A New Attack on RSA and Demytko's Elliptic Curve Cryptosystem](https://eprint.iacr.org/2019/1050.pdf)
    - [crypto-attack Nitaj-Fouotsa](https://github.com/jvdsn/crypto-attacks/blob/master/shared/small_roots/nitaj_fouotsa.py)




##### 4.1 小公钥指数攻击（Coppersmith）

###### 4.1.1 Coppersmith’s short-pad attack （短填充攻击）
假设N长度为n，令$m=\lfloor n/e^2\rfloor$，加密消息M的长度不超过(n-m) bits。若有$$M_1=2^mM+r_1 \newline M_2=2^mM+r_2$$$0\leq r_1,r_2\leq 2^m$是不同的整数，则若知道$e,M_1,M_2,C_1,C_2$，容易恢复出M。
* 令$$g_1(x,y)=x^e-C_1 \newline g_2(x,y) = (x+y)^e-C_2$$ 
其中$y=r_2-r_1$，则$M_1$是两个方程的根。因此有$M_1=gcd(g_1(x,y),g_2(x,y))$，过程：

![Coppersmith短填充攻击](crypto/images/Coppersmith_ShortPadAttack.PNG)
* **攻击条件**：$\Delta < 2^m < N^{1/e^2}$ ，可以使用此攻击。可见这时$e<5$。

###### 4.1.2 Known High Bits Message Attack(已知高比特信息攻击) 

> Stereotyped message attack
    
* 已知$C\equiv m^e\ mod\ N$，假设已知很大一部分$m_0$,则有$C\equiv(m_0+x)^e\ mod\ N$。直接使用Coppersmith定理求解$x$，但记得其中的$x$需要满足Coppersmith定理中的约束，即$x < N^{1/e}$，可见这里的$e<5$。

* ***具体Magma代码见``crypto/code/Known_High_Bits_Message_Attack.m``***



##### 4.2 Factoring with High Bits Known(已知高比特分解) $p,q$
已知$p$或$q$中其中一个数的高位比特，我们就有一定几率来分解 $N$。
**这里的原理就是Theorem 10，但是原理的具体流程没有找到。这里只是使用现成的代码能做到已知p的高比特部分，代码运行之后能得到相应的$p$。**
原理则是求解$x+p_{fake}\equiv 0\ mod\ Factor(N)$，Sage里面恰好有这样的一个函数，可以直接使用。
* 攻击要求：一般来说需要需要已知bit最少需要占据所有bit的**56%**，然后$p$需要满足$p \geq N^{\beta}$，一般有$0.4\leq \beta\leq 0.5$。**而且这里的$p$不一定是素数，可以是$N$的某些因数的乘积。**

* 代码参考：https://github.com/yifeng-lee/RSA-In-CTF/blob/master/exp6.sage
* ***具体Sagemath9.2代码见``crypto/code/Factoring_with_High_Bits_Known.py``***

###### 4.2.2 Improve Factoring with High Bits Konwn
这里是4.2节的变种，就是现在已知$p$或$q$的高位比特和低位比特，只有中间的bit不知道，而且高位bit和低位bit占所有bit的56%或以上。如果不足则可以暴力枚举某些比特使得已知比特的数量大于56%，从而实用该攻击
* 攻击原理：求解$$2^lx + p_{low} + p_{high} \equiv 0\ mod\ N$$ 同样是使用sagemath中的`small_root`函数。就是需要加上`f = f.monic()`一句保证多项式`f`是首一的。

###### 4.2.3 Coppersmith univariate
这里是最基础的Coppersmith，Sagemath中的`small_roots`函数就是根据03年的文章进行实现的，只支持单变元的函数。求解的方法参考论文和代码。

* **Theorem 10 (Coppersmith)**：已知$N=pq$，已知一个模数$b\geq N^{\beta}$，令$f_b(x)=0\ mod\ b$，$f_b(x)$是一元的首一多项式且其度数为$\delta$，则我们可以找到所有的满足$|x_0|\leq c_NN^{\frac{\beta^2}{\delta}}$
* 当$b=N^{0.5}, \delta = 0.25, c_N = 2$时，定理10就编程了定理11。
* **Theorem 11 (Factor known p MSB)** $N=pq$，$N$为$n$比特。给出私钥$p$的高或低$n/4$比特，那么可以快速分解$N$。
* 参考资料：
  * [May A., "New RSA Vulnerabilities Using Lattice Reduction Methods" (Section 3.2)](https://www.researchgate.net/publication/36147050_New_RSA_vulnerabilities_using_lattice_reduction_methods)
  * [crypto-attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/coppersmith.py)


###### 4.2.4 Coppersmith multivariate
Coppersmith也能推广到多变元上去，详细算法见论文和代码，原理都是差不多，相当于是给定一个多变元的模多项式$f_b(x_1,x_2,...,x_n) = 0\ mod\ b$，$b\geq N^P{\beta}$，其中$|x_1|\leq N^{\gamma_1},...,|x_n|\leq N^{\gamma_n}$，如果有 $$ \sum_i^n\gamma_i\leq 1-(1-\beta)^{\frac{n+1}{n}}-(n+1)(1-\sqrt[n]{1-\beta}(1-\beta)-\epsilon$$ 则可以求出$f_b(x_1,x_2,...,x_n)$ 的所有小根。

* 参考资料：
  * [Herrmann M., May A., "Solving Linear Equations Modulo Divisors: On Factoring Given Any Bits" (Section 3 and 4)](https://link.springer.com/content/pdf/10.1007%2F978-3-540-89255-7_25.pdf)
  * [crypto-attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/coppersmith.py)


##### 4.3 Partial Key Exposure attack （部分密钥泄露攻击）
###### 4.3.1 n/4个$d$的最低有效位
* **攻击条件：** $e<65537$
* **Theorem 9 (BDF)：** 给定私钥<$N,d$>，$N$长为$n$比特，并给出私钥$d$的$\lceil n/4\rceil$位最低有效位(即$d$的低位)，那么可以在时间$O(elog_2\ e)$中恢复出$d$。


**原理：** 首先已知$ed-k(N-p-q+1)=1$，因为$d<\varphi(N)$，所以有$0< k\leq e$。然后又因为$q=N/p$。则有$$(ed)p-kp(N-p+1)+kN=p\ mod\ (2^{n/4})$$因为敌手Marvin得到了$d$的$n/4$个最低有效位$d_0$，所以他知道$ed\equiv ed_0\ mod\ 2^{n/4}$。因此，他得到了一个关于$k$和$p$的方程。对于$k$的每一个可能的值$[0,e]$，求解关于$p$的二次方程$$(ed_0)x-kx(N-x+1)+kN=x\ mod\ (2^{n/4})$$得到一些$p$的候选值$x\ mod\ 2^{n/4}$。对于每一个候选值，执行定理11的算法(**4.2.3节**)去尝试分解$N$。可以看出，对于$p\ mod\ 2^{n/4}$的候选值的总数最多为$elog_2\ e$。因此，最多尝试$elog_2\ e$次后，$N$将被因式分解。然后就可以通过$e$和$\varphi (N)$求出私钥$d$。

* 代码参考：https://github.com/yifeng-lee/RSA-In-CTF/blob/master/exp8.sage
* ***具体Sagemath9.2代码见``crypto/code/Partial_Key_Exposure_attack.py``***


###### 4.3.2 Attack on Medium Exponent RSA
- **攻击条件1**：已知$t\in [\frac{n}{4},...,\frac{n}{2}]$，且有$2^t<e<2^{t+1}$且知道$e$的分解，并且直到私钥$d$的$t$位最高有效位(Most signanificant bits)，那么$N$可以被有效分解。
- **攻击原理1**：
  1. 令$$k' = (ed_0-1)/N \\ |e(d-d_0)| < c_1N \\ ed_0 < c_2N^{3/2}$$则有$$|k'-k| < 8c_2+2c_1$$ 因此通过暴力搜索可以找出$k$，其中$k$满足$ed-k\phi(N) = 1$.
  2. 计算$s\equiv N+1-k^{-1}\ (mod\ e)$，然后构造方程$x^2-sx+N=0\ (mod\ e)$，求出方程的根$x_0 = p$，因此已知$p$的低$t$比特。
  3. 通过 **4.2.3**节已知部分$p$攻击分解$N$。
- **攻击局限**：求解步骤2中的方程要么$e$是素数，要么需要知道$e$的分解。

- **攻击条件2**：在攻击条件1的情况下**不知道$e$的分解**。
- **攻击原理2**：见参考资料的4.2节定理8

- 参考资料
  - [Boneh D., Durfee G., Frankel Y., "An Attack on RSA Given a Small Fraction of the Private Key Bits"](https://link.springer.com/content/pdf/10.1007/3-540-49649-1_3.pdf)
  - [crypto-attack BDF](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/partial_key_exposure.py)


###### 4.3.3  MSBs Known: A Method for $e \in [N^{0.5} , N^{0.725}]$
- **攻击条件**：如果有$\alpha = log_N(e) \in [0.5, \frac{\sqrt{6}-1}{2}]$，已知$d$的最高有效位$d'$满足$$|d-d'| \leq N^{\frac{1}{8}(5-2\alpha-\sqrt{36\alpha^2+12\alpha-15}-\epsilon)}$$ 则$N$可以被分解。
- **攻击原理：**同样先猜测出大致的$k'$，然后列一个函数$f_N(x,y,z) = ex+(k'+y)z+ed'-1$，然后使用Coppersmith方法求解。

###### 4.3.4 已知私钥的LSB，且有$e < N^{0.875}$
- **攻击条件**：如果有$\alpha = log_N(e) < \frac{7}{8} $，已知$d$的最低有效位$d_0 = d\ mod\ M$，且有$$M\geq N^{\frac{1}{6}+\frac{1}{3}\sqrt{1+6\alpha}+\epsilon}$$ 则$N$可以被分解。
- **攻击原理**：同样是构造一个函数，然后使用Coppersmith方法求解。

- 4.3.3和4.3.4参考资料
  - [Blomer J., May A., "New Partial Key Exposure Attacks on RSA"](https://link.springer.com/content/pdf/10.1007/978-3-540-45146-4_2.pdf)
  - [crypto-attack BM](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/partial_key_exposure.py)



###### 4.3.5 paritial $d$ known with full size exponent

> 这里的攻击方案是4.3.3节的拓展，有着更高的界。都是构造拥有小根的多项式然后使用Coppersmith的方法进行求解。

- **攻击条件1 MSB small d**：令$n = log_2(e)$，$\beta n = log_2(d)$，给出$d$的$(\beta - \delta)n$位MSB，如果满足$$\delta\leq\frac{5}{6}-\frac{1}{3}\sqrt{1+6\beta} or \\ \delta\leq \frac{3}{16}-\epsilon\ and\ \beta\leq\frac{11}{16}$$则$N$能被分解。其中$0 < \delta < \beta < 1$.
- **攻击条件2 MSB small e**：令$n = log_2(d)$，$\alpha n = log_2(e)$，给出$d$的$(1 - \delta)n$位MSB，如果满足$$\delta\leq\frac{1}{3}+\frac{1}{3}\alpha-\frac{1}{3}\sqrt{4\alpha^2+2\alpha-2}-\epsilon$$ 则$N$能被分解，其中$0 < \delta < \frac{1}{2} < \alpha < 1$.
- **攻击条件3 LSB small d**：令$n = log_2(e)$，$\beta n = log_2(d)$，给出$d$的$(\beta - \delta)n$位LSB，如果满足$$\delta < \frac{5}{6}-\frac{1}{3}\sqrt{1+6\beta} - \epsilon$$ 则$N$能被分解，其中$0 < \delta < \beta < 1$.

- 参考资料：
  - [Ernst M. et al., "Partial Key Exposure Attacks on RSA Up to Full Size Exponents"](https://link.springer.com/content/pdf/10.1007/11426639_22.pdf)
  - [crypto-attack Ernst](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/partial_key_exposure.py)



##### 4.4 Boneh and Durfee attack （Coppersmith）
当 $d$ 较小时，满足 $d < N^{0.292}$ 时，我们可以利用该攻击，比 Wiener's Attack 要强一些。

* 注意：4.2~4.7节的公钥指数$e$都是非常小(一般为3)。而本节仅仅是私钥指数$d$比较的小，而一般假设$e$非常的大。

###### 4.4.1 攻击原理
假设$gcd(p-1, q-1)=2$，已知$\varphi(N)=N-p-q+1$，则有
$$ed\equiv 1\ mod\ \varphi(N)/2$$
$$ed+k(\frac{N+1}{2}-\frac{p+q}{2})=1$$
令$A=\frac{N+1}{2}, s=-\frac{p+q}{2}$，则有$$k(A+s)\equiv 1\ (mod\ e)$$
而且满足$|k|< e^{\delta}$以及$|s|< e^{0.5}$，其中$\delta < 0.292$
这里$k$和$s$是未知数，因此我们相当于求一个二元二次方程的解。这里用到的是**Coppersmith算法的广义的形式**。

* 代码参考：https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage
* ***具体Sagemath9.2代码见``crypto/code/boneh_and_durfee.sage``***

###### 4.4.2 拓展Coppersmith攻击
* 由于Coppersmith本质上是对多项式求小根，因此就出现了各种各样的多项式构造方式。
  * 若有$ed_pq = (k − 1)(N − q) + N$，此时$q,k$比较的小，从而构造$$f = x(N-y)+N\ mod\ e$$然后Coppersmith。 
    * 参考：[New Attacks on RSA with Small Secret CRT-Exponents](https://www.iacr.org/archive/pkc2006/39580001/39580001.pdf)
  * 若有$$f(x, y) = 1 + x(A + y) mod\ e$$ 一般有$X=N^{\delta}, Y = N^{0.5}, U = N^{\delta + 0.5}$，那么根据$det(L) \leq e^{m\ dim(L)}$推得$\delta\leq 0.5(2-\sqrt{2}) \approx 0.292$，这就是经典的Boneh and Durfee。 
    * 参考：[Maximizing Small Root Bounds by Linearization and Applications to Small Secret Exponent RSA](https://link.springer.com/content/pdf/10.1007%2F978-3-642-13013-7_4.pdf)
  * 若有$eu-k(q^2-1)(p^2-1)v = w$，则可构造出方程$$v(p\pm q)^2-(N+1)^2v - w \equiv 0\ (mod\ e)$$其中有$e = N^{\beta}, u = N^{\delta}$，如果有$v < 2N^{\beta + \delta-2} = X,\ p\pm q < 3N^{0.5} = Y, w < N^{\gamma} = Z$，那么可以构造方程$$f(x,y,z) = xy^2 + a_1x+z\ (mod\ e)$$ 然后使用然后Coppersmith。 
    * 参考：[A Generalized Attack on Some Variants of the RSA Cryptosystem](https://hal-normandie-univ.archives-ouvertes.fr/hal-02321006/file/sac2018paper4.pdf)
  * 若有$ed-k(p^2-1)(q^2-1) = 1$，且有$e = N^{\alpha}, d = N^{\delta}, |p-q|<N^{\beta}$，若$$\delta < 2-\sqrt{2\alpha\beta}=\epsilon$$则可以构造出$-(k)(p-q)^2-(N-1)^2(-k)+1\equiv 0\ (mod\ e)$ 即$$f(x,y) = xy+Ax+1\ mod\ e$$然后使用Coppersmith方法求解。
    * 参考：[Cryptanalysis of RSA Variants with Primes Sharing Most Significant Bits](https://eprint.iacr.org/2021/1632.pdf) 其中有一步是线性化的过程，即令$u=xy+1$，然后再构造出格，LLL算法后把$u$用$xy+1$代入求出的方程，然后再求$x,y$的根。（可以看作是Coppersmith的一种）
  * 若有$eu-(p-s)(q-r)v = w$，其中$e = N^{\beta}$，$|r|,|s| < N^{\alpha} < N^{\frac{1}{4}}$, $0 < u < N^{\delta},\ 0<v,\ |w| < N^{\gamma}$。如果满足$$\delta < \frac{7}{6} + \frac{1}{3}\alpha - \gamma - \frac{1}{3}\sqrt{(2\alpha+1)(2\alpha + 6\beta - b\gamma +1)}-\epsilon$$ 则可以用Coppersmith方法求出$(p-s)(q-r)$. 方法是构造函数$f(x,y,z) = xy-Nx+z$，则有$(x,y,z) = (v,pr+qs-rs,-w)$
    * 参考：[A New Attack on RSA and Demytko's Elliptic Curve Cryptosystem](https://eprint.iacr.org/2019/1050.pdf)


##### 4.5 公钥$e$与$\varphi(N)$不互素
* 攻击前提：$p,q,e$已知，但是由于$e$与$\varphi(N)$不互素，所以我们无法求解得到私钥$d$。只有当他们互素时，才能保证$e$的逆元$d$唯一存在。
###### 4.5.1 $e \nmid \varphi(N)$
已知$p,q,e,m,c$，假设$gcd(e, \phi(N)) = a$，则有$e = ab$，其中$gcd(b,\phi(N)=1$。计算$$c' = c^{-b} = (m^{ab})^{-b} = m^a\ mod\ N$$一般来说$a$都会比较小，这就相当于对$c' = m^a$开$a$次方，既求$c'$的$a$次剩余。**见4.5.2节**。


###### 4.5.2 $e\ |\ \varphi(N)$
* **攻击条件**：$e$比较小，不大于65536。而且有$e\ |\ (p-1)$ 和 $e\ |\ (q-1)$。

现在相当于是这样的一种情况，我们有这样的一个方程$$c\equiv m^e\ mod\ N, \tag{4.10}$$其中$c,N,e,p,q$已知，需要求$m$。但是此时有$e | \varphi(N)$。因此这个方程可以化为$$c\equiv m^e\ mod\ p \newline c\equiv m^e\ mod\ q$$因为$e$与$p,q$互素，因此两个方程各有$e$个根，从而方程$(4.10)$有$e^2$个根。我们的目的就是找到这$e^2$个根中我们需要的那个，**就是找到有特殊字符串开头比如``flag{``开头的根$m$**。

* 主要流程：
    1. 用**Adleman-Manders-Miller rth Root Extraction Method**在GF(p)和GF(q)上对$c$开$e$次根，分别得到一个解。
    2. 找到所有的$e$个primitive $e^{th}$ root of 1，乘以上面那个解，得到所有的$e$个方程$c\equiv m^e\ mod\ p$和方程$c\equiv m^e\ mod\ q$的解.
    3. 用**中国剩余定理CRT**对GF(p)和GF(q)上的两组$e$个解组合成$mod\ N$下的解，可以得到$e^2$个方程$(4.10)$解。

**Adleman-Manders-Miller rth Root Extraction Method （AMM）**
![AMM](crypto/images/AMM.PNG)
https://arxiv.org/pdf/1111.4877.pdf  **Cao Z , Sha Q , Fan X . Adleman-Manders-Miller Root Extraction Method Revisited[J]. 2011.** 这篇文章里给出了算法的推导过程，由于稍微有点复杂，就不写在这里了。
更详细的解释可参考 https://blog.csdn.net/jcbx_/article/details/105303760 这篇博客。

题外话：其实开n次方根的方法还有很多，这只是其中一种比较好理解和实现的。

**找出所有的$e$个primitive $e^{th}$ root of 1**：一种不严谨的做法就是随机生成$e$个$GF(p)$上的数记$x_i,\ i\in[1,e]$，然后计算$x^{\frac{p-1}{e}}\ mod\ p = x_i$，这样一来每个$x_i^e \equiv 1\ mod\ p$。不严谨就在于可能会出现重复的现象。

进而只要用AMM算法求出的$c$在$GF(p)$上的$e$次根记$m_p$，则计算$m_p·x_i\ mod\ p$就得到所有的$e$个方程$c\equiv m^e\ mod\ p$的解。

* 代码参考：https://blog.csdn.net/cccchhhh6819/article/details/112766888 本质上这里的代码是参考starctf2021_Crypto_little_case题目中的writeup。
* ***具体Sagemath9.2代码见``crypto/code/AMM.sage``***

###### 4.5.3 $e\ |\ \varphi(N)\ v2$
同样有$e\ |\ \varphi(N)$，但是$e\nmid (p-1)$且$e\nmid (p-1)$。假设有$gcd(e, p-1) = a$，$gcd(e, q-1) = b$，其中$1 < a,b < e$。计算出$$c_p\equiv c^{-\frac{e}{a}} \equiv m^a\ mod\ p \\ c_q\equiv c^{-\frac{e}{b}} \equiv m^b\ mod\ q$$ 其中$-\frac{e}{a} = invert(\frac{e}{a}, p-1)$. 因此我们可以用AMM算法对$c_p$在模$p$下求出$a$个根，对$c_q$在模$q$下求出$b$个根，然后用中国剩余定理求解出$m$。

###### 4.5.4 $gcd(\phi / e, e) = 1$
实际上这里也可以用AMM算法进行求解。不过在这种情况下有一种直观一点的解法，可以顺便加深一下对数论的了解。
- **方法：**
  1. 计算$\phi' = (p-1)(q-1)/e$.令$G$是阶为$\phi'$的一个子群。
  2. 任意选取$g$，计算$g_E = g^{\phi'}\ mod\ N$，直到$g_E\neq 1$.其中$E$表示的是阶为$e$的一个子群，$g_E$是该群的生成元。
  3. 因此消息$m$可以写成$G$和$E$中两个元素的乘积$m = al,\ a\in G,\ l\in E$。因此有$$c = m^e\equiv(al)^e\equiv a^e\ mod\ N$$，因此思路是先求出$a = c^{e^{-1}\ mod\ \phi'}\ mod\ N$。
  4. 遍历$i\in \{0,...,e-1\}$，计算$m'\equiv a\cdot g_E^i\ mod\ N$，找出满足条件的$m'$，就是我们想要的消息$m$。



###### 小技巧
因为题目给出的$m$一般比较的小，因此当得到了$$c' = m^e \ mod\ N,$$的时候，可以尝试用`gmpy2.iroot`函数对$c'$开$e$次方根，当$m^e < N$时可以恢复出$m$。


##### 4.6 Small private CRT-exponents $d_p, d_q$

> 这一小节主要介绍Bleichenbacher-May Attack

* Bleichenbacher-May Attack
    当$q < N^{0.468}$ 且 $d_p,d_q \leq min\{(N/e)^{0.4}, N^{0.25} \}$ 时，此攻击可以对$N$进行分解。
    * https://link.springer.com/content/pdf/10.1007%2F11745853_1
    * D. Bleichenbacher, A. May, ”New Attacks on RSA with Small Secret CRTExponents”, Proceedings of PKC 2006, LNCS 3958 [2006], pp. 1–13.
    * 已知式$$ed_p=1+k(p-1) \\ ed_q=1+l(q-1)$$相乘并展开得$$e^2d_pd_q+ed_p(l-1)+ed_q(k-1)-(N-1)kl=k+l-1$$我们令$$w = d_pd_q \\ x =d_p(l-1)+d_q(k-1) \\ y=kl \\ z=k+l-1$$则我们可以构造格$$L = \left[\begin{matrix}
    1 & 0 & e\\
    0 & 1 & 1-N\\
    0 & 0 & e^2\\
    \end{matrix}\right]$$ 因此我们有$[x\ y\ w]*L = [x\ y\ z]$，这里$[x\ y\ w]$是一个线性变换，通过LLL算法求出的最短向量将会是$[x\ y\ z]$的形式。我们不能直接对格$L$进行规约，因为还需要保证$[x\ y\ w]$有相同的大小，因此$L$需要有乘一个对角阵来平衡目标向量，即令$[x\ y\ w]$中的每个元素大小大致相同。
    * 参考代码：
    ```python
    # Sagemath 9.2
    e = 399995007353334843492700652707
    n = 183656432204946278583158645163956954879148229006140604544321
    
    m = Matrix(ZZ, 3, 3)
    m[0,0] = 1
    m[0,2] = e
    m[1,1] = 1
    m[1,2] = 1-n
    m[2,2] = e*e
    
    ml = m.LLL()
    ttt = ml.rows() 
    # print(ttt[0])
    
    kl = abs(ttt[0][1])
    kpl_1 = abs(ttt[0][2])
    # x^2-(kpl_1+1)x + kl = 0
    k = int(kpl_1+1 +((kpl_1+1)**2-4*kl)**0.5)//2
    l = kpl_1+1-k
    
    for i in range(0,5):
        dp = inverse_mod(e, k)+i*k
        for j in range(0,5):
            dq = inverse_mod(e, l) + j*l
            p = (e * dp - 1) // k + 1
            q = (e * dq - 1) // l + 1
            if is_prime(p) and is_prime(q):
                print(p,q)
    ```



* 当$d_p,d_q < N^{0.073}$时，可以使用美密会中的一篇文章对$N$进行分解
    * https://www.iacr.org/archive/crypto2007/46220388/46220388.pdf
    * Jochemsz E ,  May A . A Polynomial Time Attack on RSA with Private CRT-Exponents Smaller Than N 0.073[J]. International Cryptology Conference on Advances in Cryptology, 2007.



##### 4.7 Unbalanced Small private CRT-exponents $d_p, d_q$

当$p,q$相差比较大的时候，记$p=N^{1-\beta}, q = N^{\beta}$，其中$\beta < 0.38$，$d_p,d_q < N^{\delta}$，其中$\delta \leq 1-\frac{2}{3}\beta + \frac{2}{3}\sqrt{3\beta + \beta^2} -\epsilon$，此时使用May提出的方案可以把$N$分解。

其中May一共提出了三个算法(前两个算法在[2]，第三个算法在[1])，正常来说题目一般只会出到May的第二个算法。

在第二个算法中，由于界的问题，主要就是求解时的参数$t=\tau m$需要适当地增大，和界$X,Y$需要适当地减小。因为论文中有点理想化，因此求行列式的时候把界写小了，因此这里的参数$t$要适当地增大，直接取$t=3$或$t=5$，这样一般都能解出来。第二个坑就是界$X,Y$的选取，要求$$X=N^{\beta+\delta} \\ Y = N^{\beta}$$ 我们需要意识到方程$$ed_pq=(k−1)(N−q)+N$$ 有小根 $(k−1,q)$，则$X>k-1, Y> q$，因此$Y$可取$N^{\beta}$，但是仔细观察以下注意生成参数的时候$e,d_p,q$都比界要小，因此这里的$Y$会偏小，因此最好就是$Y = N^{\beta} // (2^5)$

* 参考资料
  * [1] https://www.iacr.org/archive/pkc2006/39580001/39580001.pdf
  * [2] https://rd.springer.com/content/pdf/10.1007%2F3-540-45708-9_16.pdf
  * [3] https://www.iacr.org/archive/eurocrypt2017/10210359/10210359.pdf

* 题目：2022年TQLCTF——hardrsa
* ***具体Sagemath9.2代码见``crypto/code/May__Unbalanced_prime_and_small_CRT_exponents.sage``***


##### 4.8 Special $e$ and small CRT-exponent $d_p$
- **攻击条件1**：$q<p<2q$，$ex+y\equiv 0\ (mod\ p),\ |x|<N^{\gamma},\  |y|< N^{\delta}$，且有$ex+y\not\equiv 0\ (mod\ p),\ \gamma+\delta\leq\frac{\sqrt{2}-1}{2}$.
- **攻击原理**：构造函数$f(x,y) = ex+y\ (mod\ N)$，然后使用Coppersmith方法求解。把$x,y$求解出来后就能求出$p$

- **攻击条件2**：$q<p<2q$，$e<N^{\frac{\sqrt{2}}{2}}$且$ed_p = 1+k_p(p-1)$。如果有$$d_p<\frac{N^{\frac{\sqrt{2}}{4}}}{\sqrt{e}}$$ 则可以对$N$进行分解。
- **攻击原理**：同样是构造出函数$f(x,y) = ex+y\ (mod\ N)$，这里的$x$就表示$d_p$. 然后使用Coppersmith方法求解。

- 参考资料：
  - [Nitaj A., "A new attack on RSA and CRT-RSA"](https://link.springer.com/content/pdf/10.1007/978-3-642-31410-0_14.pdf)
  - [crypto-attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/nitaj_crt_rsa.py)





#### 五、变种RSA密码分析

见[Cryptanalysis of RSA and It's Variants](https://www.researchgate.net/publication/266171887_Cryptanalysis_of_RSA_and_Its_Variants)的Section 11 Common Prime RSA中的内容。但是书是2009年出版的，因此后来的算法书中就没有记录了。

> **书中的许多攻击包含了Winner攻击和使用Coppersmith方法的攻击。**

##### 5.1 Common Prime RSA (素数中含有公约数)
对于$N=pq$，若有$p-1=2ag,\ q-1 = 2bg$。则此RSA为Common Prime RSA. 

###### 5.1.1 公因数$g\approx N^{1/2}$
这样一来就有$N=2g(2gab+a+b)+1$，又因为$p-1=2ga$，因此有$c^{N-1}\ mod\ N$有$ab$个元素，而在模$p$的乘法群中只有$a$个元素，然后使用Pollard rho算法的时候算法复杂度就变为了$O(\sqrt{a})$。

因此当$g\approx N^{1/2}$时，$O(\sqrt{a})$就很小，可以用Pollard rho算法进行求解。

###### 5.1.2 已知$a,b$
根据方程$N=2g(2gab+a+b)+1$，我们可以推出 $$4abg^2+2(a+b)g-N+1=0$$ 通过解一元二次方程就可以把$g$解出来。

###### 5.1.3 已知$g$
这里需要分3种情况。分别是$g>a+b$,$g=a+b$,$g < a+b$，且素数$p,q$需要是平衡的。
* $g > a+b$
  * 令$c=a+b$，有$$N=2g(2gab+a+b)+1\ (1)$$，则有$M=2gab+c$，因此$c=M\ mod\ g$，因此令$b=c-a$，代入方程(1)可以列出关于$a$的一元二次方程，从而求解出$a$。
* $g = a+b$
  * 和上面的类似
* $g < a+b$
  * 由方程(1)得$$\frac{N-1}{2g}=2gu+v$$ 其中$0\leq v < 2g$且$u,v$已知。然后$\exist c$令$$\begin{cases} a+b=v+2gc \\ ab=u-c \end{cases}$$ 则对于$gcd(x,N)=1$，有$x^{2gu}\equiv x^{2gab+2gc}\equiv x^{2gc}\ (mod\ N)$，令$y=x^{2g}$，则我们有同余方程$$y^u\equiv y^c\ (mod\ N)$$ 然后求离散对数就可以把$c$求出来。知道$c$之后代入方程组就可以把$a,b$求出，成功分解$N$。 
  * 其中$c$的取值为$c\leq a+b \approx 2N^{0.5-\gamma}$，其中$\gamma\approx\frac{1}{4}-mlog(long(N))$，$m$为常数。算法复杂度约为$O(\sqrt(c))$。



##### 5.2 Multi-Power RSA 
对于$N=p^rq$，若有$r > 1$。则此RSA为Common Prime RSA.

- 2009年后的相关攻击：[New attacks on RSA with Moduli $N = p^rq$](https://eprint.iacr.org/2015/399.pdf)


##### 5.3 Polynomial based RSA
参考资料：[Polynomial based RSA](http://www.diva-portal.se/smash/get/diva2:823505/FULLTEXT01.pdf)

一般来说多项式环的RSA的模多项式$N$有快速的分解算法，因此基于多项式环的RSA是不安全的。其阶若$N = P*Q$，$deg(P) = r, deg(Q) = s$，其素数域为$GF(p)$，则模$N$的商环$R$中的元素的最大阶为$s = (p^r-1)(p^s-1)$


##### 5.4 Special constructed RSA 
###### 5.4.1 N = pq = (a^m+r_p)(b^m+r_q)
* **攻击条件**：特殊构造的RSA，有$N = pq = (a^m+r_p)(b^m+r_q)$，其中有$r_q<r_p<2a^{m/2}$和$$r_p\equiv p\ (mod\ 2^m) \\ r_q\equiv q\ (mod\ 2^m)$$，且$max\{r_p,r_q\}<2^k$。如果$2^{k-1}(2^{\frac{m}{2}+1})$足够小且$r_p, r_q$已知，那么$N$就可以被分解。
* 更详细的条件$m$一定需要是偶数，$r_p,r_q<N^{0.039}$

* 参考资料
  * [Ghafar AHA. et al., "A New LSB Attack on Special-Structured RSA Primes"](https://www.mdpi.com/2073-8994/12/5/838)
  * [crypto-attack Ghafar-Ariffin-Asbullah attack ](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/gaa.py)



###### 5.4.2 RSALib-cve 
- **漏洞**：https://asecuritysite.com/encryption/copper
- **漏洞原理**：`RSALib`中的素数是由以下方式构造的：$$p=k\cdot M+(65537^q\ mod\ M)$$ 其中$M = \prod_{i=1}^n P_i$，$P_i$表示从0开始的第i个素数，其中$k,a$未知。 当其中的$k,a$选择不当的时候，能使得$N$能被快速分解。
- **攻击原理**：
  1. 首先$a$的替代数$a'$能被快速求解(因为$M$是小素因子的乘积)
  2. 然后构造出函数$f(x) = x+(M'^{-1}\ mod\ N) * (65537^{a'}\ mod\ M')(mod\ N)$，使用Coppersmith方法求出小素因子$k'$
  3. 计算出候选的$p$，然后判断是否是$N$的因子。
  4. 文章提出了一些改进时间复杂度的方法，比如重新选择模数$M'$使得候选的$a'$的数量减少，但又不会使得Coppersmith的运行时间过大，文章进行了一定的平衡从而找到时间复杂度最少的参数。

- 参考资料：
  - [Nemec M. et al., "The Return of Coppersmith’s Attack: Practical Factorization of Widely Used RSA Moduli"](https://dl.acm.org/doi/pdf/10.1145/3133956.3133969)
  - [crypto-attack ROCA](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/roca.py) 




##### 5.5 Unbalanced RSA
###### 5.5.1 Implicit Factorization
* **攻击条件**：已知k组模数$N_1=p_1q_1,...,N_k=p_kq_k$，存在一组整数$a_1,...,a_k$其中有$a_1p_1,...,a_kp_k$拥有相同的MSB或者LSB。则可以对$N_1,...,N_k$进行分解。
  * 当$k=2$时用到了连分数的方法，且需要满足$$|a_1p_1-a_2p_2|<\frac{p_1}{2a_2q_1q_2}$$ 且$a_1p_1,a_2p_2$有相同的$t$bit的数，$q_1,q_2$是$\alpha$bit的，$a_1,a_2 \leq 2^{\beta}$，$t\geq 2\alpha+2\beta+1$。满足以上条件可以对$N_1,N_2$进行分解。
  * 当$k>2$时用到了格的方法。需要满足条件$$t>\frac{k}{k-1}\alpha+\frac{k^2}{k-1}\beta + \frac{k}{2(k-1)}(1+log_2(\pi e))$$

- 参考资料
  - [Nitaj A., Ariffin MRK., "Implicit factorization of unbalanced RSA moduli"](https://link.springer.com/content/pdf/10.1007/s12190-014-0806-1.pdf)
  - [crypto-attack Implicit factorization](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/implicit.py)


###### 5.5.2 Factor with some known bits
- **攻击条件**：已知$N=pq > q^3$，且$p$的部分bit已知。
- 分为三种情况，
  1. 知道$p$的低$Q$位bit，Easy
  2. $p$的低$W$bit未知，但是其后的$L$bit已知。同构构造函数$f(x,y) = x(a+y)\ mod\ 2^{W+L}$，然后使用Coppersmith方法求解。
  3. 断层地知道部分bit，改进的Boneh and Durfee的Coppersmith算法。

- 参考资料：
  - [Brier E. et al., "Factoring Unbalanced Moduli with Known Bits"](https://link.springer.com/content/pdf/10.1007/978-3-642-14423-3_5.pdf)
  - [crypto-attack Factorization of unbalanced moduli](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/unbalanced.py)


#### 六、选择明密文攻击
##### 6.1 选择明文攻击
* 前提：我们有一个Oracle，对于给定任意明文，Oracle都会给出相应的密文。
* 目标：获取公钥N，e
    1. 首先通过构造多对加解密获取N。
    2. 当$e < 2^{64}$时，用 Pollard’s kangaroo algorithm 算法获取公钥$e$。

##### 6.2 选择密文攻击
* 前提：我们有一个Oracle，对于任意的合法密文，Oracle都会给出相应的明文(相当于时攻击者临时获得了解密机器的访问权)。但是我们不知道密钥。
* 目标：Alice计算$C=m^e\ mod\ N$，把Alice用自己的公钥签名的信息$m$恢复出来。
    1. 选择任意$X\in Z_N^*$
    2. 计算$Y=CX^e\ mod\ N$
    3. 想办法让Alice计算$Z = Y^d\ mod\ N$
    4. $m = ZX^{-1}\ mod\ N$

此攻击并没有把Alice的私钥恢复出来，本质上是对RSA协议本身的攻击而不是算法的攻击。

##### 6.3 RSA parity oracle
假设目前存在一个 Oracle，它会对一个给定的密文进行解密，并且会检查解密的明文的奇偶性，并根据奇偶性返回相应的值，比如 1 表示奇数，0 表示偶数。那么给定一个加密后的密文，我们只需要 log(N) 次就可以知道这个密文对应的明文消息。

Oracle返回奇偶性信息造成了信息的泄露，因此可以使用选择明文攻击的思路进行攻击，具体的攻击方案见：https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_chosen_plain_cipher/

* 本质上是二分法，然后夹逼。

##### 6.4 RSA Byte Oracle
假设目前存在一个 Oracle，它会对一个给定的密文进行解密，并且会给出明文的最后一个字节。那么给定一个加密后的密文，我们只需要$log_{256}N$次就可以知道这个密文对应的明文消息。

具体方案同样见：https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_chosen_plain_cipher/

##### 6.5 RSA parity oracle variant
如果 oracle 的参数会在一定时间、运行周期后改变，或者网络不稳定导致会话断开、重置，二分法就不再适用了，为了减少错误，应当考虑逐位恢复。

这里的攻击是基于**RSA parity Oracle** 方案，即对一个给定的密文解密后会检查明文的奇偶性，然后返回相应的值。这里所存在的问题是每次加密和解密所使用的密钥会不一样，5.3节中所介绍的二分法的原理是在相同的密钥的情况下通过选择明文攻击不断发送消息，从而得出明文。

而在不同的密钥的情况下，我们需要逐比特进行恢复。原理如下：
* 首先明文为$m$，密文为$c_i$，公钥为$e_i,N_i$，私钥为$d_i$，其中$i$表示第$i$次在Oracle中的数据，其中密文和公钥是可以获取的。与此同时，我们还可以从Oracle的手中获得明文的最后一个bit，即我们可以把$c_i$重新发给Oracle，然后Oracle会返回$y = c_i^{d_i}\ mod\ 2$。
* **攻击：** 要恢复明文的第$j$比特，则把$c_i(2^{-je_i\ mod\ N_i})$发送给Oracle，则Oracle将会返回$$y_j \equiv a_j + a_{j-1} \times 2^{j-1} \times 2^{-j} + ... + a_0 \times 2^0 \times 2^{-j}$$ 根据前面恢复出的明文$m$的前$j$比特:$a_0,a_1,...,a_{j-1}$容易计算得出明文$m$的第$j$比特$a_j$。

**注意：** 这里的攻击同样适用于5.3节说讲到的RSA parity Oracle 攻击。

具体方案同样见：https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_chosen_plain_cipher/
* ***具体Python3代码见``crypto/code/RSA_parity_oracle_variant.py``***

#### 七、侧信道攻击
侧信道攻击：攻击者能获取密码设备中的侧信道信息(例如能量消耗、运算时间、电磁辐射等等)从而获取密码信息。

攻击条件：密码实现的过程中侧信道信息泄露，能从侧信道信息中获取加密过程的信息，从而分析出明文。

详细例子见：https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_side_channel/

#### 八、基于具体RSA实现（标准）的攻击
##### 8.1  Bleichenbacher's Attack on PKCS 1
即在PKCS 1(Public Key Cryptography Standard 1)中实现时可以找出实现时的漏洞，然后相当于敌手获得一个oracle，使得敌手可以不断猜测一个伪造的签名，知道猜测成功。

这种攻击主要针对PKCS 1实现时的攻击。

- 参考资料
  - [Chosen ciphertext attacks against protocols based on the RSA encryption standard PKCS #1](https://link.springer.com/content/pdf/10.1007/BFb0055716.pdf)
  - [crypto-attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/bleichenbacher.py)

***注：这里只提供理论支撑，详细例子见crypto文件夹中的各个writeup。其实有一部分理论我也不是很清楚，特别是Coppersmith方案中的方法。要做几道题来再搞清楚一下其细节的方案，特别是***
1. ***Coppersmith方案解方程的实现***
2. ***部分密钥泄露攻击***
3. ***Boneh and Durfee attack***


##### 8.2 PKCS 1 部分密钥泄露攻击  Branch and prune attack
如果给出了RSA的私钥文件，如pem文件等，然后rsa的$n,e$已知，但是其余信息$d,p,q,dp,dq,q^{-1}\ mod\ p$等信息泄露了27%以上，那么可以使用文章[1]的方案对密钥进行恢复。算法本质上不算难，难点在于如果给出的是pem文件，那么可能pem封装的头部信息会缺失，导致信息发生偏移。还有就是消息的格式转换比较的繁琐，会花费大量的时间在处理格式上。

* 算法原理：根据已知的⽐特信息，从低位开始逐位搜索(d,dp,dq,p,q)
  1. 首先因为$e$比较的小，先爆破$k$，原理是$d$的高位比特泄露了，如果$k$正确，那么就有$\lfloor \frac{k(N+1)+1}{e} \rfloor$的高0.5bit与$d$相等。
  2. 接下来猜测$k_p,k_q$，经推导有$k_p^2-[k(N-1)+1]k_p-k\equiv 0\ mod\ e$，容易求解。
  3. 从 $[1,n]$，枚举所有可能的$ mod 2^i$的密钥并修剪那些不满足上述密钥数据之间关系的密钥。 更准确地说，给定潜在密钥的第 1 位到第 $i - 1$ 位，为 $p、q、d、dp、dq$ 的第 $i$ 位生成所有可能的值组合，如果满足 (1)、(2)、(3) 和 $(4) mod 2^i$则保留候选组合。 

* 参考文献
  * [1] Nadia Heninger, Hovav Shacham. Improved RSA Private Key Reconstruction for Cold Boot Attacks. Cryptology ePrint Archive, Report 2008/510, 2008.
  * [RSA私钥文件（PEM-PKCS#1）解析](https://cloud.tencent.com/developer/article/1543322)
  * [Crypto - God Like RSA](https://zhuanlan.zhihu.com/p/266059082)
  * [Heninger N., Shacham H., "Reconstructing RSA Private Keys from Random Key Bits"](https://link.springer.com/content/pdf/10.1007/978-3-642-03356-8_1.pdf)
  * [crypto-attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/branch_and_prune.py)


##### 8.3 PKCS #1 v2.0 选择密文攻击 Manger Attack
Manger攻击是针对 PKCS #1 v2.0 RSA OAEP 加密的自适应选择密文攻击。它从一个给定的密文中恢复明文，需要一个给予明文的$log_2N$次查询的oracle中，其中 $N$ 是 RSA 模数。

- 参考资料
  - [A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1 v2.0](https://link.springer.com/content/pdf/10.1007/3-540-44647-8_14.pdf)
  - [crypto-attack Manger's attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/manger.py)





## 背包加密 (knapsack based cryptosystem)
* 参考：https://ctf-wiki.org/crypto/asymmetric/knapsack/knapsack/#_9

![Knapsack_problem](crypto/images/Knapsack_problem.PNG)

### 超递增序列
背包问题需要满足$a_i$为超递增序列的时候才能满足解密的要求，但此时其他人也可以截获密文进行破译。因此出现了**Merkle-Hellman**算法，从而设计出背包加密。所谓的超递增序列是指满足$$a_i>\sum_{k=1}^{i-1}a_k$$的序列。

* **Merkle-Hellman算法**
    * 参考：http://en.wikipedia.org/wiki/Merkle%E2%80%93Hellman_knapsack_cryptosystem
    * 私钥：超递增序列$a_i$。
    * 公钥：首先生成模数$m$，满足$m>\sum_{i=1}^{n}a_i$。选取$w$满足$gcd(w,m)=1$，然后计算$b_i\equiv wa_i\ mod\ m$。最后序列$b_i$和$m$作为公钥。
    * 加密：假设我们要加密的明文为$v$，其每一个比特位为$v_i$，那么我们加密的结果为$$\sum_{i=1}^{n}b_iv_i\ mod\ m$$
    * 解密：计算$w^{-1}$，计算$$\sum_{i=1}^{n}w^{-1}b_iv_i\ mod\ m = \sum_{i=1}^{n}a_iv_i\ mod\ m$$从而根据背包方案恢复出明文。
* 破解：该加密体制在提出后两年后该体制即被破译，破译的基本思想是我们不一定要找出正确的乘数 $w$（即陷门信息），只需找出任意模数 $m'$ 和乘数 $w'$，只要使用 $w'$ 去乘公开的背包向量 $B$ 时，能够产生超递增的背包向量即可。
* 参考代码：https://github.com/ctfs/write-ups-2014/tree/b02bcbb2737907dd0aa39c5d4df1d1e270958f54/asis-ctf-quals-2014/archaic

* **使用格规约算法进行求解，详细参考HASH函数中FNV部分。**


### 非超递增序列
> 本质上是属于子集合问题(subset sum problem (SSP))，与奇数序列子集合问题odd order decision SSP (OSSP)一起都是属于NP完全问题。但是目前根据SSP问题所提出的密码体制中仍然有一些有漏洞。下面几篇文章都是子集合问题相关的文章，一般来说比较新的文章对SSP问题的发展会有一个比较全面的Introduction。

主要方案：
1. 2012年：[A public-key cryptosystem based on decision version of subset sum problem](https://ieeexplore.ieee.org/abstract/document/6401039/)
2. 2014年：[A knapsack public-key cryptosystem using two random sequences](https://ieeexplore.ieee.org/abstract/document/6979893/)

攻击方案：
1. [Cryptanalytic results on knapsack cryptosystem using binary particle swarm optimization](https://link.springer.com/chapter/10.1007/978-3-319-07995-0_37)
2. [An improved attack on the basic merkle–hellman knapsack cryptosystem](https://ieeexplore.ieee.org/abstract/document/8701428/)
3. [Equivalent key attack against a public-key cryptosystem based on subset sum problem](https://ieeexplore.ieee.org/iel7/4149673/8513921/08513952.pdf)
4. [Quantum algorithm and experimental demonstration for the subset sum problem](https://idp.springer.com/authorize/casa?redirect_uri=https://link.springer.com/content/pdf/10.1007/s11432-021-3334-1.pdf&casa_token=wn2Iknf01a8AAAAA:hgja8xVUFtHJDOhGNFSlRAnaJp6oFZWd6XZIFXA-Wj5H0SMxMm_sk4rkyTVkUCHHlVKniPrYAEmSJ9Z6uP0)

#### 简单的攻击方案
- **攻击条件** The density of the a_i values is < 0.9048
- [crypto-attack Low density attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/knapsack/low_density.py)

一般来说不会给这么简单的问题。




##  离散对数
**离散对数问题定义：** 给定有限乘法群$(G,\cdot)$，$g\in G$，且有$|G|=n$。则$\langle g \rangle$是$G$的一个子群，使得$g^d\equiv1\ mod\ n$成立的最小的正整数$d$为群$\langle g \rangle$的阶。（一般来说，密码体制中G一般是有限域$Z_p$。）给定一个$n$阶元素$\alpha\in G$和元素$\beta\in\alpha$，找出唯一的整数$a，0\leq a\leq n$，满足$$\alpha^a=\beta$$则整数$a$为$\beta$的离散对数。离散对数问题就是把整数$a$求出来。

性质：模$m$剩余系存在原根的充要条件$m=2,4,p^{\alpha},2p^{\alpha}$其中$p$为奇素数，$\alpha$为正整数。

* 离散对数求解相关算法实现：https://blog.csdn.net/qq_41956187/article/details/104981499
* ***具体Python3.7代码见``crypto/code/Discrete_logarithm_algorithm.py``***

#### 常见求解方法：
##### 1 Baby-step giant-step 大步小步法
有中间相遇攻击的思想。

令$m=\sqrt(n)$，对于离散对数$\beta=\alpha^a$。有$a=mj+i，i < m$。因此有$$\alpha^{mj+i}=\beta \newline \alpha^{mj}=\beta \alpha^{-i}$$因此计算出$m$个$\alpha^{mj}$记为$L_1=(j,\alpha^{mj})$。以及$m$个$\beta \alpha^{-i}$记为$L_2=(i,\beta \alpha^{-i})$。然后找出$L_1,L_2$中满足$\alpha^{mj}=\beta \alpha^{-i}$重复的数值对，那么就有$a=(mj+i)\ mod\ n$。

##### 2 Pollard’s ρ algorithm

此算法能以$O(\sqrt{n})$的时间复杂度和$O(1)$的空间复杂度来解决上述问题。

算法的原理是生日攻击。（扩展的算法有分布式Pollard $\rho$算法，时间复杂度比最初始的算法要快许多）

##### 3 Pollard’s kangaroo algorithm 也称为$\lambda$算法

若有离散对数问题$h=g^x$。那么当已知$a\leq x\leq b$时，此算法能以$O(\sqrt{b-a})$的时间复杂度求出$x$。

形象的来说，Pollard's Kangaroo算法就是使得两只袋鼠在解空间里面各自跳跃，其中一只为驯化的袋鼠，它的参数都是确定的，而另一只为野生的袋鼠，它的参数是要求的。驯化袋鼠每次跳跃之后都会做一个陷阱，如果野生袋鼠的某次跳跃碰到了这个陷阱，则表明他们的参数是一致的。这样，就可以使用驯化袋鼠的参数来推导出野生袋鼠的参数。由于这样一个过程是两条不同的路径经过变化得到一个交点，路径看起来有点像希腊字母lambda，所以该算法也称为lambda算法。

原文链接：https://blog.csdn.net/hillman_yq/article/details/1648141

* 高效算法：https://github.com/JeanLucPons/Kangaroo

* Sagemath中各种求离散对数的方法
```python
# Sagemath 9.2
#通用的求离散对数的方法
# ALGORITHM: Pohlig-Hellman and Baby step giant step.
x=discrete_log(a,base,ord,operation)

#求离散对数的Pollard-Rho算法
x=discrete_log_rho(a,base,ord,operation)

#求离散对数的Pollard-kangaroo算法(也称为lambda算法)
x=discrete_log_lambda(a,base,bounds,operation)

#小步大步法
x=bsgs(base,a,bounds,operation)
```

* 更详细的用法和例子参考Sage文档：https://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html?highlight=discrete_log_rho

##### 4 Pohlig-Hellman algorithm

此算法用于元素$\alpha\in G$的阶$n$不为素数的情况。假设$n=\prod_{i-1}^kp_i^{c_i}$，其中$p_i$为不同的素数。因为$a=log_{\alpha}\beta$是模$n$唯一确定的。因此如果能计算出每个$a\ mod\ p_i^{c_i}$，那么就可以使用中国剩余定理计算出$a\ mod\ n$。

对于每一个素数$p_i$，因为$$a = \sum_{j=0}^{c_i-1}a_jp_i^j+sp_i^{c_i}$$我们有$$\beta^{n/p_i} = (\alpha^a)^{n/p_i} \newline =(\alpha^{a_0+a_1p_i+...+a_{c-1}p_i^{c-1}+sp_i^c})^{n/p_i} \newline =\alpha^{a_0n/p_i}\alpha^{Kn} \newline =\alpha^{a_0n/p_i}$$因此有$$\beta^{n/p_i} = \alpha^{a_0n/p_i}$$这就相当于归结为1个新的离散对数问题，但是此离散对数问题规约到一个阶为$p_i$的子群。因此我们可以使用**Pollard Rho**等算法算出这个离散对数。
最后算出这$k$个离散对数$a_0$，从而利用中国剩余定理计算出$a\ mod\ n$。而算法的时间复杂度取决于$n$中最大的一个素因子$p_{max}$。因此算法的时间复杂度是$O(\sqrt{p_{max}})$。

**Sagemath 手写Pohlig-Hellman算法**，实际上可以查看`discrete_log`函数的实现
```python
# Sagemath 9.2
def Pohlig_Hellman():
    E = EllipticCurve(GF(p), [0, 0, 0, A1, B1])
    P = E(,)
    Q = E(,)
    
    order = P.order()
    factors = factor(order)
    factors = [fac^m for fac,m in factors]
    ans = []

    for factor in factors:
        this = bsgs(G * (order // factor), Q * (order // factor), (0, factor), operation='+')
        ans.append(this)
        print(this)

    return crt(ans, factors)
```

##### 5 基于有限域$GF(p)$上的特殊情况的离散对数

已知本原根$g$，已知离散对数$a$，对于$x\in F_p$，其中$p$是奇素数，已知$y=x^a\ mod\ p$，要求x。理论上这是一个求n次剩余的问题。但是这里有一种特殊情况，就是当 $gcd(a,p-1)=1$的时候，根据欧拉定理存在$a$模$p-1$的逆元。因此可以求出$a$在模$p-1$下的逆记为$a^{-1}$。因此有
$$
y^{a^{-1}} \equiv x^{aa^{-1}}\ mod\ p \\
y^{a^{-1}} \equiv x^{k(p-1)+1}\ mod\ p 
$$
同样根据欧拉定理定理，有
$$
x^{\phi(p)}\equiv 1\ mod\ p \\
x^{p-1}\equiv 1\ mod\ p
$$
因此$x = y^{a^{-1}}\ mod\ p$，**前提条件**必须是$gcd(a,p-1)=1$，否则不能使用这种方法去求解。当不满足前提条件的时候，求解$n$次剩余的问题可以归结为求解离散对数问题，在计算上是困难的。


##### 6 数域筛（Number field Sieve）

数域筛算法的原理比较复杂，但是网上有现成的实现，主要是`cado-nfs`这个工具。

* 链接：https://gitlab.inria.fr/cado-nfs/cado-nfs

根据readme安装就可以了，然后这个工具如果不自己设计数域筛算法那还是不难用的。主要见`README.dlp`,`README.msieve`,`README.nonlinear`,`README.Python`这四个readme文件，如果只是为了解决离散对数问题，我们只需要看`README.dlp`这个文件就可以了。

* windows上的安装：建议不要搞，会有各种各样的坑。首先需要安装mpi，然后windows上安装mpi又是另一个坑。建议使用windows自带的Ubuntu LTS对安装`gmp`、`mpi`和`cado-nfs`进行安装，从而避免各种坑的出现，如果是Ubuntu虚拟机的话就一般来说都没有问题。
  * 可能会出现找不到`cxxwrap.pl`文件中的`@CMAKE_CXX_COMPILER@`,`@MPI_CXX_COMPILER@`,`@MPI_C_COMPILER_CMDLINE_INSERTIONS@`问题，需要把这三者分别改为`g++`,`mpicxx`,`-cxx=g++`。
  * 可能会出现`./gf2x/gf2x_mul1.h:1:1: error: expected identifier or ‘(’ before ‘.’ token`这个问题，参考：https://www.mersenneforum.org/showthread.php?t=26834

求解的过程比较简单，输入以下命令：
`./cado-nfs.py -dlp -ell <ell> target=<target> <p>`
其中`p`表示在$GF(p)$这个有限域大小，`ell`表示`p`的一个大素因子，然后`target`表示在有限域$GF(p)$里面的一个数，我们要求出`target`的离散对数。

然后有一个注意的点是我们没有指定离散对数的基(base)，既没有给出$a$使得$a^{log(target)} = target\ mod\ p$。然后求解的时候会给出log(2),log(3)，本质上他们的基都是相同的，但是可能2，3和target会在不同的子群中。详细可以见：https://crypto.stackexchange.com/questions/74867/how-do-i-interpret-the-cado-nfs-output-for-discrete-logarithm-calculation-in-gf

因此如果我们知道$m^a \equiv c\ mod\ p$然后我们要求$a$，这个时候就要求出`log(m)`和`log(c)`，则有$$a = log(c) * log(m)^{-1}\ mod\ ell$$

* 求解：我们能够在几个小时内求解256比特的素数域有限域的离散对数，而且如果是对于同一个$p$，则运行
`If you want to compute a new target, run ./cado-nfs.py /tmp/cado... target=<target>`
从而可以快速求解在素数域$p$上的离散对数，能达到在几秒内求解出答案。







### 一 ElGamal
**密码体制**
![ElGamal](crypto/images/ElGamal.PNG)
一般来说，$p$至少是160位的十进制素数，**并且$p-1$有大的素因子**。

#### 简单的对ElGamal加密体制的攻击
* Unsafe generator attack
  * **攻击成因**：群的生成元$g$的阶不为$p$。
  * **攻击原理**：见参考文献，通过使用勒让德符号，使得攻击者能够区分是随机生成的字符串还是加密的结果。
  * 参考资料
    * [Unsafe generator attack](https://crypto.stackexchange.com/questions/3092/using-bad-generator-in-elgamal-encryption)
    * [crypto-attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/elgamal_encryption/unsafe_generator.py)






### 二 ECC 椭圆曲线加密

* **重要的参考资料**
  * [Robert Granger and Antoine Joux. Computing Discrete Logarithms](https://eprint.iacr.org/2021/1140.pdf) 椭圆曲线离散对数的综述

ECC 全称为椭圆曲线加密，Elliptic Curve Cryptography，是一种基于椭圆曲线数学的公钥密码。与传统的基于大质数因子分解困难性的加密方法不同，ECC 依赖于解决椭圆曲线离散对数问题的困难性。它的优势主要在于相对于其它方法，它可以在使用较短密钥长度的同时保持相同的密码强度。ECC密码体制在区块链等多种领域中都有应用。

* **椭圆曲线介绍**
代数闭包不完善定义：使用域K中的元素作为系数的所有多项式方程的解所构成的域。成为K的代数闭域$~K$
代数闭包一定是无限域。
椭圆曲线E定义：在域K上满足下列非奇异的Weierstrass方程的所有点$(x,y)\in K^2$的集合。$$E:y^2+a_1xy+a_3y=x^3+a_2x^2+a_4x+a_6$$下标的定义，$a_i$中的i是权重填充。x的权重是2，y的权重是3.
**非奇异：** Weierstrass方程定义的函数没有奇异点(奇点)，即没有$(x,y)$满足E，以及E的两个偏导数方程$E_x'=0$和$E_y'=0$

* 简化版的Weierstrass方程：$$E:y^2=x^3+ax+b$$其中
(1)$\Delta=-16(4a^3+27b)\neq0$，用来保证曲线是光滑的。即保证是椭圆曲线。
(2)$a,b\in K,K$为$E$的基域，$K$一般为$GF(p)$。
(3)点$O_{\infty}$是曲线上唯一的无穷远点。

* **椭圆曲线上的阿贝尔群**
**椭圆曲线上的点加运算构成一个阿贝尔群。** 此点加运算有多种形式，下面给出常见的简化版的Weierstrass方程的两种形式。
* 在素数域GF(q)上，椭圆曲线的点加公式如下：
![椭圆曲线素数域点加公式](crypto/images/GFq_PointAdd.PNG)
* 在扩域GF($2^p$)上，椭圆曲线的点加公式如下：
![椭圆曲线扩域点加公式](crypto/images/GF2-131_PointAdd.jpg)

**椭圆曲线的阶：** 如果椭圆曲线上一点$P$，存在最小的正整数$n$使得数乘$nP = O_{\infty}$，则将$n$成为点$P$的阶。若$n$不存在，则$P$是无限阶的。

#### 1 ECC中的ElGammal方案
* 假设用户B要把消息加密后传输给用户A

* 密钥生成：用户A选择椭圆曲线$E$，令$P$是椭圆曲线$E$上的点，点$P$的阶为$n$，并把点$P$作为基点。随机选取一个正整数$m,m < n$有$Q = mP$。则$E,P,Q,n$是**公钥**，$m$是私钥。
* 加密：
    1. 用户A将$E,P,G,n$传输给用户B。
    2. 用户B接受到信息后，将明文$msg$编码到椭圆曲线$E$的一个点$M$上，并生成一个随机整数$r,r < n$。
    3. 用户B计算点$C_1=M+rQ$，$C_2=rP$
    4. 用户B将$C_1,C_2$发送给用户A。
* 解密：
    用户A接受到$C_1,C_2$后，有$M=C_1-mC_2$。

原理：$$C_1-mC_2\newline=M+rQ-m(rP)\newline = M+rmP-mrP\newline=M$$

#### 2 常见ECC攻击方法
* 分布式Pollard Rho算法 （暴力破解）
* Pohlig-Hellman攻击(**攻击条件**：用于基点$P$的阶$n$是光滑(可被分解成比较小的质因数的乘积)的情景)
* 暴力枚举私钥
* 常见曲线（理论上需要使用特定的方法把该曲线转换成Weierstrass曲线的形式）：https://www.hyperelliptic.org/EFD/index.html

#### 3 一些额外的攻击方法
* 椭圆曲线中弱曲线的破解：
    1. https://wstein.org/edu/2010/414/projects/novotney.pdf
    2. https://link.springer.com/content/pdf/10.1007/s001459900052.pdf **原文**

#### 4 整环上的椭圆曲线
* (理论上数域知识扎实的话是能够自己推出的)

一般来说，椭圆曲线的构件都是在有限域上的。但是有些时候题目会出在整环上构造的椭圆曲线。一般来说，在Sagemath中椭圆曲线的构建一般是
```python
EllipticCurve(GF(p), [0, 0, 0, A, B])
```
但是有些时候会出成
```python
N = p * q   # usually we should factor N
EllipticCurve(Zmod(N), [0, 0, 0, A, B])
# given
P = (Px, Py)
```
我们把椭圆曲线看成两条椭圆曲线构成，先把点映射到两条在$GF(p)$和$GF(q)$上椭圆曲线中，因为点是由椭圆曲线方程$y^2=x^3+ax+b\ mod\ N$构成，因此只要把点的坐标模$p$和模$q$就可以映射到相应的椭圆曲线上。
```python
E1 = EllipticCurve(GF(p), [0, 0, 0, A, B])
E2 = EllipticCurve(GF(q), [0, 0, 0, A, B])
#  map point P to E1 and E2 to get E1P and E2P
E1P = E1(P) # where E1Px == Px % q, E1Py == Py % q
E2P = E2(P) # where E2Px == Px % p, E2Py == Py % p
```
根据题目要求求出两条椭圆曲线的离散对数后，通过中国剩余定理求出模$N$下椭圆曲线的离散对数。注意模数实用的是点P1q和点P1p的阶，不是用椭圆曲线E1,E2的阶
```python
# 前一个列表是余数， 后一个列表是模数
d1 = crt([d1p, d1q], [P1p.order(), P1q.order()])    
```

* 参考题目：2021广东省强网杯DLP，见`crypto/2021_GD_QWB/2021_GD_QWB_DLP`

#### 5 MOV攻击

> 与MOV-reduction攻击类似的攻击是FR-reduction。FR-reduction攻击特别适用于曲线的迹(Trace)为2的情况。

* **攻击原理**：使用双线性对进行攻击，本质上是构造一个双线性映射，将椭圆曲线$E(F_q)$的两个点映射到有限域$F_{q^k}$的一个元素，其中$k$是该曲线的**嵌入度**。设曲线$E$的阶为$n$，且$n,q$互素，我们要构造映射$$f:E[n]\times E[n]\rightarrow F_{q^k}$$ **嵌入度$k$的定义**为$$n \mid q^k-1$$ 
这里的双线性对一般使用Weil对或者Tate对。其中双线性对有双线性性，即：对于椭圆曲线上的点$P,Q$和整数$r,s$，有 $$f(rP,sQ) = f(P,Q)rs$$ 因此若要计算离散对数问题 $P' = rP$ 中的$r$。有 $$u = f(P,Q) \\ v = f(P',Q) = f(rP,Q) = f(P,Q)r \\ v = ru$$ 其中$u,v\in F_{q^k}$ 此时变成求解$ F_{q^k}$上的离散对数。

* **攻击条件**：嵌入度$k$需要足够小，对于超奇异曲线(supersingular curve)，其嵌入度足够小，一般$k\leq 6$，此时可以使用MOV攻击。非超奇异曲线的嵌入度一般会非常大。

* **Sagemath调包**：首先构造曲线；然后给出离散对数问题；接下来选择$Q$为曲线中生成元的倍点，其中倍数根据定理D.1. 或Table D.1 选择；然后生成Weil对；最后求解离散对数问题。
  **定理D.1. (Theorem)**：令$E(F_q)$是一个超奇异曲线，其阶为$q+1-t$，其中$q=p^m$，$p$为素数，则曲线$E$有以下6种类型。
    ![](crypto/images/Struct_in_supersingular_curves.PNG)
```python
# This is data for an example of
# a mov reduction using a super-
# singular curve over F{q}

p = 887421071545180331

assert(p+1 == E1.order())

k = 2 # decided by Table D.1.
F1 = GF(p)
E1=EllipticCurve(F1, [0,0,1,0,0])
F2 = GF(p^k)
phi = Hom(F1, F2)(F1.gen().minpoly().roots(F2)[0][0])
E2 = EllipticCurve(F2, [0, 0, 1, 0,0])

n = E1.order()

#random a point
P1 = E1.random_point()
R1 = 45*P1
P2 = E2(phi(P1.xy()[0]), phi(P1.xy()[1]))
R2 = E2(phi(R1.xy()[0]), phi(R1.xy()[1]))

# Choose Q in the group generated by P1 from Table D.1
# 选择一个Q点，保证它在椭圆曲线E2（E(F_{q^k})）的子群E[p+1]中，需要根据表Talbe D.1.进行选取
cn1 = p+1
coeff = ZZ(cn1 / n)
print(coeff)

Q = coeff * E2.random_point()
alpha = P2.weil_pairing(Q, n)
beta = R2.weil_pairing(Q, n)
d = beta.log(alpha)

print(d)
# 45
```

* 参考资料：
    * https://crypto.stanford.edu/pbc/thesis.pdf  双线性对
    * https://www.sagemath.org/files/thesis/hansen-thesis-2009.pdf sagemath求解MOV攻击
    * Elliptic_Curves_in_Cryptography 书
    * https://zhuanlan.zhihu.com/p/421541257 大佬的笔记
    * Menezes A. J., Okamoto T., Vanstone S. A., Reducing elliptic curve logarithms to logarithms in a finite field. IEEE Trans. Inf. Theory. 39(5), pp. 1639 -1646, 1993.     MOV攻击最初始的文章
    * [New Explicit Conditions of Elliptic Curve Traces for FR-Reduction](https://dspace.jaist.ac.jp/dspace/bitstream/10119/4432/1/73-48.pdf)



#### 6 Smart攻击

* ***攻击条件：椭圆曲线$E(F_q)$的阶为$q$，$q$是素数***

* **攻击原理**：已知$Q=kP$其中$P,Q\in E(F_p)$。首先把在$E(F_p)$中的点提升(lift)到$E(Q_p)$这个椭圆曲线中，其中$Q_p$表示的是 **$p$进域**。然后通过**P进制椭圆对数$\psi_p$**把$E_1(Q_p)$上的点映射到$pZ_p$这个**群**中。最后在群$pZ_p$中求出离散对数$k$。
    * 这里的$Z_p$不是整数模$p$所构成有限域，而是用来表示$p$进制的整数，而$Q_p$则表示$p$进制的有理数，$p$的幂可以是负数。
    * 容易得知把曲线$E(Q_p)$的系数模$p$之后就得到了$E(F_p)$上的曲线，点同样也可以根据模$p$得到。这样一来就得到了$E(Q_p)\rightarrow E(F_p)$的一个同态映射。然后我们令$E_1(Q_p)$表示的是这个同态的kernel，即$E_1(Q_p)$包含了所有映射到$E(F_p)$无穷远点的点。
    * **( P-Adic Elliptic Log) P进制椭圆对数$\psi_p: E_1(Q_p) \rightarrow pZ_p$**：对于点$S(x_S,y_S) \in E_1(Q_p)$ 有 $$\psi_p(S) = -\frac{x_S}{y_S}$$

* **攻击失败**：选取的$Q_p$不当，导致$E(Q_p)$和$E(F_p)$同构，无法获取额外信息，导致攻击失败，这种情况叫做(canonical lift)。正常来说只有$\frac{1}{p}$的概率发生，但是如果选取不当则攻击失败。

* **攻击流程**：
    1. 把点升格(lift)到$E(Q_p)$中，可使用Hensel's Lemma，得到点$P',Q'$。则有$$Q'-kP' \in E_1(Q_p)$$。
    2. 把点$P',Q'$升格到$E_1(Q_p)$中，由于椭圆曲线$E(F_p)$的阶为$p$，因此有$pP',pQ' \in E_1(Q_p)$，有$$pQ'-k(pP')\in E_2(Q_p)$$。
    3. 用P进制椭圆对数把点映射到$pZ_p$中，因此有$$\psi_p(pQ'), \psi_p(pP') \in pZ_p \\ \psi_p(pQ') - k\psi_p(pP') \in pZ_p$$。
    4. 因此有$$k = \frac{\psi_p(pQ')}{\psi_p(pP')} \in pZ_p$$ 最后计算$k = k\ mod\ p$。

* **Sagemath代码**：
    ```python
    def SmartAttack(P,Q,p):
        E = P.curve()
        Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

        P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
        for P_Qp in P_Qps:
            if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
                break

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

    E = EllipticCurve(GF(43), [0,-4,0,-128, -432])
    P = E([0,16])
    Q = 39 * P
    SmartAttack(P,Q,43)
    ```

* 参考资料
    https://zhuanlan.zhihu.com/p/40898123 $p$进域
    https://wstein.org/edu/2010/414/projects/novotney.pdf  Smart攻击
    https://zhuanlan.zhihu.com/p/421202600
    http://www.monnerat.info/publications/anomalous.pdf Anomalous曲线，适用于Smart攻击

##### Anomalous曲线的生成
Anomalous曲线的阶为$p$，适用于Smart攻击，暴力查找这样的曲线是很难的，需要特定的寻找方法。

* 参考文献：http://www.monnerat.info/publications/anomalous.pdf Generating Anomalous Elliptic Curves

* 原理文献中都有，这个给出生成曲线的代码：
    ```python
    # Sagemath 9.2
    # http://www.monnerat.info/publications/anomalous.pdf
    # if m is k-bits, then p is 2*k-bits

    import random
    D = 19
    j = -2^15*3^3

    def anon_prime(m):
        while True:
            p = (19*m*(m + 1)) + 5
            if is_prime(p):
                return m, p
            m += 1

    curves = []
    def anom_curve():
        m = random.getrandbits(128) 
        while True:
            m, p = anon_prime(m)
            a = (-3*j * inverse_mod((j - 1728), p)) % p
            b = (2*j * inverse_mod((j - 1728), p)) % p
            E = EllipticCurve(GF(p), [a,b])
            
            if E.order() == p:
                print(a,b,p)
                break
    ```


#### 7 singular曲线
既满足$-16(4a^3+27b^2)\ mod\ p = 0$的曲线。它会有落在$(x_0,0)$这样的singular点。这种形式的曲线最终会分两种情况。

* $y^2=x^3$的形式：曲线有一个 **尖点(cusp)** ，在$(0,0)$。然后有同构映射$f:E(F_p) \rightarrow GF(p)$，其中$$f : (x,y) \rightarrow \frac{x}{y}$$
* $y^2=x^2(x+a)$的形式：曲线的singular点是 **交叉点(node)** ，在$(x_0,0)$。然后求出$a$的平方剩余$a \equiv b^2\ mod\ p$，则有同构映射$f:E(F_p) \rightarrow GF(p)$，其中$$f : (x,y) \rightarrow \frac{y+bx}{y-bx}$$

* 例子：
    ```python
    # Sagemath 9.2 The second case y^2 = x^2(x+a)
    p = 23981
    P.<x> = GF(p)[]
    f = x^3 + 17230*x + 22699
    P = (1451, 1362)
    Q = (3141, 12767)
    # change variables to have the singularity at (0, 0)
    f_ = f.subs(x=x + 23796)
    P_ = (P[0] - 23796, P[1])
    Q_ = (Q[0] - 23796, Q[1])
    # show that the curve is of the form y^2 = x^3 + x^2
    print(f_.factor())
    # (x + 23426) * x^2
    t = GF(p)(23426).square_root()
    # map both points to F_p
    u = (P_[1] + t*P_[0])/(P_[1] - t*P_[0]) % p
    v = (Q_[1] + t*Q_[0])/(Q_[1] - t*Q_[0]) % p
    # use Sage to solve the logarithm
    print(discrete_log(v, u))
    ```

* 参考资料  ： 
    1. Joseph H.Silverman. The Arithmetic of Elliptic Curves[M]. 2nd Edition. 第三章
    2. https://crypto.stackexchange.com/questions/61302/how-to-solve-this-ecdlp



#### 8 指数演算法（Index Calculate）
* 简单版本的指数演算法
  * 令$G$是一个阶为$n$的加法循环群。已知两个元素$P,Q$满足$P=kQ$，求$k$
  1. 定义群$G$的一个子群$\mathcal{F}$
  2. 收集关系：
     1. 随机选择整数$a,b$并计算$R = aP+bQ$;
     2. 尝试使用$\mathcal{F}$中的元素分解$R$;
     3. 当分解成功时有$aP+bQ=\sum_{P_i\in\mathcal{F}}e_iP_i$，把$a,b,e_i$作为一行存储在一个矩阵中;
     4. 至少收集$\#\mathcal{F}$个关系，即矩阵需要有$\#\mathcal{F}$行;
  3. 在模阶$n$的情况下，把矩阵的$P_i$的系数通过线性变换化为$\bm{0}$，因此剩下$\lambda P+\mu Q = \bm{0}$
  4. $k = \lambda \mu^{-1}\ mod\ n$

* **子集$\mathcal{F}$选择的困难性：**
  * 选择的$\mathcal{F}$不能太大，否则矩阵维数过大。
  * 大部分的群元素$R$都能被分解成$\mathcal{F}$中的元素，否则第二步很难收集到足够的元素。
  * 任意的群元素$R$需要有高效的算法进行分解，否则会用过长的时间。

* 指数演算法一开始是应用于群$\mathcal{F}_P^*$中的。与椭圆曲线群相比，$\mathcal{F}_P^*$乘法群中的分解非常简单，就是整数分解。
  * 指数演算思想可以有效地应用于亏格$g > 1$的光滑射影曲线的除子群
  * 对于$\mathcal{F}_{q^n}, q\neq 2$域上的椭圆曲线，基于Weil descent and summation polynomials方法的指数演算法有比较出色的效果，也是2015年左右的一项比较热门的研究。但是对于$\mathcal{F}_{2^n}$域上的椭圆曲线，指数演算法无法进行有效的攻击。
  * 针对素数域，目前的指数演算法主要是基于Summation Polynomial Evaluation[Semaev04]的指标演算法，**其时间复杂度不如Pollard rho算法**

* 参考资料：
  * [Recent progress on the elliptic curve discrete logarithm problem](https://link.springer.com/content/pdf/10.1007/s10623-015-0146-7.pdf)
  * [Summation polynomials and the discrete logarithm problem on elliptic curves](https://eprint.iacr.org/2004/031.pdf)

#### 9 GHS Attack
> Gaudry-Hess-Smart Method


* 参考资料
  * [Robert Granger and Antoine Joux. Computing Discrete Logarithms](https://eprint.iacr.org/2021/1140.pdf) 椭圆曲线离散对数的综述


#### 10 TODO some bad Curves
**Anomalous curves**： An elliptic curve over a prime field Fp is said to be anomalous when its trace is equal to 1 or equivalently its cardinality is equal to p



#### 11 Demytko’s elliptic curve cryptosystem
密码方案参考[Demytko, N.: A new elliptic curve based analogue of RSA](https://link.springer.com/chapter/10.1007/3-540-48285-7_4)

- **特性**：
  1. 适用RSA模数的椭圆曲线。
  2. $gcd(e, (p^2-t_p^2)(q^2-t_q^2))=1$.
  3. $p\equiv q\equiv 2\ (mod\ 3)$

- **攻击方案**：参考[Nitaj A., Fouotsa E., "A New Attack on RSA and Demytko's Elliptic Curve Cryptosystem"](https://eprint.iacr.org/2019/1050.pdf) 如果满足条件则可以用Coppersmith方法攻击成功。



### 三 超椭圆曲线

一个在$F_q,q = p^l$上的亏格为$g$的超椭圆曲线$C$是由下面的方程构成 $$y^2+h(x)y=f(x)$$ 其中$h(x)$和$f(x)$是两个系数为$F_q$的多项式，其中$deg(h(x))\leq g$和$deg(f(x))=2g+1$。与此同时曲线需要满足非奇异的特性，即满足$$ \begin{cases} y^2+h(x)y=f(x)\\
2y+h(x)=0\\
h'(x)y-f'(x)=0
\end{cases} $$ 这三个方程没有解。

接下来对于有限域$F_q$的一个扩域$K$。记$L$为$F_q$的一个代数闭包，那么就有$F_q \subset K \subset L$。 

**除子：** 除子是超椭圆曲线$C$上的点$C(L)$的形式和，记$$D = Div_C(L) = \sum_{P\in C(L)}c_P[P]$$ 定义除子的度数$deg(D)$为$\sum_Pc_P$。对于扩域$K$，我们可以定义度数为0的在扩域$K$上的除子群，其中有$\#K = q^r$：$$Div_C^0(K):=\{ D\in Div_C(L) | deg(D) = 0, D^{\sigma^r} = D \}$$ 其中有$P^{\sigma} = (x^q,y^q)$且$D^{\sigma} = \sum_Pc_P[P^{\sigma}]$。

**order of vanishing：** 记$F(x,y)\in K[x,y]$，即函数$F$是系数为$K$的多项式。在P点的$F$的**order of vanishing**记$ord_P(F)$。直观上(不严谨)可以理解为$F$在$P$点上零点的重数。

定义有理函数$F/G,\ F,G\in K[x,y]$则对于有限远点$P$有$ord_P(F/G)=ord_P(F)-ord_P(G)$。非零的有理函数可以与度数为0的除子相联系$$ div(F/G) = \sum_{P\in C(L)}ord_P(F/G)[P] $$ 由系数在$L$上的有理函数生成的除子称为主除子或原则除子(principal divisor)，它构成了除子群$Div_C^0(L)$的一个子群，记为$P_C(L)$，并定义$P_C(K)=P_C(L) \cap Div_C^0(K)$

**Jacobian群：** 对于$F_q$的扩域$K$，曲线$C$的Jacobian的K-有理点的群为$Div_C^0(K)/P_C(K)$，记为$J_C(K)$。

* 椭圆曲线上的点加上一个无穷远点可以构成一个椭圆曲线点群。但是超椭圆曲线则无法找到一个运算让仅仅是超椭圆曲线上的点构成一个群。然后我们构造了$J_C(K)$这个群，它可以堪称是椭圆曲线点群的一个推广。在椭圆曲线上，我们可以找到一个映射$\phi : E(K)\rightarrow J_E(K)$。这是一个群同构映射。

接下来我们需要找到一个Jacobian群$J_C(K)$的一个显示的元素的表示方法。这种方法叫做``Mumford representation``。

* 命题：对于每个$J_C(K)$中的元素，都可以表示成一个群$Div_C^0(K)$中的一个规约除子(reduced divisor)。

**关键定义：** 一个除子$D$的``Mumford representation``是一个在$K[x]$上的多项式对$[u(x), v(x)]$。满足
1. $u(x)$是首一的；
2. $u(x) | f(x)-h(x)v(x)-v(x)^2$ ；
3. $deg(v(x)) \le deg(u(x)) \leq g$ ；

$J_C(K)$的运算规则在这里就不给出了，毕竟有现成的轮子的东西没有必要详细介绍。

**关键性质：** 若$$u(x)=\prod_{i=1}^d(x-x_i)$$ 其中$x_i \in K$。根据条件2可知点$(x_i, v(x_i))$是曲线$C$上的点。因此除子$$\sum_{i=1}^d([x_i,v(x_i)]-[\infty])$$是一个在$Div_C^0(K)$上的规约除子。因此超椭圆曲线上的$d\leq g$个点就对应着Jacobian群$J_C(K)$上的一个元素。 


> 题目 hxp CTF 2020 hyper 
题目本质上是给了超椭圆曲线的加密方案，但是密钥泄露了$u(x)$。然后只需要求出$v(x)$即可。根据$u(x)$我们可以知道$u(x)$的三个根，然后又因为点$(x_i, v(x_i))$在曲线$C$上。因此可以列出三个方程 $$(ax^2+bx+c)^2 = x^7 +x,$$解出参数$a,b,c$得到$v(x)$，然后就可以求出flag。 

参考write up：https://ctftime.org/writeup/25448







### 四 圆锥曲线
> 圆锥曲线存在着$\mathbb{F}_p$上的曲线也存在着$\mathbb{Z}_N$上的曲线。

圆锥曲线方程为$$C(\mathbb{F}_p):y^2=ax^2-bx \\ a,b\in \mathbb{F}_p$$ 其中当$a>0$时曲线为双曲线，$a=0$时曲线为抛物线，$a<0$时曲线为椭圆。这个曲线恒过$(0,0)$点。

圆锥曲线的安全性是基于离散对数问题所决定的，不同的参数选取有着不同的安全性。在选取安全性最高的情况下，GF(p)有限域上的圆锥曲线的安全性相当于扩域$\mathbb{F}_{p^2}$上DLP的安全性。

**漏洞**：其中当$a >=0$时，$a$有模$p$的二次剩余，此时可以通过同构映射映射到有限域$GF(p)$这个乘法群中。

* 存在同构映射$$M:C(\mathbb{F}_p)(x,y)\longrightarrow \phi_a(t) = \frac{t+\theta_1}{t+\theta_2} \\ t = \frac{y}{x} \\ \theta_1^2 \equiv \theta_2^2 \equiv a\ (mod\ p)$$ 把曲线上的点映射到有限域的乘法群中。因为$p$的取值不大，因此可以直接用`discrete_log`函数求解离散对数。

* 存在构造同构映射$$M:C(\mathbb{F}_p)(x,y)\longrightarrow \phi_a(t) = \frac{1}{t-\theta} \\ t = \frac{y}{x} \\ \theta^2 \equiv a\ (mod\ p)$$ 即$a$的二次剩余$\theta$有重根，把曲线上的点映射到有限域的加法群中，然后求个逆然后相乘可求解离散对数。

- 参考资料：
  - https://www.jiamisoft.com/blog/4068-yuanzhuiquxianjiamisuanfa.html
  - 徐旭东, 靳岩岩, 赵磊. 圆锥曲线公钥密码算法的参数选择[J]. 计算机工程, 2007, 33(15):3.





## 格密码 

### 格的基本定义

![格的定义](crypto/images/Lattice.png)

### 格相关研究现状

参考资料：https://ctf-wiki.org/crypto/asymmetric/lattice/overview/

1. 格中计算问题的困难性，即这些问题的计算复杂性，主要包括
   - SVP 问题
   - CVP 问题
2. 如何求解格中的困难性问题，目前既有近似算法，也有一些精确性算法。
3. 基于格的密码分析，即如何利用格理论分析一些已有的密码学算法，目前有如下研究
   - Knapsack cryptosystems
   - DSA nonce biases
   - Factoring RSA keys with bits known
   - Small RSA private exponents
   - Stereotyped messages with small RSA exponents
4. 如何基于格困难问题设计新的密码体制，这也是后量子密码时代的重要研究方向之一，目前有以下研究
   - Fully homomorphic encryption
   - The Goldreich–Goldwasser–Halevi (GGH) cryptosystem
   - The NTRU cryptosystem
   - The Ajtai–Dwork cryptosystem and the LWE cryptosystem


### 格上的困难问题
* **最短向量问题 (Shortest Vector Problem，SVP)**：给定格 $L$ 及其基向量 $B$ ，找到格 $L$ 中的非零向量 $v$ 使得对于格中的任意其它非零向量 $u$，有$||v||\leq||u||$。

* **$\gamma$-近最短向量问题(SPV-$\gamma$)**：给定格 $L$ 及其基向量 $B$ ，找到格 $L$ 中的非零向量 $v$ 使得对于格中的任意其它非零向量 $u$，有$||v||\leq\gamma||u||$。

* **连续最小长度问题 (Successive Minima Problem, SMP)**：给定一个秩为 $n$ 的格 $L$，找到格 $L$ 中 $n$ 个线性无关向量$s_i$，满足$\lambda_i(L)=||s_i||,\ 1\leq i\leq n$。

* **最短线性无关向量问题 (Shortest Independent Vector Problem, SIVP)**：给定一个秩为 $n$ 的格 $L$，找到格 $L$ 中 $n$ 个线性无关向量$s_i$，满足$||s_i||\leq\lambda_n(L),\ 1\leq i\leq n$。

* **最近向量问题 (Closest Vector Problem，CVP)**：给定格 $L$ 和目标向量$t\in R^m$，找到一个格中的非零向量 $v$，使得对于格中 $\forall u$，满足$||v-t||\leq||u-t||$。即在格$L$上找到一个离$t$最近的向量。

* **最短整数求解 (Short integer solution, SIS)**：给定$n\times m$的格$L$，找出一个非零向量解$x\in \mathbb{Z}^m$，使得$\parallel x\parallel \leq \beta$和$Lx=0\in \mathbb{Z}_q^n$成立。其中$m,n,q,\beta$是给定的数，要保证方程有非奇异解，需要满足$\beta \geq \sqrt{nlog(q)}$和$m\geq nlog(q)$。对于**ring-SIS**，只需要满足$m\approx nlog(q)$。

### 格基规约算法(Lenstra–Lenstra–Lovasz, LLL)
* 参考论文: https://cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/lll.pdf

LLL算法本质上是将A lattice basis $B$转换为 LLL-reduced basis $\tilde{B}$，其中$\tilde{B}$是一个正交基组成的矩阵，去解决SPV-$\gamma$问题。**“转换”** 就是要做Gram-Schmidt正交化，但要满足两个条件
1. For every $i < j$, we have $|\mu_{i,j}|\leq\frac{1}{2}$. (Such a basis is said to be "size reduced.") **目的是保证Gram-Schmidt正交化不会太小**
2. For every $1\leq i < n$, we have $\frac{3}{4}||\tilde{b}_i ||^2 \leq ||\mu_{i,i+1} \tilde{b}_i + \tilde{b}_{i+1}||^2$.  (This is the "Lovasz condition.") **目的是保证缩减不要太快**

这里的$\mu$表示的是，$B=\tilde{B}U$中矩阵$U$的某些元素。其中$U$是一个单位上三角矩阵，对角线全为1，然后对角线往上的元素第$i$行第$j$列的元素记为$\mu_{i,j}$。

主要性质（解决SPV-$\gamma$）：
![格LLL算法](crypto/images/LLL.PNG)

- **经常使用的界：** 对于一个$\omega\times\omega$的格基，其LLL算法规约后的格基$v_1,...,v_{\omega}$，（$det$表示的是行列式）有$$\parallel v_1\parallel \leq 2^{\frac{\omega-1}{4}}det(L)^{\frac{1}{\omega}}$$


### BKZ (Block Korkin-Zolotarev)
有兴趣可以自己研读一下下面的文献，就是具体描述BKZ算法的文章。
- https://rd.springer.com/content/pdf/10.1007%2F978-3-642-25385-0_1.pdf    BKZ 2.0: Better Lattice Security Estimates
- Shor, P.W.: Algorithms for quantum computation: discrete logarithms and factoring. In: Proceedings 35th Annual Symposium on Foundations of Computer Science. pp. 124–134. IEEE, Santa Fe, NM, USA (Nov 1994)

算法接受两个额外参数的输入，$\beta$和$\epsilon$，$\epsilon$ 是LLL算法的输入，$\beta$ 是BKZ独有的。基的输入为$B=(b_1,...,b_n)$

**目标**：求出基$B$的LLL算法的结果，然后$\forall 1\leq j \leq n$，$\parallel b_j^* \parallel = \lambda_1(L_{j,k})$，其中$k=min(j+\beta+1, n)$

**效率**：一般来说BKZ 2.0的效率和效果是格基规约算法中最好的，具体实现有兴趣可以研读论文。

LLL算法和BKZ算法在Sagemath中的调用见`crypto/Sagemath_Usage.md`

> 一般来说可以尝试一下BKZ中的$\beta$取20




### Babai's nearest plane algorithm
* 此算法用来求CVP问题的近似解，算法复杂度归结于LLL算法。
* 参考文献
    * https://cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/cvp.pdf
    * https://www.isg.rhul.ac.uk/~sdg/igor-slides.pdf

**该算法输入一组格$L$(秩为$n$) 的基$B$ 和一个目标向量$t$，输出 CVP 问题的近似解，既一个在格上的距离向量$t$最短的向量**，近似因子$\gamma =2^{\frac{n}{2}}$。具体算法如下，本质上是LLL算法：
![Babai's nearest plane algorithm](crypto/images/BabaisNearestPlaneAlgorithm.PNG)
这里的$b_j$表示的是经过LLL算法变换之后个格基的第$j$个向量。

#### Babai’s Rounding Technique
该算法是``Babai's nearest plane algorithm``的一个变种。

参考文献
- https://link.springer.com/content/pdf/10.1007/BF02579403.pdf  

#### Hidden number problem
* 该问题可以规约到CVP问题并使用Babai's nearest plane algorithm解决。

**HNP:** Recover $\alpha \in F_p$ such that for many known random $t\in F_p$ we are given $MSP_{l,p}(\alpha t)$ for some $l > 0$. 
**MSB:** $MSB_{l,p}(x)$ denotes any integer $u$ such that $$|\lfloor x \rfloor_p-u |\leq \frac{p}{2^{l+1}}$$ $MSB_{l,p}(x) \approx l$ **M**ost **S**ignificant **B**its of $x$. **表示的就是在模$p$下的$l$比特最高有效位**
**B&V, 1996:** a polynomial time algorithm to solve HNP with $l \approx log^{1/2}p = (log(p))^{1/2}$.

又参考文献 https://www.isg.rhul.ac.uk/~sdg/igor-slides.pdf 可知当$l \approx log^{\frac{1}{2}}p$时，可以讲此问题规约到一个CVP问题。

* 算法流程：
* 输入：给出素数$p$整数$l$且$l$满足$l\approx log^{\frac{1}{2}}p$，$n$个$t\in F_p$，对应的$n$个数$u_i = MSB_{l,p}(\alpha t_i)$。
* 输出：满足条件的数$\alpha$。
* 首先构造矩阵$$
\left[\begin{matrix}
p & 0 & \cdots & 0 & 0\\
0 & p & \cdots & 0 & 0\\
\vdots & \vdots & \ddots & \vdots & \vdots\\
0 & 0 & \cdots & p & 0\\
t_1 & t_2 & \cdots & t_n & \frac{1}{2^{l+1}}
\end{matrix}\right]
$$ 注意：这里每一行代表一个向量，因此使用LLL算法求线性组合的时候，最后一个向量只有一个系数，记为$\alpha$。设其它线性组合的系数为$z_i$，那么LLL算法所求的向量就入下方向量$\pmb{v}$所示。
* 然后使用``Babai's nearest plane algorithm``找出距离向量$\pmb{u} = (u_1, u_2, ..., u_n, 0)$最近的一组向量$\pmb{v}$。具体过程如下：
    * 首先对矩阵进行LLL算法得到一组格基$$(\pmb{b_1,b_2,...,b_{n+1}})  $$
    * 算法第二步有$\pmb{u}$需要减去向量$$\sum_{i=1}^{n+1}c_i\pmb{b_i} = \newline  (\sum_{i=1}^{n+1}c_i(b_{i,1}p+m_{n+1,i}t_i), ... ,  \sum_{i=1}^{n+1}c_im_{n+1,i}\frac{1}{2^{l+1}}) \newline = (z_1p+\alpha t_1, ..., z_np+\alpha t_n, \alpha\frac{1}{2^{l+1}}) \newline \equiv (\alpha t_1, \alpha t_2, ..., \frac{\alpha}{2^{l+1}}) \ mod\ p$$ 其中$m_{n+1,i}$表示LLL算法的转换矩阵的最后一行的第$i$个元素。
    因此可以求出在格上离距离向量$\pmb{u}$最短的向量$\pmb{v} = (\alpha t_1, \alpha t_2, ..., \frac{\alpha}{2^{l+1}})$，此时$\alpha$就可以求出。


参考文献：
- 标准HNP
  1. https://www.anquanke.com/post/id/204846#h2-1
  2. https://blog.soreatu.com/posts/intended-solution-to-nhp-in-gxzyctf-2020/
  3. https://www.anquanke.com/post/id/197749#h2-5


##### Hidden Number Problem with Hidden multiplier

- 参考资料：
  - [Analysis of Hidden Number Problem with Hidden Multiplier](https://www.aimsciences.org/article/doi/10.3934/amc.2017059)
  - [Hidden Number Problem with Hidden Multipliers](https://www.jstor.org/stable/4099844?seq=1#metadata_info_tab_contents)
  - [The Multivariate Hidden Number Problem](https://eprint.iacr.org/2015/111.pdf)

直观来说就是在标准的Hidden Number Problem问题$$at_i\equiv (S_i+e_i)\ (mod\ m)$$中，变成了$$a(t_i + e_{t_i})\equiv (S_i+e_i)\ (mod\ m)$$ 或者$$(a+e_a)(t_i + e_{t_i})\equiv (S_i+e_i)\ (mod\ m)$$的形式，这时一般来说都是用到第1，2篇文章进行求解。但是有时候也能自己构造格，然后进行求解。





#### Extend Hidden Number Problem (EHNP)

定义参考文献：[Extended Hidden Number Problem and Its Cryptanalytic Applications](https://link.springer.com/content/pdf/10.1007/978-3-540-74462-7_9.pdf)

该攻击可以用到DSA和ECDSA密码方案中。已知多个明文和签名对，而且知道每对签名中的随机数nonce的某个mask中的数。（即知道nonce的很多间隔的bit）。这时候可以转化位EHNP问题进行求解。已知有两篇论文提出了相关的求解，但是比较的复杂，还没有看懂。

另一个方案是先把方案转化为HPN问题，然后对HPN问题进行求解。

参考资料：[D3CTF_2022_leak_dsa](https://github.com/shal10w/D3CTF-2022-crypto-d3share_leakdsa)




#### BCTF 2018 - guess_number
比赛是一个典型的**Hidden number problem**，可以把这道题目的求解堪称是Hidden number problem的一个典型的解法。

* 题目代码``crypto/code/Hidden_Number_Problem/server.py``
* 解题代码``crypto/code/Hidden_Number_Problem/Hidden_Number_Problem.sage``



#### GGH公钥密码体制

这是一个困难性基于格的最短向量问题的密码算法($CVP_{\gamma},search$)，密码构造如下：
* KeyGen
    1. 选择一组好基(Good basis)哈达马比例(Hadamard ratio)接近1的基称为好基。记为$V = v_1,...,v_n$.
    2. 选择一个矩阵$U$满足$det(U) = \pm 1$.
    3. 计算$W = UV$，则$W$为公钥，$V,U$为私钥.
* Encryption
    1. 给定明文向量$m$；选择足够小的向量$r$，两者都有$n$个元素.
    2. 计算$e = mW+r$，$e$为密文.
* Decryption
    * 计算$m = eV^{-1}U^{-1}$.因为$r$足够小，因此可以约掉。

* 攻击：当方案设计不当时可以使用Babai's nearest plane algorithm进行求解.

* 参考代码
    ```python
    # Sagemath 9.2
    W = matrix()    # n * n

    e = vector()    # n

    def babai(A, w):
        A = A.LLL(delta=0.75)
        G = A.gram_schmidt()[0]
        t = w
        for i in reversed(range(A.nrows())):
            c = ((t * G[i]) / (G[i] * G[i])).round()
            t -= A[i] * c
        return w - t

    V = babai(W, e)
    print(V * W^-1)
    ```

* 参考文献：
    * https://zhuanlan.zhihu.com/p/337003376
    * https://staff.emu.edu.tr/alexanderchefranov/Documents/CMSE491/CMSE491%20Fall2020/Hoffstein2015%20Introduction%20to%20Mathematical%20Cryptography%20409-412%20GGH.pdf



#### LWE (learning with errors)
$b = As+e$，$b,A,e$已知，求解$s$。$b,e,s$是向量，$A$是一个矩阵。

* 有三种类型的攻击方案：
  1. 代数攻击：Arora-Ge 及其变种
  2. 组合式：Blum-Kalai-Wasserman(BKW) 及其变种
  3. 几何：格的各种攻击

- 参考资料：
  - [Lattice Attacks for Variants of LWE Slides](https://www.microsoft.com/en-us/research/uploads/prod/2019/06/Lattice-Attacks-for-Variants-of-LWE-slides.pdf)
  - [crypto-attack Arora-Ge attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lwe/arora_ge.py)




### Short integer solution, SIS
如果能构造出一个$n\times m$的格$L$使得$$Lx=0$$ 而且解$x$是长度比较小的向量。那么就可以先求解出格$L$的零空间，然后对零空间使用LLL算法，把长度比较短的解$x$求出。

**约束条件**：首先解$x$需要有一个界，其次格的维数有一定的约束，列向量的维数$m$需要大于某个界，具体的界还没有弄清楚。


参考题目：N1CTF 2019 Guess_ex





### Lattice-Based Encryption 
#### NTRU encrypt
NTRUEncrypt 公钥密码系统，也称为 NTRU 加密算法，是 RSA 和椭圆曲线密码 (ECC) 的基于 NTRU 格的替代方案，它基于格中的最短向量问题（不知道使用 量子计算机）。

它依赖于将截断多项式环中的某些多项式分解为具有非常小系数的两个多项式的商的假定难度。 破解密码系统与某些格中格约简的算法问题密切相关，但并不等同。 仔细选择参数对于阻止一些已发布的攻击是必要的。

wikipedia 中有比较详细的算法描述

* reference：
  * [NTRUEncrypt](https://en.wikipedia.org/wiki/NTRUEncrypt)
  * [Practical lattice-based cryptography: NTRUEncrypt and NTRUSign](http://citeseerx.ist.psu.edu/viewdoc/download?rep=rep1&type=pdf&doi=10.1.1.217.1642)
  * [NTRUCipher-Lattice Based Secret Key Encryption](https://arxiv.org/pdf/1710.01928.pdf)



### Lattice-Based Signature

> 相当于是用一篇文献，该文献的参考文献中就引出了很多英文文献

* GGH signature scheme
  * 使用了 **Hermite form of matrix**
  * Goldreich, O., Goldwasser, S., Halevi, S.: Public-key cryptosystems from lattice reduction problems. In: Kaliski, B.S. (ed.) Advances in Cryptology - CRYPTO ’97: 17th Annual International Cryptology Conference, Santa Barbara, California, USA, August 17-21, 1997. Proceedings. Lecture Notes in Computer Science, vol. 1294, pp. 112–131. Springer Berlin Heidelberg, Berlin, Heidelberg (1997), https://doi.org/10.1007/BFb0052231
  * Nguyen P Q ,  Regcv O . Learning a Parallelepiped: Cryptanalysis of GGH and NTRU Signatures[J]. Journal of Cryptology, 2009, 22(2):139-160.  （**给出大量签名，可以恢复出GGH和NTRU签名方案的私钥**）
* NTLU Signature
  * [NTRUSign](https://en.wikipedia.org/wiki/NTRUSign) 里面有比较多的参考文献
  * [Practical lattice-based cryptography: NTRUEncrypt and NTRUSign](http://citeseerx.ist.psu.edu/viewdoc/download?rep=rep1&type=pdf&doi=10.1.1.217.1642)
  * 迟欢欢,李金波,张平.基于NTRU格的数字签名方案[J].网络安全技术与应用,2021(12):34-36. 
* LWE Signature 
* GPV signature scheme


> 使用BKZ或LLL算法有可能能获取签名方案中所设计的好基(good basis)



## 同态加密

> 同态加密一般会因为算法本身的复杂度而不会出太难，可能就会让我们推一推解密算法。

### 半同态加密

#### 1. Paillier Encryption Scheme

* 参考：INTRODUCTION TO MODERN CRYPTOGRAPHY 第二版第13章

Paillier加密系统用到了群$Z^*_{N^2}$。而且一般来说$p = 2p'+1, q=2q'+1$都会取强素数。实质上模$N^2$的群并不是一个循环群，它与一个阶为2的群和一个阶为$2pp'qq'$的群同构，但是该阶为$2pp'qq'$的群也不是循环群，因为该群有一半的元素不是平方剩余，只有有平方剩余的元素才构成循环群。因此模$N^2$的循环群的阶为$pp'qq'$。生成的方式为任取模$N^2$中的元素$a$，则$g\equiv a^2\ mod\ N^2$是循环群的一个生成元。

其中一个比较重要的性质是群 $Z^*_{N^2}$ 同构于群$Z_N \times Z_N^*$。其中三个重要性质如下：
![](crypto/images/Proposition_for_Paillier.PNG)

* 一些有用的性质：
    * $\phi(N^2) = pq(p-1)(q-1) = N\phi(N)$ .
    * $a\in Z^*_{N^2}$，则有$a^{\phi(N)} \equiv (1 + kN)\ mod\ N^2$.
    * 若$f(a_1,b_1) = f(a_2,b_2)$，则$(1+N)^{a_1-a_2}\cdot (b_1/b_2)^N \equiv 1\ mod\ N^2$.
    * $f(a_1,b_1)\cdot f(a_2,b_2) = f(a_1+a_2, b_1\cdot b_2)$

因此我们可以看成$Z^*_{N^2}$上的元素$c$和$Z_N \times Z_N^*$上的元素$(m,r)$是等价的。
* Paillier 密码方案
* **KeyGen:** 选取两个大素数$p,q$，保证$gcd(pq,(p-1)(q-1))=1$，$n=pq$。其中$N$为公钥，$p,q$为私钥。
* **Encryption(m):**  
    1. 随机选取一个元素$r\in Z^*_N$.
    2. 计算$c = [(1+N)m\cdot r^N\ mod\ N^2]$
* **Decryption(c):** 解密条件！！！分解$N$
    * 计算$m = [\frac{[c^{\phi(N)\ mod\ N^2}]-1}{N} \cdot \phi(N)^{-1}\ mod\ N]$

* 因此此加密方案基于的困难性问题是大数分解。

* 同态性：加法同态（密文相乘等于明文相加）$$((1+N)^{m_1}r_1^N)((1+N)^{m_2}r_2^N)\ =\ (1+N)^{(m_1+m_2)mod\ N}(r_1r_2)^N\ mod\ N^2.$$


#### 2. BCP密码系统

* 参考论文：https://www.iacr.org/archive/asiacrypt2003/01_Session01/03_106/28940037.pdf

* 参考文献：https://zhuanlan.zhihu.com/p/428331342

> BCP密码系统是基于Paillier密码系统设计的，其特点是有两种解密算法，用于解密用户的私钥或使用主钥解密。

* 密码方案：
![](crypto/images/BCP.PNG)
主密钥就是$\lambda(N)$，用户的私钥是$x$。在实际使用这个密码系统的时候，有个BOSS先生成$(N,g)$（系统公钥），并知道的分解$N=pq$（系统私钥）。在这个系统下，有多个用户，每个用户都根据系统公钥并根据等式$y=g^x\ mod\ N^2$生成彼此不同的用户公钥$y$和用户私钥$x$。系统外的人不能解密任何密文，普通用户只可以用他对应的用户私钥来解密他自己的密文，而BOSS可以**利用系统密钥解密任何用户的密文**。


### 全同态加密

> TODO



## 概率加密


### Goldwasser-Micali cryptosystem

Message encryption
Suppose Bob wishes to send a message m to Alice:

1. Bob first encodes m as a string of bits $(m_1, ..., m_n)$.
2. For every bit ${\displaystyle m_{i}}m_{i}$, Bob generates a random value ${\displaystyle y_{i}}y_{i}$ from the group of units modulo $N$, or ${\displaystyle \gcd(y_{i},N)=1}\gcd(y_{i},N)=1$. He outputs the value ${\displaystyle c_{i}=y_{i}^{2}x^{m_{i}}{\pmod {N}}}c_{i}=y_{i}^{2}x^{{m_{i}}}{\pmod  {N}}$.
Bob sends the ciphertext $(c_1, ..., c_n)$.

Message decryption
Alice receives $(c_1, ..., c_n)$. She can recover m using the following procedure:

For each i, using the prime factorization $(p, q)$, Alice determines whether the value $c_i$ is a quadratic residue; if so, $m_i = 0$, otherwise $m_i = 1$.
Alice outputs the message $m = (m_1, ..., m_n)$.

参考资料：
- https://en.wikipedia.org/wiki/Goldwasser%E2%80%93Micali_cryptosystem
- 《密码学原理与实践》第三版 8.4节


### Blum–Goldwasser cryptosystem

> 此密码体制用到了BBS生成器生成的随机数,**并可以扩展到window的形式**

- **Keygen:**
  - $p\equiv q\equiv 3\ (mod\ 4)$, $n=pq$
  - $r\in Z_n^*$
  - $sk:p,q$，$pk:n$
- **Encrypt:($m:(m_1,...,m_l)$, pk)**
  - $s_0=r$，用BBS生成器生成$z_1,...,z_l$
  - $s_{l+1}=s_0^{2^{l+1}}\ mod\ n$
  - For $1\leq i\leq l$,计算$y_i=(x_i+z_i)\ mod\ 2$
  - **return** $(y_1,...,y_l,s_{l+1})$
- **Decrypt:(密文，sk)**
  - $a_1 = ((p+1)/4)^{l+1}\ mod\ (p-1)$
  - $a_2 = ((q+1)/4)^{l+1}\ mod\ (q-1)$
  - $b_1 = s_{l+1}^{a_1}\ mod\ p$
  - $b_2 = s_{l+1}^{a_2}\ mod\ q$
  - 使用中国剩余定理找出$$r\equiv b_1(mod\ p),\ r\equiv b_2(mod\ q)$$
  - 把$r$作为BBS生成器生成$z_1,...,z_l$
  - $\forall 1\leq i\leq l$计算$m_i = (y_i+z_i)\ mod\ 2$
  - 明文为$m = (m_1,...,m_l)$


> 在Sagemath中有此密码系统的加解密接口

参考资料：
- https://en.wikipedia.org/wiki/Blum%E2%80%93Goldwasser_cryptosystem
- 《密码学原理与实践》第三版 8.4节





# 哈希函数

哈希函数（Hash Function）把消息或数据压缩成摘要，使得数据量变小。即把任意长度的消息hash成固定长度的序列。

定义：一个Hash族是满足下列条件的四元组$(\mathcal{X,Y,K,H})$：
1. $\mathcal X$是所有可能的消息的集合。
2. $\mathcal Y$是由所有可能的消息摘要或认证标签构成的有限集。
3. $\mathcal K$是密钥空间，是所有可能的密钥构成的有限集。
4. 对于每个$K\in \mathcal K$，存在一个Hash函数$h_K\in \mathcal H, h_K:\mathcal X \rightarrow \mathcal Y$。

* Hash 函数的安全性
    * 抗原像(Preimage)攻击:已知$H(y)$，找出$x$，使得$H(x)=H(y)$
    * 抗第二原象攻击(抗弱碰撞性):对于任意消息 $x$，找到满足另一消息 $y$，满足$H(x)=H(y)$，在计算上不可行。
    * 抗强碰撞性:找到任意一对满足$H(x)=H(y)$的消息 $x$ 和 $y$ 在计算上不可行。
    * 伪随机性

* Hash 函数用途
    * 保证消息完整性
    * 冗余校验
    * 口令
    * 入侵检测
    * 身份认证
    * 数字签名
    * 消息认证码MAC(message authentication codes)
    * ...

## MD5
* 输入：任意长度消息，512bit分组。
* 输出：128bit的Hash值。

此外，有时候我们获得到的 md5 是 16 位的，其实那 16 位是 32 位 md5 的长度，是从 32 位 md5 值来的。是将 32 位 md5 去掉前八位，去掉后八位得到的。

一般来说，我们可以通过函数的初始化来判断是不是 MD5 函数。一般来说，如果一个函数有如下四个初始化的变量，可以猜测该函数为 MD5 函数，因为这是 MD5 函数的初始化 IV。

``0x67452301，0xEFCDAB89，0x98BADCFE，0x10325476``

* **破解:**
    * http://www.cmd5.com/
    * http://www.ttmd5.com/
    * http://pmd5.com/
    * https://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5.exe.zip (生成指定前缀的 md5 碰撞)


## SHA1
* 输入：任意长的消息，分为 512 比特长的分组。首先在消息右侧补比特 1，然后再补若干个比特 0，直到消息的比特长度满足对 512 取模后余数是 448，使其与 448 模 512 同余。
* 输出：160 比特的消息摘要。

一般来说，我们可以通过函数的初始化来判断是不是 SHA1 函数。一般来说，如果一个函数有如下五个初始化的变量，可以猜测该函数为 SHA1 函数，因为这是 SHA1 函数的初始化 IV。
``0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476 0xC3D2E1F0``
* **破解:**
    * The First Collision for Full SHA-1[C]// Annual International Cryptology Conference. Springer, Cham, 2017.
    * SHA1 已经不再安全了，因为之前谷歌公布了求得两个 sha1 值一样的 pdf，具体请参考 https://shattered.io/
    * https://alf.nu/SHA1

## MAC，HMAC，CMAC

> MAC（消息认证码）：是满足某些安全性质的带密钥的HASH函数。

* MAC的输入：信息m；密钥k
* MAC的输出：固定长度的Hash值

构造MAC的一个常用方法是通过把一个密钥作为被Hash的消息的一部分。记$h$为不带密钥的迭代Hash函数来构造一个带密钥的Hash函数$h_K$，记$K$为密钥。

> HMAC 

HMAC是于2002年3月被提议的作为FIPS标准的嵌套MAC算法。HMAC的产生是使用Hash函数。
例子：基于SHA-1描述HMAC，这个版本的HMAC使用了512bit的密钥$K$。$x$为消息，记ipad和opad为$$ipad=3636...36 \newline opad = 5C5C...5C$$ 则160bit的HMAC定义为：$$HMAC_K(x)=SHA-1((K\oplus opad)\parallel SHA-1((K\oplus ipad)\parallel x))$$ 如图：![HMAC](crypto/images/HMAC.PNG)

* HMAC作为MAC事安全的
> CMAC

CMAC是基于分组加密的消息认证码。CMAC的产生是使用分组加密算法（不用Hash函数）。它是一个ANSI标准（X9.17）。CBC-MAC实际上就是对消息使用CBC模式进行加密，取密文的最后一块作为认证码。设CMAC的输出的长度为$n$比特，那么输入的信息的长度必须是$n$的整数倍(可使用各种填充方案进行填充)。

流程如下：![CBC MAC](crypto/images/CBC_MAC.png)

* 常见的CMAC有**AES-CMAC**，本质上就是其加密函数$E$使用的就算是AES加密。

> 代码实现：
```python
#python3

############## HMAC ################
from Crypto.Hash import HMAC, SHA256
key = b'EE5815'
M = b'Hi Bob, let us meet at noon'
h = HMAC.new(key, msg=M, digestmod=SHA256)
hmac= h.hexdigest()
print(hmac)
# 668808fd32a4489382523347e23407b7c22ae25c7cb1f768c6dd1afcdcf84a3b

# 验证，若报错则表示验证失败
try:
    h.hexverify(hmac)
    print("The message '%s' is authentic" % M)
except ValueError:
    print("Unauthentic message or wrong key used")  


############## AES_CMAC ################
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
key = b'Our 16 byte key!'           # key必须是128bit
M = b'Hi Bob, let us meet at noon'  # M会自动填充
cobj = CMAC.new(key, msg=M, ciphermod=AES)  
cmac = cobj.hexdigest()
print(cmac)
# 294000f8a26b00dec9d2cd6e73c94617
#################################
# 注意：使用Crypto.Hash.CMAC函数实现CMAC的话使用的是CBC模式，
# 会自动生成填充密钥(代码里叫sub-key)，可以当作密钥，也可以当作填充，本质上是固定的
#################################
```




## Chaffing and winnowing

* 参考资料：https://en.wikipedia.org/wiki/Chaffing_and_winnowing

当通过不安全的通道发送数据时，可以在不使用加密的情况下实现机密性。这个名字来源于农业:在谷物被收获和脱粒后，它仍然与不可食用的纤维状谷壳混合在一起。然后通过簸谷将谷壳和谷粒分离，然后丢弃谷壳。这种密码技术是由Ron Rivest构想出来的，并于1998年3月18日发表在一篇在线文章中。

这个方案用到了MAC的技术。不对明文加密，但是会对明文的每一byte进行带密钥的MAC，然后随机生成一些不存在的MAC用来进行混淆。这样攻击者就无法识别到底用到了哪个明文。然后解密者和加密者有共同的私钥，对于正确的明文，解密者取满足MAC的明文，然后抛弃混淆的MAC。这样一来就在没有对明文加密的情况下实现了机密通信。





## Fowler–Noll–Vo hash function (FNV)
参考：https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function

此Hash函数首先把输入分块，然后初始化一个``FNV_offset_basis``和``FNV_prime``，最初始的hash值等于``FNV_offset_basis``。然后对于每个输入的块，把当前hash值乘以``FNV_prime``然后与输入的块进行异或。所有块处理完后就是最终的hash值。

* 这种Hash函数是一个非密码安全的Hash。一般用于快速hash，计算校验和，不用做密码。局限点如下：
    1. **计算速度**：计算速度上正向计算和逆向计算的速度接近。
    2. **粘稠**：因为只涉及乘法和异或运算，因此对于0较多的输入非常的敏感。
    3. **扩散**：因为只有异或运算，此hash函数的扩散性质可通过XOR-folding减轻。

#### 2018 网鼎杯 hashcoll
这道题目并不是标准的FNV哈希，而是有一点小的变动。该问题可以分析得到是：**给出$n$个数，求解它们的整线性组合使得线性组合所得到的结果为0**。一种求解的方法是使用格中的LLL算法进行求解。

* **算法原理：**
* 输入：给定$n$个(实/有理)数$a_1,a_2,...,a_n$
* 输出：求出$n$个数$z_1, z_2, ..., z_n$使得$\sum_{i=1}^nz_ia_i$等于0或尽可能等于0。   
* 过程：构造出矩阵$$
  B = \left[\begin{matrix}
  1 & 0 & \cdots & 0 & Ka_1 \\
  0 & 1 & \cdots & 0 & Ka_2 \\
  \vdots & \vdots & \ddots & \vdots & \vdots \\
  0 & 0 & \cdots & 1 & Ka_n
  \end{matrix}\right]^T
  $$ 然后使用LLL算法对矩阵$B$进行规约，得到转换矩阵$T'$。因此 有$B^TT' = \tilde{B}$。
  **注：若$B$是m行n列，则$T'$是m行n列，则$\tilde{B}$是n行n列的矩阵。在解决次问题的过程中，变换矩阵$T'$的最后$m-n$列是没有用的。**
    * 转换矩阵$T'$的第一行表示的就是所求的$z_1, z_2, ..., z_n$。记$\tilde{B}$的第一个向量为$v_1$。由![格LLL算法](crypto/images/LLL.PNG)这个性质可知，**LLL基的第一个向量$v_1$有着最短的向量长度**，即 $$||v_1||\leq 2^{\frac{n-1}{4}}(1+\sum^n_{i=1}\alpha_i^2)^{\frac{1}{2(n+1)}}$$ 记后一项为比较小的常数$c$。则 $$||v_1||\leq c \times 2^{\frac{n-1}{4}}$$
    * 这是一个比较小的数，然后我们知道向量$v_i$是原向量的线性组合，因此$v_i$的第$n+1$个元素为 
      $$v_i[n+1] = K\sum_{i=1}^nz_ia_i$$ 因此只要常数$K$足够大，那么后面的求和就必须足够小，因此当$a_i$全为整数的时候，该求和一定为0。(若$a_i$为实数，那么该求和可能就不为0，但是会比较接近0) 这就说明了算法的正确性。 
* 实验：在使用Sagemath进行编程实现的时候，矩阵是使用二重列表的形式表示。若记$B$为需要进行LLL变换的矩阵，那么每一个格上的向量使用一个列表进行表示。然后直接执行
``L = B.LLL()``
得到**LLL算法下新的格基**，这个新的格基的大小和$B$一致。算法的要求是转换矩阵的线性组合的系数。由于矩阵$B$在前$n\times n$的元素是个单位矩阵，因此系数矩阵与新的格矩阵在左上方$n\times n$的元素上相等。我们可以直接使用新的格基的第一行的前$n$个元素作为系数矩阵的系数来使用。

* ***具体Sagemath9.2代码见``crypto/code/LLL_n_positive_integral_combination.sage``*** 这里不是给出题解，而是给出如何使用LLL算法求解**给出$n$个数，求解它们的整线性组合使得线性组合所得到的结果为0**这个问题。

## Hash 函数的攻击
* 暴力攻击：不依赖于任何算法细节，仅与 Hash 值长度有关；
* 生日攻击 (Birthday Attack)：没有利用 Hash 函数的结构和任何代数弱性质，只依赖于消息摘要的长度，即 Hash 值的长度。
* 中间相遇攻击 (Meet-In-The-Middle)：是生日攻击的一种变形，不比较 Hash 值，而是比较中间变量。这种攻击主要适用于攻击具有分组链结构的 Hash 方案。
* 密码分析：依赖于具体算法的设计缺点。

### 暴力攻击
HashCat 工具 : https://hashcat.net/hashcat/
(没有尝试使用)








### 哈希长度拓展攻击（hash length extension attacks）
* 应用场景：MD5 和 SHA-1 等基于 Merkle–Damgård 构造的算法均对此类攻击显示出脆弱性。MD5, SHA1, SHA256, SHA512都可以。该攻击适用于在消息与密钥的长度已知的情形下，所有采取了 $H(key || message)$ 此类构造的散列函数。

* 攻击前提（hash算法的脆弱性）：MD5和SHA-1等哈希算法在运算的时候会对需要进行hash的消息进行分块，然后 **使用上一个块的运算结果作为下一个块的运算的初始向量** ，类似于AES的CBC模式，这是最关键的一点。
    * SHA-1: 参考https://www.cnblogs.com/gwind/p/8025130.html
    * MD5：参考https://blog.csdn.net/qq_35078631/article/details/70941204

* 攻击原理：最核心在于此等式成立$$h_K(x||x')=compress(h_K(x)||x')$$ 其中$h_K$需要每个输入消息的长度是$t$的倍数，然后$x'$是任意长度为$t$的倍数的比特串。

* 攻击流程：现在已知进行hash运算前会附加未知比特串salt记为$k$。已知$h(k)$的值和$k$的长度。就可以根据MD5或者SHA-1的填充规则进行填充，使得$$
h(k) = h(k||padding)
$$ 因此我们构造$x'=padding||m$，这样一来有 $$
h(k||x') = h(k||padding||x')$$  然后通过因为刚好在对$k||padding$进行hash的时候与$x'$的运算是分开两块的，因此$h(k||padding)$的输出会作为对$x'$进行hash运算的初始向量。因此有 $$ h(k||x') = h_{h(k)作为初始向量}(x')$$

* **工具 hashpump**：  https://github.com/bwall/HashPump
    * python中`hashpump`库有点难装，因此可以直接下载源码然后安装再运行。
    ```
    $ hashpump -h
        HashPump [-h help] [-t test] [-s signature] [-d data] [-a additional] [-k keylength]
        HashPump generates strings to exploit signatures vulnerable to the Hash Length Extension Attack.
        -h --help          Display this message.
        -t --test          Run tests to verify each algorithm is operating properly.
        -s --signature     The signature from known message.
        -d --data          The data from the known message.
        -a --additional    The information you would like to add to the known message.
        -k --keylength     The length in bytes of the key being used to sign the original message with.
        Version 1.2.0 with CRC32, MD5, SHA1, SHA256 and SHA512 support.
    ```
    只有少许的几个参数，然后不需要指定用的是哪个算法，因为长度都不一样，会自动识别。
    例子,可以加参数，也可以不加参数根据提示给数据：
    ``` bash
    > hashpump
    Input Signature: 571580b26c65f306376d4f64e53cb5c7
    Input Data: 123456
    Input Key Length: 20
    Input Data to Add: 654321
    af6f2842729baea20f2984f424897365
    123456\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x00\x00\x00\x00\x00\x00\x00654321
    ```

### hash 算法设计有误
一些自定义的 hash 算法可能是可逆的。通过分析出其逆函数，然后实现得到结果。

* **TIPS**：可以使用256个线性无关的256bit的hash值生成任意256bit的hash值。

### 工作量证明(proof of work)
很多时候题目要先要我们给出工作量证明，由于套路都比较类似，因此这里给出了一个方便的工作量证明的方法，在实际比赛的时候能直接用到。
```python
TABLE2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

def proof_of_work(str, hashh):
    l = len(TABLE2)
    for i in range(l):
        for j in range(l):
            for k in range(l):
                for ll in range(l):
                    tmp = (TABLE2[i] + TABLE2[j] + TABLE2[k] + TABLE2[ll]).encode()
                    if sha256(tmp + str).hexdigest().encode() == hashh:
                        print(tmp)
                        client.send(tmp + b'\n')
                        return
```

# 数字签名
数字签名（digital signature）主要用于对数字消息（digital message）进行签名，以防消息的冒名伪造或篡改，亦可以用于通信双方的身份鉴别。其基本原理如下：
![数字签名](crypto/images/Digital_Signature.PNG)

* 数字签名的特性
    * 不可伪造
    * 唯一
    * 可信(要有第三方参与)
    * 不可否认(不是所有签名都有这种特性？)

## RSA数字签名
原理类似于 RSA 加密，只是这里使用私钥进行加密，将加密后的结果作为签名。

**具体方案：** 给出$n=p,q$，有$ed\equiv1\ (mod\ \phi(n))$，其中$n,e$为公钥，$p,q,d$为私钥，则：$$sig_K(x)= y = x^e\ mod\ n$$ $$ver_K(x,y) = true \newline \Leftrightarrow x \equiv y^d\ mod\ n$$

* 破解方案与RSA破解类似

## ElGamal数字签名
> 没有加入hash

**具体方案：** 设$p$是一个使得在$Z_p$上的离散对数问题是难处理的素数，设$\alpha\in Z_p^*$是一个本原元(生成元)。设$\mathcal P = Z_p, \mathcal A = Z_P^*\times Z_{p-1}$，定义$$\mathcal K = \{(p,\alpha, a, \beta):\beta \equiv \alpha^a\ (mod\ p)\}$$ 其中$p,\alpha,\beta$是公钥，$a$是私钥。

- **Sign**
对于$K=(p,\alpha, a, \beta) \in \mathcal K$和一个(秘密)随机数$k\in Z_{p-1}^*$，$x$为需要签名的消息。则：$$sig_K(x,k)=(\gamma,\delta)$$ 其中 $$\gamma = \alpha^k\ mod\ p \newline \delta = (x-a\gamma)k^{-1}\ mod\ (p-1)$$ 
- **Verify**
对于$x,\gamma\in Z_p^*$和$\delta\in Z_{p-1}$，有 $$ver_K(x,(\gamma,\delta)) = true \newline \Leftrightarrow \beta^{\gamma}\gamma^{\delta}\equiv \alpha^{x}\ (mod\ p)$$

### 常见Elgamal攻击
#### 1.完全破译攻击
* $p$太小或$p$无大素因子
此时的攻击方法于Elgamal加密方案的破解方法一致，即使用大步小步法或者Pohlig-Hellman算法。

* 随机数$k$复用
如果签名者复用了随机数 $k$，那么攻击者就可以轻而易举地计算出私钥。

容易得$$\gamma = \alpha^k\ mod\ p \newline \delta_1 = (m_1-a\gamma)k^{-1}\ mod\ (p-1) \newline \delta_2 = (m_2-a\gamma)k^{-1}\ mod\ (p-1)$$ 进而有 $$\delta_1k \equiv m_1 - a\gamma\ mod\ (p-1) \newline \delta_2k \equiv m_2 - a\gamma\ mod\ (p-1)$$ 两式相减得 $$k(\delta_1-\delta_2)\equiv m_1-m_2\ mod\ (p-1)$$ 容易计算出随机数$k$，如果$gcd(\delta_1-\delta_2, p-1) \neq 1$，存在多个解，逐个去试即可。因此有私钥$$a = (m-k\delta)\gamma^{-1}\ mod\ (p-1)$$

#### 2. 通用伪造签名
如果消息$x$没有取哈希，或者消息$x$没有指定消息格式的情况下攻击成立。攻击者只能构造同构签名验证的信息，但无法伪造指定格式的消息。当消息$x$进行hash操作可避免此攻击。

**攻击流程：**
1. 选择整数$i,j$满足$gcd(j,p-1)=1$。
2. 计算签名：$$\gamma = \alpha^i \beta^j\ mod\ p \newline \delta = -\gamma j^{-1}\ mod\ (p-1)$$
3. 构造消息：$$x=-\gamma ij^{-1}\ mod\ (p-1)$$

验证：$$\beta^{\gamma}\gamma^{\delta} \equiv \alpha^{i\delta}\beta^{\gamma+j\delta} \equiv \alpha^{i\delta}\beta^{\gamma-j\gamma j^{-1}} \equiv \alpha^{-ij^{-1}\gamma} \equiv \alpha^x\ mod\ p$$

#### 3. 已知签名伪造
* 攻击者已知$\gamma,\delta$以及消息$x$。（已知消息攻击的存在性伪造）同样可以对消息$x$进行hash操作避免此攻击。

**攻击流程：**
1. 选择整数$h,i,j, 0\leq h,i,j \leq p-2$，且$gcd(h\gamma-j\delta, p-1)=1$。
2. 计算签名：$$\lambda = \gamma^h\alpha^i\beta^j\ mod\ p \newline \mu=\delta\lambda(h\gamma-j\delta)^{-1}\ mod\ (p-1)$$
3. 构造新消息：$$x'=\lambda(hx+i\delta)(h\gamma-j\delta)^{-1}\ mod\ (p-1)$$

验证： $$\beta^{\lambda}\lambda^{\mu}\equiv\alpha^{x'}\ mod\ p$$

#### 4. 选择签名伪造
* 如果可以做到选择消息攻击，即选择消息$m_1,m_2,...$进行签名。然后对一个消息$m'$，我们可以在不使用黑盒的前提下构造出$m'$的签名。

**攻击思想：** 因为要验证$$\beta^{\gamma}\gamma^{\delta}\equiv \alpha^{x}\ (mod\ p)$$ 只要选择一个消息$m$满足$m\equiv m'\ mod\ (p-1)$，选择$m$的签名$\gamma_m,\delta_m$，则有$$\alpha^{m'} \equiv \alpha^m \equiv \beta^{\gamma_m}\gamma_m^{\delta_m} $$

## DSA / DSS
DSA 最早在1991年8月被提出，1994年12月1日被采纳数字签名标准。DSA是ElGamal签名方案的一个变种。这个签名有时也被称为DSS签名

**具体方案：** 选择一个长度为$L$比特的素数$p$，在$Z_p$上的离散对数问题是难处理的，其中$L \equiv 0\ mod\ 64$且$512 \leq L \leq 1024$(可以更大)。选择$q$是一个$N$比特的素数，而且满足$q|p-1$。设$\alpha\in Z_p^*$是1模$p$的$q$次根，即$\alpha^q \equiv 1\ mod\ p$。设$\mathcal P = \{0,1\}^*,\mathcal A=Z_q^*\times Z_q^*$，并定义$$\mathcal K=\{(p,q,\alpha,a,\beta):\beta \equiv \alpha^a(mod\ p)\}$$ 其中$0\leq a \leq q-1$。$p,q,\alpha,\beta$是公钥，$a$为私钥。

- **Sign:**
对于$K=(p,q,a,\alpha, \beta) \in \mathcal K$和一个秘密随机数$k, 1\leq K\leq q-1$，选择一个哈希函数$H(x)$，$x$为需要签名的消息。则有
$$sig_K(x,k)=(\gamma, \delta)$$ 其中$$\gamma = (\alpha^k\ mod\ p)\ mod\ q 
\newline
\delta = (H(x) + a\gamma)k^{-1}\ mod\ q$$
且有$\gamma \neq 0$且$\delta \neq 0$。 

- **Verify：**
对于$x\in\{0,1\}^*$和$\gamma, \delta \in Z_q^*$，计算出： 
$$e_1 = H(x)\delta^{-1}\ mod\ q
\newline
e_2 = \gamma \delta^{-1}\ mod\ q$$ 验证：$$ver_K(x,(\gamma, \delta)) = true  \Leftrightarrow \newline (\alpha^{e_1}\beta^{e_2}\ mod\ p)\ mod\ q = \gamma$$

### 常见DSA攻击
#### 1. 已知随机数$k$
根据$\delta = (SHA-1(x) + a\gamma)k^{-1}\ mod\ q$，有私钥$a = \gamma^{-1}(k\delta - H(x))\ mod\ q$

#### 2. 随机数$k$复用
如果两次签名的过程中共享了随机数$k$，则有：
$$
\gamma_1 = \gamma_2 = \gamma
\newline
\delta_1 = (H(x_1) + a\gamma)k^{-1}\ mod\ q
\newline
\delta_2 = (H(x_2) + a\gamma)k^{-1}\ mod\ q
$$ 因此有 $$
\delta_1 k \equiv H(x_1) + a\gamma
\newline
\delta_2 k \equiv H(x_2) + a\gamma
$$ 两式相减得 $$
k(\delta_1 - \delta_2) \equiv H(x_1)-H(x_2)\ mod\ q$$  从而解出随机数$k$。然后使用第一个攻击方法恢复出私钥$a$。

#### 3. DSA/DSS with LCG Pseudo-Random 
**攻击条件**：如果DSA签名中的随机数$k$使用的是线性同余生成器所生成的，那么参考1997年的一篇文章（见参考文献），用格的方式可以求解。 
1. DSA签名
2. 线性同余生成器生成随机数$k$
3. 至少给出2对明文和签名对


首先会遇到$$\begin{cases} s_1k_1-r_1x = m_1\ (mod\ q) \\ s_2k_2-r_2x=m_2\ (mod\ q) \\ -ak_1+k_2 = b\ (mod\ M) \end{cases}$$ 的情况，然后我们构造下面的格进行求解 
$$\left[\begin{matrix} -r_1 & s_1 & 0 & q & 0 & 0 \\ -r_2 & 0 & s_2 & 0 & q & 0 \\ 0 & -a & 1 & 0 & 0 & M \\ \gamma_x^{-1} & 0 & 0 & 0 & 0 & 0 \\ 0 & \gamma_{k_1}^{-1} & 0 & 0 & 0 & 0 \\ 0 & 0 & \gamma_{k_2}^{-1}  & 0 & 0 & 0  \end{matrix}\right]$$ 
有时候该LCG会有不同的情况，需要根据实际情况去构造格


参考文献：
- [1] Bellare M ,  Goldwasser S ,  Micciancio D . pseudo-random number generation within cryptographic algorithms: the dss case[J].  2017.
- [2] "Pseudo-Random" Generators within cryptographic applications: the DSS case[J]. advances in cryptology—crypto ’, 1997.

参考题目： VNCTF 2022 AreYouAdmin


##### 3.1 (EC)DSA known MSB nonce
可以转化为HNP(Hidden_Number_Problem)问题，可参考格中HNP问题部分。
- [crypto-attack Lattice-based attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/hnp/lattice_attack.py)

##### 3.2 (EC)DSA known LSB nonce
可以转化为HNP(Hidden_Number_Problem)问题，可参考格中HNP问题部分。
- [crypto-attack Lattice-based attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/hnp/lattice_attack.py)

##### 3.3 (EC)DSA known Middle bits of nonce
可以转化为EHNP(Extended Hidden_Number_Problem)问题，可参考格中EHNP问题部分。
- [crypto-attack Lattice-based attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/hnp/lattice_attack.py)
- [De Micheli G., Heninger N., "Recovering cryptographic keys from partial information, by example" (Section 5.2.3)] 效果不如EHNP问题的求解。


## ECDSA 椭圆曲线数字签名算法
ECDSA算法有两种形式，第一种是类似于DSA算法的，第二种是类似于Elgamma签名方案的，本质上只是把其中的离散对数问题换成ECDLP。

参考资料：
- https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_generation_algorithm



## Schnorr签名算法

参考资料：https://en.wikipedia.org/wiki/Schnorr_signature

- **KeyGen**
  - 选择一个有限群$G$，其阶为素数$q$，生成元为$g$；选取一个hash函数$H$。
  - 随机选取$x\in \mathbb{Z}_q^*$，计算$y = g^x$。
  - 私钥为$x$，公钥为$y$。
- **Sign：(sk($x$), $M$)**
  - $M$为需要签名的消息，选取随机数$k\in \mathbb{Z}_q$，计算$r =g^k$。
  - 计算$e = H(r\parallel M)$
  - 计算$s = (k-xe)\ mod\ q$ 
  - 返回签名对$(s,e)$
- **Verify:(pk($y$), $(s,e), M$)**
  - 计算$r_v = g^sy^e$
  - 计算$e_v = H(r_v\parallel M)$
  - 如果$e_v = e$返回True，否则返回False


### EdDSA

参考资料：https://en.wikipedia.org/wiki/EdDSA
> 本质上就是schnorr算法的椭圆曲线的版本

- **KeyGen**
  - 选择一个椭圆曲线群$E(\mathbb{F}_q)$，其阶为素数$q$，生成元为$G\in E(\mathbb{F}_q)$；选取一个hash函数$H$。
  - 随机选取$x\in \mathbb{Z}_q^*$，计算$A = xG$。
  - 私钥为$x$，公钥为$A$。
- **Sign：(sk($x$), $M$)**
  - $M$为需要签名的消息，选取随机数(强调：一定要是随机的)$k\in \mathbb{Z}_q$，计算$R =kG$。
  - 计算$e = H(R\parallel xG \parallel M)$
  - 计算$s = (k+xe)\ mod\ q$ 
  - 返回签名对$(s,R)$
- **Verify:(pk($A$), $(s,R), M$)**
  - 计算$e_v = H(R\parallel A \parallel M)$
  - 计算$R_v = sG-eA$
  - 如果$R_v = R$返回True，否则返回False

**Schnorr多签名**：[Simple Schnorr Multi-Signatures with Applications to Bitcoin](https://eprint.iacr.org/2018/068.pdf)

### schnorr 算法的常见攻击
- 随机数$k$相同，手动推一下，很简单的。


- 多变量签名，如果允许多方的公钥相加，那么就能在不知道对方私钥的情况下伪造出满足条件的签名


## Boneh-Boyen Scheme 签名算法
主要算法见
![Boneh-Boyen_signature](crypto/images/Boneh-Boyen_signature.PNG)
签名算法主要基于q-SDH 问题，该问题主要见第2、3篇参考资料。

参考资料中有该签名算法的一个攻击

参考资料：
- Yoshida K . Boneh-Boyen signatures and the strong Diffie-Hellman problem. [J]. 2009. 
- Dan Boneh and Xavier Boyen. Short signatures without random oracles. In Advances in Cryptology—EUROCRYPT 2004, volume 3027 of Lecture Notes in Computer Science, pages 56–73. Springer, 2004.
- Dan Boneh and Xavier Boyen. Short signatures without random oracles and the SDH assumption in bilinear groups. Journal of Cryptology, 21(2):149–177, 2008.




# 素性检测 TODO

## Fermat Test

## Miller-Rabin Test

## Lucas Test

## Baillie-PSW

## 伪素数的生成
针对不同的素性检测算法，有着不同的伪素数生成规则，使得生成的伪素数用对应算法会以高概率判断为素数。

- 参考资料
  - [R. Albrecht M. et al., "Prime and Prejudice: Primality Testing Under Adversarial Conditions"](https://pure.royalholloway.ac.uk/portal/files/31050130/main.pdf) 文章有各种素性检测算法的介绍，并给出了针对Miller-Rabin Test和Lucas Test的伪素数生成算法。
  - [crypto-attack presudoPrime](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/pseudoprimes/miller_rabin.py) 这里的代码生成的是$p_1*p_2*p_3$形式的能通过Miller-Rain素性检测的伪素数。


# 常见数论求解
## 1. 二次剩余求解
已知
$$
x^2\equiv a\ (mod\ p)
$$
求$x$.

### 1.1 $p$是形为$4k+3$的素数
1. 若 $x^2\equiv a\ (mod\ p)$ 有解则其解为
$$
x\equiv\pm a^{\frac{p+1}{4}}(mod\ p)
$$
2. 若 $x^2\equiv a\ (mod\ pq)$ 有解,$p,q$是形为$4k+3$的素数,则其解为
$$
x\equiv\pm (a^{\frac{p+1}{4}}(mod\ p))\cdot s\cdot q\pm(a^{\frac{q+1}{4}}(mod\ q))\cdot t\cdot p\ \ (mod\ pq)
$$
### 1.2 $p$是一般的奇素数
代码见`crypto/code/square_root_of_quadratic_residue.py`
参考资料：https://learnblockchain.cn/article/1520

### $x^2+y^2=p$
> 待完成

### 1.3 光滑数
光滑数的定义：B为一个正整数，如果一个自然数N的因子分解式中没有大于B的因子，我们就称N是一个B光滑数。

## 2. 近似最大公约数(Approximate Greatest Common Divisor)
给定两个整数$n_1 = q_1p$，$n_2 = q_2p$，则两者的最大公约数为$p = gcd(n_1,n_2)$。

若$n_1 = q_1p+r_1$，$n_2 = q_2p+r_2$，则求$n_1$与$n_2$的近似最大公约数$p$是有一定难度的。在普遍情况下是一个困难问题，但是当$r_i$比较小的时候是可以用过LLL等算法进行求解。本质上是第二种算法(OL)

第二篇参考资料里面分为3个算法
1. Multivariate polynomial approach (MP)
2. Orthogonal based approach (OL)
3. Simultaneous Diophantine approximation approach (SDA)

**参考例题：2021年RCTF—— Crypto —— Uncommon_Factors_II**
writeup见`crypto\2021_RCTF\2021_RCTF_Uncommon_Factors_II`

参考资料：
* https://martinralbrecht.wordpress.com/2020/03/21/the-approximate-gcd-problem/
* https://eprint.iacr.org/2016/215.pdf

常用求解方法（不同的方法对应着一定的约束条件，不满足条件则无法完成）：
* Simultaneous Diophantine approximation approach (SDA)
* Orthogonal based approach (OL)
* Multivariate polynomial approach (MP)

## 3. 解一元多次方程组
### 3.1 整数开n次方根
使用`python`中的`gmpy2.iroot(num, n)`函数。

### 3.2 有限域中一元多次方程组
```python
# Sagemath 9.2
P.<x> = GF(p)[]
f = x^2 + ax + b
f.roots()
```

## 4. 高斯整数相关
> 这里主要使用到的是对素数进行分解，和构造$a^2+b^2=n$

* 参考资料：https://blog.csdn.net/weixin_45697774/article/details/113444562

### 4.0 基础知识
形如 $a + bi$（其中$a , b$是整数）的复数被称为高斯整数，高斯整数全体记作集合 $ Z[i] = \{ a + bi | a,b \in Z\}, \ where \ i^2 = -1$，换言之，高斯整数是实部和虚部都为整数的复数。由于高斯整数在乘法和加法下交换，它们形成了一个**交换环**。

**定义1**： 若 $\epsilon\ | \ 1$，则称高斯整数 $\epsilon$ 是 **单位** ，若 $\epsilon$ 是单位，则称 $\epsilon\alpha$ 是高斯整数 $\alpha$ 的一个**相伴**，高斯整数的单位为 $1,-1,i,-i$。

**定义2**： 若非零高斯整数 $\pi$ 不是单位，而且只能够被单位和它的相伴整除，则称之为高斯素数。

**性质：**
* 高斯整环是一个唯一分解域，所以每一个高斯整数都可以写为一个单位元和若干高斯素数的乘积，这种分解是唯一的（忽略共轭和相伴）
* 两个高斯整数的最大公约数并不唯一，若$d$ 是 $a$ 与 $b$ 的最大公约数，则 $a,b$ 的最大公约数为 $d,−d,id,−id$。
* 若$p$是一个素数，则$p$可以写成两个平方数的和，当且仅当$p=2$或$p\equiv 1(\ mod\ 4)$。
    * 证明：![](crypto/images/Fermat_sum_of_two_squares_theorem.PNG)


### 4.1 分解$4k+1$型素数
已知$p$是$4k+1$型素数，如果$k^2\equiv -1\ (mod\ p)$，则有$p|(k+i)(k-i)$，因此$p=u\bar{u}$，其中$u=k+i$。

因此因为有一半的数在模$p$下是平方剩余，因此烧出一个数$t$，验证$t^{\frac{p-1}{2}}\equiv -1(mod\ p)$，则有$k=t^{\frac{p-1}{2}}$。

* 虽然这里讲了这么多，Sagemath里面有函数可以分解：
```python
# Sagemath 9.2
K = ZZ[i]   # 声明高斯整数环
factor(K(97))
# (-4*I + 9) * (4*I + 9)
```

### 4.2 构造$a^2+b^2=n$
**问题：** 已知$n$，需要构造出$a,b$满足$a^2+b^2=n$。

* 流程：
    1. 将$n$分解成$n=\prod p_m^{e_m}$
    2. 将2分解成$(1+i)(1-i)$，将$4k+1$型素数分解为$u\bar{u}$，保留$4k+3$型素数。
    3. 将第2步的结果分成两组，$(1+i)$分去1组，$(1-i)$分去2组；将$u$分去1组，$\bar{u}$分区2组；$4k+3$型素数一定是成对出现的，即$2|e_m$，因此每组分到$\frac{e_m}{2}$个。
    4. 任意选一组，把改组所有的数乘起来得到$A+Bi$，则$a=A, b=B$，即满足$a^2+b^2=n$或者说$A^2+B^2=n$。

* Sagemath里面可以轻松对$n$进行分解
```python
K = ZZ[i]   # 声明高斯整数环
factor(K(19*19*97))
# (-4*I + 9) * (4*I + 9) * 19^2

guass_integer = (4*I + 9) * 19
a = abs(guass_integer.imag())
b = abs(guass_integer.real())
a^2+b^2 == 19*19*97
# 35017 == 35017
```

### 4.3 构造$a^2+b^2=n^k$
根据共轭的性质，首先类似4.2节中先分解$n$。得到$A+Bi$，然后计算$$(A+Bi)^k = A'+B'i$$ 则有$A'^2+B'^2=n^k$。


### 4.4 拉格朗日四平方定理

**定理内容：** 每个正整数均可表示成不超过四个整数的平方之和.


### 4.5 模$p$下的复数乘法群

关键在于要注意乘法群的形式，对于乘法群中的元素$a = x_1+y_1i$，$b = x_2 + y_2i$，有$$c = a\cdot b =x_3+y_3i\\ x_3 = x_1x_2-y_1y_2 \\ y_3 = x_1y_2+x_2y_1$$ 其中对于模$p$下的复数乘法群其阶为$p^2-1$，证明见： https://zhuanlan.zhihu.com/p/436496753 评论区中说也可以使用**陪集定理**进行证明。

如果给出复数乘法群的元素$1+i$，那么这是一种特殊的结构，以它为基生成的元素可以和一个阶为$4(p-1)$的整数乘法群同构(不过至于那个整数乘法群长什么样子还不清楚emmmmmm)。

另一种方法同样见上面的链接，就是对群中的元素取模长，然后模$p$。这种情况下就相当于$|x^2+y^2|\ mod\ p$，即控制了角度，也控制了长度，因此同样会同构于一个模$p$的乘法群。（未给出严格的证明，但是运行程序确实如此）

因此如果要求以$1+i$为生成元生成的复数群中的离散对数，那么可以先对复数元素求模，然后求模$p$下的离散对数，此离散对数就是我们要求的。






## 5. 求环上固定阶的生成元
**本原多项式**：一个次数为$n$的$F_q$上的本原多项式，就是它在域$F_q^n$上的所有根都是本原元（**本原元**能生成域$F_q^n$上的所有元素，相当于乘法的生成元）。
* 所有在$F_q$上的本原多项式在$F_q$上是不可约的（不可分解）。

### 5.1 求环上的生成元
求环$R$上的生成元。已知环的阶(元素个数)为$n$。则找生成元的过程为：任取$R$中的元素$g\in R$，若有$g^{\frac{n}{2}}\neq -1\in R$，则$g$为生成元。这种方式适用于$2|n$的情况。

### 5.2 求环上固定阶的元素
假设需要找的元素的阶为$q$，环$R$的阶为$n$，由环的性质可知$q|n$。
1. 首先找出环$R$的一个生成元（对于域来说就是找出本原元）$g$。
2. 计算$a = g^{\frac{n}{q}}$，则$a$为环$R$的一个$q$阶元素。


## 6. Chinese remainder theorem(CRT) 中国剩余定理

> 可以使用分治的思想来求CRT [crypto-attack fast crt](https://github.com/jvdsn/crypto-attacks/blob/master/shared/crt.py)

原理见https://en.wikipedia.org/wiki/Chinese_remainder_theorem

遇到模数不是素数的情况下，用CTR分解一下，可能有奇效。

```python
# python实现
from functools import reduce

def egcd(a, b):
    prevx, x = 1, 0; prevy, y = 0, 1
    while b:
        q = a//b
        x, prevx = prevx - q*x, x
        y, prevy = prevy - q*y, y
        a, b = b, a % b
    return prevx, prevy, a

def chinese_remainder(pairs):
    mod_list, remainder_list = [p[0] for p in pairs], [p[1] for p in pairs]
    mod_product = reduce(lambda x, y: x * y, mod_list)
    mi_list = [mod_product//x for x in mod_list]
    mi_inverse = [egcd(mi_list[i], mod_list[i])[0] for i in range(len(mi_list))]
    x = 0
    for i in range(len(remainder_list)):
        x += mi_list[i] * mi_inverse[i] * remainder_list[i]
        x %= mod_product
    return x

print(chinese_remainder([(3,2),(5,3),(7,4),(11,5)]))
# 368
```

在Sagemath中有函数`CRT`和`CRT_list`

## 7. 广义Fibonacci（斐波拉契）数列
* 正常的Fibonacci数列：$F_n = F_{n-1} + F_{n-2} (n\geq 2)$
* 广义Fibonacci数列：$F_n = pF_{n-1} + qF_{n-2} (n\geq 2)$
    * 快速计算的表达式为 $$ [f[n]\ f[n-1]] = [f[2]\ f[1]]
    \left[
    \begin{matrix}
    p & 1\\
    q & 0
    \end{matrix}
    \right]^{n-2}$$
    * 当$p = 1, q = 1$时变为正常的Fibonacci数列

* 从不定方程可以转换成广义Fibonacii数列的形式
    * 参考：杨艾欣,沈源钦.一类不定方程的非负整数解[J].韩山师范学院学报,2013,34(03):19-22.
    * $x^2+kxy-y^2+1 = 0$ 构成的$k~1$型广义Fibonacii数列。解为$p = k, q = 1$。
    * $x^2-kxy+y^2-1 = 0$ 的解为$p = k, q = -1$。
    一般遇到这种不懂的题可以遍历一开始那些比较小的数，获得前几个数列的值，然后用求数列通项公式的网站获得通项公式，从而求出要求的数。

### 7.1 佩尔方程 Pell Equation
#### 7.1.1 第一类佩尔方程
$$x^2-dy^2=1$$ 其中$d>1$且$d$不是完全平方数。而且方程的解满足$x>0,y>0,x,y\in \mathbb{Z}$。

* 定理：第一类佩尔方程有无数个解(这里不给出证明)

如果知道了公式的一个最小整数解$(x_1,y_1)$，则给出其通解的迭代公式$$x_n=x_{n-1}x_1+dy_{n-1}y_1 \\ y_n = x_{n-1}y_1+y_{n-1}x_1$$ 

> 证明：联立方程$$ x_1^2-dy_1^2=1 \\ x_2^2-dy_2^2=1 $$ 可以联立得到 $$(x_1x_2-dy_1y_2)^2-d(x_1y_2+x_2y_1)^2=1$$ 这样一来替换一下就可以得到通解了。

* 求解佩尔方程
    * 对于给定的$d$，可以通过暴力求解**最小整数解$x_1,y_1$**，然后用通项公式求解。
    * 使用**连分数**进行求解。
    * 使用矩阵快速幂进行求解： $$\left[ \begin{matrix}x_n \\ y_n \end{matrix}\right] = \left[ \begin{matrix}x_1 & dy_1\\ y_1 & x_1 \end{matrix}\right]^{n-1}  \left[ \begin{matrix}x_1 \\ y_1 \end{matrix}\right]$$

* 连分数求解原理：
首先简单介绍一下连分数，$n$阶简单连分数记为：$$[x_0,x_1,...,x_n]$$ 无限简单连分数记为:$$[x_0,x_1,x_2,...]$$ 可以将有限简单连分数叫做无限连分数式的第$n$个**渐进分数**。$x_n$叫做第$n$个**部分商**。
  * 定理：无限简单连分数$[x_0,x_1,x_2,...]$是收敛的，存在实数$\theta$，使得$$\lim_{n\to +\infty}[x_0,x_1,x_2,...]=\theta$$
  * 定理：设实数$\theta>1$的渐近分数为$\frac{P_n}{Q_n}$，则对任意$n\geq 1$，有$$|\theta^2Q_n^2 - P_n^2|<2\theta$$
* 实际上对$d$进行连分数展开可以把$x^2-dy^2=1$的所有解全部求出。只要有$原式=1$，则为佩尔方程的解。网上说佩尔方程的解在不同的$d$中有不同的形式，但实质上直接连分数展开找到$原式=1$时的解即可。(理论上是可以证明的，但是我还没有去证)



#### 7.1.2 第二类佩尔方程
$$x^2-ny^2=c$$

解第二类佩尔方程，需要用到第一类佩尔方程的解。

> 证明：设 $ x^2-dy^2=1 $ 的解为$x_1, y_1$。设$x^2-dy^2=k$的解为$p,q$。
> 联立方程$$ x_1^2-dy_1^2=1 \\ p^2-dq^2=k $$ 可以联立得到 $$(x_1p\pm dy_1q)^2-d(py_1\pm x_1q)^2=k$$ 这样一来替换一下就可以得到通解 $$x = x_1p_i\pm dy_1q_i \\ y = p_iy_1\pm x_1q_i$$ 化为矩阵乘法的形式为 $$ \left[ \begin{matrix}p_n \\ q_n \end{matrix}\right] = \left[ \begin{matrix}p & \pm dq\\ \pm q & p \end{matrix}\right]^{n-1}  \left[ \begin{matrix}x_1 \\ y_1 \end{matrix}\right] $$

* 参考资料：
  * https://blog.csdn.net/TheWayForDream/article/details/113772229
  * https://www.cnblogs.com/lfri/p/11650132.html

## 8. 一些密码学基本概念
称一个机器是概率多项式时间的，如果它的运行步数是安全参数的多项式函数，简记为PPT。

### 8.1 陷门置换的定义
**定义 8.1-1** 一个陷门置换族是一个 PPT 算法元组(Gen, Simple, Eval, Invert):
1. Gen($1^k$)是一个概率性算法，输入为安全参数$1^k$，输出为($i$, td)，其中$i$时定义域$D_i$上的一个置换$f_i$的标号，td时允许求$f_i$逆的陷门信息。
2. Sample($1^k,i$)时一个概率性算法，输入$i$由Gen产生，输出为$x\leftarrow_R D_i$。
3. Eval($1^k,i,x$)时一个确定性算法，输入$i$由Gen产生，$x\leftarrow_R D_i$由Sample($1^k,i$)产生，输出为$y\in D_i$。即Eval($1^k,i,\cdot$):$D_i\rightarrow D_i$时$D_i$上的一个置换。
4. Invert($1^k,(i, td),y$)时一个确定性算法，输入($i$,td)由Gen产生，$y\in D_i$。输出为$x\in D_i$。
* 陷门置换族的正确性要求：对所有的$k$，($i$,td)$\leftarrow$Gen($1^k$)以及$x\leftarrow$Sample($i^k,i$)，Invert($1^k,(i,td),Eval(1^k,i,x$))= $x$。
* Invert($1^k,(i, td),\cdot$)其实就是置换$f_i$的逆置换$f_i^{-1}$。虽然$f_i^{-1}$总是存在的，单不一定时可有效计算的。上面的定义说，已知陷门信息td，你置换$f_i^{-1}$是可有效计算的。
* **在以上定义中，没有考虑任何“困难性”或“安全性”的概念。但密码学中的陷门置换是指单向陷门置换，即当陷门信息td未知时，一个随机陷门置换的求逆是困难的。正式定义如下。**

**定义 8.1-2: 单向陷门置换(TDP)** 一个陷门置换簇(Gen,Sample, Eval, Invert)是单向的，如果对于任意的 PPT 敌手A，存在一个可忽略的函数$\grave{o}(k)$，使得A在下面的游戏中，其优势${\rm Adv}_{\rm T-Perm,A}(k) \leq \grave{o}(k)$：
* ${\rm Exp_{T-Perm,A}}(k):$
    * ($i$,td)$\leftarrow$Gen($k$);
    * $y\leftarrow$ Sample($k,i$);
    * $x\leftarrow$ A($k,i,y$);
    * 如果Eval($k,i,x$)=$y$，返回1；否则返回0.

敌手的优势定义为${\rm Adv}_{\rm T-Perm,A}(k) = {\rm Pr[Exp_{T-Perm,A}}(k)=1]$。
* 此定义主要用在安全性证明中。


## 9. 欧拉函数 (Euler's totient function)
计算与$n$互素的所有小于$n$的数的个数。假设$p_1,\cdots,p_r$是$n$的素因数，则：
$$\phi(n) = n(1-\frac{1}{p_1})\cdots(1-\frac{1}{p_r})$$


## 10. 卡迈克尔函数 (Carmichael function)
使得$$a^m\equiv 1\ mod\ n$$成立的最小正整数$m$，其中$(a,n)=1$，一般来说我们将$m$记为$\lambda(n)$。

## 11. 原根
定义**阶**：设$n\geq 1, (a,n)=1$，使得$a^d\equiv 1\ mod\ n$成立的最小正整数$d$，称为$a$模$n$的阶，记为$\delta_n(a)$或$ord_n(a)$。

定义**原根**：当$\delta_n(a)=\phi(n)$时，$a$为模$n$的原根。

* 原根的定理
    * 模$n$有原根$\Leftrightarrow n=1,2,4,p^l, 2p^l$

* 推论1：正常的RSA方案的一个公钥指数至少对应两个私钥。
  * $$a^{2k_1}\equiv 1\ mod\ n_1, \ \ a^{2k_2}\equiv 1\ mod\ n_2 \\ a^{2k_1k_2}\equiv 1\ mod\ n_1$$ 而$\phi(n) = 4k_1k_2$，因此实质上一个RSA方案一个公钥指数可以对应$gcd(p-1,q-1)$个私钥指数。
* 推论2：能构成模$n$的循环群一定满足$n=2,4,p^l, 2p^l$

## 12. Montgomery reduction 
一般来说这个方法主要应用于快速计算素数阶有限域的乘法运算。原理是把需要计算的数映射到Montgomery表示形式中，然后在这种形式中进行乘法的计算。在Montgomery表示形式中，同样适用于加法和乘法运算。

> Montgomery规约适用于模不是素数的情况，可见参考文献2中的内容，而且是在$GF(2^k)$上的。这里只说明在素数域的情况下如何去计算。

已知：模数$p$，$n=log_2(p)$，乘数$a,b\ mod\ p$

预计算：$r = 2^n$，把$a,b$转化成Montgomery表示形式，$a' = ar\ (mod\ p)\ \ b' = br\ (mod\ p)$

根据Montgomery reduction定理有：$$\forall t, 0\leq t\le nr, st. \frac{(t-tpp^{-1})}{r} \equiv tr^{-1}\ mod\ p$$ 其中的除法运算就是整数的除法，不是乘以$r$的逆。且有$pp^{-1}\equiv 1\ mod\ r$和$rr^{-1}\equiv 1\ mod\ p$

因此使用Montgomery reduction对算法进行加速的时候有两个算法需要实现。第一个是如何把乘数变成Montgomery reduction的形式，然后第二点就是对乘法进行实现。如果确定了要把乘数变成Montgomery reduction的形式，然后一直都在这个形式下进行运算。假设当前的数为$t$，那么只需要执行$tr^{-1}\ mod\ n$就可以恢复成想要的结果。

> 或者令$rr^{-1}+pp' = 1$，其中有$p' = -p^{-1}$

- 第一步中的乘法模运算可以使用最传统的方式进行预处理。然后乘法运算就用Montgomery乘法。
- Montgomery reduction乘法：
    1. $t = ab$
    2. $m = -tp^{-1}\ mod\ r $。其中求模运算只需要取乘法运算的低$n$比特即可。
    3. $u=(t+mp)/r$
    4. if $u\geq n$, then $u = u-n$
    5. 输出$u$


参考资料：
1. https://cryptography.fandom.com/wiki/Montgomery_reduction#The_Montgomery_step
2. https://www.researchgate.net/publication/225847328_Montgomery_Multiplication_in_GF2k   **Montgomery Multiplication in GF(2k)**

## 13. Hensel Lifting Lemma
Hensel's Lifting Lemma是解析数论的分支p-adic analysis的基础，它为**有限域下解高次多项式同余方程**提供了一种可行有效的方法。

在这里只讨论模数$p$为素数的情况。

- **Hensel Lifting Lemma**：若已知$f(x)$在模$p^{k-1}(k\geq 2)$下的一个解$r$满足$f(r)\equiv 0\ (mod\ p^{k-1})$，那么
  1. $f(x)\equiv 0\ (mod\ p^k)$ 有解 **iff** $\frac{f(r)}{p^{k-1}}+tf'(r)\equiv 0\ (mod\ p)$ 有解。
  2. 若$f'(r)\not\equiv 0\ (mod\ p)$，那么在模$p$意义下存在唯一的$t$满足$f(r+tp^{k-1})\equiv 0\ (mod\ p^k)$,且有$t = -\frac{f(r)}{f'(r)p^{k-1}}(mod\ p)$.
  3. 若$f'(r)\equiv 0\ (mod\ p)$,则 
     - 若$f(r)\equiv 0\ (mod\ p^k)$,则$\forall t\in Z_p,\ f(r+tp^{k-1})\equiv 0\ (mod\ p^k)$. 
     - 若$f(r)\not\equiv 0\ (mod\ p^k)$,则$\forall t\in Z_p,\ f(r+tp^{k-1})\not\equiv 0\ (mod\ p^k)$. 
- 具体证明见第一篇参考资料

- **求方程$f(x)\  mod\ p^k$的根**：写成递推的形式$$r_1\equiv r\ (mod\ p) \\ r_k\equiv r_{k-1}-\frac{f(r_{k-1})}{f'(r_{k-1})}(mod\ p^k)$$ 然后根据Hensel's Lemma，从$k=1$开始，对于每一个$k$，去计算对应的 $f'(r_k)\ mod\ p$ 和 $f(r_k)\ mod\ p^k$ 来确定$k+1$所对应的解需要如何选择。

参考资料：
1. https://zhuanlan.zhihu.com/p/457343520
2. [crypto-attack Linear Hensel lifting](https://github.com/jvdsn/crypto-attacks/blob/master/shared/hensel.py) 复杂度为$O(pk)$





# 数论外的有用的数学



## 矩阵相关

### 矩阵降维

- 参考资料：https://blog.csdn.net/qq_42722197/article/details/120858115

- **正交矩阵：**$A$为$n$阶正交实矩阵，如果满足$AA^T=A^TA=I$
  - 可见正交矩阵的性质有：
    1. $A^{-1} = A^T$
    2. $|A| = \pm 1$
    3. $A,B$是正交矩阵，$AB$也是正交矩阵
- **正交变换：** $X=UY$，$U$是正交矩阵 
  - **性质：** 正交变换不改变向量的模
  - 正交变换不改变向量的夹角

#### 特征值分解
对称方阵$A$的特征值分解:$A = U\Sigma U^{-1}$，其中$U$是正交矩阵，$\Sigma$是对角矩阵。
可得$AU = \Sigma U$，这里的$U$就是特征向量组成的矩阵，$\Sigma$是特征值组成的对角阵。
**矩阵A没有旋转特征向量，它只是对特征向量进行了拉伸或缩短（取决于特征值的大小**

#### 奇异值分解（SVD）

对于任意$m\times n$矩阵$A$，, 我们总能找到一组单位正交基, 使得A对其进行变换之后, 得到的向量组仍然是正交的。既有$$A=U\Sigma V^T$$其中$U$是$m\times m$的正交矩阵，$\Sigma$是$m\times n$的对角矩阵，$V$是$n\times n$的正交矩阵。

##### SVD几何含义
![](crypto/images/SVD.svg)


### 矩阵离散对数
> TODO 原理有待补充

- 实数域矩阵离散对数
求解方法用到了特征值和矩阵分解的性质。

- 有限域上矩阵的离散对数

参考资料：[crypto-attack Matrix discrete logarithm](https://github.com/jvdsn/crypto-attacks/blob/master/shared/matrices.py)



## 最小二乘法
最小二乘法主要用于解决函数模型最优解问题，是测量工作及其他科学工程领域中，应用最早也是最广泛的算法。

在生产实践中，经常会遇到**利用一组观测数据来估计某些未知参数的问题**。


- **最小二乘原理** ：赋予误差的平方和为极小。即给定理论最优函数$f(x)$，使得$$\sum_{i=1}^nv_i^2 = \sum_{i = 1}^n(f(x_i) - y_i)^2$$有最小值，然后我们就可以根据给定的点$(x_0,y_0),...,(x_n,y_n)$对函数$f(x)$进行估计，得到一个近似的解。



# 常见Crypto攻击思想

常见攻击方法
根据不同的攻击模式，可能会有不同的攻击方法，目前常见的攻击方法主要有

* 暴力攻击（通用）
* 中间相遇攻击（思想）
* 线性分析（常用于缺陷版AES）
* 差分分析（常用于缺陷版AES）
* 不可能差分分析
* 积分分析
* 代数分析
* 相关密钥攻击
* 侧信道攻击
* 比特攻击

# 证书格式
数字证书是指在互联网通讯中标志通讯各方身份信息的一个数字认证，人们可以在网上用它来识别对方的身份。

数字证书有着其相应的各式，常见的openssl软件会一般都能够处理证书。**详细过程见RSA第零章**。

常见的证书各式如下：
* PEM： PEM 以 -----BEGIN 开头，以 -----END 结尾，中间包含 ASN.1 格式的数据。用 Python 3 和 PyCryptodome 库可以与 PEM 文件交互并提取相关数据。例如我们想提取出模数 ``n``:
```python
# python3
from Crypto.PublicKey import RSA

with open("certificate.pem","r") as f:
    key = RSA.import_key(f.read())
    print(key.n)
```
生成公钥和私钥：
```python
from Crypto.PublicKey import RSA
x = RSA.generate(2048)              # 里面有(n,e,d,p,q)
y = RSA.construct(x.n, x.e, x.d)    # 可以通过这个函数来分解RSA得到p和q

privatekey = x.exportKey("PEM")     # 私钥
pubkey = x.publickey().exportKey()  # 公钥

with open('publicKey.pem', 'wb') as f:
    f.write(pubkey)
with open('privateKey.pem', 'wb') as f:
    f.write(privatekey)
```
PEM密钥的例子：
```
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIw/U51Fghh6WumZQjg9l3a6AjFZ+xm2
x2+9ja+8n8Yg95Hbxsp9vCpwlIol1A5wMo6p/hNlxzAE3/cY08eKzDMCAwEAAQ==
-----END PUBLIC KEY-----
```
```
-----BEGIN RSA PRIVATE KEY-----
MIIBOQIBAAJBAIw/U51Fghh6WumZQjg9l3a6AjFZ+xm2x2+9ja+8n8Yg95Hbxsp9
vCpwlIol1A5wMo6p/hNlxzAE3/cY08eKzDMCAwEAAQJAJearQxJYwSK31O9dDPPg
Le7AzvOBP4a8yP7R/o8cIp+3XdCXzuUreFzTWTXIg76tohg8cQb77HT/jVo2rLXa
AQIhAOrtFkJ0So2NZIp4xBPLqFozaSJNti8Yx8w1IOWoS2szAiEAmNQCPrBaB6p4
heIDYgaTYpJa4gbw3tLe82AAKzFLGwECIE/ZA37Uzd4s16ZlA6gCyZbW8H3zUd/S
GV6kFClauT+XAiBZuddbkNQ6vfYmvIw56Bxt+flLzMFsQSfOgaV3tmgfAQIgKW7C
LI1+rBn3TvmyLMZ7+3TEtVeTVRgabLWyOUjmv7w=
-----END RSA PRIVATE KEY-----
```

* DER：DER 是 ASN.1 类型的二进制编码。后缀 ``.cer`` 或 ``.crt`` 的证书通常包含 DER 格式的数据。我们可以用 ``openssl`` 将 PEM(``.pem``) 文件转化为 DER(``.der``) 文件：
```
openssl x509 -inform DER -in certificate.der > certificate.pem
```
* 其他格式转换 
```
openssl x509 -outform der -in certificate.pem -out certificate.der
openssl x509 -inform der -in certificate.cer -out certificate.pem
```








# CTF crypto中python技巧

## 判断素数
* `pycryptodome` : `from Crypto.Util.number import isPrime `
* `gmpy2` : `gmpy2.is_prime()`
* `Sagemath` : `is_prime()`

## CTF常见字符集
```python
import string
print(string.printable.encode())	# 可打印字符集  
TABLE1=ascii_letters+digits+"{}_@#\"| "  # 数字+字母+其它符号
TABLE2=b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,{} '
```

## 比较两个list中是否有相同的元素
一般来说常见的思路是两个for循环，嵌套但是这样的时间复杂度是$O(n^2)$。使用`set`数据结构能把复杂度降低到$O(nlog\ n)$。
```python
a, b = [1,2,3,4,5,6,7], [5,7,8,9,0,2332]
print(set(a)&set(b))
```

## 全排列   
```python
import itertools
a = [1,2,3,4]
for i in itertools.permutations(a):
    print(list(i))
```

# 其它解题技巧

遇到密文是乱七八糟的字符串而明文是正常的英文字符+数字+括号的情况的时候，可以使用这种特性缩小明文和密钥的取值。参考`crypto/2021_Mtctf/RSA_2021_MTctf_easy_RSA`这道题。

## 根据几个数求数列的通项公式

http://oeis.org/search?q=1%2C4%2C15%2C56&sort=&language=english&go=Search




# 计算复杂性理论 （必要知识）

大多数搜索型问题可以推广到判定型问题上去。

P问题：有效求解的问题

NP问题：有效验证解的问题（是不是还要加一点东西）

NPC问题(NP完备问题)：需要引入多项式时间规约的概念。
    1. 是一个NP问题
    2. 所有的NP问题都可以(多项式时间)约化到它

- Karp规约——判定型问题之间的规约
- Levin规约——搜索型问题到搜索型问题之间的规约

NP难问题：（分为两种情况）
    1. 是一个NPC问题
    2. 不是一个NP问题（没有有效验证解的问题）


传统的NP问题的定义是利用确定性图灵机实现的。




# 近年来比较热的密码技术

> 推荐知乎上一个人，介绍了很多密码学学术界的知识，如果有兴趣去研究可以去看一下ta写的文章： https://www.zhihu.com/people/steven-yue-72/posts

## 差分隐私
> 最好多看几篇文章，这里就做简单叙述
* reference: 
    * https://blog.csdn.net/shangsongwww/article/details/105121386
    * https://zhuanlan.zhihu.com/p/48534275
    * https://www.zhihu.com/question/47492648/answer/194047182

差分隐私（Differential Privacy）是密码学中的一种手段，旨在提供一种当从统计数据库查询时，最大化数据查询的准确性，同时最大限度减少识别其记录的机会。简单地说，就是在**保留统计学特征的前提下去除个体特征以保护用户隐私**。

这里说的数据查询不能是针对单个用户的数据查询，因为如果要直接查询单个用户的信息的话就没有隐私可言。因为隐私这种东西有很多中定义的方法，因此在讨论到差分隐私的时候这里使用的是一种**新的隐私定义**暂且称作**差分隐私**。

差分隐私说的是一种防止差分攻击的方法。攻击者对数据库的查询操作只能是批量进行查询然后获取查询后的统计数据，没有单个用户的查询功能。

举个简单的例子：它想做的事情就是即使你小子知道我发布的100个人的信息，以及另外99个人的信息，你也绝对没办法把这两个信息比对之后获取第100个人的信息。怎么才能做到这一点呢？**差分隐私于是定义：如果你能找出一种方法让攻击者用某种方式查询100个信息和查询那99个信息得到的结果是一致的，那攻击者就没办法找出那第100个人的信息了。** 但这个“一致” 怎么做到呢？那就加入随机性吧。如果查询100个记录和查询99个记录，输出同样值的概率是一样的，攻击者就无法进行差分攻击。这里我们就得到了**差分隐私的核心思想：对于差别只有一条记录的两个数据集，查询它们获得相同值的概率非常非常的接近。**

* 因此差分隐私的核心思想就是在查询的结果中加入随机性。差分隐私主要有两种机制： **拉普拉斯机制（Laplace Machanism）和指数机制（Exponential Mechanism）** 来实现差分隐私保护。其中，拉普拉斯机制用于数值型结果的保护，指数机制用于离散型结果的保护。

### 非形式化定义

* **Laplace机制** ：在查询结果里加入Laplace分布的噪音，适用于数值型输出。例如：zhihu里有多少人是985大学毕业的？ 假如结果是2000人，那么每一次查询得到的结果都会稍稍有些区别，比如有很高的概率输出2001，也有较高概率输出2010， 较低概率输出1990，等等，然后统计输出的结果，会发现结果服从拉普拉斯分布。

* **指数机制**： 在查询结果里用指数分布来调整概率，适用于非数值型输出。例如：中国top 3大学是哪一所。很高概率输出 浙江大学，较高概率输出上海交大，较低概率输出武汉大学，很低概率输出蓝翔技校，等等。

* **敏感度**： 差分隐私保护可以通过在查询函数的返回值中加入噪声来实现，但是噪声的大小同样会影响数据的安全性和可用性。通常使用敏感性作为噪声量大小的参数，表示删除数据集中某一记录对查询结果造成的影响。

### 形式化定义

* **$\epsilon$-差分隐私**： 给定数据集$D$,给定$D$的邻近数据集$D'$,可以理解为$||D|-|D'|| = 1$。给定一个随机函数$f:D\rightarrow S$，$S$表示函数$f$输出的值域，可能是$D$的一个抽样，也可能是统计特性。然后我们有 $$
Pr[f(D)=s]\leq Pr[f(D')=s]\times e^{\epsilon} $$ 其中$e\approx 2.718281828459$是自然对数，且$s\in S$。

拉普拉斯机制和敏感度机制暂时不提及，有兴趣可以自己研究或补充。





## 安全多方计算

### Shamir秘密分享
> 本质上是多项式的求解。Shamir的$(k,n)$秘密共享算法将秘密$S$分为$n$个子秘密，任意$k$个子秘密都可以恢复出$S$ ，而任意$k-1$个子秘密无法恢复出$S$。

下面介绍Shamir秘密分析方案，$(k,n)$秘密共享算法：
* KeyGen：
    1. 确定$(k,n)$。选择素数$p$
    2. 选择秘密$S$。
    3. 选择$k-1$个小于$p$的随机数$a_1,...,a_{k-1}$，得到多项式$y = S + \sum_{i = 1}^{k-1}a_ix^i\ mod\ p$。
    4. 选择$n$个随机数$x_1,...,x_n$，计算$y_i = S + \sum_{j = 1}^{k-1}a_jx_i^j\ mod\ p$，得到$n$对二元组$(x_i,y_i)$。将$(x_i,y_i)$作为钥匙分给$n$个人。
* Decryption：
    1. 集齐任意$k$个人的钥匙，列出$k$个方程组 $$ \begin{cases} S + a_1x_i + ... + a_{k-1}x_i^{k-1} = y_i \\ S + a_1x_{i+1} + ... + a_{k-1}x_{i+1}^{k-1} = y_{i+1} \\ \vdots \\ S + a_1x_{i+k} + ... + a_{k-1}x_{i+k}^{k-1} = y_{i+k}  \end{cases}.$$
    2. 解方程得到$S,a_1,...,a_{k-1}$，其中$S$就是分享的秘密。


* 参考资料：
    * https://blog.csdn.net/z784561257/article/details/82942581
    * https://zhuanlan.zhihu.com/p/95362628

### 零知识证明

零知识证明起源于最小泄露证明。

#### 交互式零知识证明
本质上是基于一个交互式证明系统，交互证明系统由两方参与，分别称为证明者（Prover，简记为P）和验证者（Verifier，简记为 V），其中知道某一秘密（如公钥密码体制的秘密钥或一个二次剩余$x$的平方根），P希望使V相信自己的确掌握这一秘密。交互证明由若干轮组成。

交互证明系统需要满足以下要求：
1. 完备性：如果P知道某一秘密，V将接受P的证明。
2. 可靠性：如果P能以一定的概率使V相信
的证明，则P知道相应的秘密。

**定义：交互证明系统**
* 我们称(P,V)（或记为S=(P,V)是关于语言 L 、安全参数K的交互式证明系统，如果满足：
    1. 完备性：$\forall x\in L, {\rm Pr[(P,V)[}x]=1]\geq 1-\grave{o}(K)$；
    2. 可靠性：$\forall x\notin L, {\rm \forall P^*, Pr[(P^*,V)[}x]=1]\leq 1-\grave{o}(K)$；
其中(P,V)[$x$]表示当系统的输入是$x$时系统的输出。输出为1表示V接收P的证明。$\grave{o}(K)$是可忽略的。

如果V除了知道P能证明某一事实外，不能得到其它任何信息，则称P实现了零知识证明，相应的协议称为零知识证明协议。

* 刻画交互式证明系统的零知识性。

**定义：零知识性** 设S=(P,V)是一交互证明系统，若对任一PPT的$V^*$，存在PPT的机器$S$，使得对$\forall x\in L$，$\{VIEW_{P,V^*}(x)\}_{x\in L}$和$\{S(x)\}_{x\in L}$服从相同的概率分布，记为$\{VIEW_{P,V^*}(x)\}_{x\in L}\equiv \{S(x)\}_{x\in L}$，称S是完备零知识的，如果$\{VIEW_{P,V^*}(x)\}_{x\in L}\equiv^c\{S(x)\}_{x\in L}$，则称S是计算上零知识的。
* 其中S为模拟器，$S(x)$表示输入为$x$时，S的输出$\{S(x)\}_{x\in L}$表示S输出的概率。$\{VIEW_{P,V^*}(x)\}_{x\in L}$表示$x\in L$时，$$VIEW_{P,V^*}(x)$的概率分布。


##### 基于二次剩余的零知识证明

已知y,N, 其中$N=p*q$，存在$x^2\equiv y\ mod\ N$。

* 零知识证明协议
Prover：选择随机数$r\in Z_N^*$，发送$z\equiv r^2\ mod\ N$
Verifier: 发送$b\in\{0,1\}$
Prover: 发送$v\equiv x^br\ mod\ N$
Verifier: 检查$v^2==y^bz\ mod\ N$

> 这个协议r只能玩一次，相当于一次一密。

* Schnorr身份识别方案(签名)，见数字签名一章。

#### 非交互式零知识证明
如果P和V不进行交互，证明由P产生后直接给V，V对证明直接进行验证，这种证明系统称为非交互式证明系统（简称为NIZK: Non-Interactive Zero-Knowledge）定义如下。

> 以下定义非人话，可忽略

**定义：适应性非交互式零知识证明系统**
如果满足以下条件，一对多项式时间算法$\sum_{ZK}=({\rm P,V,Sim_1,SIm_2})$就是一个语言$L\in NP$的适应性非交互式零知识证明系统:
1. 完备性：对任意$x\in L(|x|=K)$机器证据$w$，有$$Pr[r\leftarrow_R\{0,1\}^{poly(k)};\pi\leftarrow P(r,x,w):V(r,x,w)=1]=1.$$
2. 可靠性：对任意$x\notin L$，那么对任意的$P^*，有$$Pr[r\leftarrow_R\{0,1\}^{poly(k)};\pi\leftarrow P(r,x,w):V(r,x,w)=1]=0.$$
3. 零知识性：设(${\rm Sim_1,Sim_2}$),(${\rm A_1,A_2}$)是一对两阶段算法，考虑如下实验：
    * ${\rm Exp_{ZK-real}(K)}:$
        1. $r\leftarrow_R \{0,1\}^{poly(K)}$ ;
        2. $(x,w)\leftarrow_R A_1(r)(x\in L\cap\{0,1\}^K$ ;
        3. $p \leftarrow_R P(r,x,w)$ ;
        4. $b \leftarrow_R A_2(r,x,p)$ ;
        5. 返回$b$.
    * ${\rm Exp_{ZK-sim}(K)}:$
        1. $r\leftarrow_R Sim_1(K)$ ;
        2. $(x,w)\leftarrow_R A_1(r)(x\in L\cap\{0,1\}^K$ ;
        3. $\pi \leftarrow_R Sim_2(x)$ ;
        4. $b \leftarrow_R A_2(r,x,\pi)$ ;
        5. 返回$b$.

    如果$|{\rm Pr[Exp_{ZK-real}(K)=1] - Pr[Exp_{ZK-sim}(K)=1]}|$是可忽略的，则称$\sum_{ZK}$具有零知识性。

* 目前为止比较出名的是ZCash(零币)中所使用的zk-SNARK零知识证明。这个零知识证明只需要证明者Prover给出少量的信息，验证者就能相信证明者知道ZCash中的私钥和确定证明者拥有的UTXO。

* zk-SNARK比较复杂，这里就不给出原理了，见下方链接。最好一起看，因为笔者也不是每个细节都看懂得懂emmmmmm。但是这么复杂的系统起码需要懂得为什么要出现某些步骤。
    * https://www.jianshu.com/p/7b772e5cdaef 
    * https://www.jianshu.com/p/b6a14c472cc1
    * https://www.investopedia.com/terms/z/zksnark.asp
    * https://blog.csdn.net/luckydog612/article/details/80396343 非形式化介绍

* zk-SNARK中的一些总结：
    * 首先是先设计出一套不安全的零知识证明系统，这里主要是首先Prover需要计算某个多项式，而且Prover不能让Verifier知道这个解，但是又要让V相信P知道这个解。
    * P根据多项式构造出一种QAP(Quadratic Arithmetic Programs)的形式(反正就是解多项式)，然后V通过P构造出的多项式验证出P知道某个秘密。
    * 这里会出现3个问题：
        1. V需要给出单个点求值后进行比较以减少P需要传送给V的数据大小。
        2. P可以根据V给出的抽样点构造多项式。（因此用到同态加密来隐藏抽样点）
        3. P可以构造错误的多项式通过V给出的抽样点的检测。（因此用到了KCA机制(Knowledge of Coefficient Test and Assumption)，通过椭圆曲线离散对数问题保证P构造的多项式满足离散对数的约束，保证P不会构造错误的多项式）
        4. 在验证的时候会出现乘法同态隐藏的问题，因此用到椭圆曲线双线性的特点。
        5. 在ZCash种，构造“共同参考数据集”（CRS，Common Reference String），通过某种可信的方式产生，作为一种全体节点的共识，在所有交易的验证过程中使用，因而“质询-响应”的交互式验证方式变成了只需要P提交证据即可。


### 同态加密见现代密码一章

### 群签名

在一个群签名方案中，一个群体中的任意一个成员可以以匿名的方式代表整个群体对消息进行签名。与其他数字签名一样，群签名是可以公开验证的，而且可以只用单个群公钥来验证。

* 群签名的一般流程(参考百度百科)：
1. 创建：一个用以产生群公钥和私钥的概率多项式时间算法。
2. 加入：一个用户和群管理员之间的使用户成为群管理员的交互式协议。执行该协议可以产生群员的私钥和成员证书，并使群管理员得到群成员的私有密钥。
3. 签名：一个概率算法，当输入一个消息和一个群成员的私钥后，输出对消息的签名。
4. 验证：一个概率算法，当输入一个坏消息和一个群成员的私钥后，输出对消息的签名。
5. 打开：一个在给定一个签名及群私钥的条件下确认签名人的合法身份的算法。

* 群签名的安全性要求： 
    1. 匿名性(Anonymity)
        给定一个群签名后，对除了唯一的群管理员以外的任何人来说，确定签名者的身份是不可行的，至少在计算上是困难的。
    2. 不关联性(Unlinkability)
        在不打开签名的情况下，确定两个不同的签名是否为同一个群成员所签的是不可行的，至少在计算上是困难的。
    3. 不可伪造性(Unforgeability)
        只有群成员才能产生有效的群签名。其他任何人包括群管理员也不能伪造一个合法的签名。
    4. 可跟踪性(Traceability)
        群管理员在发生纠纷的情况下可以打开一个签名来确定出签名者的身份，而且任何人都不能阻止一个合法签名的打开。
    5. 正确性(Correctness)
        当验证者检验一个签名时，一个合法的群成员按照签名算法产生的群签名一定能够通过验证算法。
    6. 抵抗联合攻击(Coalition-Resistance)
        即使一些群成员串通在一起也不能产生一个合法的不能被跟踪的群签名。

* 常见的群签名方案：CS97方案


* 参考资料：
    * https://blog.csdn.net/zhang_hui_cs/article/details/8965338
    * https://en.wikipedia.org/wiki/Group_signature


### 环签名

环签名允许用户以一个自组织的用户群体 (被称为环) 的名义签名, 而不泄露签名者的确切身份。用到的思想是在$n$个公钥中隐藏自己拥有私钥的那个公钥。与群签名相比，没有了群管理员这个限制，因此使得签名一定程度上无法确定是由哪个成员签的。

> 这里的环的意思是：公钥序列构成一个环，本来在生成签名的时候只构成一条链，但是因为自身知道私钥，可以构造出相应的签名，使得签名构成一个环。（这里的环不是抽象代数中的环，只是一个抽象的定义）

![](crypto/images/ring_signature.png)

因为环签名在隐私保护中用得比较多，网上都有比较详细的描述，这里就描述一下其抽象的原理。
* KeyGen($1^{\lambda}$)
  * 假设环签名需要$n$个成员，则收集$n-1$个公钥$P_1,...,P_{n-1}$并结合自身的公钥$P_n$构成环$R=\{P_1,...,P_n\}$。
* Sign(sk,s,M,R)
  * sk为私钥，s为位置(不重要,因为构成环，自身一定是最后一个)，M为需要签名的消息。
  * 令加密算法记为$E_{k'}$，其中$k'$可以由消息M生成，也可以在加密的时候附上，反正必须要和消息M有关。记$f_i$为与公钥$P_i$有关的函数。
  * 随机选取一个值作为初始值$v$，计算 $e_{s+1} = E_{k'}(f_{s}(v))$。
  * 随机选取随机数$k_{s+1}$，计算$e_{s+2}=E_{k'}(f_{s+1}(k_{s+1} \oplus e_{s+1}))$。
  * ...
  * 随机选取随机数$k_{s-2}$，计算$e_{s-1}=E_{k'}(f_{s-2}(k_{s-2} \oplus e_{s-2}))$。
  * 随机选取随机数$k_{s-1}$，计算$e_{s}=E_{k'}(f_{s-1}(k_{s-1} \oplus e_{s-1}))$。
  * 通过私钥sk，解得$k_{s}$是方程$E_{k'}(f_{s}(v)) = e_{s+1} = E_{k'}(f_{s}(k_{s} \oplus e_{s}))$的解。（**关键步骤**）
  * 输出签名$S = \{k_1,k_2,...,k_n,e_1,e_2,...,e_n\}$。
* Verify(R,S,M)
  * 对于$1\leq i\leq n$，判断$e_{i} == E_{k'}(f_{i-1}(k_{i-1} \oplus e_{i-1}))$，若$i-1==0$，则令$i-1=n$。
  * 若都满足，则签名合法。

* 常见的环签名
  * AOS(Abe-Ohkubo-Suzuki) （区块链隐私领域）
  * Borromean （门罗币）

* 参考资料：
  * https://blog.csdn.net/qq_31739317/article/details/103706858
  * https://blog.csdn.net/jason_cuijiahui/article/details/84933744
  * 冯翰文, 刘建伟, 伍前红. 后量子安全的群签名和环签名[J]. 密码学报, 2021, 8(2): 183–201. [DOI: 10.13868/j.cnki.jcr.000430]  **一篇综述**

### OT（Oblivious Transfer，不经意传输）

* 参考资料：
    * https://en.wikipedia.org/wiki/Oblivious_transfer
      * https://www.zhihu.com/column/c_1409550861031251968 更偏向于学术的OT

**1-2 oblivious Transfer**: 方案见第一篇参考资料，写得非常的清晰了。

其中一种攻击方式：
现在已知$N,e,x_0,x_1,v$，我们可以精心构造$v$使得Alice计算出的$k_0 = k'k_1$，其中$k'$是一个常数。因此联立方程$$\begin{cases} k_0 = k'k_1\ mod\ N \\ k_0^e \equiv v - x_0\ mod\ N \\ k_1^e \equiv v - x_1\ mod\ N \end{cases}$$ 解得$v = (k'^ex_1 - x_0) / (k'^e - 1) \ mod\ N$。因此可以计算出$$m \equiv m'_0k' - m'_1 \equiv k'x - y\ (mod\ N)$$






## 区块链中的密码技术

### 盲签名 (Blind Signature)

* 非形式化定义：一种数字签名的方式,在消息内容被签名之前,对于签名者来说消息内容是不可见的。 **类比例子**:对文件签名就是通过在信封里放一张复写纸，签名者在信封上签名时，他的签名便透过复写纸签到文件上。

* 性质
  1. 签名者对其所签署的消息是不可见的，即签名者不知道他所签署消息的具体内容。
  2. 签名消息不可追踪，即当签名消息被公布后，签名者无法知道这是他哪次的签署的。

* 盲签名模型：本质上就是验证者对消息进行盲化，然后收到签名者签名后对消息进行去盲。

* RSA盲签名：
  1. 盲化消息：$m'\equiv mr^e\ mod\ N$
  2. 签名消息：$s'\equiv (m')^d\ mod\ N$
  3. 去盲消息：$s\equiv s'\cdot r^{-1}\ mod\ N$
  4. 此时$s$就是签名者对消息$m$的签名。 


* 参考资料：https://blog.csdn.net/zhang_hui_cs/article/details/8728776


### keccak256 哈希算法

目前为止此函数的安全性、灵活性、高效性还是可以的。

```python
from Crypto.Hash import keccak

keccak_hash = keccak.new(digest_bits=512)   # 224, 256, 384, 512
keccak_hash.update(b'Some data')
print keccak_hash.hexdigest()
```


### Merkle 树
> 也称为默克尔树

其主要特点为：
- 最下面的叶节点包含存储数据或其哈希值；
- 非叶子节点（包括中间节点和根节点）都是它的两个孩子节点内容的哈希值。

比较突出的作用：
1. 证明某个集合中存在或不存在某个元素
2. 快速比较大量数据
3. 快速定位修改

### 布隆过滤器（Bloom Filter)
一般来说我们会使用数据的哈希值进行搜索索引。但是当hash值限制在一定范围且数据量较大的时候，就会出现碰撞。

布隆过滤器：对同一个输入来说，布隆过滤器使用多个 Hash 函数计算出多个地址，分别在位串的这些地址上标记为 1。在查找时，进行同样的计算过程，并查看对应元素，如果都为 1，则说明较大概率是存在该输入。

## 区块链前沿隐私技术
|名称|	类型|	技术实现|
|:---:|:---:|:---:|
|Zcash|	UTXO|	零知识证明技术zk-SNARK|
|门罗币|	UTXO|	环签名技术Borromean|
|Beam|	UTXO|	Mimble-Wimble|
|EYBlockchain|	Account|	基于合约的zk-SNARK|
|AZTEC|	Account|	同态证明&&rangeproof|
|Zether|	Account|	Σ-Bullets ZK-proof零知识证明|
|PGC|	Account|	bulletproof零知识证明|

* 参考资料
  * https://blog.csdn.net/qq_31739317/article/details/103706898