# Crypto
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


# 现代密码
## $\mathrm I$ 对称密码
## $\mathrm I.\mathrm I$ 流密码

#### 伪随机数生成器PRNG

##### 随机性的严格性 
* 随机性：随机数应该不存在统计学偏差，是完全杂乱的数列。
* 不可预测性：不能从过去的序列推测出下一个出现的数。
* 不可重现性：除非数列保存下来，否则不能重现相同的数列。

#### 码安全伪随机数生成器

#### 例题：woodman - Google CTF
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


#### 线性同余生成器（LCG(linear congruential generator)）

* https://en.wikipedia.org/wiki/Linear_congruential_generator

简介：The generator is defined by recurrence relation:
$$X_{n+1}=(aX_n+c)\ mod\ m$$ 其中$X$是伪随机值(pseudorandom values)，并且
* $m,\ 0 < m$ the "modulus"模数
* $a,\ 0 < a < m$ the "multiplier"乘数
* $c,\ 0\leq c < m$ the "increment"加数
* $X_0,\ 0\leq X_0 < m$ the "seed" 种子。

求解方案参考reference：https://www.codercto.com/a/35743.html

主要流程参见`crypto/linear_congruential_generator.md`


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

> 具体的算法流程还没有完全了解，目前只需要知道怎么去破解即可。

参考：`crypto/random_number_Mersenne_Twister_2021NahamconCTF_Dice_Roll`中的writeup。
破解代码见`crypto/code/mersenne-twister-predictor-master.zip`。

## $\mathrm I.\mathrm I\mathrm I$ 块密码 TODO
所谓块加密就是每次加密一块明文，常见的加密算法有：
- IDEA 加密
- DES 加密
- AES 加密
- ARX 加密
- Simon and Speck 加密

还有许多对称加密方案，这里只列出常见的几种，每一种方法网上资料都比较多，这里就不一一列举。

在分组密码设计时，一般回使用**混淆(S盒，乘法)与扩散(线性变换，置换，移位)** 两大策略。

### DES (Data Encryption Standard)

DES is developed in 1970s until 2000s after it was broken (in 22 hours and 15 minutes by distributed.net and the Electronic Frontier Foundation in January 1999). **Triple DES** is hence recommended by the NIST for future use.

DES是一个16轮的Feistel型结构密码，它的分组长度为64比特，用一个56比特的密钥来加密一个64比特的明文串，输出一个64比特的密文串。

> TODO: DES 原理

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

### AES (Advanced Encryption Standard)
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

#### AES相关攻击
* 差分错误分析(Differential Fault Analysis)在AES的第八轮添加1个byte的错误信息，则可以恢复出AES的密钥，见``crypto/2021_CSISC/AES_2021_oddaes``。


### 分组模式
分组加密会将明文消息划分为固定大小的块，每块明文分别在密钥控制下加密为密文。当然并不是每个消息都是相应块大小的整数倍，所以我们可能需要进行填充。常见的分组模式：
- ECB：密码本模式（Electronic codebook）
- CBC：密码分组链接（Cipher-block chaining）
- PCBC：密码分组链接（Cipher-block chaining）
- CFB：密文反馈模式（Cipher feedback）
- OFB：输出反馈模式（Output feedback）
- CTR：计数器模式（Counter mode）

**注：ECB模式的AES是不安全的。**

### 填充方法
目前有不少的填充规则。常见的填充规则：
- **pkcs5**：填充字节数与填充字节数相同的值
- **pkcs7**：(OneAndZeroes Padding)Pad with 0x80 followed by zero bytes
- **Pad with zeroes except make the last byte equal to the number of padding bytes** 用零填充，并使最后一个字节等于填充字节的数目
- **null**：Pad with zero characters（零填充）
- **Pad with spaces**：空格填充

## $\mathrm I\mathrm I$ 非对称密码
## $\mathrm I\mathrm I.\mathrm I$ RSA
![](crypto/images/RSA_theory.PNG)

### RSA 相关攻击
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

* Crypto常用的python库
    * gmpy2 (pip 一般不能直接安装，要在网上下载.whl文件然后用pip进行安装)
    * Crypto (安装命令``pip install pycryptodome``)

#### 一、分解大整数N
目前最快的分解大整数N的方法是广义数域筛法(General Number Field Sieve)。对于n-bit的整数，时间为$O(exp((c+o(1))n^{\frac{1}{3}}log^{\frac{2}{3}}n))$

另一种分解大整数的方法：已知私钥$d$，和公钥$e$，则可快速对$N$进行分解。反之亦然，即已知$N$的分解$N=pq$，则可以快速恢复出$d$。

* 常见大整数$N$分解工具：
    * yafu (p,q相差过大或过小yafu可分解成功)
    * http://www.factordb.com

##### 1.1 已知 $(N, e, d)$ 求 $(p, q)$ V1
* 攻击条件，$e$或$d$足够小
* 攻击原理：$ed-1=k\varphi(N)$。因为$e$或$d$比较小，然后$\varphi(N)$与$N$比较接近，因此爆破$k$，从而找到$\varphi(N)$。**但是实际上求解$\varphi(N)$是非常困难的，只有少数特殊情况能求解**。然后由$$N=pq \newline \varphi(N)=(p-1)(q-1)$$得$$N-\varphi(N)+1=p+q$$接下来构造方程$$x^2+(N-\varphi(N)+1)x+N=(x-p)(x-q)=0 \tag{1.1}$$只需要解方程$(1.1)$就可以把$p$和$q$解出来。

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

#### 三、小解密指数攻击
##### 3.1 Wiener’s attack
* **Theorem 2 (M. WIener)：** 让$ N=pq, q<p<2q $，并且有$d<\frac{1}{3}N^{\frac{1}{4}}$。给定公钥<N,e>，则有一个有效的方法恢复出私钥d。
* 证明：此定理是基于连分数的近似。易得
$$|\frac{e}{\varphi(N)}-\frac{k}{d}|=\frac{1}{d\varphi(N)} \newline
\varphi(N)=N-p-q+1 \newline
k<d<\frac{1}{3}N^{\frac{1}{4}}
$$
因此有
$$
|\frac{e}{N}-\frac{k}{d}|\leq\frac{1}{2d^2}
$$
根据![](crypto/images/Th2.2_Continued_Fraction.PNG)
可知$\frac{e}{N}$的**连分数的收敛式**中有一项为$\frac{k}{d}$。**连分数的收敛式(Convergent)** 的定义：记为$c_i$。令$n$表示连分数最多展开$n$层。即
$$a=a_0+\frac{1}{a_1+\frac{1}{\ddots +\frac{1}{a_n}}}简写为a=[a_0;a_1,a_2,...,a_n]$$则连分数的收敛式$c_i$满足
$$\forall x\in[0,n],\ c_i=[a_0;a_1,...,a_i]$$ 因此只需要对$\frac{e}{N}$进行连分数展开，找出满足
$$ed-1=0\ mod\ k \tag{3.1}$$的收敛式$\frac{k}{d}$，即$\exists i'\in[0,n],c_{i'}=\frac{k}{d}$，则$$\phi(n)=\frac{ed-1}{k}$$可能会出现当$d$比较小的时候$(3.1)$式成立，因此需要进行特殊的判别。

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
其中$L_2$矩阵都是已知的项构成的，我们可以把$L_2$看作一个格，然后$B_2$是其最短向量，使用**LLL定理**（见4.1节）可以求出其最短向量。而且若$B_2$为最短向量，则需要满足$||B_2||\leq \sqrt{n}det(L)^{\frac{1}{n}}$，即$$2N^{1+2\alpha}\leq 2N^{(\frac{13}{2}+\alpha)\frac{1}{4}}$$解得$\alpha\leq \frac{5}{14}$从而可以代入$M_2$中。(**编程实现的过程中可稍微缩小$\alpha$使得LLL算法必定有解**)求出最短向量$B_2$后，计算$B_2*L_2^{-1}$得到A。然后用a的前两项计算$$\frac{a[1]}{a[0]}e_1 = \frac{e_1d_1g}{k_1} = \varphi(N)$$从而把$\varphi(N)$恢复出来。

* 代码参考：https://blog.csdn.net/jcbx_/article/details/109306542
* ***具体Sagemath9.2代码见``crypto/code/Extended_Wieners_Attack.py``*** 在代码中提供$\alpha,e_1,e_2,n$可恢复出$\varphi(N)$


#### 四、小公钥指数攻击(Coppersmith's Theorem)
##### 4.1 攻击原理
***本质上是当公钥指数较小$e\leq 5$，把问题变成求解$f(x)\equiv 0\ mod\ N$的问题，其中$f(x)=\sum_{i=0}^{e} a_ix^i，a_i\in Z_N$。主要应用场景在e很小，方程的根比较小的情况。***
* **Theorem 3 (Coppersmith)：** $N$是整数，$f\in Z[x]$是度数为**d**的首一多项式。令$X=N^{\frac{1}{d}-\epsilon}$*（$X$是实数）*。则给定$<N,f>$，敌手可以快速找出所有的整数$\{x_0|\ \ |x_0|<X\ 且\ f(x_0)\equiv 0\ mod\ N\}$。运行时间为运行*LLL*算法所花费的时间，记为$O(w), w=min(1/\epsilon,log_2 N)$
* **Coppersmith方法**主要通过找到与$f\ mod\ N$有 **(1.相同根 2.系数为整数域 3.系数更小)** 性质的多项式$g$，从而找出$g$的根(因为容易找出整数域上的多项式根)
    * $f到g$的转换方式：预定义一个整数m，定义$$g_{u,v}(x)=N^{m-v}x^uf(x)^v$$。因此$x_0$是$g_{u,v}(x)\ mod\ N^m$的一个根，其中$u\geq 且0\leq x_0\leq m$与此同时有$f(x_0)\equiv 0\ mod\ N$
    * 因此我们可以找到一组$g_{u,v}$的线性组合$h(x)$，满足$h(xX)$有小于$N^m$的范式(根)，其中$X$是$x_0$中满足$X<N^{\frac{1}{d}}$的上界。只要m足够大，那么一定能找到这样的$h(x)$。**此时表示我们找到了这样的$h(x)$，它在整数中有同样的根$x_0$**。
##### $h(x)$的寻找方法
* 定义$h(x)=\sum a_ix^i \in Z[x]$，则$\|h(x)\| = \sum a_i$
* **Lemma 4 (Howgrave-Graham)：** Let $h(x)\in Z[x]$ be a polynomial of degree $dg$ and let $X$ be a positive integer. Suppose $\|h(xX)\| < N/\sqrt{dg}$. If $|x_0| < X$ satisfies $h(x_0)=0\ mod\ N$, then $h(x_0)=0$ holds over the integer.（$h(x_0)=0$在整数上成立）
    * 首先我们把多项式$g_{u,v}(xX)$作为向量，并记格$L$是由它所生成的。固定一个m，我们就可以写出格$L$的表达式，形如下图。其中带``*``号的表示非0系数，空的位置代表0。下图是当$m=3,dg=2$时所构造出的格$L$。
    ![格L](crypto/images/lattice_L.PNG)
    * 通过**LLL定理**，可以找出格L中的一个向量$v\in L$，满足$\|v\|\leq 2^{w/4}det(L)^{1/w}$，w表示格的维数。接下来需要证明：$2^{w/4}det(L)^{1/w} < N^m/\sqrt{w}，其中w=dg(m+1)$。当m足够大的时候，上式可以被满足。因此通过LLL定理找出的向量$v$就是所求的$h(x)$。
    * 参数的确定:当由$X=N^{\frac{1}{dg}-\epsilon}$时，有$m=O(k/dg)，k=min(\frac{1}{\epsilon},log\ N)$

**LLL定理：** Let L be a lattice spanned by $<u_1,...,u_w>$. When $<u_1,...,u_w>$ are given as input, then the LLL algorithm outputs a point $v\in L$ satisfying $$\|v\|\leq 2^{w/4}det(L)^{1/w}$$ LLL的运行时间是输入长度$w$的四次方。
* **Coppersmith定理所使用的攻击方法一般都被写在了``Magma``的``SmallRoots``函数中，以及``SageMath``的``small_root``函数中。**
* 详细实现过程参考：https://github.com/mimoo/RSA-and-LLL-attacks
* 参考文献： Wong D. Survey: Lattice Reduction Attacks on RSA. 

##### 4.2 Hastad的广播攻击
假设$e=3$，并且加密者使用了三个不同的模数$n_1,n_2,n_3$给三个不同的用户发送了加密后的消息$m$: $$c_1=m^3\ mod\ n_1 \newline 
c_2=m^3\ mod\ n_2 \newline 
c_3=m^3\ mod\ n_3$$
其中$n_1,n_2,n_3$不互素，$m < n_i$。
* 攻击方法：首先通过中国剩余定理得到$m^3\equiv C\ mod\ n_1n_2n_3$。因此只要对$C$开三次根就可以得到$m$的值。开根可以使用``SageMath``中的``iroot``函数。
    * 代码参考：https://github.com/yifeng-lee/RSA-In-CTF/blob/master/exp2.sage
    * ***具体Sagemath9.2代码见``crypto/code/Hastad_Broadcast_Attact.sage``***
* **拓展：** 具有线性填充的广播攻击也能通过Coppersmith's Theorem被攻破。
* 因此广播攻击的避免方式可以使用随机填充(padding)

##### 4.3 Franklin-Reiter 相关信息攻击
(**Franklin-Reiter**)当 Alice 使用同一公钥对两个具有某种线性关系的消息 M1 与 M2 进行加密，并将加密后的消息 C1，C2 发送给了 Bob 时，我们就可能可以获得对应的消息 M1 与 M2。这里我们假设模数为 N，两者之间的线性关系为$M_1\equiv f(M_2)\ mod\ N，f=ax+b$。则此时可以比较容易地恢复出$M$。
* 方法：当e=3时，$C_1=M_1^e\ mod\ N$，则有$M_2$是$g_1(x) = f(x)^e - C_1\equiv 0\ mod\ N$的根，而且$M_2$也是$g_2(x)=x^e - C_2\equiv 0\ mod\ N$的根。如果$g_1,g_2$的最大公因子是线性的，那么$M_2 = gcd(g_1,g_2)$。
* 当e>3时，$g_1,g_2$不一定是线性的，此时无法用此方法求解。
##### 4.4 Coppersmith’s short-pad attack （短填充攻击）
假设N长度为n，令$m=\lfloor n/e^2\rfloor$，加密消息M的长度不超过(n-m) bits。若有$$M_1=2^mM+r_1 \newline M_2=2^mM+r_2$$$0\leq r_1,r_2\leq 2^m$是不同的整数，则若知道$e,M_1,M_2,C_1,C_2$，容易恢复出M。
* 令$$g_1(x,y)=x^e-C_1 \newline g_2(x,y) = (x+y)^e-C_2$$ 
其中$y=r_2-r_1$，则$M_1$是两个方程的根。因此有$M_1=gcd(g_1(x,y),g_2(x,y))$，过程：

![Coppersmith短填充攻击](crypto/images/Coppersmith_ShortPadAttack.PNG)
* 当padding的长度小于信息长度的1/9的时候，可以使用此攻击。
##### 4.5 Known High Bits Message Attack(已知高比特信息攻击)
已知$C\equiv m^e\ mod\ N$，假设已知很大一部分$m_0$,则有$C\equiv(m_0+x)^e\ mod\ N$。直接使用Coppersmith定理求解$x$，但记得其中的$x$需要满足Coppersmith定理中的约束，即$x < N^{\frac{1}{e}}$。

* ***具体Magma代码见``crypto/code/Known_High_Bits_Message_Attack.m``***

##### 4.6 Factoring with High Bits Known(已知高比特分解)
已知$p$或$q$中其中一个数的高位比特，我们就有一定几率来分解 $N$。
**这里的原理就是Theorem 10，但是原理的具体流程没有找到。这里只是使用现成的代码能做到已知p的高比特部分，代码运行之后能得到相应的$p$。**
原理则是求解$x+p_{fake}\equiv 0\ mod\ Factor(N)$，Sage里面恰好有这样的一个函数，可以直接使用。

* 代码参考：https://github.com/yifeng-lee/RSA-In-CTF/blob/master/exp6.sage
* ***具体Sagemath9.2代码见``crypto/code/Factoring_with_High_Bits_Known.py``***

##### 4.7 Partial Key Exposure attack （部分密钥泄露攻击）
此时公钥$e$很小
* **Theorem 9 (BDF)：** 给定私钥<$N,d$>，$N$长为$n$比特，并给出私钥d的$\lceil n/4\rceil$位最低有效位(即$d$的低位)，那么可以在时间$O(elog_2\ e)$中恢复出$d$。
* **Theorem 10 (Coppersmith)：**$N=pq$，N为n比特。给出私钥p的高或低n/4比特，那么可以快速分解N。

我们主要讨论定理10，

**原理：** 首先已知$ed-k(N-p-q+1)=1$，因为$d<\varphi(N)$，所以有$0< k\leq e$。然后又因为$q=N/p$。则有$$(ed)p-kp(N-p+1)+kN=p\ mod\ (2^{n/4})$$因为敌手Marvin得到了$d$的$n/4$个最低有效位$d_0$，所以他知道$ed\equiv ed_0\ mod\ 2^{n/4}$。因此，他得到了一个关于$k$和$p$的方程。对于$k$的每一个可能的值$[0,e]$，Marvin求解了关于$p$的二次方程$$(ed_0)x-kx(N-x+1)+kN=x\ mod\ (2^{n/4})$$得到了一些$p$的候选值$x\ mod\ 2^{n/4}$的候选值。对于每一个候选值，执行定理10的算法(**4.6节**)去尝试分解$N$。可以看出，对于$p\ mod\ 2^{n/4}$的候选值的总数最多为$elog_2\ e$。因此，最多尝试$elog_2\ e$次后，$N$将被因式分解。然后就可以通过$e$和$\varphi (N)$求出私钥$d$。
* 定理10的代码见4.6节。

* 代码参考：https://github.com/yifeng-lee/RSA-In-CTF/blob/master/exp8.sage
* ***具体Sagemath9.2代码见``crypto/code/Partial_Key_Exposure_attack.py``***

##### 4.8 Boneh and Durfee attack
当 $d$ 较小时，满足 $d < N0.292$ 时，我们可以利用该攻击，比 Wiener's Attack 要强一些。

* 注意：4.2~4.7节的公钥指数$e$都是非常小(一般为3)。而本节仅仅是私钥指数$d$比较的小，而一般假设$e$非常的大。

###### 4.8.1 攻击原理
假设$gcd(p-1, q-1)=2$，已知$\varphi(N)=N-p-q+1$，则有
$$ed\equiv 1\ mod\ \varphi(N)/2$$
$$ed+k(\frac{N+1}{2}-\frac{p+q}{2})=1$$
令$A=\frac{N+1}{2}, s=-\frac{p+q}{2}$，则有$$k(A+s)\equiv 1\ (mod\ e)$$
而且满足$|k|< e^{\delta}$以及$|s|< e^{0.5}$，其中$\delta < 0.292$
这里$k$和$s$是未知数，因此我们相当于求一个二元二次方程的解。这里用到的是Coppersmith算法的广义的形式。

* 代码参考：https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage
* ***具体Sagemath9.2代码见``crypto/code/boneh_and_durfee.sage``***

##### 4.9 低加密指数攻击
$m ^ e = kN + c$其中一般 $e = 3$，$k$比较小($k$小于10亿爆破时间一般小于半小时)

##### 4.10 公钥$e$与$\varphi(N)$不互素
* 攻击前提：$p,q$已知，$e$比较小(不超过65535)
但是由于$e$与$\varphi(N)$不互素，所以我们无法求解得到私钥$d$。只有当他们互素时，才能保证$e$的逆元$d$唯一存在。
###### 4.10.1 $e \nmid \varphi(N)$
一般情况下会对同一个信息$m$给出两对$c_1,e_1,n_1,c_2,e_2,n_2$信息，且$n_1 = pq_1$、$n_2=pq_2$。于此同时还有$$gcd(e_1,(p-1)*(q_1-1)) = gcd(e2,(p-1)*(q_2-1)) = b$$然后令$e_i=a_ib$则$a_i$与$\varphi(N)$互素，又因为$ed\equiv 1\ mod\ \varphi(N)$因此每个$a_i$都唯一确定一个$bd_i$，则有$c_i^{bd_i} \equiv m^b\ mod\ N$记$c_i^{bd_i}=res_i$从而我们可以得到$$res_1 \equiv m^b\ mod\ n_1 \newline res_2 \equiv m^b\ mod\ n_2$$展开得$$res_1 \equiv m^b\ mod\ p \newline res_1 \equiv m^b\ mod\ q_1 \newline res_2 \equiv m^b\ mod\ q_2$$通过中国剩余定理计算可得$$res \equiv m^b\ mod\ q_1q_2$$此时求出$b' = gcd(b,q_1q_2)$，$d'=e/b'$，$d'd'^{-1}\equiv 1\ mod\ \varphi(q_1q_2)$，则$$res^{d'^{-1}} \equiv m^{bd'^{-1}} \equiv m^{b'}\ mod\ q_1q_2$$一般来说$b'$为2，此时$res^{d'^{-1}}$已知，因此之需要开个平方就可以得到$m$，**若$b'$不为2，则相当于变成了4.10.2节的情况**。

###### 4.10.2 $e\ |\ \varphi(N)$
现在相当于是这样的一种情况，我们有这样的一个方程$$c\equiv m^e\ mod\ N \tag{4.10}$$，其中$c,N,e,p,q$已知，需要求$m$。但是此时有$e | \varphi(N)$。因此这个方程可以化为$$c\equiv m^e\ mod\ p \newline c\equiv m^e\ mod\ q$$因为$e$与$p,q$互素，因此两个方程各有$e$个根，从而方程$(4.10)$有$e^2$个根。我们的目的就是找到这$e^2$个根中我们需要的那个，**就是找到有特殊字符串开头比如``flag{``开头的根$m$**。

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


#### 五、选择明密文攻击
##### 5.1 选择明文攻击
* 前提：我们有一个Oracle，对于给定任意明文，Oracle都会给出相应的密文。
* 目标：获取公钥N，e
    1. 首先通过构造多对加解密获取N。
    2. 当$e < 2^{64}$时，用 Pollard’s kangaroo algorithm 算法获取公钥$e$。

##### 5.2 选择密文攻击
* 前提：我们有一个Oracle，对于任意的合法密文，Oracle都会给出相应的明文(相当于时攻击者临时获得了解密机器的访问权)。但是我们不知道密钥。
* 目标：Alice计算$C=m^e\ mod\ N$，把Alice用自己的公钥签名的信息$m$恢复出来。
    1. 选择任意$X\in Z_N^*$
    2. 计算$Y=CX^e\ mod\ N$
    3. 想办法让Alice计算$Z = Y^d\ mod\ N$
    4. $m = ZX^{-1}\ mod\ N$

此攻击并没有把Alice的私钥恢复出来，本质上是对RSA协议本身的攻击而不是算法的攻击。

##### 5.3 RSA parity oracle
假设目前存在一个 Oracle，它会对一个给定的密文进行解密，并且会检查解密的明文的奇偶性，并根据奇偶性返回相应的值，比如 1 表示奇数，0 表示偶数。那么给定一个加密后的密文，我们只需要 log(N) 次就可以知道这个密文对应的明文消息。

Oracle返回奇偶性信息造成了信息的泄露，因此可以使用选择明文攻击的思路进行攻击，具体的攻击方案见：https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_chosen_plain_cipher/

* 本质上是二分法，然后夹逼。

##### 5.4 RSA Byte Oracle
假设目前存在一个 Oracle，它会对一个给定的密文进行解密，并且会给出明文的最后一个字节。那么给定一个加密后的密文，我们只需要$log_{256}N$次就可以知道这个密文对应的明文消息。

具体方案同样见：https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_chosen_plain_cipher/

##### 5.5 RSA parity oracle variant
如果 oracle 的参数会在一定时间、运行周期后改变，或者网络不稳定导致会话断开、重置，二分法就不再适用了，为了减少错误，应当考虑逐位恢复。

这里的攻击是基于**RSA parity Oracle** 方案，即对一个给定的密文解密后会检查明文的奇偶性，然后返回相应的值。这里所存在的问题是每次加密和解密所使用的密钥会不一样，5.3节中所介绍的二分法的原理是在相同的密钥的情况下通过选择明文攻击不断发送消息，从而得出明文。

而在不同的密钥的情况下，我们需要逐比特进行恢复。原理如下：
* 首先明文为$m$，密文为$c_i$，公钥为$e_i,N_i$，私钥为$d_i$，其中$i$表示第$i$次在Oracle中的数据，其中密文和公钥是可以获取的。与此同时，我们还可以从Oracle的手中获得明文的最后一个bit，即我们可以把$c_i$重新发给Oracle，然后Oracle会返回$y = c_i^{d_i}\ mod\ 2$。
* **攻击：** 要恢复明文的第$j$比特，则把$c_i(2^{-je_i\ mod\ N_i})$发送给Oracle，则Oracle将会返回$$y_j \equiv a_j + a_{j-1} \times 2^{j-1} \times 2^{-j} + ... + a_0 \times 2^0 \times 2^{-j}$$ 根据前面恢复出的明文$m$的前$j$比特:$a_0,a_1,...,a_{j-1}$容易计算得出明文$m$的第$j$比特$a_j$。

**注意：** 这里的攻击同样适用于5.3节说讲到的RSA parity Oracle 攻击。

具体方案同样见：https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_chosen_plain_cipher/
* ***具体Python3代码见``crypto/code/RSA_parity_oracle_variant.py``***

#### 六、侧信道攻击
侧信道攻击：攻击者能获取密码设备中的侧信道信息(例如能量消耗、运算时间、电磁辐射等等)从而获取密码信息。

攻击条件：密码实现的过程中侧信道信息泄露，能从侧信道信息中获取加密过程的信息，从而分析出明文。

详细例子见：https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_side_channel/

#### 七、基于具体RSA实现的攻击
##### 7.1  Bleichenbacher's Attack on PK CS 1
即在PKCS 1(Public Key Cryptography Standard 1)中实现时可以找出实现时的漏洞，然后相当于敌手获得一个oracle，使得敌手可以不断猜测一个伪造的签名，知道猜测成功。

这种攻击主要针对PKCS 1实现时的攻击。

***注：这里只提供理论支撑，详细例子见crypto文件夹中的各个writeup。其实有一部分理论我也不是很清楚，特别是Coppersmith方案中的方法。要做几道题来再搞清楚一下其细节的方案，特别是***
1. ***Coppersmith方案解方程的实现***
2. ***部分密钥泄露攻击***
3. ***Boneh and Durfee attack***


## $\mathrm I\mathrm I.\mathrm I\mathrm I$ 背包加密
* 参考：https://ctf-wiki.org/crypto/asymmetric/knapsack/knapsack/#_9

![Knapsack_problem](crypto/images/Knapsack_problem.PNG)
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


## $\mathrm I\mathrm I.\mathrm I\mathrm I\mathrm I$ 离散对数
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

### 一 ElGamal
**密码体制**
![ElGamal](crypto/images/ElGamal.PNG)
一般来说，$p$至少是160位的十进制素数，**并且$p-1$有大的素因子**。

### 二 ECC 椭圆曲线加密
ECC 全称为椭圆曲线加密，EllipseCurve Cryptography，是一种基于椭圆曲线数学的公钥密码。与传统的基于大质数因子分解困难性的加密方法不同，ECC 依赖于解决椭圆曲线离散对数问题的困难性。它的优势主要在于相对于其它方法，它可以在使用较短密钥长度的同时保持相同的密码强度。ECC密码体制在区块链等多种领域中都有应用。

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
* 在扩域GF(2^p)上，椭圆曲线的点加公式如下：
![椭圆曲线扩域点加公式](crypto/images/GF2-131_PointAdd.jpg)

**椭圆曲线的阶：** 如果椭圆曲线上一点$P$，存在最小的正整数$n$使得数乘$nP = O_{\infty}$，则将$n$成为点$P$的阶。若$n$不存在，则$P$是无限阶的。

#### ECC中的ElGammal方案
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

#### 常见ECC攻击方法
* 分布式Pollard Rho算法
* Pohlig-Hellman攻击(同样用于基点$P$的阶是可被分解成比较小的质因数的情景)
* 暴力枚举私钥
* 常见曲线（理论上需要使用特定的方法把该曲线转换成Weierstrass曲线的形式）：https://www.hyperelliptic.org/EFD/index.html


### 三 超椭圆曲线

一个在$F_q,q = p^l$上的亏格为$g$的超椭圆曲线$C$是由下面的方程构成$$y^2+h(x)y=f(x)$$其中$h(x)$和$f(x)$是两个系数为$F_q$的多项式，其中$deg(h(x))\leq g$和$deg(f(x))=2g+1$。与此同时曲线需要满足非奇异的特性，即满足$$
\begin{cases}
y^2+h(x)y=f(x)\\
2y+h(x)=0\\
h'(x)y-f'(x)=0
\end{cases}
$$ 这三个方程没有解。

接下来对于有限域$F_q$的一个扩域$K$。记$L$为$F_q$的一个代数闭包，那么就有$F_q \subset K \subset L$。 

**除子：** 除子是超椭圆曲线$C$上的点$C(L)$的形式和，记$$D = Div_C(L) = \sum_{P\in C(L)}c_P[P]$$ 定义除子的度数$deg(D)$为$\sum_Pc_P$。对于扩域$K$，我们可以定义度数为0的在扩域$K$上的除子群，其中有$\#K = q^r$：
$$Div_C^0(K):=\{ D\in Div_C(L) | deg(D) = 0, D^{\sigma^r} = D \}$$ 其中有$P^{\sigma} = (x^q,y^q)$且$D^{\sigma} = \sum_Pc_P[P^{\sigma}]$。

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
题目本质上是给了超椭圆曲线的加密方案，但是密钥泄露了$u(x)$。然后只需要求出$v(x)$即可。根据$u(x)$我们可以知道$u(x)$的三个根，然后又因为点$(x_i, v(x_i))$在曲线$C$上。因此可以列出三个方程
$$(ax^2+bx+c)^2 = x^7 +x$$，解出参数$a,b,c$得到$v(x)$，然后就可以求出flag。

参考write up：https://ctftime.org/writeup/25448

## $\mathrm I\mathrm I.\mathrm I\mathrm V$ 格密码 

### 格的基本定义

![格的定义](crypto/images/Lattice.png)

### 格上的困难问题
* **最短向量问题 (Shortest Vector Problem，SVP)**：给定格 $L$ 及其基向量 $B$ ，找到格 $L$ 中的非零向量 $v$ 使得对于格中的任意其它非零向量 $u$，有$||v||\leq||u||$。

* **$\gamma$-近最短向量问题(SPV-$\gamma$)**：给定格 $L$ 及其基向量 $B$ ，找到格 $L$ 中的非零向量 $v$ 使得对于格中的任意其它非零向量 $u$，有$||v||\leq\gamma||u||$。

* **连续最小长度问题 (Successive Minima Problem, SMP)**：给定一个秩为 $n$ 的格 $L$，找到格 $L$ 中 $n$ 个线性无关向量$s_i$，满足$\lambda_i(L)=||s_i||,\ 1\leq i\leq n$。

* **最短线性无关向量问题 (Shortest Independent Vector Problem, SIVP)**：给定一个秩为 $n$ 的格 $L$，找到格 $L$ 中 $n$ 个线性无关向量$s_i$，满足$||s_i||\leq\lambda_n(L),\ 1\leq i\leq n$。

* **最近向量问题 (Closest Vector Problem，CVP)**：给定格 $L$ 和目标向量$t\in R^m$，找到一个格中的非零向量 $v$，使得对于格中 $\forall u$，满足$||v-t||\leq||u-t||$。即在格$L$上找到一个离$t$最近的向量。

### 格基规约算法(Lenstra–Lenstra–Lovasz, LLL)
* 参考论文: https://cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/lll.pdf

LLL算法本质上是将A lattice basis $B$转换为 LLL-reduced basis $\tilde{B}$，其中$\tilde{B}$是一个正交基组成的矩阵，去解决SPV-$\gamma$问题。**“转换”** 就是要做Gram-Schmidt正交化，但要满足两个条件
1. For every $i < j$, we have $|\mu_{i,j}|\leq\frac{1}{2}$. (Such a basis is said to be "size reduced.") **目的是保证Gram-Schmidt正交化不会太小**
2. For every $1\leq i < n$, we have $\frac{3}{4}||\tilde{b}_i ||^2 \leq ||\mu_{i,i+1} \tilde{b}_i + \tilde{b}_{i+1}||^2$.  (This is the "Lovasz condition.") **目的是保证缩减不要太快**

这里的$\mu$表示的是，$B=\tilde{B}U$中矩阵$U$的某些元素。其中$U$是一个单位上三角矩阵，对角线全为1，然后对角线往上的元素第$i$行第$j$列的元素记为$\mu_{i,j}$。

主要性质（解决SPV-$\gamma$）：
![格LLL算法](crypto/images/LLL.PNG)

### Babai's nearest plane algorithm
* 此算法用来求CVP问题的近似解，算法复杂度归结于LLL算法。
* 参考文献
    * https://cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/cvp.pdf
    * https://www.isg.rhul.ac.uk/~sdg/igor-slides.pdf

该算法输入一组格$L$(秩为$n$) 的基$B$ 和一个目标向量$t$，输出 CVP 问题的近似解，近似因子$\gamma =2^{\frac{n}{2}}$。具体算法如下，本质上是LLL算法：
![Babai's nearest plane algorithm](crypto/images/BabaisNearestPlaneAlgorithm.PNG)
这里的$b_j$表示的是经过LLL算法变换之后个格基的第$j$个向量。

#### Babai’s Rounding Technique
该算法是``Babai's nearest plane algorithm``的一个变种。

#### Hidden number problem
* 该问题可以规约到CVP问题并使用Babai's nearest plane algorithm解决。

**HNP:** Recover $\alpha \in F_p$ such that for many known random $t\in F_p$ we are given $MSP_{l,p}(\alpha t)$ for some $l > 0$. 
**MSB:** $MSP_{l,p}(x)$ denotes any integer $u$ such that $$|\lfloor x \rfloor_p-u |\leq \frac{p}{2^{l+1}}$$ $MSP_{l,p}(x) \approx l$ most significant bits of $x$.
**B&V, 1996:** a polynomial time algorithm to solve HNP with $l \approx log^{1/2}p = (log(p))^{1/2}$.

又参考文献 https://www.isg.rhul.ac.uk/~sdg/igor-slides.pdf 可知当$l \approx log^{\frac{1}{2}}p$时，可以讲此问题规约到一个CVP问题。

* 算法流程：
* 输入：给出素数$p$整数$l$且$l$满足$l\approx log^{\frac{1}{2}}p$，$n$个$t\in F_p$，对应的$n$个数$u_i = MSP_{l,p}(\alpha t_i)$。
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

#### BCTF 2018 - guess_number
比赛是一个典型的**Hidden number problem**，可以把这道题目的求解堪称是Hidden number problem的一个典型的解法。

* 题目代码``crypto/code/Hidden_Number_Problem/server.py``
* 解题代码``crypto/code/Hidden_Number_Problem/Hidden_Number_Problem.sage``

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

## Fowler–Noll–Vo hash function (FNV)
参考：https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function

此Hash函数首先把输入分块，然后初始化一个``FNV_offset_basis``和``FNV_prime``，最初始的hash值等于``FNV_offset_basis``。然后对于每个输入的块，把当前hash值乘以``FNV_prime``然后与输入的块进行异或。所有块处理完后就是最终的hash值。

* 这种Hash函数是一个非密码安全的Hash。一般用于快速hash，计算校验和，不用做密码。局限点如下：
    1. **计算速度**：计算速度上正向计算和逆向计算的速度接近。
    2. **粘稠**：因为只涉及乘法和异或运算，因此对于0较多的输入非常的敏感。
    3. **扩散**：因为只有异或运算，此hash函数的扩散性质可通过XOR-folding减轻。

#### 2018 网鼎杯 hashcoll
这道题目并不是标准的FNV哈希，而是有一点小的变动。该问题可以分析得到是：**给出
$n$个数，求解它们的整线性组合使得线性组合所得到的结果为0**。一种求解的方法是使用格中的LLL算法进行求解。

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

* ***具体Sagemath9.2代码见``crypto/code/LLL_n_positive_integral_combination.sage``*** 这里不是给出题解，而是给出如何使用LLL算法求解**给出
$n$个数，求解它们的整线性组合使得线性组合所得到的结果为0**这个问题。

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

* 攻击原理：最核心在于此等式成立$$h_K(x||x')=compress(h_K(x)||x')$$ 其中$h_K$需要每个输入消息的长度是$t$的倍数，然后$x'$是任意长度为$t$的倍数的比特串。

* **工具 hashpump**：  https://github.com/bwall/HashPump

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
**具体方案：** 设$p$是一个使得在$Z_p$上的离散对数问题是难处理的素数，设$\alpha\in Z_p^*$是一个本原元(生成元)。设$\mathcal P = Z_p, \mathcal A = Z_P^*\times Z_{p-1}$，定义$$\mathcal K = \{(p,\alpha, a, \beta):\beta \equiv \alpha^a\ (mod\ p)\}$$ 其中$p,\alpha,\beta$是公钥，$a$是私钥。

队$K=(p,\alpha, a, \beta) \in \mathcal K$和一个(秘密)随机数$k\in Z_{p-1}^*$，则：$$sig_K(x,k)=(\gamma,\delta)$$ 其中 $$\gamma = \alpha^k\ mod\ p \newline \delta = (x-a\gamma)k^{-1}\ mod\ (p-1)$$ 对于$x,\gamma\in Z_p^*$和$\delta\in Z_{p-1}$，有 $$ver_K(x,(\gamma,\delta)) = true \newline \Leftrightarrow \beta^{\gamma}\gamma^{\delta}\equiv \alpha^{x}\ (mod\ p)$$

### 常见Elgamal攻击
#### 1.完全破译攻击
* $p$太小或$p$无大素因子
此时的攻击方法于Elgamal加密方案的破解方法一致，即使用大步小步法或者Pohlig-Hellman算法。

* 随机数$k$复用
如果签名者复用了随机数 k，那么攻击者就可以轻而易举地计算出私钥。

容易得$$\gamma = \alpha^k\ mod\ p \newline \delta_1 = (m_1-a\gamma)k^{-1}\ mod\ (p-1) \newline \delta_2 = (m_2-a\gamma)k^{-1}\ mod\ (p-1)$$ 进而有 $$\delta_1k \equiv m_1 - a\gamma\ mod\ (p-1) \newline \delta_2k \equiv m_2 - a\gamma\ mod\ (p-1)$$ 两式相减得 $$k(\delta_1-\delta_2)\equiv m_1-m_2\ mod\ (p-1)$$ 容易计算出随机数$k$，如果$gcd(\delta_1-\delta_2, p-1) \neq 1$，存在多个解，逐个去试即可。因此有私钥$$a = (m-k\delta)\gamma^{-1}\ mod\ (p-1)$$

#### 2. 通用伪造签名
如果消息$m$没有取哈希，或者消息$m$没有指定消息格式的情况下攻击成立。攻击者只能构造同构签名验证的信息，但无法伪造指定格式的消息。当消息$m$进行hash操作可避免此攻击。

**攻击流程：**
1. 选择整数$i,j$满足$gcd(j,p-1)=1$。
2. 计算签名：$$\gamma = \alpha^i \beta^j\ mod\ p \newline \delta = -\gamma j^{-1}\ mod\ (p-1)$$
3. 构造消息：$$x=-\gamma ij^{-1}\ mod\ (p-1)$$

验证：$$\beta^{\gamma}\gamma^{\delta} \equiv \alpha^{i\delta}\beta^{\gamma+j\delta} \equiv \alpha^{i\delta}\beta^{\gamma-j\gamma j^{-1}} \equiv \alpha^{-ij^{-1}\gamma} \equiv \alpha^x\ mod\ p$$

#### 3. 已知签名伪造
* 攻击者已知$\gamma,\delta$以及消息$x$。（已知消息攻击的存在性伪造）同样可以对消息$m$进行hash操作避免此攻击。

**攻击流程：**
1. 选择整数$h,i,j, 0\leq h,i,j \leq p-2$，且$gcd(h\gamma-j\delta, p-1)=1$。
2. 计算签名：$$\lambda = \gamma^h\alpha^i\beta^j\ mod\ p \newline \mu=\delta\lambda(h\gamma-j\delta)^{-1}\ mod\ (p-1)$$
3. 构造新消息：$$x'=\lambda(hx+i\delta)(h\gamma-j\delta)^{-1}\ mod\ (p-1)$$

验证： $$\beta^{\lambda}\lambda^{\mu}\equiv\alpha^{x'}\ mod\ p$$

#### 4. 选择签名伪造
* 如果可以做到选择消息攻击，即选择消息$m_1,m_2,...$进行签名。然后对一个消息$m'$，我们可以在不使用黑盒的前提下构造出$m'$的签名。

**攻击思想：** 因为要验证$$\beta^{\gamma}\gamma^{\delta}\equiv \alpha^{x}\ (mod\ p)$$ 只要选择一个消息$m$满足$m\equiv m'\ mod\ (p-1)$，选择$m$的签名$\gamma_m,\delta_m$，则有$$\alpha^{m'} \equiv \alpha^m \equiv \beta^{\gamma_m}\gamma_m^{\delta_m} $$

## DSA
DSA 最早在1991年8月被提出，1994年12月1日被采纳数字签名标准。DSA是ElGamal签名方案的一个变种。

**具体方案：** 选择一个长度为$L$比特的素数$p$，在$Z_p$上的离散对数问题是难处理的，其中$L \equiv 0\ mod\ 64$且$512 \leq L \leq 1024$(可以更大)。选择$q$是一个$N$比特的素数，而且满足$q|p-1$。设$\alpha\in Z_p^*$是1模$p$的$q$次根，即$\alpha^q \equiv 1\ mod\ p$。设$\mathcal P = \{0,1\}^*,\mathcal A=Z_q^*\times Z_q^*$，并定义$$\mathcal K=\{(p,q,\alpha,a,\beta):\beta \equiv \alpha^a(mod\ p)\}$$ 其中$0\leq a \leq q-1$。$p,q,\alpha,\beta$是公钥，$a$为私钥。对于$K=(p,q,a,\alpha, \beta) \in \mathcal K$和一个秘密随机数$k, 1\leq K\leq q-1$，选择一个哈希函数$H(x)$，则有
$$sig_K(x,k)=(\gamma, \delta)$$ 其中$$\gamma = (\alpha^k\ mod\ p)\ mod\ q 
\newline
\delta = (H(x) + a\gamma)k^{-1}\ mod\ q$$
且有$\gamma \neq 0$且$\delta \neq 0$。 
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
$$ 两式相减得 $$k(\delta_1 - \delta_2) \equiv H(x_1)-H(x_2)\ mod\ q$$ 从而解出随机数$k$。然后使用第一个攻击方法恢复出私钥$a$。


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

# 比赛
* angstromctf (https://2021.angstromctf.com/)
    * Cache Money
    https://mystiz.hk/posts/2021-04-08-angstromctf-2021/


# 练习题

## Hash相关
* 2017 34c3 Software_update
    * https://sectt.github.io/writeups/34C3CTF/crypto_182_software_update/Readme
    * https://github.com/OOTS/34c3ctf/blob/master/software_update/solution/exploit.py
* 2019 36c3 SaV-ls-l-aaS
    * https://ctftime.org/writeup/17966

# 解题技巧
遇到密文是乱七八糟的字符串而明文是正常的英文字符+数字+括号的情况的时候，可以使用这种特性缩小明文和密钥的取值。参考`crypto/2021_Mtctf/RSA_2021_MTctf_easy_RSA`这道题。