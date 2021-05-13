- writer: github.com/hex-16   data: from 2020   contact: hexhex16@outlook.com
> **Tips** : Highly recommend open with markdown editor **Typora**, and enable all *syntax support* and sidebar *Outline*.

# Reverse Engineering Introduction

- 软件代码逆向主要指对软件的结构，流程，算法，代码等进行逆向拆解和分析
- Software Reverse Engineering: 主要应用于软件维护，软件破解，漏洞挖掘，恶意代码分析

要求

- 熟悉如操作系统，汇编语言，加解密等相关知识
- 具有丰富的多种高级语言的编程经验
- 熟悉多种编译器的编译原理
- 较强的程序理解和逆向分析能力



## To-Do List

- [ ] 疑似用python生成的exe文件 可以直接运行 文件较大的 急需补充背景知识(shadowCTF secure protocol)





## Warning List

> 记录做题史中犯过的低级错误

- 特别注意Python**位操作**与其他常见操作符之间的优先级关系

| 运算符说明 | Python运算符             | 优先级 | 结合性 |
| ---------- | ------------------------ | ------ | ------ |
| 小括号     | `( )`                    | 19     | 无     |
| 索引运算符 | `x[i], x[i1: i2 [:i3]]`  | 18     | 左     |
| 属性访问   | `x.attribute`            | 17     | 左     |
| 乘方       | `**`                     | 16     | 右     |
| 按位取反   | `~`                      | 15     | 右     |
| 符号运算符 | `+`（正号）、`-`（负号） | 14     | 右     |
| 乘除       | `*, /, //, %`            | 13     | 左     |
| 加减       | `+, -`                   | 12     | 左     |
| 位移       | `>>, <<`                 | 11     | 左     |
| 按位与     | `&`                      | 10     | 右     |
| 按位异或   | `^`                      | 9      | 左     |
| 按位或     | `|`                      | 8      | 左     |
| 比较运算符 | `==, !=, >, >=, <, <= `  | 7      | 左     |
| is 运算符  | `is, is not`             | 6      | 左     |
| in 运算符  | `in, not in`             | 5      | 左     |
| 逻辑非     | `not`                    | 4      | 右     |
| 逻辑与     | `and`                    | 3      | 左     |
| 逻辑或     | `or`                     | 2      | 左     |
| 逗号运算符 | `exp1, exp2`             | 1      | 左     |



## Reverse Workflow

1. 使用`exeinfope/PEiD/strings/file/binwalk/IDA`等静态分析工具收集信息，并根据这些静态信息进行google/github搜索
2. 研究程序的保护方法，如代码混淆，保护壳及反调试等技术，并设法破除或绕过保护
3. 反汇编目标软件(IDA)，快速定位到关键代码进行分析
4. 结合动态调试(OllyDbg, gdb, etc)，验证自己的初期猜想，在分析的过程中理清程序功能
5. 针对程序功能，写出对应脚本，求解出 flag



动态分析 

- 动态分析的目的在于定位关键代码后，在程序运行的过程中，借由输出信息（寄存器，内存变化，程序输出）等来验证自己的推断或是理解程序功能
- 主要方法：调试，符号执行，污点分析





## Encryption and Encoding

> 常见加密算法、编码等。也放上一些常用的python cases，主要涉及字符串操作的





### Base64

Base64 是一种基于 64 个可打印字符来表示二进制数据的表示方法。转换的时候，将 3 字节的数据，先后放入一个 24 位的缓冲区中，先来的字节占高位。数据不足 3 字节的话，于缓冲器中剩下的比特用 0 补足。每次取出 6 比特（因为 $$ 2^{6}=64$$），按照其值选择`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`中的字符作为编码后的输出，直到全部输入数据转换完成。

通常而言 Base64 的识别特征为索引表，当我们能找到 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` 这样索引表，再经过简单的分析基本就能判定是 Base64 编码。

有些题目 base64 的索引表是会变的，一些变种的 base64 主要 就是修改了这个索引表



#### Bash64: python

```python
str_ori = "abcd"
bytes_str = str_ori.encode("utf-8")  
str_b64 = base64.b64encode(bytes_str) # b64encode # 被编码的参数必须是二进制数据 

str_result = base64.b64decode(str_b64).decode("utf-8") # b64decode # 连用b64解码后按utf-8解析
```

- case: 将bash64编码进行解码后，逆向一个加密算法的过程

```python
import base64
correct = 'XlNkVmtUI1MgXWBZXCFeKY+AaXNt'
def decode(message):
    message = base64.b64decode(message) # base64 to byte
    print(type(message), message)
    s = ''
    for i in message:
        x = ord(chr(i))
        x = x - 16
        x = x ^ 32
        s += chr(x)
    return s

print(decode(correct))
```



### Tea

在[密码学](https://zh.wikipedia.org/wiki/密码学)中，**微型加密算法**（Tiny Encryption Algorithm，TEA）是一种易于描述和[执行](https://zh.wikipedia.org/w/index.php?title=执行&action=edit&redlink=1)的[块密码](https://zh.wikipedia.org/wiki/塊密碼)，通常只需要很少的代码就可实现。其设计者是[剑桥大学计算机实验室](https://zh.wikipedia.org/wiki/剑桥大学)的[大卫 · 惠勒](https://zh.wikipedia.org/w/index.php?title=大卫·惠勒&action=edit&redlink=1)与[罗杰 · 尼达姆](https://zh.wikipedia.org/w/index.php?title=罗杰·尼达姆&action=edit&redlink=1)。

参考代码：

```cpp
#include <stdint.h>

void encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;                                   
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}
```

在 Tea 算法中其最主要的识别特征就是 拥有一个 image number ：0x9e3779b9 。当然，这 Tea 算法也有魔改的，感兴趣的可以看 2018 0ctf Quals milk-tea。





### RC4

在[密码学](https://zh.wikipedia.org/wiki/密碼學)中，**RC4**（来自 Rivest Cipher 4 的缩写）是一种[流加密](https://zh.wikipedia.org/wiki/流加密)算法，[密钥](https://zh.wikipedia.org/wiki/密钥)长度可变。它加解密使用相同的密钥，因此也属于[对称加密算法](https://zh.wikipedia.org/wiki/对称加密)。RC4 是[有线等效加密](https://zh.wikipedia.org/wiki/有線等效加密)（WEP）中采用的加密算法，也曾经是 [TLS](https://zh.wikipedia.org/wiki/传输层安全协议) 可采用的算法之一。

```cpp
void rc4_init(unsigned char *s, unsigned char *key, unsigned long Len) { //初始化函数
    int i =0, j = 0;
    char k[256] = {0};
    unsigned char tmp = 0;
    for (i=0;i<256;i++) {
        s[i] = i;
        k[i] = key[i%Len];
    }
    for (i=0; i<256; i++) {
        j=(j+s[i]+k[i])%256;
        tmp = s[i];
        s[i] = s[j]; //交换s[i]和s[j]
        s[j] = tmp;
    }
 }

void rc4_crypt(unsigned char *s, unsigned char *Data, unsigned long Len) { //加解密
    int i = 0, j = 0, t = 0;
    unsigned long k = 0;
    unsigned char tmp;
    for(k=0;k<Len;k++) {
        i=(i+1)%256;
        j=(j+s[i])%256;
        tmp = s[i];
        s[i] = s[j]; //交换s[x]和s[y]
        s[j] = tmp;
        t=(s[i]+s[j])%256;
        Data[k] ^= s[t];
     }
} 
```

通过分析初始化代码，可以看出初始化代码中，对字符数组 s 进行了初始化赋值，且赋值分别递增。之后对 s 进行了 256 次交换操作。通过识别初始化代码，可以知道 rc4 算法。

其伪代码表示为：

初始化长度为 256 的 [S 盒](https://zh.wikipedia.org/wiki/S盒)。第一个 for 循环将 0 到 255 的互不重复的元素装入 S 盒。第二个 for 循环根据密钥打乱 S 盒。

```
  for i from 0 to 255
     S[i] := i
 endfor
 j := 0
 for( i=0 ; i<256 ; i++)
     j := (j + S[i] + key[i mod keylength]) % 256
     swap values of S[i] and S[j]
 endfor
```

下面 i,j 是两个指针。每收到一个字节，就进行 while 循环。通过一定的算法（(a),(b)）定位 S 盒中的一个元素，并与输入字节异或，得到 k。循环中还改变了 S 盒（©）。如果输入的是[明文](https://zh.wikipedia.org/wiki/明文)，输出的就是[密文](https://zh.wikipedia.org/wiki/密文)；如果输入的是密文，输出的就是明文。

```
 i := 0
 j := 0
 while GeneratingOutput:
     i := (i + 1) mod 256   //a
     j := (j + S[i]) mod 256 //b
     swap values of S[i] and S[j]  //c
     k := inputByte ^ S[(S[i] + S[j]) % 256]
     output K
 endwhile
```

此算法保证每 256 次循环中 S 盒的每个元素至少被交换过一次

### MD5

**MD5 消息摘要算法**（英语：MD5 Message-Digest Algorithm），一种被广泛使用的[密码散列函数](https://zh.wikipedia.org/wiki/密碼雜湊函數)，可以产生出一个 128 位（16 [字节](https://zh.wikipedia.org/wiki/字节)）的散列值（hash value），用于确保信息传输完整一致。MD5 由美国密码学家[罗纳德 · 李维斯特](https://zh.wikipedia.org/wiki/罗纳德·李维斯特)（Ronald Linn Rivest）设计，于 1992 年公开，用以取代 [MD4](https://zh.wikipedia.org/wiki/MD4) 算法。这套算法的程序在 RFC 1321中被加以规范。

伪代码表示为：

```assembly
/Note: All variables are unsigned 32 bits and wrap modulo 2^32 when calculating
var int[64] r, k

//r specifies the per-round shift amounts
r[ 0..15]：= {7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22} 
r[16..31]：= {5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20}
r[32..47]：= {4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23}
r[48..63]：= {6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21}

//Use binary integer part of the sines of integers as constants:
for i from 0 to 63
    k[i] := floor(abs(sin(i + 1)) × 2^32)

//Initialize variables:
var int h0 := 0x67452301
var int h1 := 0xEFCDAB89
var int h2 := 0x98BADCFE
var int h3 := 0x10325476

//Pre-processing:
append "1" bit to message
append "0" bits until message length in bits ≡ 448 (mod 512)
append bit length of message as 64-bit little-endian integer to message

//Process the message in successive 512-bit chunks:
for each 512-bit chunk of message
    break chunk into sixteen 32-bit little-endian words w[i], 0 ≤ i ≤ 15

    //Initialize hash value for this chunk:
    var int a := h0
    var int b := h1
    var int c := h2
    var int d := h3

    //Main loop:
    for i from 0 to 63
        if 0 ≤ i ≤ 15 then
            f := (b and c) or ((not b) and d)
            g := i
        else if 16 ≤ i ≤ 31
            f := (d and b) or ((not d) and c)
            g := (5×i + 1) mod 16
        else if 32 ≤ i ≤ 47
            f := b xor c xor d
            g := (3×i + 5) mod 16
        else if 48 ≤ i ≤ 63
            f := c xor (b or (not d))
            g := (7×i) mod 16

        temp := d
        d := c
        c := b
        b := leftrotate((a + f + k[i] + w[g]),r[i]) + b
        a := temp
    Next i
    //Add this chunk's hash to result so far:
    h0 := h0 + a
    h1 := h1 + b 
    h2 := h2 + c
    h3 := h3 + d
End ForEach
var int digest := h0 append h1 append h2 append h3 //(expressed as little-endian)
```

其鲜明的特征是：

```python
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
```

#### md5: python

```python
import hashlib
m = hashlib.md5()
m.update(b'sssssssdddddddsssssssssssddddddddddsddssddwddssssssdddssssdddss')
print(m.hexdigest()) # 999ea6aa6c365ab43eec2a0f0e5968d5
```





## Labyrinth Problem

> 迷宫问题

特点:

- 在内存中布置一张 "地图"
- 将用户输入限制在少数几个字符范围内，一般对应上下左右的移动操作
- 一般只有一个迷宫入口和一个迷宫出口



Workflow:

1. IDA分析函数操作，是否符合迷宫移动的特征。特征包含：二维矩阵寻址，移动并修改新旧位置的标记
2. IDA找到迷宫地图，通常有两个出现频率高的表示路和墙，有两个出现频率很小的表示出入口
3. 恢复迷宫地图至可直接观察的状态，解迷宫





### Cases

- `xctf_2020` MIPS: MIPS的代码，注意IDA的版本，有的不支持MIPS decompile。用了三张地图，三张地图都过了之后，会输出提示`puts((int)"success! the flag is flag{md5(your input)}");` 逆向迷宫处理的主函数可知`wasd`控制方向，地图大小`15*15`



## pyc Reverse

> `.pyc`文件
>
> ctf-wiki中将pyc归类为misc，但是在adworld中pyc在reverse中出现
>
> https://www.zhihu.com/question/30296617  知乎 Python什么情况下会生成pyc文件？

- pyc文件是由.py文件经过编译后生成的**字节码文件**(二进制文件)，其加载速度相对于.py文件有所提高，可以实现源码隐藏，一定程度上的反编译。e.g. Python3.3编译生成的.pyc文件，Python3.4无法运行
- pyo文件也是优化编译后的程序（相比于.pyc文件更小），也可以提高加载速度。但对于嵌入式系统，它可将所需模块编译成.pyo文件以减少容量
- `Python` 是一种全平台的解释性语言，全平台其实就是 `Python` 文件在经过解释器解释之后 (或者称为编译) 生成的 `pyc` 文件可以在多个平台下运行，这样同样也可以隐藏源代码。其实， `Python` 是完全面向对象的语言， `Python` 文件在经过解释器解释后生成字节码对象 `PyCodeObject` ， `pyc` 文件可以理解为是 `PyCodeObject` 对象的持久化保存方式
- 而 `pyc` 文件只有在文件被当成模块导入时才会生成。也就是说， `Python` 解释器认为，只有 `import` 进行的模块才需要被重用。 生成 `pyc` 文件的好处显而易见，当我们多次运行程序时，不需要重新对该模块进行重新的解释。主文件一般只需要加载一次，不会被其他模块导入，所以一般主文件不会生成 `pyc` 文件。
- `python path/to/projectDir` 程序运行结束后便自动为当前目录下所有的脚本生成字节码文件，并保存于本地新文件夹`__pycache__`当中
- `python path/to/projectDir/__main__.py`生成除`__main__.py`外脚本的字节码文件

> `-O`，表示优化生成.pyo字节码（这里又有“优化”两个字，得注意啦！）
> `-OO`，表示进一步移除-O选项生成的字节码文件中的文档字符串（这是在作用效果上解释的，而不是说从-O选项得到的文件去除）
> `-m`，表示导入并运行指定的模块

```python
# 生成pyc文件：
python -m py_compile /path/to/a.py #若批量处理.py文件则替换为/path/to/{a, b,...}.py 或 /path/to/
# 生成pyo文件：
python -O -m py_compile /path/to/a.py
```

```python
# 生成pyc文件 python脚本版：
import py_compile
py_compile.compile(r'/path/to/a.py') #同样也可以是包含.py文件的目录路径
#此处尽可能使用raw字符串，从而避免转义的麻烦。比如，这里不加“r”的话，你就得对斜杠进行转义
```

- 无论是生成.pyc还是.pyo文件，都将在当前脚本的目录下生成一个含有字节码的文件夹`__pycache__`

### uncompyle6

- 原生python的跨版本反编译器和fragment反编译器，是decompyle、uncompyle、uncompyle2等的接替者
- uncompyle6可将python字节码转换回等效的python源代码，它接受python 1.3版到3.8版的字节码，这其中跨越了24年的python版本，此外还包括Dropbox的Python 2.5字节码和一些PyPy字节码

> https://github.com/rocky/python-uncompyle6 github repo

```bash
pip install uncompyle6 # install in Linux
uncompyle6 -o out.py task.pyc # pyc to py
```



## Python: Encoding

> 编码相关知识与Python实现 包含转换等 Base64等在别的章节

- **Attention! Python里按位异或 `^` 等的优先级低于 `+, -`等操作符**

### int, hex, str, byte

```python
ord('a') # 97 # char to int, ord以Unicode字符为参数 返回对应的ASCII数值或Unicode数值
chr(0x30) # '0' # 用一个整数作参数，返回对应的字符(include Unicode) # chr(97) # 'a'

s = "".ljust(18,'0') # len should be 18 # 特定长度的字符串
arr = [97]*6 # 6个97的list
arr = [ord('a') + i for i in range(4)] # [97, 98, 99, 100]
''.join(map(chr,arr)) # abcd # int list to str 


# python 3.5之后 str和bytes实现由重大变化，无法使用encode/decode完成，而是使用bytes.fromhex()等
s_key = bytes.fromhex("39343437") # hex bytes str to str
print(type(s_key), s_key) # <class 'bytes'> b'9447'
h_key = s_key.hex() # bytes to hex bytes
print(type(h_key), h_key) # <class 'str'> 39343437

```

```python
# class bytes to str # and class str to bytes
s = "ABCabc" # <class 'str'>
arr = bytes(s, 'utf-8') # <class 'bytes'> # b'ABCabc' # for byte in arr: 65 66 67 97 98 99
arr2 = bytes(s, 'ascii') # <class 'bytes'> # b'ABCabc' # for byte in arr: 65 66 67 97 98 99
bytearray(str(s), "ascii") # str to bytes
```





### Cases

```python
import random
arr = [0x5F, 0xF2, 0x5E, 0x8B, 0x4E, 0x0E, 0xA3, 0xAA, 0xC7, 0x93,
       0x81, 0x3D, 0x5F, 0x74, 0xA3, 0x09, 0x91, 0x2B, 0x49, 0x28,
       0x93, 0x67]

in_str = [0 for i in range(len(arr))]

for idx in range(len(arr)):
    v19 = 0
    for i in range(idx + 1):
        v19 = 1828812941 * v19 + 12345
    in_str[idx] = arr[idx] ^ v19 & 0xff
print(len(in_str), in_str)
print(''.join(map(chr, in_str)))

# below: original algorithm
v20 = 10  # 其实这个循环控制变量不影响解题 因为这里idx是随机生成的 相当于10是生成随机idx的次数
v21 = True
while(v20 > 0):
    idx = random.randint(0, 22) % 22
    v16 = arr[idx]
    v15 = in_str[idx]
    v18 = 0
    v19 = 0
    while(v18 < idx + 1):  # 做idx+1次加密
        v18 += 1
        v19 = 1828812941 * v19 + 12345
    v13 = v19 ^ v15
    if(v16 != v19 ^ v15):
        v21 = False
    v20 -= 1
```









## **.NET** Reverse

> .NET Decompiler: dnSpy(https://github.com/dnSpy/dnSpy), ILSpy

- 可以大致了解一下 .NET Native



## Java Reverse

- 命令行工具：jad
- 带GUI的逆向工具：jadx(https://github.com/skylot/jadx)

```java
带参数运行.jar文件: java -jar Guess-the-Number.jar 309137378
```





---

# Linux Reverse



## ELF

ELF (Executable and Linkable Format)文件，也就是在 Linux 中的目标文件，主要有以下三种类型

1. 可重定位文件 Relocatable File: 包含由编译器生成的代码以及数据。链接器会将它与其它目标文件链接起来从而创建可执行文件或者共享目标文件。在 Linux 系统中，这种文件的后缀一般为 `.o` 。
2. 可执行文件 Executable File: 就是我们通常在 Linux 中执行的程序
3. 共享目标文件 Shared Object File: 包含代码和数据，这种文件是我们所称的库文件，一般以 `.so` 结尾。一般情况下，它有以下两种使用情景：
   - 链接器 (Link eDitor, ld ) 可能会处理它和其它可重定位文件以及共享目标文件，生成另外一个目标文件。
   - 动态链接器 (Dynamic Linker) 将它与可执行文件以及其它共享目标组合在一起生成进程镜像。

目标文件由汇编器和链接器创建，是文本程序的二进制形式，可以直接在处理器上运行。那些需要虚拟机才能够执行的程序 (Java) 不属于这一范围

### Format

- 目标文件既会参与程序链接又会参与程序执行。出于方便性和效率考虑，根据过程的不同，目标文件格式提供了其内容的两种并行视图: 链接视图与执行视图

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/object_file_format.png)

**链接视图**：文件开始处是 ELF 头部（ **ELF Header**），它给出了整个文件的组织情况。

如果程序头部表（Program Header Table）存在的话，它会告诉系统如何创建进程。用于生成进程的目标文件必须具有程序头部表，但是重定位文件不需要这个表。

节区部分包含在链接视图中要使用的大部分信息：指令、数据、符号表、重定位信息等等。

节区头部表（Section Header Table）包含了描述文件节区的信息，每个节区在表中都有一个表项，会给出节区名称、节区大小等信息。用于链接的目标文件必须有节区头部表，其它目标文件则无所谓，可以有，也可以没有。

对于**执行视图**来说，其主要的不同点在于没有了 section，而有了多个 segment。其实这里的 segment 大都是来源于链接视图中的 section。

>  尽管图中是按照 ELF 头，程序头部表，节区，节区头部表的顺序排列的。但实际上除了 ELF 头部表以外，其它部分都没有严格的的顺序。



![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/ELF-Walkthrough.png)



### 程序加载

程序加载过程其实就是系统创建或者或者扩充进程镜的过程。它只是按照一定的规则把文件的段拷贝到虚拟内存段中。进程只有在执行的过程中使用了对应的逻辑页面时，才会申请相应的物理页面。通常来说，一个进程中有很多页是没有被引用的。因此，延迟物理读写可以提高系统的性能。为了达到这样的效率，可执行文件以及共享目标文件所拥有的段的文件偏移以及虚拟地址必须是合适的，也就是说他们必须是页大小的整数倍。





# Windows Reverse

- TBD



# Android Reverse



## apktool

```bash
apktool.jar d andra.apk # 然后会出现一个文件夹 andra 保存经过了解压的apk里面的文件
apktool.jar d -r andra.apk -o andra # 与上面一样 
```







### Installation

> test in 2020.3, Kali20.04, apktool 2.5   https://ibotpeaches.github.io/Apktool/install/

1. Download Linux [wrapper script](https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool) (Right click, Save Link As `apktool`)
2. Download apktool-2 ([find newest here](https://bitbucket.org/iBotPeaches/apktool/downloads/))
3. Rename downloaded jar to `apktool.jar`
4. Move both files (`apktool.jar` & `apktool`) to `/usr/local/bin` (root needed)
5. Make sure both files are executable (`chmod +x`)
6. Try running apktool via cli. (actually, use apktool.jar)



# Assembly Instruction Quick Find

> http://c.biancheng.net/view/3560.html
>
> https://blog.csdn.net/abc_12366/article/details/79774530   汇编语言入门：CALL和RET指令（一）
>
> 这里仅记录较重要 / 少见 / IDA开启Auto comments后仍可能不清楚功能 的汇编指令

| Instructions              | Comments                                                     |
| ------------------------- | ------------------------------------------------------------ |
| `test al, 00001001b`      | 测试0, 3bit是否置1，全都置0时，`ZF=1`，否则`ZF=0`            |
| `test eax, eax`           | 如果`eax`为0，`ZF=1`; 否则`ZF=0`                             |
| `lea dst, src`            | Load Effective Address 取有效地址 将src的4bit偏移地址到寄存器dst |
| `jnz label`               | `if( ZF!=0 )` 跳转                                           |
| `leave`                   | High Level Procedure Exit, in 32bit: `mov esp, ebp; pop ebp`, 将`ebp`的值赋值给`esp`，从栈中恢复`ebp`的值 |
| `call tag`                | `push IP;  jmp near ptr tag`                                 |
| `call dword ptr mem_addr` | `push CS; push IP; jmp dword ptr mem_addr`                   |
| `ret`                     | 相等于执行`pop IP`，指令用栈中的数据，修改IP的内容，从而实现近转移 |
|                           |                                                              |
|                           |                                                              |
|                           |                                                              |

> `int 3` https://blog.csdn.net/trochiluses/article/details/20209593



---

# **Reverse Engineering for Beginners**

> 主要内容摘自 **逆向工程权威指南** [乌克兰]Dennis Yurichev 著, Archer安天安全研究与应急处理中心 译



```cpp
int f(){ // 第二章 最简函数
    return 123;
}
```
```assembly
; 开启优化功能后，GCC产生的x86汇编指令(MSVC编译的程序也一样)：
f:
	mov  eax, 123 ; 将123存放在EAX寄存器里
	ret ; ret指令会把EAX的值当作返回值传递给调用函数，而调用函数(caller)会从EAX取值当作返回结果
```

```assembly
; Optimizing Keil 6/2013(ARM模式)
f PROC
	MOV r0, #0x7b ; 123 ; ARM程序使用R0寄存器传递函数返回值
	BX  lr ; 跳转到返回地址，即返回到caller然后继续执行caller的后续指令; ARM使用LR(Link Register)寄存器存储函数结束之后的返回地址(RA/Return Address)
	ENDP
```



- **Calling Convention, 调用约定, 调用规范**



## 3. Hello, world!



### 3.1-2 x86 and x86-64

```cpp
#include <stdio.h>
int main(){
    printf("hello, world\n"); // 将为"hello, world\n"分配一个const char[]指针
    return 0;
}
```

- 使用MSVC2010 编译: `cl 1.cpp /Fa1.asm`，`/Fa`将使编译器生成汇编指令清单文件(assembly listing file)，并指定汇编列表文件的文件名是`1.asm`
- MSVC生成的汇编清单文件都采用了**Intel语体**(另一种主流语体为**AT&T语体**)
- 所有函数都有标志性的**函数序言function prologue** 和**函数尾声function epilogue**

```assembly
; 指令清单3.1 ; x86; MSVC2010
CONST 	SEGMENT
$SG3830 DB		'hello, world', 0AH, 00H ; 编译器内部把字符串常量命名为 $SG3830 0AH为\n, 00H为\0, 字符串常量结束标志
CONST	ENDS
PUBLIC	_main
EXTRN	_printf:PROC
; Function compile flags: /0dtp
_TEXT	SEGMENT
_main	PROC       ; 函数序言function prologue
    push ebp      ; 把ebp的值入栈 将 caller 的 ebp 入栈
    mov  ebp, esp ; 把esp的值保存在ebp中，此时ebp的值被改变了
    push OFFSET $SG3830 ; 把字符串$SG3830指针入栈
    call _printf  ; printf结束后，程序的控制流会返回到main()函数中，此时字符串$SG3830指针仍残留在数据栈中，需要调整栈指针ESP来释放这个指针
    add  esp, 4   ; 把ESP寄存器(栈指针 Stack Pointer)里的值+4, 因为x86内存地址用32bit(4Byte)数据描述; 直接舍弃了栈里的数据($SG3830指针)
    xor  eax, eax ; main返回值为0，由该指令计算出来 ; main函数的最后一项任务是使EAX的值为0
    pop  ebp      ; 把栈中保存的ebp的旧值pop出来赋值给ebp, 还原caller的ebp
    ret  0        ; 将控制权交给调用程序，通常起到的作用是将控制权交给操作系统，这部分功能由C/C++的CRT实现
_main ENDP  ; 函数尾声function epilogue
_TEXT ENDS
```

- GCC 4.4.1编译 `gcc 1.c -o 1`, 也采用Intel语体，指定生成Intel语体的汇编列表文件，GCC的选项:`-S -masm=intel`

```assembly
; 指令清单3.3 GCC 4.4.1 x86; 在IDA中观察到的汇编指令
Main proc near
var_10	= dword ptr -10h
	push ebp ; 将EBP旧值入栈 (后面在leave指令中恢复) 将caller的ebp入栈
	mov  ebp, esp ; 将ESP的值赋值给EBP
	and  esp, 0FFFFFFF0h ; 令栈地址(ESP的值)向16字节边界对齐(成为16的整数倍)，属于初始化的指令，如果地址位没有对齐，那么CPU可能需要访问两次内存才能获得栈内数据
	sub  esp, 10h ; 在栈中分配0x10bytes，即16字节，程序只用4字节空间，但编译器对栈地址ESP进行了16字节对齐
	mov  eax, offset aHelloWorld ; "hello, world\n" ;首先把hello, world字符串在数据段的地址存储到EAX寄存器里
	mov [esp+10h+var_10], eax  ; 将字符串地址用mov指令直接写入到数据栈
	call _printf
	mov  eax, 0 ; 除非人工指定优化选项，否则GCC(不同于MSVC)会生成与源码直接对应的MOV EAX,0; MOV指令opcode比XOR指令的opcode长
	leave ; 等效于 MOV ESP, EBP; POP EBP ；复原caller的ESP; 复原caller的EBP(将caller的ebp出栈)
	retn
main endp
```

- 虽然在8字节边界处对齐就可以满足32位x86和64位x64 CPU的要求，但是主流编译器编译规则规定：**程序访问的地址必须向16字节对齐(被16整除)**

> p10有对应的AT&T语体的汇编指令



```assembly
; 指令清单 3.7 MSCV2012 x64  ;用64位MSVC编译(MSVC 2012 x64):
$SG2989	DB	'hello, world', 0AH 00H
main PROC
	sub  rsp, 40
	lea  rcx, OFFSET FLAT:$SG2989
	call printf
	xor  eax, eax ; 出于兼容性和可移植性的考虑，C语言的编译器仍将使用32位的0。EAX为0，RAX不一定为0
	add  rsp, 40 ; 阴影空间shadow space
	ret  0
main ENDP
```

- x86-64硬件平台上，寄存器和指针都是64位的，存储于R-字头的寄存器里，但是出于兼容性的考虑，64位寄存器的低32位也要能担当32位寄存器的角色
- main函数的返回值是整数类型的0，出于兼容性和可移植性的考虑，C语言的编译器仍将使用32位的0。即程序结束时，EAX为0，RAX不一定为0



### 3.3 GCC的其他特性

> 可能会把字符串拆出来单独使用

- 只要C代码里使用了字符串常量，编译器就会把这个字符串常量置于常量字段，以保证其内容不会发生变化
- GCC的有趣特征之一：可能会把字符串拆出来单独使用

```cpp
#include <stdio.h> // 多数C/C++编译器会将下面两个字符串分配出两个直接对应的字符串
void f1(){ printf("world\n"); }
void f2(){ printf("hello world\n"); }
int main(){
	f1();
    f2();
}
```

```assembly
; 指令清单3.10 在IDA中观察GCC4.8.1的汇编指令
f1	proc near
s	= dword ptr -1Ch ; dec:28 为什么是-1Ch? 如果是-0Ch 即-12 则刚好对应aHello, s的总字节数
	sub  esp, 1Ch
	mov  [esp+1Ch+s], offset s; "world\n"
	call _puts ; f1 从s的地址开始输出
	add  esp, 1Ch
	retn
f1	endp

f2 	proc near
s	= dword ptr -1Ch ; dec:28
	sub  esp, 1Ch
	mov  [esp+1Ch+s], offset aHello ; "hello "的地址
	call _puts
	add  esp, 1Ch
	retn
f2	endp

aHello  db 'hello'  ; 前后两个字符串相邻，hello后面没有\0，调用puts时，函数本身不知道这是两个字符串
s       db 'world', 0xa, 0 ; '\n' '\0'
```

- GCC编译器会充分使用这种技术来节省内存



### 3.4 ARM

> 3.4 ARM p13 

`armcc.exe --arm --c90 -O0 1.c`用Keil编译器把hello world程序编译为ARM指令集架构的汇编程序

虽然armcc编译器生成的汇编指令清单同样采用了Intel语体，但是程序所使用的宏却极具ARM处理器的特色(e.g. ARM模式的指令集里没有PUSH/POP指令)

**IDA显示ARM平台的指令时的opcode显示顺序**：

- ARM及ARM64模式的指令：4-3-2-1
- Thumb模式的指令：2-1
- Thumb-2模式的16位指令对：2-1-4-3



- Thumb模式程序的每条指令都对应着2 bytes / 16 bit 的opcode，这是Thumb模式程序的特征



- **形实转换函数 thunk function**: 形参与实参互相转换的函数 (http://www.catb.org/jargon/html/T/thunk.html) p17
- 在编译过程中，为满足当时的过程(函数)调用约定，当形参为表达式时，编译器都会产生thunk，把返回值的地址传递给形参
- 微软和IBM都对thunk一词有定义，将从16位到32位和从32位到16位的转变叫做thunk



#### 3.4.5 ARM64

使用GCC 4.8.1编译为ARM64程序

```assembly
; 指令清单 3.15 Non-optimizing GCC 4.8.1 + objdump
<main>:
stp  x29, x30, [sp, #-16]!   ; store pair 把两个寄存器x29, x30的值存储到栈; 每个寄存器8B, 两个要16B的空间; 感叹号表示其标注的运算会被优先执行
mov  x29, sp               ; 把SP的值复制给X29(FP) 用来设置函数的栈帧
adrp x0, 400000 <_init-0x3b8>  ; adrp和add相互配合 把Hello!字符串的指针传递给X0寄存器，继而充当函数参数传递给被调用函数
add  x0, x0, #0x648        ; 0x400000 + 0x648 = 0x400648 即Hello!的地址
bl   400420 <puts@plt>    ; 调用puts函数
mov  w0, #0x0             ; #0 给W0寄存器置零 W0是X0寄存器的低32bit; 与x86-64一样，ARM64的int数据仍然是32bit 兼容性考虑
ldp  x29, x30, [sp], #16   ; load pair 还原X29, X30的值. 没有感叹号 先赋值 后把SP的值与16做求和运算
ret   ; RET指令是ARM64平台的特色指令
...
Contents of section .rodata:
400640             01000200 00000000 48656c6c 6f210000 .........Hello!..
```

- **ARM64的CPU只可能运行于ARM模式**，不可运行于Thumb或Thumb-2模式，所以必须使用32bit的指令
- 64bit的寄存器数量翻了一番，拥有了32个X-字头的寄存器，程序可以通过W-字头的名称直接访问寄存器的低32bit空间
- ARM64平台的寄存器都是64位寄存器，每个寄存器可存储8byte
- `stp  x29, x30, [sp, #-16]!`中的感叹号标志意味着其标注的运算会被优先执行，即该指令先把SP的值减去16，然后再把两个寄存器的值写在栈里。属于 **预索引/pre-index** 指令。`ldp  x29, x30, [sp], #16`属于**延迟索引 post-index**指令
- X29寄存器是帧指针FP，X30起着LR的作用

```cpp
uint64_t main(){ // 注意返回值类型
    printf("Hello!\n");
    return 0;
}//这将返回64位的值
```

```assembly
mov  x0, #0x0    ; 返回的是64bit的0 X0寄存器的64bit都是0
```



### 3.5 MIPS

MIPS指令分为3类:

> 本节内容：逆向工程权威指南下册 附录C MIPS C.2 指令

1. **R-Type**: Register/寄存器类指令。此类指令操作**3**个寄存器
```assembly
指令目标寄存器    源寄存器1    源寄存器2
; 当前两个操作数相同时，IDA可能会以以下形式显示。这种显示风格与x86汇编语言的Intel语体十分相似
指令目标寄存器/源寄存器1       源寄存器2 
|      6bit     |   5bit    |   5bit    |   5bit    |   5bit    |      6bit     |  ; 32位的MIPS R型指令 二进制表示
|    opcode     |     rs    |    rt     |    rd     |   shamt   |     funct     |
|    操作码     | 源操作数1  | 源操作数2  | 目标寄存器  |   偏移量   |     函数码     |
```
2. **I-Type**: **Immediate/立即数类指令**。涉及2个寄存器和1个立即数

```c
|   Op   |   Rs   |   Rt   |          Address       |
|  6bit  |  5bit  |  5bit  |           16bit        |
```

3. **J-Type**: **Jump/转移指令**。在MIPS转移指令的opcode里，共有26位空间可存储偏移量的信息

转移指令：

- 实现转移功能的指令可分为 B 开头的指令(BEQ, B ...)和 J 开头的指令(JAL, JALR ...)
- B类转移指令属于 I-type 指令，即opcode封装有 16bit 立即数/偏移量
- J和JAL属于J-type指令，opcode里存有 26bit 立即数
- 简言之，B开头的转移指令可以把转移条件(cc)封装到opcode里(B指令是` BEQ $ZERO, $ZERO, Label` 的伪指令)。但是J开头的指令无法在opcode里封装转移条件表达式





#### MIPS Register

MIPS寄存器的两种命名方式：

1. 数字命名: `$0 ~ $31`，在GCC编译器生成的汇编指令中，寄存器都采用数字方式命名
2. 伪名称(`pseudoname`): `$V0 ~ VA)`

| **Register Number** | Conventional Name | **Usage**                                                    |
| ------------------- | ----------------- | ------------------------------------------------------------ |
| \$0                 | \$zero            | Hard-wired to 0 永远为0                                      |
| \$1                 | \$at              | Reserved for pseudo-instructions 汇编宏和伪指令使用到临时寄存器 |
| \$2 - \$3           | \$v0, \$v1        | **Return values** from functions 传递函数返回值              |
| \$4 - \$7           | \$a0 - \$a3       | **Arguments** to functions - **not** preserved by subprograms 传递函数参数 |
| \$8 - \$15          | \$t0 - \$t7       | **Temporary data**, **not** preserved by subprograms         |
| \$16 - \$23         | \$s0 - \$s7       | Saved registers, **preserved** by subprograms 寄存器变量，callee必须保全 |
| \$24 - \$25         | \$t8 - \$t9       | **More temporary registers**, **not** preserved by subprograms |
| \$26 - \$27         | \$k0 - \$k1       | **Reserved** for kernel. Do not use. OS异常/中断处理程序使用 后不会恢复 |
| \$28                | \$gp              | **Global Area Pointer** (base of global data segment) 全局指针，callee必须保全PIC code以外的值 |
| \$29                | \$sp              | 栈指针 **Stack Pointer**                                     |
| \$30                | \$fp / s8         | 帧指针 **Frame Pointer**                                     |
| \$31                | \$ra              | **Return Address (RA)** 子函数的返回地址                     |
| n/a                 | pc                | PC                                                           |
| n/a                 | hi                | 专门存储商或积的高32bit，可通过 `MFHI` 访问                  |
| n/a                 | lo                | 专门存储商或积的低32bit，可通过 `MFLO` 访问                  |
| \$f0 - \$f3         |                   | Floating point return values 函数返回值 (附录C说\$f2~\$f3未被使用) |
| \$f4 - \$f10        |                   | Temporary registers, not preserved by subprograms 用于临时数据 |
| \$f12 - \$f15       |                   | First two arguments to subprograms, not preserved by subprograms 函数前两个数据 |
| \$f16 - \$f19       |                   | More temporary registers, not preserved by subprograms 用于临时数据 |
| \$f20 - \$f31       |                   | Saved registers, preserved by subprograms 用于临时数据，callee必须保全 |

> 通用寄存器GPR: 其中t开头的为临时寄存器，用于保存代码里的临时值，caller负责保存这些寄存器的数值(caller-saved)，因为可能会被callee重写
>
> 浮点寄存器FPR: 表格中Register Number 为f开头的，在表格末尾的那些

- MIPS里没有状态码。CPU状态寄存器或内部都不包含任何用户程序计算的结果状态信息
- hi和lo是与乘法运算器相关的两个寄存器大小的用来存放结果的地方。它们并不是通用寄存器，除了用在乘除法之外，也不能有做其他用途。 MIPS里定义了一些指令可以往hi和lo里存入任何值

#### 全局指针 Global Pointer

> `$28  /  $gp` Global Area Pointer, base of global data segment

每条MIPS指令都是 32bit ( 4Byte ) 指令，所以单条指令无法容纳32位地址，这种情况下MIPS需要传递一对指令才能使用一个完整的指针。另一方面说，单条指令可以容纳一组寄存器、有符号的16位偏移量（有符号数）。因此任何一条指令都可以访问的取值范围为"寄存器 - 32768 \~ 寄存器 + 32767"，总共 64KB。

- **全局指针寄存器**：为了简化操作，MIPS保留了一个专用的寄存器，并且把数据分配到一个大小为64KB的内存数据空间中。这种专用寄存器就叫全局指针寄存器
- **全局指针寄存器的值**：指向64KB（静态）数据空间的正中间
- 这64KB空间通常用于存储全局变量，以及 `printf` 这类由外部导入的外部函数地址
- 在ELF格式文件中，这个64KB的静态数据位于 `.sbss`(small BSS/ Block Started by Symbol) 和 `.sdata`(small data)之中。用于存储有初始化数值的数据
- 根据这种数据布局，编程人员可能会把全局指针和MS-DOS内存或MS-DOS的XMS、EMS内存管理器联系起来。这些内存管理方式都把数据的内存存储空间划分为数个64KB区间
- 为了使用`$gp`，编译器在编译时必须知道一个数据是否在 `gp`的64K范围之内

#### Optimizing GCC

```assembly
$LC0:                         ; MIPS 指令清单3.18 Optimizing GCC 4.4.5 汇编输出
; \000 is zero byte in octal base(8进制):
    .ascii "Hello, world!\012\000" ; \012 = 0x0A = LF
main:
; function prologue 函数序言
; set the GP($28): 初始化全局指针寄存器GP寄存器的值，并把它指向64KB数据段的正中央
    lui   $28, %hi(__gnu_local_gp) ;lui: Load Upper Immediate 读取一个16bit立即数放入寄存器高16bit，低16bit补0; $28=$gp 全局指针
    addiu $sp, $sp, -32 ; sp=sp-32; SP通常被调整到这个被调用子函数需要的堆栈的最低处，从而编译器可以通过相对于sp的偏移量来存取堆栈上的堆栈变量
    addiu $28, $28, %lo(__gnu_local_gp)
; save the RA to the local stack; 注意该指令后有一条指令在GCC的汇编输出看不到
    sw    $31, 28($sp) ; $31=$ra函数返回地址; 将RA寄存器的值存储于本地数据栈sp+28 且$sp自动抬栈
; load the address of the puts() function from the GP to $25 
    lw    $25, %calll6(puts)($28) ; 将puts()函数地址通过load word指令加载到$25寄存器
; load the address of the text string to $4 ($a0)
    lui   $4, %hi($LC0) ; $4=$a0 在调用函数时传递函数参数; Load Upper Immediate 将字符串高16bit地址加载到$4寄存器
; jump to puts(), saving the return address in the link register: 写入RA寄存器的值是PC+8, 即addiu后面的lw指令的地址
    jalr  $25 ; Jump and Link Register 跳转到$25中的地址(puts函数启动地址)并把下一条lw指令(不是指addiu)的地址存储于$31($RA); 
    addiu $4, $4, %lo($LC0) ; branch delay slot分支延迟槽; 先于jalr指令先执行; 将$LC0低16bit与$4相加; 至此 $4存储的是$LC0 字符串的地址
; restore the RA
    lw    $31, 28($sp) ; 从本地栈恢复当前函数的$ra ; 与前面的 sw $31, 28($sp) 对应; 这条指令不位于callee的函数尾声
; copy 0 from $zero to $v0
    move  $2, $0 ; 将$0的值赋值给$2; 有关move指令后面会详述
; return by jumping to the RA:
    j     $31 ; $ra ; 跳转到函数返回地址$ra; 从callee(指当前的这个函数)返回到caller，其后的addiu会先执行，构成函数尾声; 跳转地址= PC中原高4位 | 指令中的26位 | 00
; function epilogue: 函数尾声
    addiu $sp, $sp, 32 ; branch delay slot分支延迟槽; 会先于j指令先执行
```

- MIPS系统中没有在寄存器之间复制数值的(硬件)指令
- `move  dst, src`是通过加法指令 `add  dst, src, $zero` 变相实现的，即 `dst=src+0`。两种操作等效。尽可能复用opcode，精简opcode总数
- 然而并不代表每次运行`move`指令时CPU都会进行实际意义上的加法运算。CPU能够对这类伪指令进行优化处理，在运行它们的时候并不会用到ALU(Arithmetic Logic Unit)

```assembly
; 代码清单 3.19 Optimizing GCC4.4.5(IDA) IDA生成的指令清单
main:
var_10   = -0x10
var_4    = -4
; function prologue

lui   $gp, (__gnu_local_gp >> 16) ; set the GP(step 1) ; __gnu_local_gp高16bit被写入到$gp高16bit，且$gp低16bit置0
addiu $sp, -0x20 ; sp=sp-32; SP被调整到这个callee需要的堆栈的最低的地方
la    $gp, (__gnu_local_gp & 0xFFFF) ; set the GP(step 2) ; Load Address 将一个地址/标签存入寄存器; $gp低16bit赋值为__gnu_local_gp低16bit
sw    $ra, 0x20 + var_4($sp) ; save the RA to the local stack; 将RA寄存器的值存储于本地数据栈sp+28(32-4) 且$sp自动抬栈
; save the GP to the local stack: for some reason, 这一指令在GCC汇编输出中missing
sw    $gp, 0x20 + var_10($sp) ; 使用局部栈保存GP的值，GCC的汇编输出里看不到这条指令，可能为GCC本身的问题。严格的说，此处需要保存GP，因为每个函数都有自己的64KB数据窗口
; load the address of the puts() function from the GP to $t9:
lw    $t9, (puts & 0xFFFF)($gp) ; 将puts函数地址的低16bit存储到 $t9 ..... 高16bit就是gp的值???
lui   $a0, ($LC0 >> 16) # "Hello, world!" ; 将$LC0的高16bit写入到$a0的高16bit
; jump to puts(), saving the return address in the link register:
jalr  $t9 ; 跳转到$t9中的地址(puts地址)并且把下一条lw指令(不是指la)的地址存储于$31($RA); 写入RA寄存器的值是PC+8, 即la后面的lw指令的地址
la    $a0, ($LC0 >> 16) # "Hello, world!" ; 将$LC0的低16bit写入到$a0的低16bit; 这条指令先于jalr执行，之后a0存储的为$LC0的值
lw    $ra, 0x20 + var_4($sp) ; 从本地栈恢复当前函数的$ra ; 与前面的 sw $ra, 0x20 + var_4($sp) 对应; 这条指令不位于函数尾声
move  $v0, $zero ; 将v0寄存器置0
jr    $ra ; 跳转到函数返回地址$ra; 完成从callee(指当前的这个函数)返回caller的操作; 其后的指令先执行
; function epilogue: 函数尾声
addiu $sp, 0x20 ; 注意这里由于 源操作数1 与 目标寄存器 相同，IDA省略了; 实际上: addiu $sp, $sp, 0x20
```

> #### 3.5.4 栈帧
>
> 本例使用寄存器来传递文本字符串的地址(`$LC0`)，但是它同时设置了局部栈。
>
> 这是由于程序在调用`printf`时，由于必须保存`$ra, $gp`的值，故出现了数据栈。
>
> 如果此函数是叶函数，它有可能不会出现函数的序言和尾声(参加2.3节)







## 4. 函数序言和函数尾声

> function prologue and function epilogue

- 函数序言 function prologue 是函数在启动的时候运行的一系列指令，其汇编指令大致如下：

```assembly
push ebp      ; 在栈里保存EBP寄存器的内容
mov  ebp, esp ; 将ESP的值复制到EBP寄存器
and esp, 0FFFFFFF0h ; (可能有)16bit对齐
sub  esp, X   ; 修改栈的高度，以便为本函数的局部变量申请存储空间 ; e.g. add esp, -80h
```

- 在函数执行期间，EBP寄存器不受函数运行的影响，EBP是函数访问局部变量和函数参数的基准值
- 虽然也可以使用ESP寄存器来存储局部变量和运行参数，但是ESP寄存器的值总是会发生变化，使用起来并不方便
- 函数在退出时，要做启动过程的反操作，释放栈中申请的内存，还原EBP寄存器的值，将代码控制权还原给调用者函数(callee??? 疑似错误 应该为caller吧)

```assembly
mov  esp, ebp ; 还原esp的值
pop  ebp      ; 还原ebp的值
ret  0
```

- 借助函数序言和函数尾声的有关特征，可以在汇编语言里识别各个函数

> 递归调用：函数序言和尾声都会调整数据栈，受硬件IO性能影响，所有递归函数的性能都不太理想。详见36.3节



## 5. 栈 Stack

- 栈: 寄存器的某个指针所指向的一片内存区域。某个指针通常为：
  - x86/x64: ESP/RSP
  - ARM: SP
- 栈向下(栈已经处于高地址)向低地址方向增长
- 在分配栈的空间之后，栈指针Stack Pointer所指向的地址是栈的底部。PUSH将减少栈指针的值，POP会增加栈指针的值
- ARM的栈分为递增栈(ascending stack)和递减栈(descending stack). 递减栈和上面描述的相似，而递增栈首地址占用栈的最低地址，栈向高地址增长



### 保存函数结束时的返回地址

x86:

- CALL == PUSH 返回地址; JMP 函数地址
- RET == POP 返回地址; JMP 函数地址

ARM

- 返回地址保存在LR(link register)寄存器里。如果程序会继续调用其他函数，就需要在调用前保存LR寄存器的值。通常在序言看到`PUSH R4-7, LR`，尾声`POP R4-7, PC`
- 如果一个函数不调用其他函数，就叫**叶函数(leaf function)**. 叶函数不必保存LR寄存器的值。若用不到几个寄存器，可能不会使用数据栈

### 参数传递与局部变量

> 包含`cdecl, stdcall, fastcall, thiscall` ...

- x86平台中，最常用的参数传递约定是`cdecl`，其上下文大体为：

```assembly
push arg3
push arg2
push arg1
call f
add esp, 12; 3 * 4byte = 12byte
```

Callee functions通过栈指针获取所需参数。

在运行f()之前，传递给它的参数以以下格式存储在内存里

| ESP     | 返回地址              |
| ------- | --------------------- |
| ESP+4   | arg1, IDA记为 `arg_0` |
| ESP+8   | arg2, IDA记为 `arg_4` |
| ESP+0xC | arg3, IDA记为 `arg_8` |
| ......  | ......                |



- 栈与局部变量：通过向栈底调整栈指针的方法，函数可在数据栈里分配出一篇可用于存储**局部变量**的内存空间。无论函数声明了多少个局部变量，都不影响分配栈空间的速度。虽然可以在栈以外的地方存储局部变量，但是用数据栈来存储局部变量已经是一种约定俗成的习惯了。

### x86 alloca() 函数

> 书p30有对应的汇编指令

- alloca()函数直接使用栈来分配内存，除此之外与malloc函数没有显著区别
- 函数尾声的代码会还原ESP的值，把数据栈还原为函数启动前的状态，直接抛弃由alloca函数分配的内存，所以程序不需要使用free函数释放由alloca申请的内存

### 典型的栈的内存存储格式

在32bit系统中，在程序调用函数之后，执行它的第一条指令前，栈在内存中的存储格式一般如下所示

| ......    | ......                          |
| --------- | ------------------------------- |
| ESP - 0xC | 第2个局部变量，IDA中记为`var_8` |
| ESP - 8   | 第1个局部变量，IDA中记为`var_4` |
| ESP - 4   | 保存的EBP值                     |
| ESP       | 返回地址                        |
| ESP + 4   | arg1，IDA中记为`arg_0`          |
| ESP + 8   | arg2，IDA中记为`arg_4`          |
| ESP + 0xC | arg3，IDA中记为`arg_8`          |
| ......    | ......                          |



### 5.4 栈的噪音

> 噪音，脏数据

- 函数退出后，原有栈里的局部变量不会自动清除，就成了栈的噪音、脏数据

```cpp
// 使用MSVC2010 non-optimizing 编译 // 
void f1(){
    int a=1, b=2, c=3; // 在栈上分配局部变量，f1调用结束后，栈上的内容不会被释放
}
void f2(){
    int a, b, c; // 在栈上分配空间时，刚好和 f1() 的 a, b, c 重合 由于没有对这个空间重新赋值，所以因地址相同而获得之前的三个值
    printf("%d, %d, %d\n", a, b, c); // 这里会输出 1, 2, 3 使用的是栈里残存的脏数据
}
int main(){
    f1();f2(); // 先后调用 f1 f2 // 
}
```



- main argv的申请和释放应该由系统来负责，是传入参数，算不上全局或者局部变量。所以这块内存就不在程序内部



## 6. printf()函数与参数传递

- MSVC 32bit，cdecl调用约定下，函数调用后有`ADD ESP, X`指令修正ESP寄存器中的栈指针，因为在函数调用前通常会有多个push指令使ESP减小。如果有连续调用多个函数，且调用函数的指令之间不夹杂其他指令，编译器可能把释放参数存储空间的`ADD ESP, X`指令进行合并，放在最后一次性释放所有空间。
- MSVC用push将参数入栈，gcc用`sub esp, X, mov [esp+a], b`的方式直接对栈进行操作

```assembly
# x86 调用函数时的传参模式
push 3rd arg
push 2nd arg
push 1st arg
call function
; modify stack pointer esp if needed
```



### Win x64

- Win64使用RCX, RDX, R8, R9寄存器传递前4个参数，使用栈来传递其余参数

```assembly
; printf("a=%d; b=%d; c=%d; d=%d; e=%d; f=%d; g=%d; h=%d\n", 1,2,3,4,5,6,7,8); 在Win64下的调用传参过程
mov DWORD PTR [rsp+64], 8
......
mov DWORD PTR [rsp+32], 4 # 5th arg
mov r9d, 3 # 4th arg
mov r8d, 2 # 3rd arg
mov edx, 1 # 用的是 edx 而非完整的 rdx # 2nd arg
lea rcx, OFFSET FLAT:$SG2923 ; $SG2923 DB 'a=%d; b=%d; c=%d; d=%d; e=%d; f=%d; g=%d; h=%d', 0aH, 00H # 1st arg
call printf
```

- 64bit系统中，int只占用4Byte，但编译器给int分配了8B。即使数据的存储空间不足64bit，编译器还是会分配8B存储空间。为了方便系统对每个参数进行内存寻址，而且编译器都会进行地址对齐。所以64bit系统为所有类型的数据都保留8B空间，同理32bit系统为所有类型的数据保留4B空间

### \*nix x64

- \*nix x64系统先使用RDI, RSI, RDX, RCX, R8, R9寄存器传递前6个参数，然后利用栈传递其余的参数
- 在生成汇编代码时，gcc把**字符串指针**(fmt str pointer)存储到 **EDI** 中，而非完整的 RDI 寄存器

```assembly
; printf("a=%d; b=%d; c=%d; d=%d; e=%d; f=%d; g=%d; h=%d\n", 1,2,3,4,5,6,7,8); 在 *nix 64 下的调用传参过程 ; x64 gcc
sub esp, 40
mov r9d, 5 # 6th arg
mov r8d, 4 # 5th arg
mov ecx, 3 # 4th arg
mov edx, 2 # 3rd arg
mov esi, 1 # 2nd arg
mov edi, OFFSET FLAT:.LC0 # .LC0: .string "a=%d; b=%d; c=%d; d=%d; e=%d; f=%d; g=%d; h=%d\n" # 1st arg
xor eax, eax ; number of vector registers passed
mov DWORD PTR [rsp+16], 8 # 注意这里用的是DWORD，4B，所以实际上rsp的高4B没有被赋值，仍然为脏数据 # 9th arg
mov DWORD PTR [rsp+8], 7 # 8th arg
mov DWORD PTR [rsp], 6 # 7th arg
call printf
```



```assembly
; ARM 调用函数时的传参过程
mov R0, 1st arg
mov R1, 2nd arg
mov R2, 3rd arg
mov R3, 4th arg
; pass 5th 6th... arg in stack if needed
BL function
; modify stack pointer if needed
```

```assembly
; ARM64 调用函数时的传参过程
mov X0, 1st arg
mov X1, 2nd arg
mov X2, 3rd arg
mov X3, 4th arg
mov X4, 5th arg
mov X5, 6th arg
mov X6, 7th arg
mov X7, 8th arg
; pass 9th 10th... arg in stack if needed
BL CALL function
; modify stack pointer if needed
```

```assembly
; MIPS O32调用约定 调用函数时的传参过程
LI $4, 1st arg ; AKA $A0
LI $5, 2nd arg ; AKA $A1
LI $6, 3rd arg ; AKA $A2
LI $7, 4th arg ; AKA $A3
; pass 9th 10th... arg in stack if needed
LW temp_reg, address of function
JALR temp_reg
```

- x86, x64, ARM, MIPS平台上程序向函数传参的方法不同，说明函数间传参方式与CPU关系不密切。CPU不在乎程序使用何种调用约定



## 7. scanf()

- TBD





---

# **IDA Pro**

> 静态分析
>
> 入门笔记 含快捷键 窗口介绍  https://www.zybuluo.com/oro-oro/note/137244

- 查看版本号与逆编译器版本 Help => About program => `Version 7.5.201028 Windows x64 (32-bit address size)` => Addons => 32 bit: `e.g. x86 ARM PowerPC MIPS Decompiler`
- Option:
  - General:
    - Disassembly:
      - Auto comments: 可以显示汇编指令的含义e.g.  `li  $a3, 0x10019C80 # Load Immediate`





## Shortcut Quick Find

| Short Cut | Functionality                                                |
| --------- | ------------------------------------------------------------ |
| space     | 切换显示方式                                                 |
| C         | 转换为代码                                                   |
| D         | 转换为数据                                                   |
| R         | 转换为char                                                   |
| Alt + M   | Mark position 也可以在地址处右键(可在汇编/伪c窗口使用，对文件位置mark，在Jump菜单) |
| Ctrl + M  | Jump to marked position也可以在地址处右键(与上一个一起用，方便分析复杂指令) |
| N         | 为标签重命名(包含寄存器等)                                   |
| ?         | 计算器                                                       |
| G         | 跳转到地址(然后会出来Jump to address对话框)                  |
| ;         | 添加注释(Pseudocode窗口下按 / 添加注释)                      |
| Ctrl+X    | 查看当前函数、标签、变量的参考(显示栈)                       |
| X         | 查看当前函数、标签、变量的参考                               |
| Alt + I   | 搜索常量constant                                             |
| Ctrl + I  | 再次搜索常量constant                                         |
| Alt + B   | 搜索byte序列                                                 |
| Ctrl + B  | 再次搜索byte序列                                             |
| Alt + T   | 搜索文本(包括指令中的文本)                                   |
| Ctrl + T  | 再次搜索文本                                                 |
| P         | 创建函数(Edit=>Functions)                                    |
| Alt + P   | 编辑当前函数                                                 |
| Enter     | 跳转到函数、变量等对象                                       |
| Esc       | 返回                                                         |





## IDA View

- 程序基本信息：在Text view下，拉到最前面。可看到的信息：大/小端序，架构，文件名...

| Short Cut | Functionality                                              |
| --------- | ---------------------------------------------------------- |
| F5        | 反汇编为伪代码Pseudocode                                   |
| space     | 在Text view和Graph view显示模式之间切换                    |
| a         | 转换显示形式为char (如在.rodata段将一些整型转换成char显示) |
| x         | Jump to xref to operand... 将打开                          |
| shift+E   | 光标选中后，提取对应位置的数据。Edit => Export data        |
|           |                                                            |
|           |                                                            |
|           |                                                            |
|           |                                                            |



## Pseudocode

> 伪代码窗口 在IDA View窗口中按F5可以打开该窗口

- Pseudocode窗口下右键函数名，可以点击`Jump to xref`查看调用了这个函数的地方
- 在立即数处右键，可以选择改成不同的数据表现形式
- 在变量/类型声明处右键 => Set lvar type (Y) : 改变变量的解析形式(类型)，有时可以更加直观的分析代码。之后可以再右键 => Reset pointer type: 改回原本IDA解析的变量类型

```cpp
while ( v4 != 1LL && v4 != -1LL ); // LL for long long // v4 is __int64
v7 = 28537194573619560LL; // 右键，可以选择改成Char Enum Hex等
v7 = 'ebmarah'; // 改成Char之后
```



## Strings Window

- shift+F12 打开 **Strings Window** 查看关键字符串，双击某个string后可以跳到IDA View，查看对应汇编代码
- 双击后面的提示信息`; DATA XREF:`可以跳转到用到了该string的函数

```assembly
.rodata:0000000000400965 ; char aYouEnteredTheC[]
.rodata:0000000000400965 aYouEnteredTheC db 'You entered the correct password!',0Ah
.rodata:0000000000400965                                         ; DATA XREF: sub_4007F0+8↑o
```







## Remote Debug

> 远程调试 这里一般指Win上的IDA分析虚拟机/局域网内的Linux上的程序 也可指本机上的程序



Remote Linux: (test in Kali 2020.4 64bit)

1. **Copy** `linux_server64` in `IDAroot\dbgsrv\` to Linux server.
2. `chmod a+x ./linux_server64`
3. Run: `./linux_server64`

Then, on local windows:

1. Under the IDA menu bar，debugger change to: **Remote Linux debugger**
2. IDA menu bar: Debugger => **Process option**
   - fill the full path or relative path of ELF file in the `Application` and `Input file` fields
   - `Directory`: the directory path, or empty if using relative path above
   - `Hostname` field: IP address of the remote machine
   - `parameters`: run the program with some parameters
3. [opt] Setup support for x86 on Linux x64(when your ELF is 32bit and Linux is 64bit):
   - `sudo dpkg --add-architecture i386`
   - `sudo apt-get update`
   - `sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386`
4. Run! Set breakpoint in pseudocode. F9 start/continue; F7 step into; F8 step over.





## Python

> 主要记录如何使用python与IDA交互

在IDA中使用python的两种方式

1. At the bottom of the IDA window, below Output window: Python
2. File => Script command

```python
print(get_bytes(0x6010E0, 10)) # 输出 0x6010E0 地址及其后的 10 Byte
```





# Function Reference

> 一些典型/常见函数的解析，有助于阅读逆向出来的代码





## File / IO Related



### FILENO

- This function returns the file descriptor number associated with a specified stream.

```cpp
#define _POSIX_SOURCE
#include <stdio.h>
int fileno(const FILE *stream);
```

- `stream`: The stream for which the associated file descriptor will be returned.
- `unistd.h`定义了如下宏，映射到标准流的fd
- `STDIN_FILENO`: Standard input, `stdin` (value 0).
- `STDOUT_FILENO`: Standard output, `stdout` (value 1).
- `STDERR_FILENO`: Standard error, `stderr` (value 2).

```cpp
#define _POSIX_SOURCE
#include <errno.h>
#include <stdio.h>
main() {
  FILE *stream;
  char my_file[]="my.file";
  printf("fileno(stdin) = %d\n", fileno(stdin)); // fileno(stdin) = 0
  if ((stream = fopen(my_file, "w")) == NULL)
    perror("fopen() error");
  else {
    printf("fileno() of the file is %d\n", fileno(stream)); // fileno() of the file is 3
    fclose(stream);   remove(my_file);
  }
}
```



- `_fileno`: Gets the file descriptor associated with a stream.

```cpp
int _fileno(
   FILE *stream
);
#include <stdio.h>
int main( void ){ //  uses _fileno to obtain the file descriptor(fd) for some standard C streams
   printf( "fd of stdin %d\n", _fileno( stdin ) ); // fd of stdin 0
   printf( "fd of stdin %d\n", _fileno( stdout ) ); // fd of stdin 1
   printf( "fd of stdin %d\n", _fileno( stderr ) ); // fd of stdin 2
}
```









# Ghidra

> 由美国国家安全局开发的免费和开源的逆向工程工具，可在Windows\macOS\Linux进行源代码分析

- TBD











---

#  Dynamic Analysis

> 动态分析 实践部分

- 对gdb进行强化的两个工具：peda，pwndbg。强化视觉效果

```bash
gcc a.c -g -o a # -g选项可以保存调试信息
```





## gdb

> Linux下使用最多的一款调试器Debugger，也有Windows移植版
>
> 逆向工程权威指南(下册) p940 有**GDB指令速查表**

Installation: `sudo apt-get install gdb`

- 启动gdb，设置语体

```bash
gdb ./a # 将文件加载到gdb中 # 使用gdb调试文件a
gdb ./a -silent # 不打印gdb前导信息(含免责条款)
gdb attach PID # 调试某个正在运行的进程 进程ID为PID
set disassembly-flavor intel # 令gdb采用intel语体
```

- 下断点、运行程序

```bash
b decrypt # 将断点设置在decrypt处
b 10 # 在第10行设置断点
b * 0x804865c # 在该地址设置断点
r # 运行(会在断点处停止)
run # 运行被调试的程序
c # 继续运行
continue # 继续运行
n # 单步运行

stepi # 每步执行

set $eax=1 # 设置寄存器 eax 为 0

finish # 继续执行余下指令直到(当前)函数结束为止
q # 退出调试 
```

### 查看、显示信息

```bash
p v0 # 打印变量v0的值
p $1 # 依据编号 打印编号为1的变量的值 # 编号由gdb赋予
p system # 获取 system 函数的地址 # 该方法可以获取任意libc函数的地址
list 2 # 列出第二行的源文件
list main # 列出函数main
list # 不带参数 展示10行

disas # 检查汇编 给出当前对应的代码的汇编 其中箭头指向的是接下来将要运行的指令
disassemble 0xf7e39980 # 查看该地址的汇编代码，如果是函数，到ret结束
info reg # 查看寄存器信息
info registers # 查看寄存器内容  # same as: i r
info break # i b # 查看断点编号 # 还可以看到断点命中几次
print $rsp # 查看寄存器内容
info  proc # 查看进程信息

x/200wx $eax # x: 查看内存中数值 200表示查看200个 wx以word字节查看 $eax代表eax寄存器中的值
x/10w $esp # 显示栈里的10个数据
x/5i 0x0804844a # 显示某个地址开始的5条指令
x/s 0x080484f0 # 将某个地址开始的内容以字符串形式输出
x/s $rdi # 将rdi寄存器指向的地址开始的内容以字符串形式输出
x/10g $rsp # g: giant words 以64bit words格式显示各数据 显示$rsp开始的10个
```



```python
# 查看完内存后 可能需要将内存中显示的16进制数转换为字符串
key = "393434377b"
flag = key.decode('hex') # hex to str
```



### gdb调试时输入不可见字符

- 使用类似如下的python脚本，将输入写入文件`input`中：

```python
s = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x00\n\n\n\nabcdABCD"
with open("input", "wb") as f:
    f.write(s)
```

- 存入`input`的内容：

```assembly
$ hexdump input
0000000 0201 0403 0605 0807 0a09 0c0b 0e0d 000f
0000010 0a0a 0a0a 6261 6463 4241 4443
```

- 在GDB 开始调试时，使用run时添加`< input`

```assembly
r < input
```

- 将不可见字符保存成文件`input`的demo

```python
#!/usr/bin/env python  # gdb调试时输入不可见字符 demo 
from pwn import *
from LibcSearcher import LibcSearcher 
context.log_level = "DEBUG"
sh = process("./ret2libc3")

ret2libc3 = ELF("./ret2libc3")
puts_plt = ret2libc3.plt["puts"] 
libc_start_main_got = ret2libc3.got["__libc_start_main"] 
main = ret2libc3.symbols["main"] 

print("leak libc_start_main_got addr and ret to main", str(hex(puts_plt)), str(hex(main)), str(hex(libc_start_main_got)))
# puts_plt, main, libc_start_main_got: 0x08048460 0x08048618 0x0804a024
payload = flat(['A' * (108+4), puts_plt, main, libc_start_main_got])
print("payload: ", payload.hex(), type(payload)) # <class 'bytes'>
# ...... 41414141 60840408 18860408 24a00408 
with open("input", "wb") as f:
    f.write(payload) 
```



## gef

```assembly
hexdump qword
hexdump dword
hexdump word
hexdump byte # display the ASCII character values if the byte is printable (similarly to the hexdump -C command on Linux)
gef➤  hexdump byte 0xffd58258 132
0xffd58258     bc 82 d5 ff 25 30 31 32 64 25 36 24 6e 00 d5 ff    ....%012d%6$n...
0xffd58268     02 00 00 00 66 8d f2 f7 34 80 04 08 00 00 00 00    ....f...4.......
0xffd58278     00 90 f3 f7 00 00 00 00 00 00 00 00 00 00 00 00    ................
0xffd58288     34 80 04 08 28 da ee f7 00 c0 ee f7 80 00 f2 f7    4...(...........
0xffd58298     00 00 00 00 1e ec d3 f7 fc c3 ee f7 ff ff ff ff    ................
0xffd582a8     00 00 00 00 8b 85 04 08 01 00 00 00 84 83 d5 ff    ................
0xffd582b8     8c 83 d5 ff 15 03 00 00 80 00 f2 f7 e0 82 d5 ff    ................
0xffd582c8     00 00 00 00 46 5e d2 f7 00 c0 ee f7 00 c0 ee f7    ....F^..........
0xffd582d8     00 00 00 00    ....
```



## pwndbg

> https://github.com/pwndbg/pwndbg
>
>https://blog.csdn.net/Breeze_CAT/article/details/103789233  指令参考

Installation: 

1. `git clone https://github.com/pwndbg/pwndbg`
2. `cd pwndbg`
3. `chmod 777 ./setup.sh`
4. `./setup.sh`

- 安装完成后，使用`gdb`指令后，命令行左侧显示的是`pwndbg`



### cmd quick find

- 指的是执行`gdb`后，可以使用的指令。(`gdb exefile -q`, `-q` for quiet)

```bash
pwndbg # 显示可用命令
b *0x080486AE # 在这个地址处下断点
r # 运行
help # 帮助 # 会显示不同类别的帮助信息 但是没有详细的指令帮助信息
help breakpoints # 显示 breakpoints 类目下的指令
backtrace # 显示函数调用栈
```

- 执行指令

```bash
s # 单步步入 step into # 源码层的一步
si # step into 汇编层的一步
n # 单步步过 step over # 源码层面的一步
ni # step over 汇编层面的一步
c # continue # 继续执行到断点，没断点就一直执行下去
r # run # 重新开始执行
```

- 断点指令

```bash
# 普通断点指令b(break)
b *0x080486AE # 在这个地址处下断点
b func # 给函数 func 下断点，目标文件需保留符号 # b file_name:func
b file_name:15 # 给 file_name 的15行下断点，需有源码 # b 15
b +0x10 # 在程序当前停住的位置下 0x10 处下断点

# 查看 删除 禁用断点
info break # i b # 查看断点编号 # 还可以看到断点命中几次
delete 1 # 删除 1 号断点
disable 1 # 禁用 1 号断点
enable 1 # 启用 1 号断点

# 内存断点指令watch
watch 0x123456 # 0x123456地址的数据改变的时候会断
watch a # 变量 a 改变时命中断点
info watchpoints # 显示watch断点信息

# 捕获断点catch
catch syscall # syscall 系统调用时断
tcatch syscall # syscall 系统调用时断 但只断一次
info break # i b # 查看catch的断点
```

- 打印指令

```bash
# 查看内存指令x   # x /nuf 0x123456

# 打印指令p(print)
p *(0x123456) # 查看0x123456地址的值 # 与x指令的区别： x指令查看地址的值不用星号

# 打印汇编指令disass(disassemble)
disass 0x123456 # 显示0x123456前后的汇编指令

# 打印源代码指令list
```





```bash
stack # 查看栈
retaddr # 打印包含返回地址的栈地址
canary # 直接看canary的值
plt # 查看plt表
got # 查看got表
hexdump # 像 IDA 那样显示数据，带字符串
hexdump 0xffffd3cc # 像 IDA 那样显示 0xffffd3cc 地址后的64bytes，带字符串
```





## OllyDbg

> Shareware/Freeware	http://www.ollydbg.de/  v2.01 (27-Sep-2013), v1.10 是v1.x的最终版，v2彻底重写
>
> windows的 32bit  x86 汇编级分析调试器, Ring3
>
> 吾爱破解论坛上有包含很多插件的v1.1汉化版

- 标题栏 module a: 表示当前在a.exe代码内
- 菜单栏File下方一栏左边: 显示当前状态，paused一般是到了断点
- 反汇编窗口（左上）：显示反汇编代码。标题栏上的地址、HEX 数据、反汇编、注释可以通过在窗口中右击出现的菜单 界面选项->隐藏标题 或 显示标题 来进行切换是否显示。用鼠标左键点击注释标签可以切换注释显示的方式
- 信息窗口（在反汇编窗口下方）：显示选中的第一条指令及跳转目标地址、字串等
- 寄存器窗口（右上）：显示当前所选线程的 CPU 寄存器内容。点击标签 寄存器 (FPU) 可以切换显示方式
- 数据窗口（左下）：内存/文件的内容。右键菜单可切换显示方式
- 堆栈窗口（右下）：显示当前线程的堆栈



- View =>
  - Executable modules: 查看可执行模块。右键用户程序 => View names 查看某个模块用到的函数。在函数处右键可以Find references to import(enter)，出现新窗口显示引用到该函数的地址与指令，双击跳转到对应汇编指令处
- Option => 
  - Appearance => Directories: 修改udd, plugins 路径。UDD 目录的作用是保存调试工作
  - Debugging options: 修改调试选项，包括异常、字符串等



- 配置：od将所有配置放在安装目录的ollydbg.ini中
- 插件：将下载的插件(e.g. dll)复制到`plugin`文件夹，od启动时会自动识别。但不可超过32个否则会出错



主界面右键 => Search for => All referenced text strings: 会显示被引用的所有文本文件





### shortcut / cmd

| shortcut  | functionality                                                |
| --------- | ------------------------------------------------------------ |
| F2        | 设置/删除断点(光标处)                                        |
| F8        | 单步步过。执行一条指令，call等子过程不进入                   |
| F7        | 单步步入。遇到call等子过程会进入，进入后停在子过程第一条指令 |
| F4        | 运行到光标处                                                 |
| F9        | 运行至断点处                                                 |
| Ctrl + F9 | 执行到ret指令处暂停。常用于从系统领空返回用户程序领空        |
| Alt + F9  | 执行到用户代码。可用于从系统领空快速返回到调试程序的领空     |
|           |                                                              |
|           |                                                              |



### Cases

```python
# 从od的汇编指令窗口复制过来的，修改过的地方的原始指令及修改原因将在注释中说明
00F7108C    .  FF15 1460F700 call dword ptr ds:[<&KERNEL32.IsDebuggerPr>; [IsDebuggerPresent
00F71092    .  85C0          test eax,eax # 前面在测试是否有debugger 
00F71094       90            nop # je short 00F710B9 # 这里会导致flag处理函数被跳过
00F71095       90            nop # 因为指令长度不同 前面改为nop后 这里会自动填充一个nop
00F71096    >  41            inc ecx
00F71097    .  41            inc ecx
00F71098    .  41            inc ecx
00F71099    .  41            inc ecx
00F7109A       90            nop # int 3 # 中断3 软件中断
00F7109B    .  8B55 F4       mov edx,dword ptr ss:[ebp-0xC]
00F7109E    .  E8 5DFFFFFF   call csaw2013.00F71000 ; 对flag处理的调用 # 因前面的修改，现在可以执行到这
00F710A3       90            nop # jmp short 00F710EF # 这条指令会导致跳过第1个MessageBoxA
00F710A4       90            nop # 自动填充 nop
00F710A5    .  6A 02         push 0x2 ; /Style = MB_ABORTRETRYIGNORE|MB_APPLMODAL
00F710A7    .  68 2078F700   push csaw2013.00F77820                     ; |Flag
00F710AC    .  FF75 F4       push dword ptr ss:[ebp-0xC]                ; |Text = ""
00F710AF    .  6A 00         push 0x0                                   ; |hOwner = NULL
00F710B1    .  FF15 E460F700 call dword ptr ds:[<&USER32.MessageBoxA>]  ; \MessageBoxA第一次使用
00F710B7       90            nop # jmp short 00F710CD # 这条指令会导致跳过第2个MessageBoxA
00F710B8       90            nop # 自动填充 nop
00F710B9    >  6A 02         push 0x2               ; /Style = MB_ABORTRETRYIGNORE|MB_APPLMODAL
00F710BB    .  68 2078F700   push csaw2013.00F77820                     ; |Flag
00F710C0    .  8B45 F4       mov eax,dword ptr ss:[ebp-0xC]             ; |
00F710C3    .  40            inc eax                                    ; |
00F710C4    .  50            push eax                                   ; |Text = 00000005 ???
00F710C5    .  6A 00         push 0x0                                   ; |hOwner = NULL
00F710C7    .  FF15 E460F700 call dword ptr ds:[<&USER32.MessageBoxA>]  ; \MessageBoxA
```





# Machine Code 机器码

> 常见机器码速查，用于应对花指令

```assembly
90 nop
9A CALL # CALL immed32
E8 call # CALL immed16
E9 # JMP immed16
EB # JMP immed8
```



# 反调试技术





## SMC(Self Modifying Code)

- SMC技术,就是一种将可执行文件中的代码或数据进行加密，防止别人使用逆向工程工具（e.g. 反汇编工具）对程序进行静态分析的方法，只有程序运行时才对代码和数据进行解密，从而正常运行程序和访问数据
- 计算机病毒通常也会采用SMC技术动态修改内存中的可执行代码来达到变形或对代码加密的目的，从而躲过杀毒软件的查杀或者迷惑反病毒工作者对代码进行分析。现在，很多加密软件（或者称为“壳”程序）为了防止Cracker（破解者）跟踪自己的代码，也采用了动态代码修改技术对自身代码进行保护

SMC应对方式：

1. 找到程序中的SMC解密过程，IDA分析并手动解密被SMC加密过的代码/数据
2. 动态调试，在SMC解密结束后的地方下断点



```cpp
// IDA  逆向出来的一个片段 包含简单smc解密过程
  for ( i = 0; i <= 181; ++i ) // simple smc decrypt
    judge[i] ^= 0xCu; // 使用异或解密
  printf("Please input flag:");
  __isoc99_scanf("%20s", s);
  v5 = strlen(s);
  if ( v5 == 14 && (*(unsigned int (__fastcall **)(char *))judge)(s) ) // call function judge(after decrypted)
    puts("Right!");
```

- 在IDA中打开后，因为上述解密代码需要在程序运行后才会执行，所以IDA打开的judge函数还处于被加密过的状态（即乱码状态）
- 因为已经可以看到smc解密过程了，可以根据smc解密过程，对程序文件做patch，使用脚本在未运行时解密
- 以下为上述smc解密过程的python脚本，可以解密judge函数。注意只能运行一次

```python
from ida_bytes import patch_byte, get_byte
s = 0x600b00 # judge函数的地址
for i in range(182): # 182为judege函数的总长度
    patch_byte(s+i, get_byte(s+i) ^ 0xc)
```

> IDA python ida_bytes:  https://www.hex-rays.com/products/ida/support/idapython_docs/ida_bytes-module.html

- 脚本运行结束后，U取消原本定义，C生成汇编代码，P生成函数。至此judge函数可以正常逆向了



## 花指令

> 可能会涉及修改机器码，参考**Machine Code**章节

1. 不影响程序本身的运行
2. 阻碍静态分析工具正确分析

- 企图隐藏掉不想被逆向工程的代码块/功能的一种方法, 在真实代码中插入一些垃圾代码的同时保证原有程序的正确执行, 而程序无法很好地反编译, 难以理解程序内容, 达到反调试的效果

> 比如使用`jz ... jnz ... call`(`call`机器码`E8`). call 永不执行，而后面一些指令的机器码被当成`call`的一部分而被掩藏



花指令情形列举：

- IDA中显示类似`jump short xxx+2`，该地址`xxx`很可能就是一个混淆用的机器码，将被跳过的字节改为`90`(`nop`)来消除影响
- 





### Cases

- 使用了多种花指令   `mathematic_sage_starctf_2021_wherekey`:  https://github.com/hex-16/CTF-detailed-writeups/tree/main/reverse/mathematic_sage_starctf_2021_wherekey 



