





# Reverse Engineering Introduction

- 软件代码逆向主要指对软件的结构，流程，算法，代码等进行逆向拆解和分析
- Software Reverse Engineering: 主要应用于软件维护，软件破解，漏洞挖掘，恶意代码分析

要求

- 熟悉如操作系统，汇编语言，加解密等相关知识
- 具有丰富的多种高级语言的编程经验
- 熟悉多种编译器的编译原理
- 较强的程序理解和逆向分析能力

常规逆向流程 

1. 使用`strings/file/binwalk/IDA`等静态分析工具收集信息，并根据这些静态信息进行google/github搜索
2. 研究程序的保护方法，如代码混淆，保护壳及反调试等技术，并设法破除或绕过保护
3. 反汇编目标软件，快速定位到关键代码进行分析
4. 结合动态调试，验证自己的初期猜想，在分析的过程中理清程序功能
5. 针对程序功能，写出对应脚本，求解出 flag



动态分析 

- 动态分析的目的在于定位关键代码后，在程序运行的过程中，借由输出信息（寄存器，内存变化，程序输出）等来验证自己的推断或是理解程序功能
- 主要方法：调试，符号执行，污点分析





## Common Encryption Algorithms and Code Recognition

> 常见加密算法与代码识别

### Base64

Base64 是一种基于 64 个可打印字符来表示二进制数据的表示方法。转换的时候，将 3 字节的数据，先后放入一个 24 位的缓冲区中，先来的字节占高位。数据不足 3 字节的话，于缓冲器中剩下的比特用 0 补足。每次取出 6 比特（因为 $$ 2^{6}=64$$），按照其值选择`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`中的字符作为编码后的输出，直到全部输入数据转换完成。

通常而言 Base64 的识别特征为索引表，当我们能找到 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` 这样索引表，再经过简单的分析基本就能判定是 Base64 编码。

有些题目 base64 的索引表是会变的，一些变种的 base64 主要 就是修改了这个索引表



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

```
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



## Labyrinth Problem

> 迷宫问题

迷宫问题有以下特点:

- 在内存中布置一张 "地图"
- 将用户输入限制在少数几个字符范围内.
- 一般只有一个迷宫入口和一个迷宫出口













# Linux Reverse







# Windows Reverse







---

# Reverse Engineering for Beginners

> [乌克兰]Dennis Yurichev 著, Archer安天安全研究与应急处理中心 译



```cpp
int f(){
    return 123;
}
```
- 开启优化功能后，GCC产生的汇编指令：MSVC编译的程序也一样
```assembly
f:
	mov 	exa,	123
	ret
```

- Calling Convention, 调用约定, 调用规范：ret指令会把EAX的值当作返回值传递给调用函数，而调用函数(caller)会从EAX取值当作返回结果





# IDA Pro





