





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









# The Function Stack

> 函数栈，ESP EBP寄存器
>
> https://www.tenouk.com/Bufferoverflowc/Bufferoverflow2a.html

1. ESP: 栈指针寄存器(extended stack pointer), 该指针永远指向系统栈最上面一个栈帧的栈顶
2. EBP: 基址指针寄存器(extended base pointer), 该指针永远指向系统栈最上面一个栈帧的底部

intel系统中栈是向下生长的(栈越扩大其值越小,堆恰好相反)

在通常情况下ESP是可变的，随着栈的生产而逐渐变小，用ESP来标记栈的底部

ESP寄存器是固定的，只有当函数的调用后，发生入栈操作而改变

通过固定的地址与偏移量来寻找在栈参数与变量，EBP寄存器存放的就是固定的地址。但是这个值在函数调用过程中会变化，函数执行结束后需要还原，因此要在函数的出栈入栈中进行保存

---

# Reverse Engineering for Beginners

> 逆向工程权威指南 [乌克兰]Dennis Yurichev 著, Archer安天安全研究与应急处理中心 译



```cpp
int f(){ // 第二章 最简函数
    return 123;
}
```
```assembly
; 开启优化功能后，GCC产生的汇编指令(MSVC编译的程序也一样)：
f:
	mov 	eax, 123 ; 将123存放在EAX寄存器里
	ret ; ret指令会把EAX的值当作返回值传递给调用函数，而调用函数(caller)会从EAX取值当作返回结果
```

- Calling Convention, 调用约定, 调用规范

MIPS寄存器的两种命名方式：

1. 数字命名(`$0 ~ $31`)
2. 伪名称(`pseudoname`)



## Hello, world!



### x86 and x86-64

```cpp
#include <stdio.h>
int main(){
    printf("hello, world\n"); // 将为"hello, world\n"分配一个const char[]指针
    return 0;
}
```

- 使用MSVC2010 编译: `cl 1.cpp /Fa1.asm`，`/Fa`将使编译器生成汇编指令清单文件(assembly listing file)，并指定汇编列表文件的文件名是`1.asm`
- MSVC生成的汇编清单文件都采用了Intel语体(另一种主流语体为AT&T语体)
- 所有函数都有标志性的函数序言function prologue 和函数尾声function epilogue

```assembly
CONST 	SEGMENT
$SG3830 DB		'hello, world', 0AH, 00H ; 编译器内部把字符串常量命名为 $SG3830 0AH为\n, 00H为\0, 字符串常量结束标志
CONST	ENDS
PUBLIC	_main
EXTRN	_printf:PROC
; Function compile flags: /0dtp
_TEXT	SEGMENT
_main	PROC       ; 函数序言function prologue
		push	ebp      ; 把ebp的值入栈 将caller的ebp入栈
		mov		ebp, esp ; 把esp的值保存在ebp中，此时ebp的值被改变了
		push	OFFSET $SG3830 ; 把字符串$SG3830指针入栈
		call	_printf  ; printf结束后，程序的控制流会返回到main()函数中，此时字符串$SG3830指针仍残留在数据栈中，需要调整栈指针ESP来释放这个指针
		add		esp, 4   ; 把ESP寄存器(栈指针 Stack Pointer)里的值+4, 因为x86内存地址用32bit(4Byte)数据描述; 直接舍弃了栈里的数据($SG3830指针)
		xor		eax, eax ; main返回值为0，由该指令计算出来 ; main函数的最后一项任务是使EAX的值为0
		pop		ebp      ; 把栈中保存的ebp的旧值pop出来赋值给ebp, 还原caller的ebp
		ret		0        ; 将控制权交给调用程序，通常起到的作用是将控制权交给操作系统，这部分功能由C/C++的CRT实现
_main ENDP             ; 数尾声function epilogue
_TEXT ENDS
```

- GCC 4.4.1编译 `gcc 1.c -o 1`, 也采用Intel语体，指定生成Intel语体的汇编列表文件，GCC的选项:`-S -masm=intel`

```assembly
Main	proc	near
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
	ret n
main endp
```

- 虽然在8字节边界处对齐就可以满足32位x86和64位x64 CPU的要求，但是主流编译器编译规则规定：**程序访问的地址必须向16字节对齐(被16整除)**

> p10有对应的AT&T语体的汇编指令



用64位MSVC编译(MSVC 2012 x64):

```assembly
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





### ARM

> 3.4 ARM p13 







# IDA Pro

- 在IDA Pro中，IDA View界面按F5，将反汇编为伪代码Pseudocode



- shift+F12 查看关键字符串，将打开Strings window，双击某个string后可以跳到IDA View，查看对应汇编代码
- 双击后面的提示信息`; DATA XREF:`可以跳转到用到了该string的函数

```assembly
.rodata:0000000000400965 ; char aYouEnteredTheC[]
.rodata:0000000000400965 aYouEnteredTheC db 'You entered the correct password!',0Ah
.rodata:0000000000400965                                         ; DATA XREF: sub_4007F0+8↑o
```



- Pseudocode窗口下右键函数名，可以点击`Jump to xref`查看调用了这个函数的地方



- 在变量处右键，可以选择改成不同的数据表现形式

```cpp
v7 = 28537194573619560LL; // 右键，可以选择改成Char Enum Hex等
v7 = 'ebmarah'; // 改成Char之后
```



