





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

```cpp
#include <stdio.h>
int MyFunc(int parameter1, char parameter2){
	int local1 = 9;
	char local2 = 'Z';
    return 0;
}
int main(int argc, char *argv[]){
	MyFunc(7, '8');
	return 0;
}
```

![](https://raw.githubusercontent.com/hex-16/pictures/master/Code_pic/RE_function_call_function_stack_layout.png)









---

# Reverse Engineering for Beginners

> 逆向工程权威指南 [乌克兰]Dennis Yurichev 著, Archer安天安全研究与应急处理中心 译



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
		push	ebp      ; 把ebp的值入栈 将 caller 的 ebp 入栈
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
; 指令清单3.3 GCC 4.4.1 x86; 在IDA中观察到的汇编指令
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
sub  esp, X   ; 修改栈的高度，以便为本函数的局部变量申请存储空间
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



# 5. 栈 Stack







---

# IDA Pro

- 查看版本号与逆编译器版本 Help => About program => `Version 7.5.201028 Windows x64 (32-bit address size)` => Addons => 32 bit: `e.g. x86 ARM PowerPC MIPS Decompiler`
- Option:
  - General:
    - Disassembly:
      - Auto comments: 可以显示汇编指令的含义e.g.  `li  $a3, 0x10019C80 # Load Immediate`





## Shortcut Quick Find

| Key      | Function                                    |
| -------- | ------------------------------------------- |
| space    | 切换显示方式                                |
| C        | 转换为代码                                  |
| D        | 转换为数据                                  |
|          |                                             |
|          |                                             |
|          |                                             |
| N        | 为标签重命名(包含寄存器等)                  |
| ?        | 计算器                                      |
| G        | 跳转到地址(然后会出来Jump to address对话框) |
| ;        | 添加注释                                    |
| ctrl+X   | 查看当前函数、标签、变量的参考(显示栈)      |
| X        | 查看当前函数、标签、变量的参考              |
| Alt + I  | 搜索常量constant                            |
| Ctrl + I | 再次搜索常量constant                        |
| Alt + B  | 搜索byte序列                                |
| Ctrl + B | 再次搜索byte序列                            |
| Alt + T  | 搜索文本(包括指令中的文本)                  |
| Ctrl + T | 再次搜索文本                                |
| Alt + P  | 编辑当前函数                                |
| Enter    | 跳转到函数、变量等对象                      |
| Esc      | 返回                                        |





## IDA View

- 在IDA Pro中，IDA View界面按F5，将反汇编为伪代码Pseudocode
- 按空格space可以在Text view和Graph view之间转换
- 程序基本信息：在Text view下，拉到最前面。可看到的信息：大/小端序，架构，文件名...





## Pseudocode

> 伪代码窗口 在IDA View窗口中按F5可以打开该窗口

- Pseudocode窗口下右键函数名，可以点击`Jump to xref`查看调用了这个函数的地方

- 在变量处右键，可以选择改成不同的数据表现形式

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

