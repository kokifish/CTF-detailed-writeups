# pwn

- 部分较为简单、适合入门/速查/回忆的被归档在对应的 `[Simple_Cases]_xxx` 文件夹中
- pwn速查表，知识导览 见repo根目录 `[CTF]_Pwn.md`

writeup开头通常包含以下信息(可选)：

1. 赛事名称、年份、链接
2. challenge name: 题目名称
3. description: 题目描述
4. file: 题目给予的文件
5. writeup文件夹下提供的额外文件，一般为IDA的`.i64`文件
6. writeup writer: 
7. refer writeup: links or writer name/homepage

然后简要描述题目逻辑，pwn的思路，需要注意的地方，重要的知识点等。

下一个一级标题开始，描述详细的分析步骤

Exploit 放出带有注释的exp

可能含有用gdb的Post Analysis，一般用于分析栈、寄存器变化



# Game Name Year Challenge Name

> challenge name: `xxx`   level: 1(checkin) 2(easy) 3(medium) 4(hard) 5()
>
> file: `pwn`, `libc-2.27.so`
>
> ld.so and .i64 with comments provided
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16
>
> something wanna say...



# Challenges Consolidation

- 用于理解某一知识点的入门级题目放在  `[Simple_Cases]_xxx` 中
- 同一比赛若有赛题过程相似，知识点相似的，合并赛题文件夹
- 不同赛事中，如果有赛题相似度过高，属于同一类别的，也合并。合并后文件夹以赛题类别命名 e.g.`Heap_OffByOne`



# pwn Exploit Template

exp template, usually be used in heap pwn.

```python
from pwn import *
context.arch = "amd64"
context.log_level = "debug"
IP = "172.0.0.0"
PORT = 123
DEBUG = 1

if DEBUG:
    p = process("./pwn")
    # p = process(["./ld-2.31.so", "./pwn"], env={"LD_PRELOAD": "./libc-2.31.so"})
    base = p.libs()[p._cwd + p.argv[0].decode().strip(".")]  # fix bytes str error in py3.9
    success("base:" + hex(base) + str(p.libs()))
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") # for local libc heap pwn
else:
    p = remote(IP, PORT)  # flag{...}
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
        cmd += "b *%d\n" % (base + 0x15D5)
        cmd += "b *%d\n" % (base + 0x154D)
        cmd += "set $a=%d\n" % (base + 0x5080)  # arrPtr
        debug(cmd)
        
# ===================================================================================
def menu(choice_num: int):
    sla("choice>> ", str(choice_num))

# ... something else
libc_addr = l64()  # leak libc
libc_base = libc_addr - 0x70 - libc.sym["__malloc_hook"]  # for local and remote libc compatibility
p.interactive()
```

```c
def get_base_address(proc):
	return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)
def debug(breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(p)
    script += "set $_base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    gdb.attach(p,gdbscript=script)
```



