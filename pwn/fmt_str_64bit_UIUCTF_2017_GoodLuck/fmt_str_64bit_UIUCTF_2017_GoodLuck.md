# UIUCTF 2017 GoodLuck

> challenge name: GoodLuck
>
> file: goodluck, flag.txt
>
> original writeup: https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2017-UIUCTF-pwn200-GoodLuck
>
> 

- 64bit format string



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

