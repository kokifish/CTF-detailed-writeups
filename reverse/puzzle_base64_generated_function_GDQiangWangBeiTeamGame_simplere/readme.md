# simplere

> 2021 广东省强网杯团队赛 reverse simplere
>
> challenge name: simplere
>
> file: simple
>
> .i64 with comments provided
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16 

本质上是一道很简单的题目，flag有两部分，前半部分是解迷宫，wasd组成，后半部分是程序中一个字符串的base64之后的编码。

TODO: 

把这个题目放在这是挖个坑：main函数中，在处理后半部分的flag时，会使用两个.data段上的数组（已有初值）来计算得到一个数组，这个数组被返回之后，memcpy一份后，当作函数来调用了。问题就在于，怎么把这种运行时生成的函数还原出来。

另，熟悉base64编码解码特征。

# IDA Analysis

```cpp
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  __int64 result; // rax
  char flag_part2[33]; // [rsp+0h] [rbp-250h] BYREF
  char flag_part1[15]; // [rsp+21h] [rbp-22Fh] BYREF
  char flag[256]; // [rsp+30h] [rbp-220h] BYREF
  char out_arr[256]; // [rsp+130h] [rbp-120h] BYREF
  void *ret_arr; // [rsp+230h] [rbp-20h]
  void *dest; // [rsp+238h] [rbp-18h]
  int v10; // [rsp+244h] [rbp-Ch]
  int j; // [rsp+248h] [rbp-8h]
  int i; // [rsp+24Ch] [rbp-4h]

  printf("your flag:");
  __isoc99_scanf("%s", flag);
  putchar(10);
  if ( flag[15] == '-' )                        // part1-part2 也就是说最终格式： flag{part1-part2}
  {
    for ( i = 0; i <= 14; ++i )
      flag_part1[i] = flag[i];                  // ssddddwddddssas
    for ( j = 0; j <= 17; ++j )
      flag_part2[j] = flag[j + 16];
    v10 = func_flag_part1((__int64)flag_part1);
    if ( v10 == 1 )
    {
      dest = mmap(0LL, 0x1000uLL, 7, 33, -1, 0LL);
      ret_arr = generate_afunc();               // 不仅生成一个函数 而且改变了ini_arr
      memcpy(dest, ret_arr, 0x28CuLL);          // dest最终是由ret_arr表示的一个函数(maybe)
      ((void (__fastcall *)(char *, char *, _BYTE *))dest)(out_arr, flag_part2, ini_arr);// 虽然看着很怪，但这确实是个函数调用，只是传参可能有问题，需看汇编
      v10 = test_ans((__int64)out_arr);         // r60ihyZ/m4lseHt+m4t+mIkc 传入的字符串要与这个相等
      if ( v10 )
        puts("congratulations!");
      else
        printf("nonono");
      result = 0LL;
    }
    else
    {
      printf("nonono");
      result = 0LL;
    }
  }
  else
  {
    printf("nonono");
    result = 0LL;
  }
  return result;
}
```

```cpp
_BYTE *generate_afunc()
{
  _BYTE *ret_arr; // [rsp+8h] [rbp-18h]
  int j; // [rsp+14h] [rbp-Ch]
  int i; // [rsp+18h] [rbp-8h]
  int idx; // [rsp+1Ch] [rbp-4h]

  ret_arr = malloc(0x200uLL);
  idx = 0;
  for ( i = 0; i < 652; ++i )
  {
    if ( idx == 64 )
      idx = 0;
    ret_arr[i] = data_arrbig[i] ^ data_arr1[idx++];
  }
  for ( j = 0; j <= 63; ++j )
    ini_arr[j] ^= data_arr1[j];
  return ret_arr;
}
```



# Exploit

1. 迷宫：ssddddwddddssas
2. base64：cjYwaWh5Wi9tNGxzZUh0K200dCttSWtj   (在线base64编码 `r60ihyZ/m4lseHt+m4t+mIkc` 得到的结果)