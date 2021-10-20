# XiangYunBei 2021 Final pwn: quiet_baby

> 第二届“祥云杯”网络安全大赛暨吉林省第四届大学生网络安全大赛线下决赛 吉林长春
>
> 第二日 社会组 Jeopardy赛制   point: 400  solved: less than 5
>
> files: `pwn`(renamed to `pwn_ori`), libc-2.31.so
>
> additional files: no alarm pwn, i64 with comment, corresponding ld-2.31.so
>
> exp files: redbud_wh_babyquiet_ori.py: redbud wh师傅的原始exp
>
> 写在最前：第一次参加线下赛，很感谢liwl给予的机会，以及gztime 春哥的carry。这题没做出来十分可惜，逆向层对程序理解已经十分充分了，主要是对IO file结构不了解，且此前未接触过通过修改`stdout._flags`来泄露libc地址，其余知识都是之前学过的。还想着用程序中依据1B泄露高1B的逻辑，1B1B的泄露libc地址，1B1B的修改指针。总之就是学艺不精，见识尚浅，才学浅薄，仍需积累。最原始的exp出自redbud wh师傅，特别感谢！wh在赛后对exp的描述及后续的释疑对我理解exp过程、学习新知识帮助很大。redbud🐂🐸

所需知识/考察知识点：

1. unsorted bin leak libc addr: fw of chunk in unsorted bin
2. `_IO_2_1_stdout_, main_arena, fw of unsorted bin chunk` 三个地址很接近，基本只有最后2B有区别 
3. `_IO_FILE: _IO_2_1_stdout_` structure, 修改 `_IO_2_1_stdout_._flags` 达到 leak libc addr
4. Tcache Poisoning: UAF. cover `__free_hook` to `system` 常规套路 注意绕安全检查





# Preanalysis and ld.so libc.so

```bash
$ strings libc-2.31.so| grep GLIBC
GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.2) stable release version 2.31.
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

- 保护全开
- 现场没有给出ld.so，给出的ld从http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/ 中下载的`libc6_2.31-0ubuntu9.2_amd64.deb`中提取出来，其中的libc.so就是题目给的libc-2.31.so，hash相同。

# IDA Analysis

- 程序有alarm函数，超时未响应则退出，影响debug，pwn文件已经将这段代码nop
- 程序有两处影响IDA逆向的指令，`00000000000012E8	0x1	FF 	90; 00000000000019DD	0x1	3E 	90 `，会影响main中跳转表的逆向，可以将其nop掉，但不要将其apply到binary中，否则会有段错误。即这部分指令实际上是参与执行的，但是会影响IDA分析

```cpp
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  ini_seed();                                   // alarm function here
  menu();
  while ( 1 )
  {
    menu_sub();
    read(0, buf, 2uLL);
    switch ( buf[0] )
    {
      case '1':
        give();  // idx最大为10 可以为负数 malloc时可以覆盖之前malloc的指针
        break;
      case '2':
        edit();   // 指针不为空，就可以依据arr_size改arr_ptr+idx处的指针
        break;
      case '3':
        talk();   // 最后1B不变，所以可以根据输出得到低第二B
        break;
      case '4':
        delete();  // free后未置0 UAF 可多次free 但要绕double free检查 要改bk后再free
        break;
      case '5':
        exit(8);
      default:
        continue;
    }
  }
}
```

- talk函数，后续会用这里的逻辑来泄露unsorted bin fw的低第二byte

```cpp
unsigned __int64 talk()
{
  char ptr_1B; // [rsp+6h] [rbp-1Ah]
  char ptr_2B; // [rsp+7h] [rbp-19h]
  unsigned int idx; // [rsp+8h] [rbp-18h]
  int rand_num; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  puts("          /Speaking fluently is difficult for a small baby");
  puts("      ,==.              |~~~          ");
  puts("     /  66\\             |");
  puts("     \\c  -_)         |~~~");
  puts("      /   \\       |~~~");
  puts("     /   \\ \\      |");
  puts("    ((   /\\ \\_ |~~~");
  puts("     \\  \\ `--`|");
  puts("     / / /  |~~~");
  puts("___ (_(___)_|");
  puts("Show your baby something to teach him to talk:");
  read(0, buf, 3uLL);
  idx = str2int(buf);
  if ( idx > 0xA )
  {
    puts("Segmentation Fault");
    exit(0);
  }
  if ( !arrPtr[idx] )
  {
    puts("Segmentation Fault");
    exit(0);
  }
  if ( flagILoveC )               // 注意这个是只要前面set过一次就行 不是每个chunk都要满足ILoveC
  {
    ptr_1B = *(_BYTE *)arrPtr[idx];             // 最低1B
    ptr_2B = *((_BYTE *)arrPtr[idx] + 1);
    rand_num = rand() % 127;                    // 生成randnum
    printf("Baby said: ! @ # $ % ^ & * ( %c\n", (unsigned int)(char)(rand_num ^ ptr_1B));// 输出randnum ^ 最低1B
    printf("Continued the baby: ! @ # $ % ^ & * ( %c\n", (unsigned int)(char)(rand_num ^ ptr_2B));// 输出randnum ^ 低第2B
    puts("Sure enough...The baby slurred his speech");
  }
  else
  {
    puts("Baby said: ! I@ % ^  & # & W* ( A!  N # ! T @  ! % $ C ^ @");
    puts("It looks like the baby is unhappy that he didn't get the primer plus");
  }
  return __readfsqword(0x28u) ^ v6;
}
```



# vul

1. give: idx最大为10，可以为负(这个没用到)，malloc时不检查arr[idx]处是否为空，可以覆盖。size记录在另一个数组arrSize中
2. edit: arr[idx]不为空就可以edit，size依据arrSize[idx]
3. talk: 之前give时的content出现过`ILoveC`时，输出`randnum ^ lsB, randnum ^ ls2ndB`，lsB指指针的最低byte，ls2ndB指指针的低第二byte，但是在开启ASLR时，低12bit不变，实际上这里可以leak最低2B
4. delete: UAF. free后未置NULL，且不改变arrSize[idx]. 可以对一个指针多次free



# exp process 

1. 填满tcache，放一个chunk到unsorted bin
2. 



# Step-1: full tcache, a chunk to unsorted bin

