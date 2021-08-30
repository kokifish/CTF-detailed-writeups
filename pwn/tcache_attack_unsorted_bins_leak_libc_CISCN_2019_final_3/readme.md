# CISCN 2019 final 3

> CISCN 2019 全国大学生信息安全竞赛 pwn babyheap  https://buuoj.cn/challenges#ciscn_2019_final_3
>
> file: ciscn_final_3, libc.so.6
>
> .i64 with comments provided, corresponding ld.so (2.27-3ubuntu1) provided
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16
>
> refer writeup:  https://bbs.pediy.com/thread-262480.htm  and   waterdrop lwl



# Pre Analysis

保护全开

```bash
checksec --file=ciscn_final_3  
[*] '/home/kali/CTF/buuoj/ciscn_final_3'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```bash
strings libc.so.6 | grep GLIBC
......
GLIBC_2.26
GLIBC_2.27
GLIBC_PRIVATE
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.
```

- 根据 **Ubuntu GLIBC 2.27-3ubuntu1** 去 http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/ 找对应的deb 提取出ld.so，这里已经提供了ld.so，查找ld.so的具体方法见pwn.md





# IDA Analysis

程序有两个功能

1. add：input(index, size, content), 向BSS区上的一个指针数组上分配空间，并调用read读入至多size个char
2. delete：input(index) 然后free(arr+index) free后没有置零，index没有做重复free检查，存在double free漏洞

注意add函数的几个要点：

1. add时判断arr[idx]是否为NULL 不为NULL则退出，而由于delete不置零，故每个idx仅可add一次
2. 输入的size值至多为0x78，这个大小的chunk不会进入unsort bin，而是进入fast bin.(指tcache满时)
3. 输入content调用的是read函数，可以输入\x00

```cpp
unsigned __int64 add()
{
  __int64 v0; // rax
  __int64 v1; // rax
  unsigned int v2; // ebx
  __int64 v3; // rax
  size_t size; // [rsp+0h] [rbp-20h] BYREF 这个size_t记录index 也记录size
  unsigned __int64 v6; // [rsp+8h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  v0 = std::operator<<<std::char_traits<char>>(&std::cout, "input the index");
  std::ostream::operator<<(v0, &std::endl<char,std::char_traits<char>>);
  std::istream::operator>>(&std::cin, (char *)&size + 4);// size+4是index
  if ( *((_QWORD *)&arr_p + HIDWORD(size)) || HIDWORD(size) > 0x18 )
    exit(0);
  v1 = std::operator<<<std::char_traits<char>>(&std::cout, "input the size");
  std::ostream::operator<<(v1, &std::endl<char,std::char_traits<char>>);
  std::istream::operator>>(&std::cin, &size);
  if ( (unsigned int)size <= 0x78 )             // 可输入内容的长度
  {
    v2 = HIDWORD(size);
    *((_QWORD *)&arr_p + v2) = malloc((unsigned int)size);// malloc
    v3 = std::operator<<<std::char_traits<char>>(&std::cout, "now you can write something");
    std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
    sub_CBB(*((_QWORD *)&arr_p + HIDWORD(size)), (unsigned int)size);// 调read 往arr_p+idx 写入size 个字节
    puts("OK!");
    printf("gift :%p\n", *((const void **)&arr_p + HIDWORD(size)));
  }
  return __readfsqword(0x28u) ^ v6;
}
```

delete函数没有需要过多注意的地方，仅需注意到free后没有置NULL即可





# Step-1: Make and Get Fake Chunk







# Step-2:





# Step-3:



