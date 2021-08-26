
# 考古

> 2021 08 21 https://ctf.ichunqiu.com/2021xiangyuncup
> 
> origin writeup：https://blog.gztime.cc/posts/2021/eee18328/

题目描述：小明在家里翻到一台很古老的xp笔记本，换电池之后发现可以正常开机，但是发现硬盘空间不足。清理过程中却发生了一些不愉快的事情...

> 相关文件： memory https://pan.baidu.com/s/12Vagp9-EBgELXQx8xoFJKg 提取码：GAME

本质上是一道内存取证题

首先使用`volatility`进行取证，这道题也可以当作是`volatility`的入门：
首先`imageinfo`插件得到系统信息
```bash
> volatility -f memory imageinfo 

imageinfo: WinXPSP2x86
```
然后就是靠撞了，一般用到的是`cmdsacn`,`pslist`,`filescan`等。
这道题目使用`cmdscan`得到：
```bash
> volatility -f memory imageinfo 

Cmd #0 @ 0x3832110: It's useless to find so many things
Cmd #1 @ 0x3832ed0: ........................
Cmd #2 @ 0x52c778: what can i do about it
Cmd #3 @ 0x3833360: Heard that there is a one-click cleaning that is very useful
Cmd #4 @ 0x52b3c8: try it
Cmd #5 @ 0x52b7e8: "C:\Documents and Settings\Administrator\??\Oneclickcleanup.exe"
Cmd #6 @ 0x5224a0: what???
Cmd #7 @ 0x52d5c0: what happened??
Cmd #8 @ 0x52d410: who is 1cepeak?
Cmd #9 @ 0x3832de0: what's the meaning of hack?
Cmd #10 @ 0x3830e50: oh,no
Cmd #11 @ 0x52af40: holy shit
Cmd #12 @ 0x3830cf8: aaaaaa
Cmd #13 @ 0x522d28: Nonononononononononononono!!!!!!!!!!!!!!!!
Cmd #14 @ 0x522d88: "C:\Documents and Settings\Administrator\??\Oneclickcleanup.exe"
Cmd #15 @ 0x5224b8: fuc
```
其中提到一个`Oneclickcleanup.exe`，然后我们就使用`filescan`查看
```bash
> volatility -f memory --profile=WinXPSP2x86 filescan | grep "Oneclick"

0x00000000017bcbc0      1      0 R--rw- \Device\HarddiskVolume1\Documents and Settings\Administrator\桌面\Oneclickcleanup.exe
0x000000000180c758      1      0 RW-rwd \Device\HarddiskVolume1\temp\Oneclickcleanup.exe
0x0000000001956d88      1      0 R--r-d \Device\HarddiskVolume1\Documents and Settings\Administrator\桌面\Oneclickcleanup.exe
```

使用filedump提取出Oneclickcleanup.exe文件，提取出的文件不一定叫这个名字，但只要知道是exe文件就行
```bash
> volatility -f memory --profile=WinXPSP2x86 dumpfiles -Q 0x00000000017bcbc0 -D ./
```

然后把dump出的文件放入IDA，直接按F5进行反编译得到伪c代码：
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *v4; // [esp+10h] [ebp-14h]
  int k; // [esp+14h] [ebp-10h]
  signed int j; // [esp+18h] [ebp-Ch]
  int i; // [esp+1Ch] [ebp-8h]

  sub_4271C0();
  for ( i = 0; i <= 44; ++i )
    FileName[i] ^= byte_4B8030[i % 10];
  for ( j = 0; j < (int)ElementSize; ++j )
    byte_4B8040[j] ^= byte_4B8030[j % 10];
  for ( k = 0; k <= 9; ++k )
    puts("Hacked by 1cePack!!!!!!!");
  v4 = fopen(FileName, "wb+");
  fwrite(byte_4B8040, ElementSize, 1u, v4);
  return 0;
}
```

从逻辑上看，文件名循环异或`byte_4B8030`中的内容，然后要写入文件的内容`byte_4B8040`同样循环异或`byte_4B8030`中的内容。然后我们可以发现
`byte_4B8030`是`this_a_key`
然后提取出`FileName`和`byte_4B8040`中的内容然后与`this_a_key`进行循环异或。

首先我们可以得到文件名为`C:\Documents and Settings\All Users\Template_k`，但是通过filescan在镜像中找不到这个文件。因此我们集中看一下`byte_4B8040`中的内容。我们print了一下，发现里面有microsoft word字样，因此我们认为它是一个word文件。使用word打开可以看到：
```word
My friend, I said, there is really no flag here, why don’t you believe me?
```
然后理论上不知道怎么做，最后origin writeup的做法是对文档进行逐位异或
```python
for k in range(256):
    m3 = [chr(ord(x) ^ k) for x in out]
    m3 = ''.join(m3)
    if ('flag' in m3):
        print(type(m3))
        offset = m3.find('flag{')
        print('offset', offset, k)
        flag = ''
        while offset < len(m3) and m3[offset] in dirlist:
            flag += m3[offset]
            offset += 1
        print(flag)
        # print(m3)
        f2 = open('word.doc', 'wb')
        f2.write(m3)
```

然后打开word文件搜索flag就把flag搜出来了
`flag{8bedfdbb-ba42-43d1-858c-c2a5-5012d309}`