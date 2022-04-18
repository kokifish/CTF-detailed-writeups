# \*CTF starCTF re simplefs

> challenge name: simplefs    level: 1(checkin)
>
> file: flag, image.flag, instruction.txt, simplefs
>
> exp.py .i64 with comments provided
>
> writeup writer: https://github.com/hex-16
>
> 当天身体不适，早上9点开赛，晚上九点才正经的开始看题，先是搞pwn，近12点开始看simplefs，后来看排名，不差这simplefs。两小时后化为困兽，就睡了。第二天早上10点继续看了下，午饭前出了，很伤心，为自己的菜感到伤心，但能够暂时逃离gnn，总体还是心情舒畅些。这题陷入了部分无关紧要的代码中，浪费了一部分时间，主要原因还是太久没做题，老带空空。
>
> 这题在最后一次看时，是pwn re里面解出数最多的，属于简单题，但是程序本身的逻辑很复杂，包含大量的与解题没有太大关系的代码。出于好奇，还是认真的逆了一部分代码，算是从源码层稍稍理解了inode相关的只是，也稍稍感受到了linux文件系统巨大的代码量。

总的来说就是，实现了一个简易的文件系统，在触发`plantflag`时，会随机存储随机数量的数据到block(大小为4KB)里，并把flag文件的内容也存到其中一个block里面，存储是经过简单弱加密的，可逆。解题思路就是了解清楚image文件的组织形式，把所有block的内容（密文）都做一次解密，找出满足flag格式的明文。

simplefs是个64bti ELF，实现了简单的文件系统，模仿inode。image.flag大小为2M，flag为26B的flag模板。

# Program Main Logic

```bash
Commands are:   # 这个是simplefs 的help信息
    format
    mount
    debug
    create
    delete  <inode>
    cat     <inode>
    captureflag
    plantflag
    copyin  <file> <inode>
    copyout <inode> <file>
    help
    quit
    exit
```

程序的cmd还挺多的，可以观察format、mount的逻辑了解image文件的组织形式，也可以直接观察image文件，image文件里面从`0x33000`开始每隔`0x1000(4096)`，直到`0xE1000`都有固定31B长度的内容，共175个block。

iamge最前面存有小端序的`0x0, 0x01f4(500), 0x32(50), 0x1900(6400), 0xDEEDBEEF`，除第一个0外，前三个数字是记录这个image文件的属性的，可以发现`500*4KB=2MB`，刚好是文件大小，所以这个500就是block的数量。

从`0x1000`开始到`0x19c0`每`32B`（称这个结构为inode）有类似`01...1f...33`的内容，`0x33000`刚好就是后面有内容的block的起始地址，`0x1f=31`就是后面有内容的block的内容字节长度。结合程序逻辑，可以推断出inode的结构信息：

inode大小为32B，inode结构:

```cpp
       4B      8B        12B      16B       20B       24B       28B          32B
| inuse | size | iblock0 | iblock1 | iblock2 | iblock3 | iblock4 | indirect_b | 
```

- inuse: 标记这个inode是否在使用
- size: 标记这个inode的总长度(bytes)
- iblockx: x表示的是这个`iblock`在这个inode里面的idx，其值是block号`iblock`

为叙述方便，定义以下标记：

- `iblock`: block号。block在image里面的索引，`iblock << 12`就是block号为`iblock`的block在image文件里面的偏移，simplefs会用`fseek(disk_file, iblock << 12, 0); fread(buf, 4096uLL, 1uLL, disk_file)`来读取一个block
- `block_idx`: 在inode里的block索引。指的是在inode里面，记录某个block的`iblock`的索引



# plantflag

1. 随机生成两个随机数a, b
2. 存a个随机str到空闲block里，str的长度与`flag`对应密文的长度一样
3. 对`flag`做加密，存到空闲block里
4. 存b个随机str到空闲block里，str的长度与`flag`对应密文的长度一样

```cpp
		else if ( !strcmp(cmd0, "plantflag") )
        {
          v9 = time(&v24);
          srand(v9);
          rand_num0 = rand() % 100;
          rand_num1 = rand() % 100;
          for ( i = 0; i < rand_num0; ++i )
          {
            inode_id_1 = create_inode();
            if ( copy_file2inode("flag", inode_id_1, 2) )// 2: 值与flag文件无关，随机生成同等长度的密文存到block里
              printf("copied file %s to inode %d\n", cmd1, inode_id_1);// 复制flag到新创建的inode上
            else
              puts("copy failed!");
          }
          inode_id = create_inode();
          if ( copy_file2inode("flag", inode_id, 1) )// 1:做hash flag由这里存储进image
            printf("plant flag to inode %d!\n", inode_id);
          else
            puts("copy failed!");
          for ( j = 0; j < rand_num1; ++j )
          {
            inode_id_2 = create_inode();
            if ( copy_file2inode("flag", inode_id_2, 2) )
              printf("copied file %s to inode %d\n", cmd1, inode_id_2);
            else
              puts("copy failed!");
          }
        }
```



# Encrypt Decrypt

`plantflag`第三个参数传的是1的时候，会触发对`flag`的加密函数。不论`plantflag`第三个参数是什么，所调用的函数里面都会调用一个函数，将字符串（随机的或者是`flag`加密后的）写入到一个或多个block里面

```cpp
__int64 __fastcall encrypt_func(unsigned __int8 *buf, int len) { // 用于加密的函数
  int i; // [rsp+10h] [rbp-10h]
  int deedbeef; // [rsp+14h] [rbp-Ch]
  unsigned __int8 *ptr; // [rsp+18h] [rbp-8h]
  deedbeef = get_block0_4(); // 这里会获取block0的 unsigned int block_buf[4] 也就是image文件里面的DEEFBEEF
  for ( i = 0; i < len; ++i ) { // 逐Byte做加密
    ptr = &buf[i];
    *ptr = (*ptr >> 1) | (*ptr << 7); // 类似这种操作相当于把8bit做了一个平移，比如12345678->81234567
    *ptr ^= deedbeef;                           // EF
    *ptr = (*ptr >> 2) | (*ptr << 6);
    *ptr ^= BYTE1(deedbeef);                    // BE
    *ptr = (*ptr >> 3) | (32 * *ptr);           // ptr << 5
    *ptr ^= BYTE2(deedbeef);                    // ED
    *ptr = (*ptr >> 4) | (16 * *ptr);           // ptr << 4
    *ptr ^= HIBYTE(deedbeef);                   // DE
    *ptr = (*ptr >> 5) | (8 * *ptr);            // ptr << 3
  }
  return 0LL;
}
```

对于每一Byte，解密过程就是把上面的所有过程逆过来，比如解密时第一行应执行`(((s[i] << 5) & 0xff) | ((s[i] >> 3) & 0xff)) & 0xff`，对应于加密时的最后一行`*ptr = (*ptr >> 5) | (8 * *ptr);`

# exp

```python
f = open('./image.flag', 'rb')
image = f.read()
print("f", f, "image", len(image), len(image) / 4096)

enc_block = [list(image[0x33000 + i * 0x1000: 0x33000 + i * 0x1000 + 32]) for i in range(175)]


def decrypt(s):
    for i in range(len(s)):
        s[i] = (((s[i] << 5) & 0xff) | ((s[i] >> 3) & 0xff)) & 0xff
        s[i] ^= 0xDE
        s[i] = (((s[i] << 4) & 0xff) | ((s[i] >> 4) & 0xff)) & 0xff
        s[i] ^= 0xED
        s[i] = (((s[i] << 3) & 0xff) | ((s[i] >> 5) & 0xff)) & 0xff
        s[i] ^= 0xBE
        s[i] = (((s[i] << 2) & 0xff) | ((s[i] >> 6) & 0xff)) & 0xff
        s[i] ^= 0xEF
        s[i] = (((s[i] << 1) & 0xff) | ((s[i] >> 7) & 0xff)) & 0xff
    return s


for s in enc_block:
    dec = bytes(decrypt(s))
    if b"CTF" in dec:
        print(dec)

```

