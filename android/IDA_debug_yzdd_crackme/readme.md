# apk:yzdd_crackme


> 请给出flag，并写出writeup。解压密码 apksafe.答案有多解，给出一个可见字符串即可。
>
> 腾讯一面



In analysis: 真机调试可以绕ptrace了，可以看到最后用于对比的静态字符串。然后依据用户输入改变的字符串在进入libprotect.so `Java_com_yzdd_crackme_LoginActivity_check`处理的时候，传的并不是原本的字符串，故需要分析调用`Java_com_yzdd_crackme_LoginActivity_check`之前的代码，TBD



# Anti ptrace Anti-Debug

`.text:00001D88`的函数先fork()，父进程记录子进程pid，子进程轮询当前进程的TracerPid，并且写入到一个.bss的变量`bss_tracer_pid`上。

在`.text:00001D88`函数前创建了一个管道`pipe(&before_bss_tracer_pid);`，使得`bss_tracer_pid`的值能够传递到前面4B

然后`pthread_create`创建了一个线程，该线程如果检测到`before_bss_tracer_pid`不为0，则会kill当前进程，以及`.text:00001D88`的函数fork出来的子进程



反ptrace反调试的其中一个途径：nop掉`.text:00001D88`函数的调用，这样`bss_tracer_pid`就不会被赋值了，自然也不会触发kill了。

1. IDA attach上crackme进程后，在protect.so的`Java_com_yzdd_crackme_LoginActivity_check`函数Add breakpoint
2. F9 continue，直至在`Java_com_yzdd_crackme_LoginActivity_check`起始地址断下，然后找到call/BLX`0x00001D88`的地方，将其nop掉，两种方法：
   1. Patch program->change bytes: 把对应的 `BLX sub_xxx88`的4B改成`00 BF 00 BF`
   2. Keypatch (ctrl+alt+K): assembly里填nop; nop，因为要对应原本4B长的机器码（貌似以前x86会自动对齐？注意按一次ok后点cancel，不然一直patch下去）
3. F9 continue，可以正常执行到后面的语句，Anti ptrace Anti-Debug SUCCEED



# `Java_com_yzdd_crackme_LoginActivity_check`

原型可能为：

`JNIEXPORT jstring JNICALL Java_com_yzdd_crackme_LoginActivity_check(JNIEnv *env, jclass cls, jstring j_str)`

```cpp
c_str = (*env)->GetStringUTFChars(env, j_str, 0); // 从Java字符串转换成C/C++字符串, 0表示返回原字符串的指针
// 做了ptrace反调试 检测 TracerPid 写入一个bss地址上 # 另有一个线程 如果TracerPid不为零 kill 当前线程及parent线程
rhs = a_hash_function(c_str)
// 接下来做一堆操作 目的是构造一个字符串lhs 动态调试发现lhs每次都不变 看伪代码可以发现是利用.rodata上的数据来构造的
strcmp(lhs, rhs) 
```



- 刚刚进入`Java_com_yzdd_crackme_LoginActivity_check`时R0即第一个参数的值为: 0xEF320654

- strcmp R0: 也就是用于对比的const字符串lhs: `16D71D14B3F9B6519A28AB54`   len=24

```assembly
[anon:stack_and_tls:24238]:C06B0604 31          DCB 0x31 ; 1
[anon:stack_and_tls:24238]:C06B0605 36          DCB 0x36 ; 6
[anon:stack_and_tls:24238]:C06B0606 44          DCB 0x44 ; D
[anon:stack_and_tls:24238]:C06B0607 37          DCB 0x37 ; 7
[anon:stack_and_tls:24238]:C06B0608 31          DCB 0x31 ; 1
[anon:stack_and_tls:24238]:C06B0609 44          DCB 0x44 ; D
[anon:stack_and_tls:24238]:C06B060A 31          DCB 0x31 ; 1
[anon:stack_and_tls:24238]:C06B060B 34          DCB 0x34 ; 4
[anon:stack_and_tls:24238]:C06B060C 42          DCB 0x42 ; B
[anon:stack_and_tls:24238]:C06B060D 33          DCB 0x33 ; 3
[anon:stack_and_tls:24238]:C06B060E 46          DCB 0x46 ; F
[anon:stack_and_tls:24238]:C06B060F 39          DCB 0x39 ; 9
[anon:stack_and_tls:24238]:C06B0610 42          DCB 0x42 ; B
[anon:stack_and_tls:24238]:C06B0611 36          DCB 0x36 ; 6
[anon:stack_and_tls:24238]:C06B0612 35          DCB 0x35 ; 5
[anon:stack_and_tls:24238]:C06B0613 31          DCB 0x31 ; 1
[anon:stack_and_tls:24238]:C06B0614 39          DCB 0x39 ; 9
[anon:stack_and_tls:24238]:C06B0615 41          DCB 0x41 ; A
[anon:stack_and_tls:24238]:C06B0616 32          DCB 0x32 ; 2
[anon:stack_and_tls:24238]:C06B0617 38          DCB 0x38 ; 8
[anon:stack_and_tls:24238]:C06B0618 41          DCB 0x41 ; A
[anon:stack_and_tls:24238]:C06B0619 42          DCB 0x42 ; B
[anon:stack_and_tls:24238]:C06B061A 35          DCB 0x35 ; 5
[anon:stack_and_tls:24238]:C06B061B 34          DCB 0x34 ; 4  //后面跟着一堆0  strcmp时会截断 这段不会变的
```



```assembly
R2 即第三个参数  （01234567890abcdef）
[anon:stack_and_tls:26729]:C06716C0 48          DCB 0x48 ; H
[anon:stack_and_tls:26729]:C06716C1 35          DCB 0x35 ; 5
[anon:stack_and_tls:26729]:C06716C2 E0          DCB 0xE0
[anon:stack_and_tls:26729]:C06716C3 12          DCB 0x12
R2 即第三个参数  （0000000000000000）
[anon:stack_and_tls:27020]:C06F16C0 F8          DCB 0xF8
[anon:stack_and_tls:27020]:C06F16C1 35          DCB 0x35 ; 5
[anon:stack_and_tls:27020]:C06F16C2 E0          DCB 0xE0
[anon:stack_and_tls:27020]:C06F16C3 12          DCB 0x12
```

# WhatIsThis

1234567890abcdef

```assembly
[anon:scudo:primary]:F4731C00 46          DCB 0x46 ; F
[anon:scudo:primary]:F4731C01 37          DCB 0x37 ; 7
[anon:scudo:primary]:F4731C02 44          DCB 0x44 ; D
[anon:scudo:primary]:F4731C03 36          DCB 0x36 ; 6
[anon:scudo:primary]:F4731C04 45          DCB 0x45 ; E
[anon:scudo:primary]:F4731C05 35          DCB 0x35 ; 5
[anon:scudo:primary]:F4731C06 41          DCB 0x41 ; A
[anon:scudo:primary]:F4731C07 33          DCB 0x33 ; 3
[anon:scudo:primary]:F4731C08 34          DCB 0x34 ; 4
[anon:scudo:primary]:F4731C09 34          DCB 0x34 ; 4
[anon:scudo:primary]:F4731C0A 35          DCB 0x35 ; 5
[anon:scudo:primary]:F4731C0B 44          DCB 0x44 ; D
[anon:scudo:primary]:F4731C0C 38          DCB 0x38 ; 8
[anon:scudo:primary]:F4731C0D 46          DCB 0x46 ; F
[anon:scudo:primary]:F4731C0E 37          DCB 0x37 ; 7
[anon:scudo:primary]:F4731C0F 33          DCB 0x33 ; 3
[anon:scudo:primary]:F4731C10 45          DCB 0x45 ; E
[anon:scudo:primary]:F4731C11 44          DCB 0x44 ; D
[anon:scudo:primary]:F4731C12 41          DCB 0x41 ; A
[anon:scudo:primary]:F4731C13 45          DCB 0x45 ; E
[anon:scudo:primary]:F4731C14 30          DCB 0x30 ; 0
[anon:scudo:primary]:F4731C15 46          DCB 0x46 ; F
[anon:scudo:primary]:F4731C16 45          DCB 0x45 ; E
[anon:scudo:primary]:F4731C17 34          DCB 0x34 ; 4
[anon:scudo:primary]:F4731C18 46          DCB 0x46 ; F
[anon:scudo:primary]:F4731C19 34          DCB 0x34 ; 4
[anon:scudo:primary]:F4731C1A 34          DCB 0x34 ; 4
[anon:scudo:primary]:F4731C1B 41          DCB 0x41 ; A
[anon:scudo:primary]:F4731C1C 46          DCB 0x46 ; F
[anon:scudo:primary]:F4731C1D 36          DCB 0x36 ; 6
[anon:scudo:primary]:F4731C1E 44          DCB 0x44 ; D
[anon:scudo:primary]:F4731C1F 38          DCB 0x38 ; 8
[anon:scudo:primary]:F4731C20 38          DCB 0x38 ; 8
[anon:scudo:primary]:F4731C21 42          DCB 0x42 ; B
[anon:scudo:primary]:F4731C22 44          DCB 0x44 ; D
[anon:scudo:primary]:F4731C23 34          DCB 0x34 ; 4
[anon:scudo:primary]:F4731C24 36          DCB 0x36 ; 6
[anon:scudo:primary]:F4731C25 31          DCB 0x31 ; 1
[anon:scudo:primary]:F4731C26 32          DCB 0x32 ; 2
[anon:scudo:primary]:F4731C27 42          DCB 0x42 ; B
[anon:scudo:primary]:F4731C28 31          DCB 0x31 ; 1
[anon:scudo:primary]:F4731C29 45          DCB 0x45 ; E
[anon:scudo:primary]:F4731C2A 42          DCB 0x42 ; B
[anon:scudo:primary]:F4731C2B 45          DCB 0x45 ; E
[anon:scudo:primary]:F4731C2C 46          DCB 0x46 ; F
[anon:scudo:primary]:F4731C2D 35          DCB 0x35 ; 5
[anon:scudo:primary]:F4731C2E 30          DCB 0x30 ; 0
[anon:scudo:primary]:F4731C2F 41          DCB 0x41 ; A
```

- 0000000000000000  16个0
- F7D6E5A3445D8F73EDAE0FE4F44AF6D88BD4612B1EBEF50A
- 480E1C995149230BC5DF87EEB25E2F8A4B01B9F307391E35
- 480E1C995149230B3A673FA830E3B789           15个0时的前32B
```assembly
[anon:scudo:primary]:F4732470 34          DCB 0x34 ; 4
[anon:scudo:primary]:F4732471 38          DCB 0x38 ; 8
[anon:scudo:primary]:F4732472 30          DCB 0x30 ; 0
[anon:scudo:primary]:F4732473 45          DCB 0x45 ; E
[anon:scudo:primary]:F4732474 31          DCB 0x31 ; 1
[anon:scudo:primary]:F4732475 43          DCB 0x43 ; C
[anon:scudo:primary]:F4732476 39          DCB 0x39 ; 9
[anon:scudo:primary]:F4732477 39          DCB 0x39 ; 9
[anon:scudo:primary]:F4732478 35          DCB 0x35 ; 5
[anon:scudo:primary]:F4732479 31          DCB 0x31 ; 1
[anon:scudo:primary]:F473247A 34          DCB 0x34 ; 4
[anon:scudo:primary]:F473247B 39          DCB 0x39 ; 9
[anon:scudo:primary]:F473247C 32          DCB 0x32 ; 2
[anon:scudo:primary]:F473247D 33          DCB 0x33 ; 3
[anon:scudo:primary]:F473247E 30          DCB 0x30 ; 0
[anon:scudo:primary]:F473247F 42          DCB 0x42 ; B
[anon:scudo:primary]:F4732480 43          DCB 0x43 ; C
[anon:scudo:primary]:F4732481 35          DCB 0x35 ; 5
[anon:scudo:primary]:F4732482 44          DCB 0x44 ; D
[anon:scudo:primary]:F4732483 46          DCB 0x46 ; F
[anon:scudo:primary]:F4732484 38          DCB 0x38 ; 8
[anon:scudo:primary]:F4732485 37          DCB 0x37 ; 7
[anon:scudo:primary]:F4732486 45          DCB 0x45 ; E
[anon:scudo:primary]:F4732487 45          DCB 0x45 ; E
[anon:scudo:primary]:F4732488 42          DCB 0x42 ; B
[anon:scudo:primary]:F4732489 32          DCB 0x32 ; 2
[anon:scudo:primary]:F473248A 35          DCB 0x35 ; 5
[anon:scudo:primary]:F473248B 45          DCB 0x45 ; E
[anon:scudo:primary]:F473248C 32          DCB 0x32 ; 2
[anon:scudo:primary]:F473248D 46          DCB 0x46 ; F
[anon:scudo:primary]:F473248E 38          DCB 0x38 ; 8
[anon:scudo:primary]:F473248F 41          DCB 0x41 ; A
[anon:scudo:primary]:F4732490 34          DCB 0x34 ; 4
[anon:scudo:primary]:F4732491 42          DCB 0x42 ; B
[anon:scudo:primary]:F4732492 30          DCB 0x30 ; 0
[anon:scudo:primary]:F4732493 31          DCB 0x31 ; 1
[anon:scudo:primary]:F4732494 42          DCB 0x42 ; B
[anon:scudo:primary]:F4732495 39          DCB 0x39 ; 9
[anon:scudo:primary]:F4732496 46          DCB 0x46 ; F
[anon:scudo:primary]:F4732497 33          DCB 0x33 ; 3
[anon:scudo:primary]:F4732498 30          DCB 0x30 ; 0
[anon:scudo:primary]:F4732499 37          DCB 0x37 ; 7
[anon:scudo:primary]:F473249A 33          DCB 0x33 ; 3
[anon:scudo:primary]:F473249B 39          DCB 0x39 ; 9
[anon:scudo:primary]:F473249C 31          DCB 0x31 ; 1
[anon:scudo:primary]:F473249D 45          DCB 0x45 ; E
[anon:scudo:primary]:F473249E 33          DCB 0x33 ; 3
[anon:scudo:primary]:F473249F 35          DCB 0x35 ; 5
```

- 000000000000000 15个0
- 480E1C995149230B3A673FA830E3B789

```assembly
[anon:scudo:primary]:F46DDDD0 34          DCB 0x34 ; 4
[anon:scudo:primary]:F46DDDD1 38          DCB 0x38 ; 8
[anon:scudo:primary]:F46DDDD2 30          DCB 0x30 ; 0
[anon:scudo:primary]:F46DDDD3 45          DCB 0x45 ; E
[anon:scudo:primary]:F46DDDD4 31          DCB 0x31 ; 1
[anon:scudo:primary]:F46DDDD5 43          DCB 0x43 ; C
[anon:scudo:primary]:F46DDDD6 39          DCB 0x39 ; 9
[anon:scudo:primary]:F46DDDD7 39          DCB 0x39 ; 9
[anon:scudo:primary]:F46DDDD8 35          DCB 0x35 ; 5
[anon:scudo:primary]:F46DDDD9 31          DCB 0x31 ; 1
[anon:scudo:primary]:F46DDDDA 34          DCB 0x34 ; 4
[anon:scudo:primary]:F46DDDDB 39          DCB 0x39 ; 9
[anon:scudo:primary]:F46DDDDC 32          DCB 0x32 ; 2
[anon:scudo:primary]:F46DDDDD 33          DCB 0x33 ; 3
[anon:scudo:primary]:F46DDDDE 30          DCB 0x30 ; 0
[anon:scudo:primary]:F46DDDDF 42          DCB 0x42 ; B
[anon:scudo:primary]:F46DDDE0 33          DCB 0x33 ; 3
[anon:scudo:primary]:F46DDDE1 41          DCB 0x41 ; A
[anon:scudo:primary]:F46DDDE2 36          DCB 0x36 ; 6
[anon:scudo:primary]:F46DDDE3 37          DCB 0x37 ; 7
[anon:scudo:primary]:F46DDDE4 33          DCB 0x33 ; 3
[anon:scudo:primary]:F46DDDE5 46          DCB 0x46 ; F
[anon:scudo:primary]:F46DDDE6 41          DCB 0x41 ; A
[anon:scudo:primary]:F46DDDE7 38          DCB 0x38 ; 8
[anon:scudo:primary]:F46DDDE8 33          DCB 0x33 ; 3
[anon:scudo:primary]:F46DDDE9 30          DCB 0x30 ; 0
[anon:scudo:primary]:F46DDDEA 45          DCB 0x45 ; E
[anon:scudo:primary]:F46DDDEB 33          DCB 0x33 ; 3
[anon:scudo:primary]:F46DDDEC 42          DCB 0x42 ; B
[anon:scudo:primary]:F46DDDED 37          DCB 0x37 ; 7
[anon:scudo:primary]:F46DDDEE 38          DCB 0x38 ; 8
[anon:scudo:primary]:F46DDDEF 39          DCB 0x39 ; 9
[anon:scudo:primary]:F46DDDF0 00          DCB    0
[anon:scudo:primary]:F46DDDF1 74          DCB 0x74 ; t
[anon:scudo:primary]:F46DDDF2 79          DCB 0x79 ; y
[anon:scudo:primary]:F46DDDF3 5F          DCB 0x5F ; _
[anon:scudo:primary]:F46DDDF4 63          DCB 0x63 ; c
[anon:scudo:primary]:F46DDDF5 68          DCB 0x68 ; h
[anon:scudo:primary]:F46DDDF6 65          DCB 0x65 ; e
[anon:scudo:primary]:F46DDDF7 63          DCB 0x63 ; c
[anon:scudo:primary]:F46DDDF8 6B          DCB 0x6B ; k
[anon:scudo:primary]:F46DDDF9 00          DCB    0
[anon:scudo:primary]:F46DDDFA 00          DCB    0
[anon:scudo:primary]:F46DDDFB 00          DCB    0
[anon:scudo:primary]:F46DDDFC 00          DCB    0
[anon:scudo:primary]:F46DDDFD 00          DCB    0
[anon:scudo:primary]:F46DDDFE 00          DCB    0
[anon:scudo:primary]:F46DDDFF 00          DCB    0
[anon:scudo:primary]:F46DDE00 03          DCB    3
```

