# TOPIC
from dataTransformation import *
# flag = "flag{xxxxxxxxxxxxxxxx}"
# assert flag.startswith("flag{")
# assert flag.endswith("}")
# assert len(flag)==14

def lfsr(R,mask):
    output = (R << 1) & 0xffffffff
    i=(R&mask)&0xffffffff
    lastbit=0
    while i!=0:
        lastbit^=(i&1)
        i=i>>1
    output^=lastbit
    return (output,lastbit)

# R=int(flag[5:-1],16)
mask = 0b10100100000010000000100010010100

# f = open("key","w")
# for i in range(100):
#     tmp=0
#     for j in range(8):
#         (R,out)=lfsr(R,mask)
#         tmp=(tmp << 1)^out
#     f.write(chr(tmp))
# f.close()

key = 0x20FDEEF8A4C9F4083F331DA8238AE5ED083DF0CB0E7A83355696345DF44D7C186C1F459BCE135F1DB6C76775D5DCBAB7A783E48A203C19CA25C22F60AE62B37DE8E40578E3A7787EB429730D95C9E1944288EB3E2E747D8216A4785507A137B413CD690C

# SOLUTION 1 暴力破解
'''
因为题目中说明了flag的长度只有14，因此去掉头5个字节和尾部的1个字节就剩8个字节，然后又可以通过
R=int(flag[5:-1],16)
这行代码看出flag中存储的是16进制的数，因此flag只有32bit，因此可以直接暴力生成flag进行破解，
判断条件是前32bit如果相同则认为是正确的。缺点是这种方法的时间复杂的比较大，可能要很几十个线程
跑几个小时才能出结果，因此可以先比较其前20bit，然后把结果记录下来，
'''


# SOLUTION 2
'''
原理：因为key里面的每个bit是由它的前32个bit生成，即key种的第33个bit是由前32个bit生成的。可以推出，
key中的第第32个bit是由前31个bit和flag里面的最后1 bit生成的，由于key的前31bit已知，因此可以得到flag
的最后1 bit。以此类推，key中的第31个bit是由key的前30bit和flag中的最后2bit生成的，从而可以计算得到
flag的倒数第2 bit，以此类推。最终可以得到所有flag中的bit
'''

b = hex(key)[2:]
N = 32
tmp = ''
b = hexStr_to_str_2(b)
for i in range(N // 8):  # 把key的前32bit编程二进制的字符串的形式存在tmp中
    t = ord(b[i])
    for j in [7,6,5,4,3,2,1,0]:
        tmp += str(t >> j & 1)
idx = 0
ans = ""
tmp = tmp[31] + tmp[:32]    # tmp通过后面的32bit，来求出tmp的第1 bit
while idx < 32:             # 由于mask的第一bit一定是1，因此把最后一位当作第一位然后进行mask异或
    tmp2 = 0                # 就可以得到原来的第一bit
    for i in range(32):
        if mask >> i & 1:
            tmp2 ^= int(tmp[31 - i])
    ans = str(tmp2) + ans
    idx += 1
    tmp = tmp[31] + str(tmp2) + tmp[1:31]
num = int(ans, 2)
print(hex(num))

# num = 2455896535

# VERIFY
ans = ''
for i in range(100):
    tmp=0
    for j in range(8):
        (num,out)=lfsr(num,mask)
        tmp=(tmp << 1)^out
    ans += chr(tmp)

h = ''
for i in range(len(ans)):
    tmp = ord(ans[i])
    hi = (tmp >> 4) & 0xf
    lo = tmp & 0xf
    if hi in range(10):
        h += chr(48+hi)
    else:
        h += chr(87+hi)
    if lo in range(10):
        h += chr(48 + lo)
    else:
        h += chr(87 + lo)
print(h)
