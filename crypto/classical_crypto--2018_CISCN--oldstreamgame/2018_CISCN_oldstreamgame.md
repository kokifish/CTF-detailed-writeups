## 2018 CISCN 初赛 oldstreamgame

题目
```py
flag = "flag{xxxxxxxxxxxxxxxx}"
assert flag.startswith("flag{")
assert flag.endswith("}")
assert len(flag)==14

def lfsr(R,mask):
    output = (R << 1) & 0xffffffff
    i=(R&mask)&0xffffffff
    lastbit=0
    while i!=0:
        lastbit^=(i&1)
        i=i>>1
    output^=lastbit
    return (output,lastbit)

R=int(flag[5:-1],16)
mask = 0b10100100000010000000100010010100

f=open("key","w")
for i in range(100):
    tmp=0
    for j in range(8):
        (R,out)=lfsr(R,mask)
        tmp=(tmp << 1)^out
    f.write(chr(tmp))
f.close()

key = 0x20FDEEF8A4C9F4083F331DA8238AE5ED083DF0CB0E7A83355696345DF44D7C186C1F459BCE135F1DB6C76775D5DCBAB7A783E48A203C19CA25C22F60AE62B37DE8E40578E3A7787EB429730D95C9E1944288EB3E2E747D8216A4785507A137B413CD690C
```

**解：**
理论上题目中的随机数生成器生成的随机数没有给出，需要上网找到相应题目的所对应的随机数bit串，就是题目文档中给出的key。

首先题目中说明了flag的长度只有14，因此去掉头5个字节和尾部的1个字节就剩8个字节，然后又可以通过
```py
R=int(flag[5:-1],16)
```
这行代码看出flag中存储的是16进制的数，因此flag只有32bit。

因此有两个方法做这道题，首先是可以直接暴力生成flag进行破解，暴力模拟flag，然后通过该flag然后使用题目给出的生成算法生成100bit，与key中的相对比，如果相等，则相当于该flag就是所求。直接暴力破解的缺点是这种方法的时间复杂的比较大，可能要很几十个线程跑几个小时才能出结果。

第二种方法是对随机数生成的过程进行分析，首先分析lfsr函数发现其本质就是根据一个mask，取该R中mask的位置为1的比特进行异或，从而得到一个新的比特z，然后把生成的比特z放在R的最后并返回新得到的比特串R'和一个随机比特z。因为mask的第一位是1，这样如果知道mask和R'，就可以反向恢复出R的第一位。这是因为R的后n-1位和R'的前n-1位是相同的，而且mask又是不变的，因此两边可以互推。

因为key里面的每个bit是由它的前32个bit生成，即key种的第33个bit是由前32个bit生成的。可以推出，key中的第第32个bit是由前31个bit和flag里面的最后1 bit生成的，由于key的前31bit已知，因此可以得到flag的最后1 bit。以此类推，key中的第31个bit是由key的前30bit和flag中的最后2bit生成的，从而可以计算得到flag的倒数第2 bit，以此类推。最终可以得到所有flag中的bit

##### 实际求解
```py
def hexStr_to_str_2(hex_str):
	if len(hex_str) & 1:
		print("Warnning: the length of hex string is odd")
	s = ''
	hex_str = hex_str.lower()
	for i in range(len(hex_str)//2):
		hi = ord(hex_str[2 * i]) - 48
		lo = ord(hex_str[2 * i + 1]) - 48
		if hi not in range(10):
			hi = ord(hex_str[2 * i]) - 87
		if lo not in range(10):
			lo = ord(hex_str[2 * i + 1]) - 87
		s += chr((hi << 4) + lo)
	return s

mask = 0b10100100000010000000100010010100

key = 0x20FDEEF8A4C9F4083F331DA8238AE5ED083DF0CB0E7A83355696345DF44D7C186C1F459BCE135F1DB6C76775D5DCBAB7A783E48A203C19CA25C22F60AE62B37DE8E40578E3A7787EB429730D95C9E1944288EB3E2E747D8216A4785507A137B413CD690C
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

```
运行结果：
```
0x926201d7
```

验证代码：
```py
# VERIFY
num = 0x926201d7
ans = ''    # 生成随机bit串，类型为str
for i in range(100):
    tmp=0
    for j in range(8):
        (num,out)=lfsr(num,mask)
        tmp=(tmp << 1)^out
    ans += chr(tmp)

h = ''      # 把str转换为hex的形式，然后输出
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
```
运行结果：
```
20fdeef8a4c9f4083f331da8238ae5ed083df0cb0e7a83355696345df44d7c186c1f459bce135f1db6c76775d5dcbab7a783e48a203c19ca25c22f60ae62b37de8e40578e3a7787eb429730d95c9e1944288eb3e2e747d8216a4785507a137b413cd690c
```

发现运行结果与题目中给出的key相同，因此可见flag是正确的。

* 思考：这道题还是相对简单，即使没有学过密码学的人，看到类似的构造方法，也比较容易想到对函数进行分析，然后逆向生成flag的方法。