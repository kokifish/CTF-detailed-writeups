# 2021年西湖论剑CTF—— Crypto —— FilterRandom

题目见`FilterRandom.py`

首先这是一个简单的lfsr线性移位反馈生成器。

然后题目给出了以概率0.9取l1中的元素，以0.1的概率取l2中的元素。如果要恢复出这个生成器的seed，只需要知道连续的64bit的流。但是如果以连续出现64个都是l1中的元素的概率很低，但是在2048bit中，存在一段64bit的流，其中l2的元素只出现了一次的概率是比较大的(后面给出证明的思路)。因此我们遍历每一段64bit的流，并暴力模拟l2元素出现的位置，并枚举该位置l1的值，如果模拟出的seed和后面的结果高度匹配，那么表示我们正确地找到了l1的一串连续的64bit的流。然后就可以恢复出l1.

* 证明：这里需要用到随机过程的知识，我们发现，这个问题可以转换为设计一个马尔可夫状态转移图，然后求**期望首达时间**。求的方法是设计好状态转移图之后，列出方程求解即可。

* 这里可以用概率逼近频率的方法，我们根据概率生成多组2048长度的比特串，然后找出第一次出现64bit的满足至多有一个0出现的子串的位置。然后对这个位置求平均，会发现均值大概在1150左右。这就表示题目给出的数据有很大概率是能通过这样的方法求出l1的。

```python
class lfsr():
    def __init__(self, init, mask, length):
        self.init = init
        self.mask = mask
        self.lengthmask = 2 ** length - 1
        self.length = length

    def next(self):
        nextdata = (self.init << 1) & self.lengthmask
        i = self.init & self.mask & self.lengthmask
        # output = 0
        # while i != 0:
        #     output ^= (i & 1)
        #     i = i >> 1
        output = bin(i).count('1') & 1    # 为了加快运算速度
        nextdata ^= output
        self.init = nextdata
        return output

    def last(self):
        lastdata = self.init >> 1
        i = lastdata & self.mask & self.lengthmask
        output = self.init & 1
        # while i != 0:
        #     output ^= (i & 1)
        #     i = i >> 1
        output ^= bin(i).count('1') & 1
        lastdata ^= output << (self.length - 1)
        self.init = lastdata
        return output


N = 64
mask1 = 17638491756192425134
mask2 = 14623996511862197922
stream = 

for i in range(2048 - N):
    # i = 194
    if i % 100 == 0:
        print(i, sep=',')
    for j in range(64):
        raw_data = stream[i:i+64]
        for k in range(2):
            data1 = int(raw_data[:j-1] + str(k) + raw_data[j:], 2)

            l1 = lfsr(data1, mask1, N)
            pt_front, pt_back = i-1, i+64

            count_front, count_back = 0, 0
            while pt_back < 2048:
                t = l1.next()
                if str(t) == stream[pt_back]:
                    count_back += 1
                pt_back += 1

            l1 = lfsr(data1, mask1, N)
            while pt_front >= 0:
                t = l1.last()
                if str(t) == stream[pt_front]:
                    count_front += 1
                pt_front -= 1

            num_l1 = count_front + count_back + 64
            if num_l1 > 1700: # find l1
                print(i,j,k, count_front, count_back)
                init1 = ''
                for _ in range(64):
                    t = l1.last()
                    init1 = str(t) + init1
                print(int(init1,2))
                exit(0)
```

恢复完成l1之后，我们可以确定l2的出现的位置。然后根据题目中lfsr的实现，因为只有异或运算，因此可以把运算看成是GF(2)中的加法运算，因此就可以建立线性方程组。使用z3生成方程组，然后使用sagemath求解线性方程组。

```python
# 生成方程组
import z3

class z3_lfsr():
    def __init__(self, init, mask, length):
        self.init = init
        self.mask = mask
        self.lengthmask = 2**length-1

    def next(self):
        nextdata = self.init[1:]
        i = []
        for _ in range(N):
            if self.mask[_] == '1':
                i.append(self.init[_])
            else:
                i.append(0)
        output = 0
        assert len(i) == 64
        for _ in range(N):
            output += i[_]
        # while len(i):
        #     output += i[-1]
        #     i.pop()
        self.init = nextdata + [output]
        return output

init1 = 15401137114601469828
l1 = lfsr(init1, mask1, N)

init2 = [z3.BitVec('x{}'.format(i), 1) for i in range(N)]
l2 = z3_lfsr(init2, bin(mask2)[2:], N)

s = z3.Solver()
f = open('equation.txt', 'w')
count = 0
for i in range(2048):
    t1 = l1.next()
    t2 = l2.next()
    if str(t1) != stream[i]:
        s.add(z3.simplify(t2) == int(stream[i]))
        f.write(f'---\n{z3.simplify(t2)}\n---\n{int(stream[i])}\n---\n===\n')
f.close()
```


```python
# Sagemath 9.2
# 求解线性方程组
with open('equation.txt') as f:
    s = f.read()

sitem = s.split('===')
M = []
v = []
print(len(sitem))
for eq in sitem[:-1]:
    _, lhs, rhs, _ = eq.split('---')
    cur_m = [0 for i in range(64)]
    cur_v = 0
    for x in lhs.splitlines():
        x = x.rstrip(' +')
        if (x == ''):
            pass
        elif (x == '1'):
            cur_v += 1
        elif (x[:1] == 'x'):
            pos = int(x[1:])
            cur_m[pos] += 1
        else:
            raise ValueError(x)
            
#     print(cur_m)
    rhs = eval(rhs)
    cur_v += rhs
    M.append(cur_m)
    v.append(cur_v)

M = Matrix(GF(2), M)
v = vector(GF(2), v)
x = M.solve_right(v)
print(x)
```

最后我们可以验证一下正确性：
```python
init1 = 
l1 = lfsr(init1, mask1, N)

init2 = 
init2 = [str(i) for i in init2]
init2 = int(''.join(init2), 2)
l2 = lfsr(init2, mask2, N)

for i in range(2048):
    t1 = l1.next()
    t2 = l2.next()
    if str(t1) != stream[i]:
        assert str(t2) == stream[i]
```

`l1,l2 = 15401137114601469828, 11256716742701089092`