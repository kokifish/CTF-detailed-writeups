# CISCN reverse baby.bc

> CISCN 2021 初赛 第十四届全国大学生信息安全竞赛 创新实践能力赛 线上初赛 reverse
>
> https://cup.360.cn/competition/home/index
>
> challenge name: baby.bc
>
> file: baby.bc
>
> writeup writer: hexhex16@outlook.com
>
> 

提供的 baby.bc 文件为LLVM bitcode文件，需要先编译为可执行文件，然后在IDA中分析，分析中可以得知程序需要输入一个长为25，每个元素为0-5的字符串，然后依据给定的三个数组，需要满足一定条件，求一个数独Sudoku问题，最后flag为CISCN{MD5(input)}

# Compile

> for kali 20.04: `sudo apt install llvm`

- LLVM中，IR有三种表示：

1. 可读的IR，类似于汇编代码，但其实它介于高等语言和汇编之间，这种表示就是给人看的，磁盘文件后缀为.ll
2. 不可读的二进制IR，被称作位码（bitcode），磁盘文件后缀为.bc
3. 一种内存格式，只保存在内存中，所以谈不上文件格式和文件后缀，这种格式是LLVM之所以编译快的一个原因，它不像gcc，每个阶段结束会生成一些中间过程文件，它编译的中间数据都是这第三种表示的IR

三种格式是完全等价的，我们可以在Clang/LLVM工具的参数中指定生成这些文件（默认不生成，对于非编译器开发人员来说，也没必要生成）

可以通过llvm-as和llvm-dis来在前两种文件之间做转换

先编译为可执行文件:

```bash
clang baby.bc -o baby # 将.bc文件编译成可执行文件
llvm-dis baby.bc -o - # 将 .bc 文件反汇编成汇编代码
```

- 至此，baby.bc 已经被编译为 baby 可执行文件

```bash
$ file baby
baby: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a2455b8c2fc27c2fb50c8e42e20f103f08ec1b66, for GNU/Linux 3.2.0, not stripped
```



# IDA Analysis

- IDA中分析程序逻辑，程序总体逻辑如下：

1. `scanf`用户输入，判断长度是否为25，并且判断是否有数字大于5，若有则程序返回
2. `f`函数再对用户输入进行判断，要求矩阵m不为0的地方([12], [18])，输入应为0，其余为1-5，然后将矩阵m中为0的元素替换为用户输入的对应元素
3. `c`函数对赋值完成的矩阵m进行合法性判断，要求横行数列没有重复元素(1-5)，同时根据另外两个矩阵的元素，判断两个方向上某些位置的相邻元素是否满足规定的大小关系。
4. 如果`f`和`c`函数判断为合法，执行`printf("CISCN{MD5(%s)}", x);`

小结：除两个位置的数值需要为0，为原来的m数组的值以外，其余m数组的值由input指定，值在1到5之间。分析c函数，可以发现这是一个5x5的数独问题，要求横行竖列没有重复数字，并且已经给定两个位置的值，此外还有两个方向上某些位置的大小关系约束。



- main函数如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 v4; // [rsp+8h] [rbp-20h]
  unsigned __int64 i; // [rsp+10h] [rbp-18h]
  size_t v6; // [rsp+18h] [rbp-10h]

  __isoc99_scanf(&unk_403004, x, envp);
  if ( (unsigned int)strlen(x) == 25 )
  {
    if ( x[0] )
    {
      if ( (unsigned __int8)(x[0] - '0') > 5u )
        return 0;
      v6 = strlen(x);
      for ( i = 1LL; ; ++i )
      {
        v4 = i;
        if ( i >= v6 )
          break;
        if ( (unsigned __int8)(x[v4] - '0') > 5u )
          return 0;
      }
    }
    if ( (f(x) & 1) != 0 && (c() & 1) != 0 )
      printf("CISCN{MD5(%s)}", x);
  }
  return 0;
}
```



## c function

- 整个程序分析最复杂的为判断是否满足数独条件的函数c，IDA中显示如下：

```c
__int64 c()
{
  char v1; // [rsp+2Eh] [rbp-9Ah]
  __int64 l_plus1; // [rsp+30h] [rbp-98h]
  __int64 l; // [rsp+40h] [rbp-88h]
  __int64 kk; // [rsp+50h] [rbp-78h]
  __int64 k; // [rsp+58h] [rbp-70h]
  char *v6; // [rsp+68h] [rbp-60h]
  __int64 jj; // [rsp+70h] [rbp-58h]
  char v8; // [rsp+7Fh] [rbp-49h]
  char *v9; // [rsp+88h] [rbp-40h]
  __int64 ii; // [rsp+90h] [rbp-38h]
  __int64 j; // [rsp+98h] [rbp-30h]
  __int64 i; // [rsp+A8h] [rbp-20h]
  char str_b[6]; // [rsp+BCh] [rbp-Ch] BYREF
  char str_a[6]; // [rsp+C2h] [rbp-6h] BYREF

  i = 0LL;
  do
  {
    ii = i;
    memset(str_a, 0, sizeof(str_a));
    v9 = &str_a[(unsigned __int8)m[5 * i]];
    if ( *v9                                    // 一开始这里必为0
      || (*v9 = 1, str_a[(unsigned __int8)m[5 * i + 1]])
      || (str_a[(unsigned __int8)m[5 * i + 1]] = 1, str_a[(unsigned __int8)m[5 * i + 2]])
      || (str_a[(unsigned __int8)m[5 * i + 2]] = 1, str_a[(unsigned __int8)m[5 * i + 3]])
      || (str_a[(unsigned __int8)m[5 * i + 3]] = 1, str_a[(unsigned __int8)m[5 * i + 4]]) )
    {
      v8 = 0;                                   // 故m[5*i], m[5*i+1], m[5*i+2], m[5*i+3], m[5*i+4]需要为不同的[1,5]数字
      return v8 & 1;                            // return 0 不能进入到这里 所以条件判断要为false
    }
    ++i;
  }                                             // m的横轴方向上没有相同数字
  while ( ii + 1 < 5 );                         // i: 0 1 2 3 4
  j = 0LL;
  while ( 1 )
  {
    jj = j;
    memset(str_b, 0, sizeof(str_b));
    v6 = &str_b[(unsigned __int8)m[j]];
    if ( *v6 )
      break;
    *v6 = 1;
    if ( str_b[(unsigned __int8)m_5[j]] )
      break;
    str_b[(unsigned __int8)m_5[j]] = 1;
    if ( str_b[(unsigned __int8)m_10[j]] )
      break;
    str_b[(unsigned __int8)m_10[j]] = 1;
    if ( str_b[(unsigned __int8)m_15[j]] )
      break;
    str_b[(unsigned __int8)m_15[j]] = 1;
    if ( str_b[(unsigned __int8)m_20[j]] )
      break;
    ++j;
    if ( jj + 1 >= 5 )                          // m的纵轴方向上没有相同数字
    {
      k = 0LL;
      while ( 1 )
      {
        kk = k;
        if ( n[4 * k] == 1 )                    // k = 1, 4命中
        {
          if ( (unsigned __int8)m[5 * k] < (unsigned __int8)m[5 * k + 1] )
            goto LABEL_27;
        }
        else if ( n[4 * k] == 2 && (unsigned __int8)m[5 * k] > (unsigned __int8)m[5 * k + 1] )// k=3 hit
        {
LABEL_27:
          v8 = 0;
          return v8 & 1;
        }
        if ( n_plus1[4 * k] == 1 )
        {
          if ( (unsigned __int8)m[5 * k + 1] < (unsigned __int8)m[5 * k + 2] )
            goto LABEL_27;
        }
        else if ( n_plus1[4 * k] == 2 && (unsigned __int8)m[5 * k + 1] > (unsigned __int8)m[5 * k + 2] )
        {
          goto LABEL_27;
        }
        if ( n_plus2[4 * k] == 1 )              // k=4 hit
        {
          if ( (unsigned __int8)m[5 * k + 2] < (unsigned __int8)m[5 * k + 3] )
            goto LABEL_27;
        }
        else if ( n_plus2[4 * k] == 2 && (unsigned __int8)m[5 * k + 2] > (unsigned __int8)m[5 * k + 3] )
        {
          goto LABEL_27;
        }
        if ( n_plus3[4 * k] == 1 )              // k=0,2 hit
        {
          if ( (unsigned __int8)m[5 * k + 3] < (unsigned __int8)m[5 * k + 4] )
            goto LABEL_27;
        }
        else if ( n_plus3[4 * k] == 2 && (unsigned __int8)m[5 * k + 3] > (unsigned __int8)m[5 * k + 4] )
        {
          goto LABEL_27;
        }
        ++k;
        if ( kk + 1 >= 5 )                      // k = 0,1,2,3,4
        {
          l = 0LL;
          while ( 1 )
          {
            l_plus1 = l + 1;
            if ( o[5 * l] == 1 )
            {
              v1 = 0;
              if ( (unsigned __int8)m[5 * l] > (unsigned __int8)m[5 * l_plus1] )
                goto LABEL_26;
            }
            else if ( o[5 * l] == 2 )
            {
              v1 = 0;
              if ( (unsigned __int8)m[5 * l] < (unsigned __int8)m[5 * l_plus1] )
              {
LABEL_26:
                v8 = v1;
                return v8 & 1;
              }
            }
            if ( o_plus1[5 * l] == 1 )          // l=3 hit
            {
              v1 = 0;
              if ( (unsigned __int8)m[5 * l + 1] > (unsigned __int8)m[5 * l_plus1 + 1] )
                goto LABEL_26;
            }
            else if ( o_plus1[5 * l] == 2 )
            {
              v1 = 0;
              if ( (unsigned __int8)m[5 * l + 1] < (unsigned __int8)m[5 * l_plus1 + 1] )
                goto LABEL_26;
            }
            if ( o_plus2[5 * l] == 1 )
            {
              v1 = 0;
              if ( (unsigned __int8)m[5 * l + 2] > (unsigned __int8)m[5 * l_plus1 + 2] )
                goto LABEL_26;
            }
            else if ( o_plus2[5 * l] == 2 )     // l=0 hit
            {
              v1 = 0;
              if ( (unsigned __int8)m[5 * l + 2] < (unsigned __int8)m[5 * l_plus1 + 2] )
                goto LABEL_26;
            }
            if ( o_plus3[5 * l] == 1 )          // l=2 hit
            {
              v1 = 0;
              if ( (unsigned __int8)m[5 * l + 3] > (unsigned __int8)m[5 * l_plus1 + 3] )
                goto LABEL_26;
            }
            else if ( o_plus3[5 * l] == 2 )
            {
              v1 = 0;
              if ( (unsigned __int8)m[5 * l + 3] < (unsigned __int8)m[5 * l_plus1 + 3] )
                goto LABEL_26;
            }
            if ( o_plus4[5 * l] == 1 )          // l=3 hit
            {
              v1 = 0;
              if ( (unsigned __int8)m[5 * l + 4] > (unsigned __int8)m[5 * l_plus1 + 4] )
                goto LABEL_26;
            }
            else if ( o_plus4[5 * l] == 2 )     // l=0 hit
            {
              v1 = 0;
              if ( (unsigned __int8)m[5 * l + 4] < (unsigned __int8)m[5 * l_plus1 + 4] )
                goto LABEL_26;
            }
            ++l;
            v1 = 1;
            if ( l_plus1 >= 4 )
              goto LABEL_26;                    // !!!!!!程序运行到这 才能返回1
          }
        }
      }
    }
  }
  v8 = 0;
  return v8 & 1;
}
```



## Puzzle

```c
0   0   0   0 > 0
        $       $
0 > 0   0   0   0
    
0 < 0   4   0 > 0
            ^
0   0   0   3   0
    ^           ^
0 > 0   0 > 0   0
```

> 其中`$`表示的是上大下小

最后人工解出来的puzzle解为：

```python
1 4 2 5 3
5 3 1 4 2
3 5 4 2 1
2 1 5 3 4
4 2 3 1 5
```
- 与解puzzle相关的三个矩阵：

```python
# m前25个，不是0的，会保留，其余的被修改为input对应下标的值
m = [0, 0, 0, 0, 0,  # No.0 row
     0, 0, 0, 0, 0,
     0, 0, 4, 0, 0,
     0, 0, 0, 3, 0,
     0, 0, 0, 0, 0]
print(len(m))
for i in range(25):
    print(m[i], end=" ")
    if((i + 1) % 5 == 0):
        print()

s = "1111111111110111110111111"  # s[12], s[18] 要为0
print(len(s), s[12], s[18])
# 这个是规定横行方向上大小关系的矩阵，1表示左大右小 > ，2表示左小右大 < 
n = [0, 0, 0, 1,
     1, 0, 0, 0,
     2, 0, 0, 1,
     0, 0, 0, 0,
     1, 0, 1, 0]  # No.4(from 0) row
print("n:", len(n))
# 2表示上大下小， 1表示上小下大 ^
o = [0, 0, 2, 0, 2,
     0, 0, 0, 0, 0,
     0, 0, 0, 1, 0,
     0, 1, 0, 0, 1]
print("o:", len(o))
```



# Solve

- 计算输入(其中两个要改为0)的MD5值，即为flag

```python
import hashlib
m = hashlib.md5()
m.update(b'1425353142350212150442315')  # 1425353142354212153442315
# s[12], s[18] 要为0
print(m.hexdigest()) # 8a04b4597ad08b83211d3adfa1f61431
# CISCN{8a04b4597ad08b83211d3adfa1f61431}
```

- flag: `CISCN{8a04b4597ad08b83211d3adfa1f61431}`

## Using z3

> 安装
> 
> ```bash
> pip install z3
> pip install z3-solver
> ```

- z3是微软公司开发的一个优秀的SMT求解器，它能够检查逻辑表达式的可满足性

Solver()：创建一个通用求解器，创建后我们可以添加我们的约束条件，进行下一步的求解

add()：用来添加约束条件，通常在solver()命令之后，添加的约束条件通常是一个逻辑等式

check()：该函数通常用来判断在添加完约束条件后，来检测解的情况，有解的时候会回显sat，无解的时候会返回unsat

model()：在存在解的时候，该函数会将每个限制条件所对应的解集的交集，进而得出正解

```python
from z3 import *
import hashlib
rows = [
    [0, 0, 0, 1],
    [1, 0, 0, 0],
    [2, 0, 0, 1],
    [0, 0, 0, 0],
    [1, 0, 1, 0]]
cols = [[0, 0, 2, 0, 2],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 1, 0],
        [0, 1, 0, 0, 1]]

s = Solver()
map = [[Int('x_%d_%d' % (i, j)) for i in range(5)] for j in range(5)]
print("map: ", map)
# 数独约束条件：数字为1~5的整数
Sudoku = [And(map[i][j] >= 1, map[i][j] <= 5) for i in range(5) for j in range(5)]
Sudoku += [map[2][2] == 4]  # 添加约束
Sudoku += [map[3][3] == 3]  # 添加约束
for i in range(5):  # 横行元素不相等约束
    for j in range(5):
        for k in range(j):
            Sudoku += [map[i][j] != map[i][k]]
for j in range(5):  # 竖列元素不相等约束
    for i in range(5):
        for k in range(i):
            Sudoku += [map[i][j] != map[k][j]]
for i in range(5):  # 横行部分大小关系约束
    for j in range(4):
        if (rows[i][j] == 1):
            Sudoku += [map[i][j] > map[i][j + 1]]
        elif (rows[i][j] == 2):
            Sudoku += [map[i][j] < map[i][j + 1]]
for i in range(4):  # 竖列部分大小关系约束
    for j in range(5):
        if (cols[i][j] == 2):
            Sudoku += [map[i][j] > map[i + 1][j]]
        elif (cols[i][j] == 1):
            Sudoku += [map[i][j] < map[i + 1][j]]
s.add(Sudoku)  # 添加约束到 Solver()
answer = s.check()
print(answer, type(answer))  # sat <class 'z3.z3.CheckSatResult'>
if(s.check()):
    m = s.model()
    res = [[m[map[i][j]] for j in range(5)] for i in range(5)]
    print(res)
    flag = []
    for i in map:
        for j in i:
            flag.append(m[j].as_long() + 0x30)
    flag[12] = 0x30  # '0'
    flag[18] = 0x30  # '0'
    print(flag)
    flag = bytes(flag)
    print(flag)  # b'1425353142350212150442315'
    print(hashlib.md5(flag).hexdigest())
```

