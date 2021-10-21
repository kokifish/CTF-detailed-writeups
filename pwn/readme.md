# pwn

- 部分较为简单、适合入门/速查/回忆的被归档在对应的 `[Simple_Cases]_xxx` 文件夹中
- pwn速查表，知识导览 见repo根目录 `[CTF]_Pwn.md`



writeup开头通常包含以下信息(可选)：

1. 赛事名称、年份、链接
2. challenge name: 题目名称
3. description: 题目描述
4. file: 题目给予的文件
5. writeup文件夹下提供的额外文件，一般为IDA的`.i64`文件
6. writeup writer: 
7. refer writeup: links or writer name/homepage

然后简要描述题目逻辑，pwn的思路，需要注意的地方，重要的知识点等。

下一个一级标题开始，描述详细的分析步骤

Exploit 放出带有注释的exp

可能含有用gdb的Post Analysis，一般用于分析栈、寄存器变化



# wp header demo

> 2021 第二届祥云杯网络安全大赛 pwn
>
> challenge name: xxx
>
> file: chall, libc-2.27.so
>
> ld227-3ubuntu1.so and .i64 with comments provided
>
> Description: just solve it
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16



# 赛题合并

- 用于理解某一知识点的入门级题目放在  `[Simple_Cases]_xxx` 中
- 同一比赛若有赛题过程相似，知识点相似的，合并赛题文件夹
