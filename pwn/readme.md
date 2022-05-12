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



# Game Name Year Challenge Name

> challenge name: `xxx`   level: 1(checkin) 2(easy) 3(medium) 4(hard) 5()
>
> file: `pwn`, `libc-2.27.so`
>
> ld.so and .i64 with comments provided
>
> writeup writer: hexhex16@outlook.com    https://github.com/hex-16
>
> something wanna say...



# 赛题合并

- 用于理解某一知识点的入门级题目放在  `[Simple_Cases]_xxx` 中
- 同一比赛若有赛题过程相似，知识点相似的，合并赛题文件夹
- 不同赛事中，如果有赛题相似度过高，属于同一类别的，也合并。合并后文件夹以赛题类别命名 e.g.`Heap_OffByOne`

