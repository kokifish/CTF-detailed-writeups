# Executable

> 记录：可执行文件相关的内容，未来可能包含编译链接的过程
>
> 通常CTF中不会直接考察可执行文件的知识，但在做reverse, pwn, misc, android可能会有题目涉及到可执行文件相关的知识

可执行文件在计算机科学中指一种内容可被电脑解释为程序的电脑文件。zh.wiki 如是说



# Linux





## ELF

ELF (Executable and Linkable Format) 文件，即 Linux 中的目标文件，主要有以下三种类型

1. 可重定位文件 Relocatable File: 含编译器生成的代码及数据。链接器会将它与其它目标文件链接起来从而创建可执行文件或者共享目标文件。e.g. `x.o` 。
2. 可执行文件 Executable File: 即通常在 Linux 中执行的程序
3. 共享目标文件 Shared Object File: 含代码和数据的库文件，e.g. `x.so` 。一般有两种使用情景：
   - 链接器 (Link eDitor, ld ) 可能会处理它和其它可重定位文件以及共享目标文件，生成另外一个目标文件。
   - 动态链接器 (Dynamic Linker) 将它与 可执行文件 及其它共享目标 组合在一起生成进程镜像。

Object File由汇编器+链接器创建，是文本程序的二进制形式，可直接在处理器上运行。不含需虚拟机才能执行的程序 (e.g. Java)

### ELF File Format

- 目标文件(Object File)既参与程序链接又参与程序执行。根据过程不同，目标文件格式提供了其内容的两种并行视图: 链接视图与执行视图

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/object_file_format.png)

**链接视图**
1. ELF 头部(**ELF Header**): 在文件开始处，给出整个文件的组织情况
2. 程序头部表(**Program Header Table**) opt.: 描述如何创建进程。用于生成进程的目标文件必须具有程序头部表，但是重定位文件不需要
3. 节区(**Section**): 包含在链接视图中要使用的大部分信息: 指令、数据、符号表、重定位信息...
4. 节区头部表(**Section Header Table**): 包含了描述文件section的信息，每个section在表中都有一个表项，内容含节区名称、大小...。用于链接的目标文件必须有节区头部表，其它目标文件则为可选项。

**执行视图**
主要不同点在于没有 section，而有多个 segment。segment 大都是来源于链接视图中的 section。
![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/executable_elf_layout.png)

>  尽管图中是按照 ELF Header, Program Header Table, section/segment, Section Header Table 的顺序排列的。但实际上除了 ELF 头部表以外，其它部分没有严格的的顺序。



![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/ELF-Walkthrough.png)

### Data Type
ELF 文件格式支持 8 bit / 32 bit 体系结构，且可拓展支持更小/大位数的处理器架构。
Object File含一些控制数据，用以表明Object File所使用的架构，以便以通用的方式识别和解释。Object File的其他数据采用目的处理器的格式编码，与在何种机器上创建无关。即Object File可以交叉编译，e.g. x86平台生成arm可执行代码



|名称|长度|对齐方式|用途|
|---|---|---|---|
|Elf32_Addr|4|4|无符号程序地址|
|Elf32_Half|2|2|无符号半整型|
|Elf32_Off|4|4|无符号文件偏移|
|Elf32_Sword|4|4|有符号大整型|
|Elf32_Word|4|4|无符号大整型|
|unsigned char|1|1|无符号小整型|

> 数据结构可以包含显式补齐来确保 4B 对象按 4B 对齐，强制数据结构的大小是 4 的整数倍... 包含 Elf32_Addr 类型成员的结构体会在文件中 4B 边界处对齐。为可移植性，ELF不使用位域

### ELF Header

- ELF Header 描述 ELF 文件的概要信息，利用这个数据结构可索引到 ELF 文件的全部信息

```cpp
#define EI_NIDENT   16

typedef struct {
    unsigned char   e_ident[EI_NIDENT];
    ELF32_Half      e_type;
    ELF32_Half      e_machine;
    ELF32_Word      e_version;
    ELF32_Addr      e_entry;
    ELF32_Off       e_phoff;
    ELF32_Off       e_shoff;
    ELF32_Word      e_flags;
    ELF32_Half      e_ehsize;
    ELF32_Half      e_phentsize;
    ELF32_Half      e_phnum;
    ELF32_Half      e_shentsize;
    ELF32_Half      e_shnum;
    ELF32_Half      e_shstrndx;
} Elf32_Ehdr;
```


#### e_ident

| Macro Name | idx  | Description    | Value |
| :--------- | :--- | :------------- | ----- |
| EI_MAG0    | 0    | 文件标识       | 0x7f  |
| EI_MAG1    | 1    | 文件标识       | 'E'   |
| EI_MAG2    | 2    | 文件标识       | 'L'   |
| EI_MAG3    | 3    | 文件标识       | 'F'   |
| EI_CLASS   | 4    | 文件类         |       |
| EI_DATA    | 5    | 数据编码       |       |
| EI_VERSION | 6    | 文件版本       |       |
| EI_PAD     | 7    | 补齐字节开始处 |       |

`e_ident[EI_MAG0]` 到 `e_ident[EI_MAG3]`，即文件的头 4 个字节，被称作 “魔数”，标识该文件是一个 ELF 目标文件

`e_ident[EI_CLASS]` 为 `e_ident[EI_MAG3]`的下一个字节，标识文件的类型或容量

| e_ident[EI_CLASS] Macro | Value | Description |
| :---------------------- | :---- | :---------- |
| ELFCLASSNONE            | 0     | 无效类型    |
| ELFCLASS32              | 1     | 32 bit 文件 |
| ELFCLASS64              | 2     | 64 bit 文件 |

`e_ident[EI_DATA]`字节给出了目标文件中的特定处理器数据的编码方式。下面是目前已定义的编码

| e_ident[EI_DATA] Macro | Value | Description  |
| :--------------------- | :---- | :----------- |
| ELFDATANONE            | 0     | 无效数据编码 |
| ELFDATA2LSB            | 1     | 小端         |
| ELFDATA2MSB            | 2     | 大端         |

`e_ident[EI_DATA]`: ELF 头的版本号。目前这个值必须是`EV_CURRENT`，即 `e_version`

`e_ident[EI_PAD]`: `e_ident` 中未使用字节的开始地址。这些字节被保留并置为 0；处理目标文件的程序应该忽略它们。如果之后这些字节被使用，EI_PAD 的值就会改变



#### e_type

`e_type` 标识目标文件类型。

| 名称      | 值     | 意义           |
| :-------- | :----- | :------------- |
| ET_NONE   | 0      | 无文件类型     |
| ET_REL    | 1      | 可重定位文件   |
| ET_EXEC   | 2      | 可执行文件     |
| ET_DYN    | 3      | 共享目标文件   |
| ET_CORE   | 4      | 核心转储文件   |
| ET_LOPROC | 0xff00 | 处理器指定下限 |
| ET_HIPROC | 0xffff | 处理器指定上限 |

虽然核心转储文件的内容没有被详细说明，但 `ET_CORE` 还是被保留用于标志此类文件。从 `ET_LOPROC` 到 `ET_HIPROC` (包括边界) 被保留用于处理器指定的场景。其它值在未来必要时可被赋予新的目标文件类型。



### Program Header Table

Program Header Table 是一个结构体数组，每一个元素的类型是 `Elf32_Phdr`，描述了一个段或者其它系统在准备程序执行时所需要的信息。其中，ELF 头中的 `e_phentsize` 和 `e_phnum` 指定了该数组每个元素的大小以及元素个数。一个目标文件的段包含一个或者多个节。

**Program Header Table 只对可执行文件和共享目标文件有意义。即为ELF文件运行时中的段准备的**

```cpp
typedef struct {
    ELF32_Word  p_type;  // 段的类型，或者表明了该结构的相关信息
    ELF32_Off   p_offset;// 给出了从文件开始到该段开头的第一个字节的偏移
    ELF32_Addr  p_vaddr; // 给出了该段第一个字节在内存中的虚拟地址
    ELF32_Addr  p_paddr; // 仅用于物理地址寻址相关的系统中， 由于 "System V" 忽略了应用程序的物理寻址，可执行文件和共享目标文件的该项内容并未被限定
    ELF32_Word  p_filesz;// 给出了文件镜像中该段的大小，可能为 0
    ELF32_Word  p_memsz; // 给出了内存镜像中该段的大小，可能为 0
    ELF32_Word  p_flags; // 给出了与段相关的标记
    ELF32_Word  p_align; // 可加载的程序的段的 p_vaddr, p_offset 的大小必须是 page 的整数倍。p_align表示section在文件及内存中的对齐方式。p_align == 0/1: 不需要对齐。除此之外，p_align 应是 2 的整数指数次方，且 p_vaddr, p_offset 在模 p_align 的意义下应相等
} Elf32_Phdr;
```

- 段类型 `ELF32_Word  p_type`

| p_type Macro        | Value                  | Description                                                  |
| :------------------ | :--------------------- | :----------------------------------------------------------- |
| PT_NULL             | 0                      | 段未使用，其结构中其他成员都是未定义的                       |
| PT_LOAD             | 1                      | 可加载的段，大小由 p_filesz 和 p_memsz 描述。文件中的字节被映射到相应内存段开始处。如果 p_memsz 大于 p_filesz，“剩余” 的字节都要被置为 0。p_filesz 不能大于 p_memsz。可加载的段在程序头部中按照 p_vaddr 的升序排列。 |
| PT_DYNAMIC          | 2                      | 此类型段给出动态链接信息。                                   |
| PT_INTERP           | 3                      | 此类型段给出了一个以 NULL 结尾的字符串的位置和长度，该字符串将被当作解释器调用。这种段类型仅对可执行文件有意义（也可能出现在共享目标文件中）。此外，这种段在一个文件中最多出现一次。而且这种类型的段存在的话，它必须在所有可加载段项的前面 |
| PT_NOTE             | 4                      | 此类型段给出附加信息的位置和大小                             |
| PT_SHLIB            | 5                      | 该段类型被保留，不过语义未指定。而且，包含这种类型的段的程序不符合 ABI 标准 |
| PT_PHDR             | 6                      | 该段类型的数组元素如果存在的话，则给出了程序头部表自身的大小和位置，既包括在文件中也包括在内存中的信息。此类型的段在文件中最多出现一次。**此外，只有程序头部表是程序的内存映像的一部分时，它才会出现**。如果此类型段存在，则必须在所有可加载段项目的前面。 |
| PT_LOPROC~PT_HIPROC | 0x70000000 ~0x7fffffff | 此范围的类型保留给处理器专用语义                             |

#### p_vaddr and Base Address

**地址无关代码使用段之间的相对地址来进行寻址，内存中的虚拟地址之间的差必须与文件中的虚拟地址之间的差相匹配**

**基地址Base Address**：内存中任何段的虚拟地址与文件中对应的虚拟地址之间的差值对于任何一个可执行文件或共享对象来说是一个单一常量值。这个差值就是基地址，基地址的一个用途就是在动态链接期间重新定位程序



#### Segment Permissions: p_flags

被系统加载到内存中的程序至少有一个可加载的段。当系统为可加载的段创建内存镜像时，它会按照 p_flags 将段设置为对应的权限

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/segment_flag_bits.png)

> 在 PF_MASKPROC 中的比特位都是被保留用于与处理器相关的语义信息

p_flags == 0: 段是不可访问的。

实际的内存权限取决于相应的内存管理单元，不同的系统可能操作方式不一样。尽管所有的权限组合都是可以的，但OS一般会授予比请求更多的权限

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/segment-permission.png)

一般来说，.text 段一般具有读和执行权限，但是不会有写权限。数据段一般具有写，读，以及执行权限

#### Segment Content

一个segment可能包括一到多个section，但不影响程序的加载。但仍需要各种各样的数据来使得程序可以执行、动态链接

对于不同segment来说，section顺序及所包含的section个数有所不同。与处理相关的约束可能会改变对应segment的结构

**代码段**：只包含只读的指令和数据。下图未给出所有可能的段

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/text_segment.png)

**数据段**：包含可写的数据和指令。通常含

- `.data`: 
- `.dynamic`:
- `.got`:
- `.bss`:

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/data_segment.png)

程序头部的 PT_DYNAMIC 类型的元素指向 `.dynamic` section。其中，got 表和 plt 表包含与地址无关的代码(PIE)相关信息。

> 上例 plt section 出现在代码段Text Segment，但对于不同的处理器可能会有所变动
>
> .bss 节的类型为 SHT_NOBITS，这表明它在 ELF 文件中不占用空间，但是它却占用可执行文件的内存镜像的空间。通常情况下，没有被初始化的数据在段的尾部，因此，`p_memsz` 才会比 `p_filesz` 大
>
> 不同的segment可能会有所重合，即不同的segment包含相同的section

### Section Header Table






### Loader

程序加载过程其实就是系统创建或者或者扩充进程镜的过程。它只是按照一定的规则把文件的段拷贝到虚拟内存段中。进程只有在执行的过程中使用了对应的逻辑页面时，才会申请相应的物理页面。通常来说，一个进程中有很多页是没有被引用的。因此，延迟物理读写可以提高系统的性能。为了达到这样的效率，可执行文件以及共享目标文件所拥有的段的文件偏移以及虚拟地址必须是合适的，也就是说他们必须是页大小的整数倍。



# Windows