# Executable

> 记录：可执行文件相关的内容，未来可能包含编译链接的过程
>
> 通常CTF中不会直接考察可执行文件的知识，但在做reverse, pwn, misc, android可能会有题目涉及到可执行文件相关的知识

可执行文件在计算机科学中指一种内容可被电脑解释为程序的电脑文件。——zh.wiki



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

> 

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

> 段基址

**地址无关代码使用段之间的相对地址来进行寻址，内存中的虚拟地址之间的差必须与文件中的虚拟地址之间的差相匹配**

**基地址Base Address**：内存中任何段的虚拟地址与文件中对应的虚拟地址之间的差值对于任何一个可执行文件或共享对象来说是一个单一常量值。这个差值就是基地址，基地址的一个用途就是在动态链接期间重新定位程序



#### Segment Permissions: p_flags

> 段权限: p_flags

被系统加载到内存中的程序至少有一个可加载的段。当系统为可加载的段创建内存镜像时，它会按照 p_flags 将段设置为对应的权限

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/segment_flag_bits.png)

> 在 PF_MASKPROC 中的比特位都是被保留用于与处理器相关的语义信息

p_flags == 0: 段是不可访问的。

实际的内存权限取决于相应的内存管理单元，不同的系统可能操作方式不一样。尽管所有的权限组合都是可以的，但OS一般会授予比请求更多的权限

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/segment-permission.png)

一般来说，.text 段一般具有读和执行权限，但是不会有写权限。数据段一般具有写，读，以及执行权限

#### Segment Content

> 段内容

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

> 节头表

- 该结构用于定位 ELF 文件中的每个section的具体位置

节头表Section Header Table是一个数组，每个数组的元素的类型是 `ELF32_Shdr` ，每`ELF32_Shdr`都描述了一个section的概要内容

```cpp
typedef struct {
    ELF32_Word      sh_name;
    ELF32_Word      sh_type;
    ELF32_Word      sh_flags;
    ELF32_Addr      sh_addr;
    ELF32_Off       sh_offset;
    ELF32_Word      sh_size;
    ELF32_Word      sh_link;
    ELF32_Word      sh_info;
    ELF32_Word      sh_addralign;
    ELF32_Word      sh_entsize;
} Elf32_Shdr;
```

| 成员         | 说明                                                         |
| ------------ | :----------------------------------------------------------- |
| sh_name      | 节名称，是节区头字符串表节区中（Section Header String Table Section）的索引，因此该字段实际是一个数值。在字符串表中的具体内容是以 NULL 结尾的字符串。 |
| sh_type      | 根据节的内容和语义进行分类，具体的类型下面会介绍。           |
| sh_flags     | 每一比特代表不同的标志，描述节是否可写，可执行，需要分配内存等属性。 |
| sh_addr      | 如果节区将出现在进程的内存映像中，此成员给出节区的第一个字节应该在进程镜像中的位置。否则，此字段为 0。 |
| sh_offset    | 给出节区的第一个字节与文件开始处之间的偏移。SHT_NOBITS 类型的节区不占用文件的空间，因此其 sh_offset 成员给出的是概念性的偏移。 |
| sh_size      | 此成员给出节区的字节大小。除非节区的类型是 SHT_NOBITS ，否则该节占用文件中的 sh_size 字节。类型为 SHT_NOBITS 的节区长度可能非零，不过却不占用文件中的空间。 |
| sh_link      | 此成员给出节区头部表索引链接，其具体的解释依赖于节区类型。   |
| sh_info      | 此成员给出附加信息，其解释依赖于节区类型。                   |
| sh_addralign | 某些节区的地址需要对齐。例如，如果一个节区有一个 doubleword 类型的变量，那么系统必须保证整个节区按双字对齐。也就是说，sh_addr%sh_addralignsh_addr%sh_addralign=0。目前它仅允许为 0，以及 2 的正整数幂数。 0 和 1 表示没有对齐约束。 |
| sh_entsize   | 某些节区中存在具有固定大小的表项的表，如符号表。对于这类节区，该成员给出每个表项的字节大小。反之，此成员取值为 0。 |





### Sections

> 节区

包含目标文件中除了 ELF 头部、程序头部表、节区头部表的所有信息





### Code Section





### Data Related Sections



### .symtab: Symbol Table



### String Sections





### Dynamic Sections



### Misc Sections





## Loader

程序加载过程其实就是系统创建或者或者扩充进程镜的过程。它只是按照一定的规则把文件的段拷贝到虚拟内存段中。进程只有在执行的过程中使用了对应的逻辑页面时，才会申请相应的物理页面。通常来说，一个进程中有很多页是没有被引用的。因此，延迟物理读写可以提高系统的性能。为了达到这样的效率，可执行文件以及共享目标文件所拥有的段的文件偏移以及虚拟地址必须是合适的，也就是说他们必须是页大小的整数倍。



# Windows







# Calling Convention

> 函数调用约定  Calling Convention  调用规范  调用协定  调用约定

函数调用约定通常规定如下几方面内容：

1. 函数**参数的传递顺序和方式**：最常见的参数传递方式是通过堆栈传递。主调函数将参数压入栈中，被调函数以相对于帧基指针的正偏移量来访问栈中的参数。对于有多个参数的函数，调用约定需规定主调函数将参数压栈的顺序(从左至右还是从右至左)。某些调用约定允许使用寄存器传参以提高性能
2. **栈**的维护方式：主调函数将参数压栈后调用被调函数体，返回时需将被压栈的参数全部弹出，以便将栈恢复到调用前的状态。清栈过程可由主调函数或被调函数负责完成。
3. 名字修饰(Name-mangling)策略(函数名修饰 Decorated Name 规则：编译器在链接时为区分不同函数，对函数名作不同修饰。若函数之间的调用约定不匹配，可能会产生堆栈异常或链接错误等问题。因此，为了保证程序能正确执行，所有的函数调用均应遵守一致的调用约定



## cdecl

> C调用约定

- **C/C++编译器默认的函数调用约定**。所有非C++成员函数和未使用stdcall或fastcall声明的函数都默认是cdecl方式
- **参数从右到左入栈**
- **caller负责清除栈中的参数，返回值在EAX**
- 由于每次函数调用都要产生清除(还原)堆栈的代码，故使用cdecl方式编译的程序比使用stdcall方式编译的程序大(后者仅需在被调函数内产生一份清栈代码)
- cdecl调用方式**支持可变参数**函数(e.g. `printf`)，且调用时即使实参和形参数目不符也不会导致堆栈错误
- 对于**C**函数，cdecl方式的名字修饰约定是**在函数名前添加一个下划线**；对于C++函数，除非特别使用extern "C"，C++函数使用不同的名字修饰方式

> ### 可变参数函数支持条件
>
> 1. 参数自右向左进栈
> 2. 由**主调函数caller负责清除栈中的参数**(参数出栈)
>
> 参数从右向左压栈，则参数列表最左边(第一个)的参数最接近栈顶(高地址)位置。所有参数距离帧基指针RBP的偏移量都是常数，而不必关心已入栈的参数数目。只要不定的参数的数目能根据第一个已明确的参数确定，就可使用不定参数。e.g.`printf`函数，第一个参数即format string可作为后继参数指示符。通过format string就可得到后续参数的类型和个数。当传递的参数过多时，以帧基指针RBP为基准，获取适当数目的参数，其他忽略即可。
>
> 若函数参数自左向右进栈，则第一个参数距离栈帧指针的偏移量与已入栈的参数数目有关，需要计算所有参数占用的空间后才能精确定位。当实际传入的参数数目与函数期望接受的参数数目不同时，偏移量计算会出错
>
> caller将参数压栈，只有caller知道栈中的参数数目和尺寸，因此caller可安全地清栈。而callee永远也不能事先知道将要传入函数的参数信息，难以对栈顶指针进行调整
>
> C++为兼容C，仍然支持函数带有可变的参数。但在C++中更好的选择常常是函数多态

## stdcall

- Pascal程序缺省调用方式，WinAPI也多采用该调用约定
- 主调函数参数从右向左入栈，除指针或引用类型参数外所有参数采用传值方式传递，由callee清除栈中的参数，返回值在`EAX`
- `stdcall`调用约定仅适用于参数个数固定的函数，因为被调函数清栈时无法精确获知栈上有多少函数参数；而且如果调用时实参和形参数目不符会导致堆栈错误。对于C函数，`stdcall`名称修饰方式是在函数名字前添加下划线，在函数名字后添加`@`和函数参数的大小，如`_functionname@number`



## fastcall

- `stdcall`调用约定的变形，通常使用ECX和EDX寄存器传递前两个DWORD(四字节双字)类型或更少字节的函数参数，其余参数从右向左入栈
- callee在返回前负责清除栈中的参数，返回值在`EAX`
- 因为并不是所有的参数都有压栈操作，所以比`stdcall`, `cdecl`快些
- 编译器使用两个`@`修饰函数名字，后跟十进制数表示的函数参数列表大小(字节数)，如@function_name@number。需注意`fastcall`函数调用约定在不同编译器上可能有不同的实现，比如16位编译器和32位编译器。另外，在使用内嵌汇编代码时，还应注意不能和编译器使用的寄存器有冲突



## thiscall

- C++类中的非静态函数必须接收一个指向主调对象的类指针(this指针)，并可能较频繁的使用该指针。主调函数的对象地址必须由调用者提供，并在调用对象非静态成员函数时将对象指针以参数形式传递给被调函数
- 编译器默认使用`thiscall`调用约定以高效传递和存储C++类的非静态成员函数的`this`指针参数
- `thiscall`调用约定函数参数按照从右向左的顺序入栈。若参数数目固定，则类实例的this指针通过ECX寄存器传递给被调函数，被调函数自身清理堆栈；若参数数目不定，则this指针在所有参数入栈后再入栈，主调函数清理堆栈。
- `thiscall`不是C++关键字，故不能使用`thiscall`声明函数，它只能由编译器使用
- 注意，该调用约定特点随编译器不同而不同，g++中`thiscall`与`cdecl`基本相同，只是隐式地将`this`指针当作非静态成员函数的第1个参数，主调函数在调用返回后负责清理栈上参数；而在VC中，this指针存放在`%ecx`寄存器中，参数从右至左压栈，非静态成员函数负责清理栈上参数

## naked call

- 对于使用naked call方式声明的函数，编译器不产生保存(prologue)和恢复(epilogue)寄存器的代码，且不能用return返回返回值(只能用内嵌汇编返回结果)，故称naked call
- 该调用约定用于一些特殊场合，如声明处于非C/C++上下文中的函数，并由程序员自行编写初始化和清栈的内嵌汇编指令
- naked call并非类型修饰符，故该调用约定必须与`__declspec`同时使用

> `__declspec`是微软关键字，其他系统上可能没有

| **调用方式**       | `stdcall(Win32)` | `cdecl` | `fastcall`                       | `thiscall(C++)`           | `naked call` |
| ------------------ | ---------------- | ------- | -------------------------------- | ------------------------- | ------------ |
| **参数压栈顺序**   | 右至左           | 右至左  | 右至左，Arg1在`ecx`，Arg2在`edx` | 右至左，`this`指针在`ecx` | 自定义       |
| **参数位置**       | 栈               | 栈      | 栈 + 寄存器                      | 栈，寄存器`ecx`           | 自定义       |
| **负责清栈的函数** | callee           | caller  | callee                           | callee                    | 自定义       |
| **支持可变参数**   | 否               | 是      | 否                               | 否                        | 自定义       |
| **函数名字格式**   | _name@number     | _name   | @name@number                     |                           | 自定义       |
| **参数表开始标识** | "@@YG"           | "@@YA"  | "@@YI"                           |                           | 自定义       |



- 不同编译器产生栈帧的方式不尽相同，主调函数不一定能正常完成清栈工作；而被调函数必然能自己完成正常清栈，因此，在跨(开发)平台调用中，通常使用stdcall调用约定(不少WinApi均采用该约定)



```c
// 采用C语言编译的库应考虑到使用该库的程序可能是C++程序(使用C++编译器)，通常应这样声明头文件
#ifdef _cplusplus
extern "C" { // 使用extern "C" 告知caller所在模块：callee是C语言编译的
#endif
    
int func(int para);
    
#ifdef _cplusplus
}
#endif
```

- 这样C++编译器就会按照C语言修饰策略链接Func函数名，而不会出现找不到函数的链接错误