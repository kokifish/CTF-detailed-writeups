

- `GET`命令通过`perl`执行，`perl`在`open`当中可以执行命令，`open(FD,'ls|')`或者`open(FD,'|ls')`，前提是文件需要存在，所以使用`GET`命令的执行shell脚本命令时，需要先创建文件夹，例如使用`GET`执行`ls`命令，就需要先创建`'ls|'`（注意后面的`|`），`touch 'ls|'`,然后`GET ‘file:ls|'`，这个命令和直接在命令行执行`ls`获得的结果是一样的。

<img src="images\image-20201129150737662.png" alt="image-20201129150737662"  />

- 可以先在服务器上写上反弹shell命令
  1. 靶机请求页面写入文件当作脚本
  2. 创建bash命令文件
  3. `perl`漏洞执行反弹获取shell

- `GET`可以读取文件`GET ./filename`，读取根目录`GET /`

> 暂且不知道是什么：
>
> d2eeea69938b284db9fd454a4f1483f4
>
> 9872edb0e32d04659381b860b130a2b7
>
> 3b002f7b524b83f6c68cb45b0b217338

## Git源码泄露题目（Lottery）

> 攻防世界 _ web _ 高手进阶区 _ Lottery

- 拿到题目，如下图所示：

  <img src="images\image-20210118162601439.png" alt="image-20210118162601439" style="zoom:67%;" />

  <img src="images\image-20210118161825427.png" alt="image-20210118161825427" style="zoom:67%;" />

  是买彩票题目，输入七个数字，如果全部正确就可以获得最多的钱，我们的目标就是拿到最多的钱。

- 使用**御剑**进行扫描

<img src="images\BAEC3I(VH}Q8BBU_ZZD%[)X.png" alt="img" style="zoom:67%;" />

发现存在`robots.txt`文件，进入看:

![img](images\41T8]AG5%2{@QW5N$%]}~CK.png)

- 网上说是源码**git源码泄露**问题，使用**GitHack**工具将源码下载到本地：

  ![image-20210118162132338](images\image-20210118162132338.png)

  - 查看`api.php`代码：

  ![image-20210118162237499](images\image-20210118162237499.png)

  是将你输入的字母和随机生成的7个`win_numbers`一个一个地进行比较，又由于php是弱类型比较，**if (true==任何非零数字) 就会返回true** ，所以本题的思路就是使用**burp suite**抓包，改包，将`numbers`的值全部改为`true`。如下图所示：

  ![image-20210118163528907](images\image-20210118163528907.png)

  可以看到网页的返回结果如下图所示：

  <img src="images\image-20210118164159098.png" alt="image-20210118164159098" style="zoom:67%;" />

  而且我们的钱数已经加了5000000：

  ![image-20210118164219264](images\image-20210118164219264.png)

  - 继续再抓一次包改一次包：

    <img src="images\image-20210118164256811.png" alt="image-20210118164256811" style="zoom:67%;" />

    钱数已经超过一千万了：

    ![image-20210118164322671](images\image-20210118164322671.png)

    这个时候就可以买flag了：

    <img src="images\image-20210118164337064.png" alt="image-20210118164337064" style="zoom:67%;" />

## php代码审计题目（warmup）

> 攻防世界_ web _ 高手进阶区_warmup

- 这道题目通过查看源代码发现包含的`.php`文件，查看后进行代码审计，满足条件则，`include`文件。

- **include语句的作用**

  `include  $_REQUEST['file']`

  - `include`语句包含并运行指定文件？？

  - 意思是包含`file`参数，`file`参数是从`url`中传递进来的参数，我们要构造这个参数使得它满足代码中的条件，并且还能够被执行，执行后得到flag，一般执行的都是系统命令，命令类型是文件路径，目标也是要找到包含flag文件的路径（一般根据题目提示找到，在本题中，它提示flag在`ffffllllaaaagggg`中，这暗示了flag在当前目录的下面第四层目录中）

- 被包含文件先按照参数给出的路径寻找，如果没有给出目录时则按照`include_path`指定的目录寻找。如果定义了路径，不管是绝对路径还是当前目录的相对路径（以`..`或者`.`开头）`--include_path`都会被完全忽略，如果文件以`../`开头，解析器会在当前目录的父目录下寻找改文件。（看不懂.jpg）

- 因此构造的payload如下：

  `?file=source.php?/../../../../ffffllllaaaagggg`

  第一个问号表示传参。

上面是根据代码审计构造的payload，是为了让`file`参数能够满足判断条件然后使得`include`语句能够成功执行。

![image-20210118211155850](images\image-20210118211155850.png)

看得懂代码才是关键。需要绕过各种判断条件。

<img src="images\image-20210118211913655.png" alt="image-20210118211913655" style="zoom:67%;" />

## URL编码与解码

给服务器传递url的时候，会对传递的参数进行url解码一次，有些网页源代码会将解码后的结果再解码一次，这就要求我们构造原字符两次编码之后的结果再进行传递。