## 一. sql注入题目

1. **题目：攻防世界web高手进阶区的newscenter题目：**

   - 为什么要使用单引号`'`，为什么要使用`#`，联合查询的时候，直接select 1，2，3看结果回显哪一个？？为什么还要 0 union。

     `'and 0 union select 1,2,3 # `

     ![image-20210203205653243](images/image-20210203205653243.png)

     

   - 由于上面的查询语句得到的是2 3的结果，所以这题的思路就是在2 3位置输入查询的数据库名和表名。

     ````mysql
     ' and 0 union select 1, table_schema,table_name from information_schema.columns #
     ````

     ![image-20210203205912343](images/image-20210203205912343.png)

     ![image-20210203205929110](images/image-20210203205929110.png)

     由查询结果可知，数据库为news，表名为secret_table。

   - 这一步查询secret_table的字段名：

     ```mysql
     ' and 0 union select 1,2,column_name from information_schema.columns where table_name='secret_table' #
     ```

     ![image-20210203210237927](images/image-20210203210237927.png)

   - 由结果可得：

     结果在fl4g字段中：

     ![image-20210203210657111](images/image-20210203210657111.png)

     `QCTF{sq1_inJec7ion_ezzz} `

## 二. 序列化与反序列化题目

1. **攻防世界web高手进阶区的unserialize3题目**

   ![image-20210204203304279](images/image-20210204203304279.png)

   题目提示的是让我们狗仔一个参数?code=传入url，题目又是说的反序列化，所以我们将整个xctf对象进行反序列化，得到结果：

   ![image-20210204203733292](images/image-20210204203733292.png)

   因此我们构造payload：`?code=o:4:"xctf":1:{s:4:"flag";s:3:"111";}`,得到结果：

   ![image-20210204203935707](images/image-20210204203935707.pn

## 三. Git源码泄露题目（Lottery）

> 攻防世界 _ web _ 高手进阶区 _ Lottery

- 拿到题目，如下图所示：

  ![image-20210118162601439](images/image-20210118162601439.png?lastModify=1612442930)

  ![image-20210118161825427](images/image-20210118161825427.png?lastModify=1612442930)

  是买彩票题目，输入七个数字，如果全部正确就可以获得最多的钱，我们的目标就是拿到最多的钱。

- 使用**御剑**进行扫描

![img](images/BAEC3I(VH%7DQ8BBU_ZZD%25%5B)X.png?lastModify=1612442930)

发现存在`robots.txt`文件，进入看:

![img](images/firefox_robot.png?lastModify=1612442930)

- 网上说是源码**git源码泄露**问题，使用**GitHack**工具将源码下载到本地：

  ![image-20210118162132338](images/image-20210118162132338.png?lastModify=1612442930)

  - 查看`api.php`代码：

  ![image-20210118162237499](images/image-20210118162237499.png?lastModify=1612442930)

  是将你输入的字母和随机生成的7个`win_numbers`一个一个地进行比较，又由于php是弱类型比较，**if (true==任何非零数字) 就会返回true** ，所以本题的思路就是使用**burp suite**抓包，改包，将`numbers`的值全部改为`true`。如下图所示：

  ![image-20210118163528907](images/image-20210118163528907.png?lastModify=1612442930)

  可以看到网页的返回结果如下图所示：

  ![image-20210118164159098](images/image-20210118164159098.png?lastModify=1612442930)

  而且我们的钱数已经加了5000000：

  ![image-20210118164219264](images/image-20210118164219264.png?lastModify=1612442930)

  - 继续再抓一次包改一次包：

    ![image-20210118164256811](images/image-20210118164256811.png?lastModify=1612442930)

    钱数已经超过一千万了：

    ![image-20210118164322671](images/image-20210118164322671.png?lastModify=1612442930)

    这个时候就可以买flag了：

    ![image-20210118164337064](images/image-20210118164337064.png?lastModify=1612442930)

## 四. php代码审计题目（warmup）

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

![image-20210118211155850](images/image-20210118211155850.png?lastModify=1612442930)

看得懂代码才是关键。需要绕过各种判断条件。

![image-20210118211913655](images/image-20210118211913655.png?lastModify=1612442930)

