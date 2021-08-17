# Web Security

> https://owasp.org/www-project-top-ten/ owasp top 10  十大 Web 应用程序安全风险



# Git Leak



# SQL Injection

SQL注入是因为后台**SQL语句拼接了用户的输入**，而且Web应用程序对用户输入数据的合法性没有判断和过滤，**前端传入后端的参数是攻击者可控的**，攻击者可以通过构造不同的SQL语句来实现对数据库的任意操作，e.g. 增删改查...，如果数据库的用户权限足够大，还可以对操作系统执行操作。SQL注入是针对数据库、后台、系统层面的攻击

1. 平台层注入：由不安全的数据库配置或数据库平台的漏洞所致
2. 代码层注入：由于程序员对输入未进行细致地过滤

mysql: 

- 单行注释：`#`
- 多行注释：`/* */`

在**MySQL5.0以上**，MySQL默认添加 `information_schema` 数据库，该数据库中的表是只读的，不能进行更新、删除和插入...，不能加载触发器，实际只是一个视图，不是基本表，没有关联的文件

`information_schema`数据库中三个很重要的表

- `information_schema.schemata`: mysql数据库中所有数据库的库名
- `information_schema.tables`： mysql数据库中所有数据表的表名
- `information_schema.columns`: mysql数据库中所有列的列名

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




## 分类

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

文件包含：



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



