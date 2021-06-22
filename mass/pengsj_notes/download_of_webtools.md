# web相关工具的使用

## 一. 中国菜刀

直接添加网站url，在上传的文件中包含一句话木马之后，可以直接对网站进行文件管理

[https://github.com/raddyfiy/caidao-official-version](https://blog.csdn.net/Aaron_Miller/article/details/105971538)

https://blog.csdn.net/Aaron_Miller/article/details/105971538

https://www.dazhuanlan.com/2019/10/06/5d997f288e45a/

上面的网站可以直接下载caidao.exe文件

## 二. Burp suite

抓包改包工具

https://down.52pojie.cn/Tools/Network_Analyzer/

上面的网址包含破解版

## 三. 后台扫描工具

所谓扫描后台就是扫描站点的目录下还有哪些页面可以访问，看一下有没有类似的管理员页面、备份文件泄露和其他文件等。

### 3.1 御剑

###  3.2 dirsearch

https://github.com/maurosoria/dirsearch

### 3.3 备份文件泄露

题目经常需要代码审计，不过有时候不会把源码直接给我们，而是要我们自己发现。备份文件就是常见的源码泄露的方式，实践中往往是开发者的疏忽而忘记删除  备份文件，从而导致服务器中残留源码。我们可以通过访问这些备份文件来审计代码，一般情况下可以用后台扫描工具扫描。常见的备份文件格式有：

```
index.phps
index.php.swp
index.php.swo
index.php.php~
index.php.bak
index.php.txt
index.php.old
```

phps文件就是php的源代码文件。通常用于提供给用户查看php代码，因为用户无法直接通过web浏览器看到php文件的内容，所以需要用phps文件代替。除了php备份文件，有时候也会遇到整个站点的源码被打包成压缩文件，被放置在网站的根目录下。

www.cnblogs.com/linfangnan/p/13543040.html

## 四. Hackbar

使用hackbar工具加密解密，编码解码，通过传入url，设置方式对服务器进行传递。

![image-20210117212245428](images\image-20210117212245428.png)

## 五. GitHack

下载地址https://github.com/lijiejie/GitHack

GitHack是一个`.git`泄露利用脚本，通过泄露的`.git`文件夹下的文件，重建还原工程源代码。渗透测试人员、攻击者，可以进一步审计代码，挖掘；文件上传，SQL注入等web安全漏洞。





