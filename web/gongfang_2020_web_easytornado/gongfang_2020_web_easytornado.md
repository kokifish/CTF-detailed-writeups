---
typora-copy-images-to: ./images
typora-root-url: ../gongfang_2020_web_easytornado
---

> 题目来源：攻防世界 web 高手进阶区 easytornado
>
> 待办事项：
>
> - [ ] SSTI模版注入
> - [ ] tornado的cookie获取：handler.settings对象

一. 题目描述

如下图所示：

![image-20210205160011437](images/image-20210205160011437.png)

有三个文件，依次点开：

![image-20210205160043484](images/image-20210205160043484.png)

![image-20210205160055748](images/image-20210205160055748.png)

![image-20210205160109434](images/image-20210205160109434.png)

二. 分析

- 首先，flag.txt文件提示flag在/fllllllag文件中，所以我们要构造的东西如下图格式构成：

![image-20210205160225224](images/image-20210205160225224.png)

filename我们知道了，filehash是由hints.txt中提示的md5计算得到的，我们不知道的是cookie_secret。



cookie_secret则是由/welcome.txt那里得到的启发得到的。



- 先直接构造filename=/fllllllllllag去掉filehash，得到：

![image-20210205161449566](images/image-20210205161449566.png)

/welcome.txt中提示render，猜测可能是SSTI（服务器模板注入攻击）模版注入：

- 输入{{2}}

![image-20210205161926105](images/image-20210205161926105.png)

- 输入{{2*2}}返回ORZ，说明操作符被过滤了。

![image-20210205162031931](images/image-20210205162031931.png)

- 预备知识：

使用handler.settings对象，通过模板注入拿到tornado中的cookie：

所以我们在msg参数中输入{{handler.settings}}，得到了cookie_secret：

![image-20210205162930865](images/image-20210205162930865.png)



- 最后一步就是得到md5值：

md5(cookie_secret+md5(filename))=f955b629506fee95324f8b9950cbefac

![image-20210205163619160](images/image-20210205163619160.png)



- 在url中传参，最终得到flag：

![image-20210205163647936](images/image-20210205163647936.png)

flag{3f39aea39db345769397ae895edb9c70}

