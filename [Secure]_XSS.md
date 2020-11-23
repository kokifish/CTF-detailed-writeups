[TOC]





---

# What is Cross Site Scripting(XSS)

> Cross Site Scripting, XSS, 跨站脚本攻击

原理：通过存在的漏洞网站欺骗用户在当前域执行黑客提前设计好的恶意JavaScript脚本

Cross site scripting (XSS) is a common attack vector that injects malicious code into a vulnerable web application. XSS differs from other web attack vectors (e.g., SQL injections), in that it does not directly target the application itself. Instead, **the users of the web application are the ones at risk**. 攻击面向web应用使用者

Cross site scripting attacks can be broken down into two types: **stored** and **reflected**. 分为存储型和反射型







## Stored Cross Site Scripting

> 存储型跨站脚本攻击，持久性XSS

- To successfully execute a stored XSS attack, a perpetrator has to locate a vulnerability in a web application and then inject malicious script into its server (e.g., via a comment field).
- 存储型XSS是通过**POST请求**等方法将恶意参数持久地提交进一个页面中
- 数据是存储在服务器上的









## Reflected Cross Site Scripting

> 反射型跨站脚本攻击
>
> DOM XSS也可作为一种XSS类型，从效果来看也可以说是反射型XSS





