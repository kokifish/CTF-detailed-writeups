# Web Security

> https://owasp.org/www-project-top-ten/ owasp top 10  十大 Web 应用程序安全风险



# Git Leak











# XSS

> Cross Site Scripting 跨站脚本攻击

往Web页面里插入恶意Script代码，当用户浏览该页时，嵌入Web里的Script会被执行，达到恶意攻击用户的目的

xss漏洞通常是通过php的输出函数将javascript代码输出到html页面中，通过用户本地浏览器执行的，所以在代码审计中xss漏洞关键就是寻找参数未过滤的输出函数

