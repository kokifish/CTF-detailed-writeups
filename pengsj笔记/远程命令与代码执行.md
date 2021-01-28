RCE：Remote Command/Code Execute，远程命令/代码执行

## 一. 漏洞成因

当web应用程序代码包含操作系统调用并且调用中使用了用户输入时，才可能进行OS命令注入攻击。

操作系统使用web服务器的特权执行注入的任意命令。因此，命令注入漏洞本身不会导致整个系统受损。但是，攻击者可能能够使用特权升级和其他漏洞来获得更多访问权限。

## 二.敏感函数

PHP：

代码执行

```php
eval()//把字符串作为php代码执行
assert()//检查一个断言是否为false，可用来执行代码
preg_replace()//执行一个正则表达式的搜索和替换
call_user_func()//把第一个参数作为回调函数调用
call_user_func_array()//调用回调函数，并把一个数组参数作为回调函数的参数
array_map()//为数组的每个元素应用回调函数
```

```php
动态函数$a($b)
由于PHP 的特性原因，PHP 的函数支持直接由拼接的方式调用，这直接导致了PHP 在安全上的控制有加大了难度。不少知名程序中也用到了动态函数的写法，这种写法跟使用`call_user_func()`的初衷一样，用来更加方便地调用函数，但是一旦过了不严格就会造成代码执行漏洞。

举例：不调用`eval()`
<?php
if(isset($_GET['a'])){
    $a=$_GET['a'];
    $b=$_GET['b'];
    $a($b);
}else{
    echo "
    ?a=assert&amp;b=phpinfo()
    ";
}
```

命令执行

```php
system()//执行外部程序，并且显示输出
exec()//执行一个外部程序
shell_exec()//通过 shell 环境执行命令，并且将完整的输出以字符串的方式返回
passthru()//执行外部程序并且显示原始输出
pcntl_exec()//在当前进程空间执行指定程序
popen()//打开进程文件指针
proc_open()//执行一个命令，并且打开用来输入/输出的文件指针
```

python:
代码执行

```python
exec(string)# Python代码的动态执行
eval(string)# 返回表达式或代码对象的值
execfile(string)# 从一个文件中读取和执行Python脚本
input(string)#Python2.x 中 input() 相等于 eval(raw_input(prompt)) ，用来获取控制台的输入
compile(string)# 将源字符串编译为可执行对象
```

命令执行

```php
system()#执行系统指令
popen()#popen()方法用于从一个命令打开一个管道
subprocess.call #执行由参数提供的命令
spawn #执行命令
```

