# 2021年广东省强网杯团体赛—— Crypto —— Different_RSA
题目见`task.py`和`Reference.zip`

* 题目描述见参考wp或者自己看`task.py`这里不赘述。

* 题解

题目分为两个步骤，第一步是解方程$$\frac{b}{a}+\frac{a}{b}-\frac{1}{ab} = k$$$k$从1到1000，然后可以推导得到对于每个$k$,有$$a^2-kab+b^2=1.$$对于每一组满足条件的$(a,b)$，按大小排序后是一个广义斐波拉契数列，其中$p=k,q=-1$。**最难的是发现这一点，自己从公式推导比较困难。** 参考wp的做法是找出$k$比较小的时候的几组解，然后找规律发现是广义斐波拉契数列。

第二步得到hint后解压压缩包，密码`2581424b7ae1a576831e63ebf774f201`。里面是一篇paper，按照paper的Section 5进行实现从而分解RSA的$n$就可以得到flag，用到的方法是：**连分数+ Coppersmith**

参考wp: https://zhuanlan.zhihu.com/p/421202600

