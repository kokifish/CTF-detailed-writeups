# 2021年西湖论剑CTF—— Crypto —— unknown_dsa

题目见`unknown_dsa.py`

1. 首先使用连分数的方法找出三组pell方程可能的解，并使用中国剩余定理进行尝试，如果发现中国剩余定理得出的结果能开7次方根的，就表示找到符合条件的解，从而恢复出m1和m2。
2. 然后根据$p*q, (p-1)//q, t$恢复出$g,p,q$
3. 两种方法
   1. 使用dsa的公共随机数攻击求得随机数$k$，其中$$k=((s1-s2)*(hm1-hm2)^{-1})^{-1}\ mod\ q$$然后就可以求出x1,x2
   2. 列出关于k, x1, x2在模q意义下的线性方程组，并求解。 $$
   \left[ \begin{matrix}s1 & -r1 & 0\\ s2 & -r1 & 0 \\ s3 & 0 & -r2 \end{matrix}\right]
   \left[ \begin{matrix}k \\ x1 \\ x2 \end{matrix}\right]    =  
   \left[ \begin{matrix}hm1 \\ hm2 \\ hm1 \end{matrix}\right]
   $$

* 参考资料： https://blog.csdn.net/Fred_Bohr_Locke/article/details/121454059
