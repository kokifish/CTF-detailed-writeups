# 2021年ByteCTF—— Crypto —— Overheard

题目见`Overheard.py`

题目主要的意思是给出$g^a, g^b$，然后oracle允许计算$m^b$，但是不知道$m^b$的低64bit。然后给出$g^{ab}$则题目返回flag。

* 题解1：官方解法，构造$$[k, x_2, 1] \left[\begin{matrix}
p & 0 & 0\\
t & 1 & 0\\
u & 0 & 2^{64} 
\end{matrix}\right] = [x_1, x_2, 2^{64}]$$ 从而可以使用LLL算法进行求解。其中已知$p,g=5$随机生成一个$$t = g^{-bc}\ mod\ p$$ $$u = (g^{ab}-x_1) - g^{-bc}(g^{ab}g^{bc} - x_2) = g^{-bc}x_2 - x_1 + kp$$

* 题解2：把题目看成一个HNP问题(可见`[CTF]_Crypto.md`)，具体解法见第二篇参考资料。

* 题解3：由于$p$并不是一个强素数，可以对$p-1$进行分解得到`2 * 139 * 42798235205263 * 181440306484546562787712787 * 29001270706552925994696287850627469`。因为$p$大约是256bit，因此可以使用`cado-nfs`进行求解，然后使用Polig-Hellman算法进行求解。 （这里并没有进行实现，因为程序限定了需要在10秒内进行求解，时间上不一定能来得及，TODO：可以尝试实现一下）

* 参考资料：
    * https://bytectf.feishu.cn/docs/doccnq7Z5hqRBMvrmpRQMAGEK4e#
    * https://blog.csdn.net/m0_57291352/article/details/120935264