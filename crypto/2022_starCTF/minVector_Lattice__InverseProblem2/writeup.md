# 2021年西湖论剑CTF—— Crypto —— hardRSA

题目见`problem.py`

题目生成了一个$(B||A)\cdot(z||x)^T$的结果$z$，$A$和$B$是矩阵，$z$是flag向量，$x$是额外的向量。得到的结果记为$y$。

根据题目产生的系数矩阵很明显是两个子矩阵的SVD形式构成。矩阵的拼接对于奇异值影响不大，因此可以通过直接SVD分解$\begin{bmatrix}B & A\end{bmatrix}$来计算出flag长度$n$。

然后我们的目标是计算向量$e = y-Ax-Bz$使得$|y-Ax-Bz|_2$，其中$y,A,B$已知。相当于就是最小二乘法的一个变种。

根据官方wp，我们有：若$z$已知，则由连续情形下的最小二乘解法我们有$$(A^T A)x \approx A^T(y-Bz)$$ 即$$x \approx (A^T A)^{-1}A^T(y-Bz)$$只对矩阵$A$进行了求逆。代入原问题，我们有$$y-Ax \\= y-A(A^T A)^{-1}A^T(y-Bz)\\ = Bz+e$$ 即$$[I-A(A^T A)^{-1}A^T]y\\=[I-A(A^T A)^{-1}A^T]Bz+e.$$记$$Ky=[I-A(A^T A)^{-1}A^T]y,\\KB=[I-A(A^T A)^{-1}A^T]B$$ 则有$$Ky=KB z + e$$ 因此变为了LWE问题求解。使用babai算法求解最邻近格向量从而求出$z$。

- 官方wp：https://github.com/sixstars/starctf2022/tree/main/crypto-InverseProblem2