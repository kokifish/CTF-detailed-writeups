## 2020_纵横杯--common

比赛日期：2020年12月26日

***TODO 未完成***

记 Wiener equations 和 Guo equations 为

$W_i : e_i d_i g − k_i N = g − k_i s$
$G_{i,j} : k_i d_j e_j − k_j d_i e_i = k_i − k_j$

则 $k_1 k_2 = k_1 k_2, k_2 W_1, g G_{1,2}, W_1 W_2$ 转化成矩阵形式, 有 $x B = v$, 其中

$x = (k_1 k_2, k_2 d_1 g, k_1 d_2 g, d_1 d_2 g^2 )$
$$
B = \begin{bmatrix}
1 & −N & 0 & N^2 \\
& e_1 & −e_1 & −e_1 N \\
& & e_2 & −e_2 N \\
& & & e_1 e_2 \\
\end{bmatrix}
$$
$v = ( k_1 k_2, k_2 (g − k_1 s), g(k_1 − k_2 ), (g − k_1 s)(g − k_2 s) ) $

令 $D = diag(N, N^{1/2}, N^{1+δ}, 1)$, 使其满足 Minkowski’s bound, 有 $||vD|| < vol(L) = |\det(B) \det(D)|$
即 $N^{2(1/2+δ)} < 2N^{(13/2+δ)/4}$, $\delta < 5/14 – \epsilon$.

利用 LLL 求出最短向量 $vD$, 进而求出 $x$, 根据 Wiener’s attack,$\varphi(N) = g(ed-1)/k = \lfloor{edg/k}\rfloor$
有了 $\varphi(N)$ 即可构造一元二次方程分解 $N$.