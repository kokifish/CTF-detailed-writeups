

* 此wp绝大部分是官方wp的内容

⾸先观察 scheme.py， 发现⽣成的私钥是⼀个格的⽐较短的基 $\mathbf{R}$， ⽽公钥则是格的 Hermite normal form 的基 $\mathbf{B}$。 令 $\Lambda=\mathcal{L}(\mathbf{R})=\mathcal{L}(\mathbf{B})$。 签 名的过程是利⽤ $\mathbf{R}$ 与 Babai's rounding technique， 在格 $\Lambda$ 中找到与待签名向量 $\mathbf{v}$ 相近的格向量 $\mathbf{v}'$， 签名为 $\mathbf{e}=\mathbf{v}'-\mathbf{v}$。 验证签名则是 给定 $\mathbf{B}, \mathbf v, \mathbf e$, 验证 $\mathbf v+\mathbf e\in \Lambda$ 且 $\mathbf e$ 的 $\ell_\infty$ ⻓度较短。 可以看出， 这是⼀个 Micciancio 改进的 Goldreich-Goldwasser-Halevi cryptosystem 中的签名算法。

https://rd.springer.com/content/pdf/10.1007%2F11761679_17.pdf   Learning a Parallelepiped: Cryptanalysis of GGH and NTRU Signatures

本题正是利⽤这篇⽂章中的⽅法， 利⽤给出的 32768 个签名， 还原出私钥 $\mathbf{R}$， 达到签名任何消息 的⽬的。 具体⽅法如下。

由 Babai's rounding technique 的性质， 容易发现给出的签名向量⼀定在 $\Lambda$ 的基本平⾏多⾯体 $\mathcal{P}_{1/2}(\mathbf{R})={\mathbf{xR};|;\mathbf{x}\in[-1/2,1/2]^n}$ 内。 我们不妨假设， 签名算法的输出向量 $\mathbf{e}$ 的分布是这个平⾏多⾯体上的⼀个均匀分布。 令 $\mathbf{x}=2\mathbf{e}$，那么 $\mathbf{x}$ 服从 $\mathcal{P}(\mathbf{R})={\mathbf{xR};|;\mathbf{x}\in[-1,1]^n}$ 上的均匀分布。 那么我们有如下结论：
- $\mathbb{E}[\mathbf{ee}^t]=\mathbf{R}^t\mathbf{R}/3$。
- 令 $\mathbf{L}$ 为 $(\mathbf{R}^t\mathbf{R})^{-1}$ 的 Cholesky factor（亦即 $\mathbf{LL}^t=(\mathbf{R}^t\mathbf{R})^{-1}$） 。 则矩阵$\mathbf{C}=\mathbf{RL}$ 的各⾏向量为互相正交的单位向量， $\mathcal{P}(\mathbf{C})$ 为⼀超⽴⽅体， 且 $\mathbf u=\mathbf{xL}$ 服从$\mathcal{P}(\mathbf{C})$ 上的均匀分布。
- 定义 $k$ 阶矩 $\mathrm{mom}{\mathbf{V},k}(\mathbf w)=\mathbb{E}[\langle\mathbf{u},\mathbf{w}\rangle^k]$， 其中 $\mathbf{u}$ 服从 $\mathcal{P}(\mathbf{V})$ 上的均匀分布。 则对于单位球⾯上的 $\mathbf w$， $\mathrm{mom}{\mathbf{C},4}(\mathbf w)$ 的极⼩值为 $1/5$， 且极⼩值点恰为 $\pm \mathbf c_i$， 其中 $\mathbf c_i$ 为 $\mathbf C$ 的各⾏向量。
  
因此， ⾸先我们拿 32768 个签名中的 $\mathbf e$ 估算出 $\mathbf R^t\mathbf R$， 进⽽估算出 $\mathbf L$。 对于每个 $\mathbf e$， 我们算出 $\mathbf u=\mathbf{xL}$， 并利⽤其估算 $\mathrm{mom}{\mathbf{C},4}(\mathbf w)$。 对 $\mathbf w$ 进⾏梯度下降， 即可找到 $\mathrm{mom}{\mathbf{C},4}(\mathbf w)$ 的极⼩值点 $\mathbf c_i$， 也就是 $\mathbf{C}$ 的各⾏向量。 则 $\mathbf c_i\mathbf L^{-1}$ 应该很接近 $\mathbf{R}$ 的某个⾏向量， 也就是⼀个 $\mathcal{L}(\mathbf{B})$ 中的格向量。 我们最后利⽤ embedding technique 求出 $\mathbf c_i\mathbf L^{-1}$ 在 $\mathcal{L}(\mathbf{B})$ 中的CVP， 即能还原出 $\mathbf{R}$ 中的⼀⾏。 重复⾜够多次， 就可以还原出整个私钥 $\mathbf R$。⼀个技巧是观察 $\mathbf{R}$ 的构造过程， 可以发现它是由单位矩阵的若⼲倍加上⼀个⼩扰动⽽成的。 因此我们在选取梯度下降中 $\mathbf w$ 的初值时直接选取各个标准基中的单位向量， 既能定向得到不同的$\mathbf R$ 的⾏向量， 也可以减少梯度下降所需的迭代数量。