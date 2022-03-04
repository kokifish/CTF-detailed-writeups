# 2022年TQLCTF—— Crypto —— hardrsa

题目见`hardrsa.py`

看一下题面发现$e$很大，但是$d > 2 * N ** gama$不能直接用Boneh and Durfee。观察参数的生成，$dp,dq$很小因此也是在这里做文章。搜索一下RSA coppersmith CRT-exponent attack就能找到解题方法了（但是实际上还是要找比较久的），有很多相关paper介绍了May’s attack。具体原理是利用题面条件给出等式：$ed_pq=(k−1)(N−q)+N$, 因此双变量多项式 $f_e(x,y)=x(N−y)+N mod e$ 有小根 $(k−1,q)$，使用coppersmith attack就能给出解了，具体写法可以参考exp。出题的时候卡了一下参数，生成参数的时候beta=0.233不是0.223，还是比较影响解题的，如果不知道怎么调参数想出结果还是有点难度的（最后就是不会调参数，看了wp之后发现自己已经写完了，就是参数不对GG）。

其中May一共提出了三个算法(前两个算法在[2]，第三个算法在[1])，然后题目给出的$beta, delta$用第二个算法可以解出。

然后就是自己踩到的坑，本质上是由于界的问题，主要就是求解时的参数$t=\tau m$和界$X,Y$。因为论文中有点理想化，因此求行列式的时候把界写小了，因此这里的参数$t$要适当地增大，直接取$t=3$或$t=5$，这样一般都能解出来。第二个坑就是界$X,Y$的选取，要求$$X=N^{\beta+\delta} \\ Y = N^{\beta}$$ 我们需要意识到方程$$ed_pq=(k−1)(N−q)+N$$ 有小根 $(k−1,q)$，则$X>k-1, Y> q$，因此$Y$可取$N^{\beta}$，但是仔细观察以下注意生成参数的时候$e,d_p,q$都比界要小，因此这里的$Y$会偏小，因此最好就是$Y = N^{\beta} // (2^5)$

以下是我自己写的解题,具体代码见：`crypto/code/May__Unbalanced_prime_and_small_CRT_exponents.sage`

* 参考文献：
  * [1] https://www.iacr.org/archive/pkc2006/39580001/39580001.pdf
  * [2] https://rd.springer.com/content/pdf/10.1007%2F3-540-45708-9_16.pdf
  * [3] https://www.iacr.org/archive/eurocrypt2017/10210359/10210359.pdf

* 官方wp：https://hackmd.summershrimp.com/s/aovEzjSDI#hardrsa


