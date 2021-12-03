# Abused Key


## 目标方案
Server通过如下两个协议为合法的Client提供秘密信道建立服务，和安全的***flag/hint***传输服务：

### 协议一
协议一是Client-Server形式的认证密钥交换方案，在双方建立会话密钥后，Server将flag使用会话密钥进行加密发送给Client。协议中使用的是secp256k1曲线，$G$表示椭圆曲线群的生成元，$n$是阶数。Client和Server的公私钥对分别是$(d_C,P_C)$和$(d_S,P_S)$，其中$P_=d_C⋅G$和$P_S=d_S⋅G$；$sid_1$是32字节长的随机session id；$\mathcal{H}$是抗碰撞的哈希函数SHA256；$\{K\}_x$表示椭圆曲线点$K$的x坐标；$sk$表示32字节的会话密钥；$||$代表前后两个16进制字符串进行连接；$E_{sk}(\cdot)$和$D_{sk}(\cdot)$分别代表以$sk$为对称密钥，使用AES256算法和GCM(iv长度为12字节，mac长度为16字节)模式进行加解密。协议流程：
__________
__________

&emsp; &emsp; &emsp;&emsp;&emsp; Client($P_C,d_C$) &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;Server($P_S,d_S$)

&emsp;&emsp;&emsp;&emsp;$sid_1 \stackrel{R}{\leftarrow} \{0,1\}^{256}$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; $\underrightarrow{\qquad \ \ \ \ msg_{11} = sid_1 \qquad \ \ \ \ \ }$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;$t_S \stackrel{R}{\leftarrow} {\mathbb Z}_p^*$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;$T_S = t_S \cdot G$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; $\underleftarrow{\qquad \ \ \ \ \ msg_{12} = T_S \qquad \ \ \ \ \ }$

&emsp;&emsp;&emsp;&emsp;$t_C \stackrel{R}{\leftarrow} {\mathbb Z}_p^*$

&emsp;&emsp;&emsp;&emsp;$T_C = r_C \cdot G$

&emsp;&emsp;&emsp;&emsp;$K_{CS} = (d_C+t_C)\cdot T_S + t_C\cdot P_S$

&emsp;&emsp;&emsp;&emsp;$sk_1 = \mathcal{H}(\{K_{CS}\}_x)$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;$\underrightarrow{\qquad \ msg_{13} = sid_1||T_C\qquad \ }$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;$K_{CS} = (d_S+t_S)\cdot T_C + t_S\cdot P_C$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;$sk_1 = \mathcal{H}(\{K_{CS}\}_x)$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;$C_{flag} = E_{sk_1}(flag)$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; $\underleftarrow{\qquad \ \ \ msg_{14} = C_{flag} \qquad \ \ \ \ }$

&emsp;&emsp;&emsp;&emsp;$flag = D_{sk_1}(C_{flag})$
__________
__________

### 协议二
协议二是一个三方口令认证协议，合法的Client在TTP（Trusted Third Party）的帮助下完成，与Server完成双向认证。在协议中，$sid_2$是32字节长的随机session id；$\pi_C$和$\pi_S$分别是Client和Server的口令(password)，仅有2字节长；其他参数与协议一类似。协议流程如下：
__________
__________

&emsp; &emsp; &emsp;$Client(\pi_C)$ &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; $Server(\pi_S)$ &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;  $TTP(\pi_C, \pi_S)$


&emsp;&emsp;$sid_2 \stackrel{R}{\leftarrow} \{0,1\}^{256}$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;$\underrightarrow{\ \ \ \ \ \ \ \ msg_{21} = sid_2 \ \ \ \ \ \ \ }$

&emsp;&emsp;&emsp;&emsp;&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;$r_S \stackrel{R}{\leftarrow} {\mathbb Z}_p^*$

&emsp;&emsp;&emsp;&emsp;&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp; $R_S = r_S \cdot G$

&emsp;&emsp;&emsp;&emsp;&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp; $h_S = \mathcal{H}(\pi_S)$

&emsp;&emsp;&emsp;&emsp;&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp; $Q_S = h_S \cdot R_S$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;$\underleftarrow{\ \ \ \ \ \ \ \ msg_{22} = Q_S\ \ \ \ \ \ \ \ }$

&emsp; &emsp; &emsp; $r_C \stackrel{R}{\leftarrow} {\mathbb Z}_p^*$

&emsp; &emsp; $R_C = r_C \cdot G$

&emsp; &emsp; $h_C = \mathcal{H}(\pi_C)$

&emsp; &emsp; $Q_C = h_C \cdot R_C$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; $\underrightarrow{\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ msg_{23} = Q_C||Q_S\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ }$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; $r_T \stackrel{R}{\leftarrow} {\mathbb Z}_p^*$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; $h_C = \mathcal{H}(\pi_C)$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; $h_S = \mathcal{H}(\pi_S)$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; $Y_C = r_T\cdot(h_C^{-1} \cdot Q_C)$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; $Y_S = r_T\cdot(h_S^{-1} \cdot Q_S)$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; $\underleftarrow{\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ msg_{24} = Y_C||Y_S\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ }$


&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; $\underrightarrow{\ \ \ \ \ msg_{25} = sid_2 || Y_C\ \ \ \ }$

&emsp;&emsp;&emsp;&emsp;&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp; $Z_{CS} = r_S \cdot Y_C$

&emsp;&emsp;&emsp;&emsp;&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp; $sk_2 = \mathcal{H}(\{Z_{CS}\}_x)$

&emsp;&emsp;&emsp;&emsp;&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp; $C_{hint} = E_{sk_2}(hint)$

&emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; $\underleftarrow{\ \ \ \ \ \ \ msg_{26} = C_{hint}\ \ \ \ \ \ \ }$

&emsp; $Z_{CS} = r_C \cdot Y_S$

&emsp; $sk_2 = \mathcal{H}(\{Z_{CS}\}_x)$

&emsp; $hint = D_{sk_2}(C_{hint})$
__________
__________


## 题目描述
Server和TTP为Client提供了两个协议实例，在工程实现层面，为Client提供了5个http接口，要求选手在拥有有限数据信息的情况下，尝试扮演Client并获得flag；成功执行完协议二可以获得hint，可能对选手解题提供一定帮助。

密钥/口令设置：
* 在两个协议中，Server的私钥/口令哈希，都源自同一个2字节口令，即$\pi_S \in \{0,1\}^{32}$，并且$d_S = {\mathcal H}(\pi_S)$；
* 选手已知Client的口令，该口令的16进制字符串形式表示为$\pi_C$='FFFF'，长度同样是2字节；
* Server的公私钥对，选手未知；
* 选手已知Client的公钥$P_C$='b5b1b07d251b299844d968be56284ef32dffd0baa6a0353baf10c90298dfd117' + 'ea62978d102a76c3d6747e283091ac5f2b4c3ba5fc7a906fe023ee3bc61b50fe'，长度是64字节。

算法和参数设置：
* 请求数据均以16进制字符串发送给接口，大小写均可，接口也会返回16进制的响应数据；多个元素时按照协议流程图中的排列顺序将字符串拼接起来：
  * 会话发起时使用的session id，包括$sid_1$和$sid_2$，为32字节随机数；
  * 椭圆曲线点为64字节转化成的字符串；
* 大整数和字节数组之间按照**Big Endian**方式转换。

网络请求/响应设置
* 五个http路由，均为GET请求：
  * @abusedkey.route('/abusedkey/server/msg11', methods=['GET'])
  * @abusedkey.route('/abusedkey/server/msg13', methods=['GET'])
  * @abusedkey.route('/abusedkey/server/msg21', methods=['GET'])
  * @abusedkey.route('/abusedkey/ttp/msg23', methods=['GET'])
  * @abusedkey.route('/abusedkey/server/msg25', methods=['GET'])
* 发送get请求使用 requests.get(url, data='abcd').text 来得到响应，其中'abcd'为选手发送的16进制数据内容。
