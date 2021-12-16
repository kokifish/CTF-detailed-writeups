# 2021年西湖论剑CTF—— Crypto —— hardRSA

题目见`hardrsa.py`

首先根据y,c1,g求解离散对数得到x。由于y是光滑的，因此可以使用Polig-Hellmen攻击求解，Sagemath调库就行。然后根据x开四次方求解出p，然后根据dp和p求解出m。能求解的原因是$m<p$。


