# 2021年广东省强网杯团体赛—— Crypto —— RSA_and_BASE
题目见`task.txt`

* 题解
题目首先给出了一个RSA的参数，看到$e$很大马上联想到小解密指数攻击，见`Crypto.md`。
解出$d$后解密得到一个`flag{TCMDIEOH2MJFBLKHT2J7BLYZ2WUE5NYR2HNG====}`然后题目还给出了一个`GHI45FQRSCX****UVWJK67DELMNOPAB3`，是换表base32。

参考wp: https://www.zhihu.com/people/ZM_________J/posts

