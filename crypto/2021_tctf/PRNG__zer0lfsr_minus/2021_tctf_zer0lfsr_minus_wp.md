# 2021年TCTF—— Crypto —— zer0lfsr-minus

## 题目
见当前目录的`task.py`文件

题目给了3个LFSR和NFSR的只要选2个解出key就行了。这里看Generator的难度一般就选1和3。
看这个题目形式，与2019年0CFT比赛中的一道叫zer0lfsr的题目相类似，参考    
https://www.anquanke.com/post/id/184828?from=groupmessage 以及 https://fireshellsecurity.team/0ctf-zer0lfsr/
这道题是直接可以用z3解出来的。
但是这道题目，直接用前120个bits去用z3解就行了。参照当年的题目写成z3的形式然后solve一下里面算一算就行了。
注意一下Generator的形式，传入参数的时候需要修改一下。然后用Solver()直接解就可以了

但是可以把变量换成64个Bool，更符合这里LFSR的形式。把Generator里面的运算都换成z3的API，然后直接让他解就行了。

参考writeup中说：需要注意的是LFSR和NFSR的内部状态每次推的时候都最好simplify一下，不然时间过不了。
然后我实际写程序测试了一下只需要在Solver对象的add成员函数中把约束条件加上simplify就可以了。通过实际测试发现第二个Generator使用z3求解过慢，无法解出结果。

题解：
见``solution.py``文件

参考writeup: WaterDrop战队writeup