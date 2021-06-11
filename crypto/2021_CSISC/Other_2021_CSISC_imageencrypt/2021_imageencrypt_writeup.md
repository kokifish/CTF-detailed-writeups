## imageencrypt

题目：见`task.py`和`out`文件

说是对图像进行加密，但是实际上是流密码（也可能图像加密也属于流密码这一范畴）。

题目中有四个未知变量x,r,key1,key2。
1. `out`文件中的testimage和encrypt(testimage)进行异或可以得出有[78,177,169,86]四种结果，分析得到[78,177],[169,86]两组值。

2. 恢复出r，通过手动测试发现r是一个小于1.3而且小数精度只有1位的正数。本来打算的做法是反正r只有少数的情况，直接爆破（暴力模拟）即可。然后有个writeup的做法是通过确定key1和key2的值(不知道怎么确定就模拟4种情况)，然后根据模拟的key值恢复出seqs。接下来模拟r的值，然后通过generate(x)这个函数来进行测试，首先取seqs的前16bit作为x的初始值，然后如果能恢复出seqs的接下来的16bit，那么就表示key1、key2和r都选对了。

3. 因为x的精度有限，因此暴力破解x即可。

4. 因为加密函数使用的是异或运算，因此加密函数即为解密函数，把encrypt(image)进行解密就得到原消息，进行md5哈希后就是flag。

参考writeup：
* 不知道是那个dalao给出的`CISCN Crypto`专门为Crypto方向写的writeup。
* http://www.xl-bit.cn/index.php/archives/434/  程序是这个writeup的，感觉上面那个writeup的程序好像有点问题。

解题程序
```python
# 难点在于求解r这个思路，其它思路都比较简单，因此这里只给出求解r的程序（没测试能不能跑，给个思路）
initial = int(bins[0:16], 2)
x = round(initial / 22000.0, 6)
print initial,x
r = 0.1
while (r < 9.9):
    delta = 9 - 4 * x / r
    if (delta < 0):
        r += 0.1
        # print "gg"
        continue
    x1 = (-3 + math.sqrt(delta)) / -2.0
    x2 = (-3 - math.sqrt(delta)) / -2.0
    if (not (x1 > 0 and x1 < 1) and not (x2 > 0 and x2 < 1)):
        r += 0.1
        # print "gg"
        continue
    next_x = round(r * x * (3 - x), 6)
    if (next_x > 3):
        print (r, "gg")
        break
    next_bin = int(next_x * 22000)
    for i in range(32, 35):
        second = int(bins[16:i], 2)
        # print second, next_bin
        if (abs(second - next_bin) <= 1000):
            print(r, i)
    r += 0.1
```