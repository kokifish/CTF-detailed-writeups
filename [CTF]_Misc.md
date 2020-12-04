# Misc

Misc 是英文 Miscellaneous 的前四个字母，杂项、混合体、大杂烩的意思

Misc 在国外的比赛中其实又被具体划分为各个小块，有

- Recon
- Forensic
- Stego
- Misc
- ...

在国内的比赛中，被统一划分入 Misc 领域，有时 Crypto（尤其是古典密码）也被划入其中



# Information Gathering Technology

> 信息搜集技术



# Code Analysis



## Commonly Used Coding in the Communication Field

电话拨号编码：1-9 分别使用 1-9 个脉冲，0 则表示使用 10 个脉冲

Morse编码

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/Misc_morse.jpg)

> 莫尔斯编码在线转换 http://www.zhongguosou.com/zonghe/moErSiCodeConverter.aspx

敲击码

曼彻斯特编码

格雷编码





## Computer Related Coding



### ASCII编码

### Base编码

### 霍夫曼编码

### URL编码

- 大量的百分号

### Unicode编码

有四种表现形式。



e.g. 源文本： `The`

&#x [Hex]: `The`

&# [Decimal]: `The`

\U [Hex]: `\U0054\U0068\U0065`

\U+ [Hex]: `\U+0054\U+0068\U+0065`

## Commonly Used Encodings in the Real World

条形码

二维码

# Forensic Steganography

> 隐写

任何要求检查一个静态数据文件从而获取隐藏信息的都可以被认为是隐写取证题（除非单纯地是密码学的知识），一些低分的隐写取证又常常与古典密码学结合在一起，而高分的题目则通常用与一些较为复杂的现代密码学知识结合在一起



# Image Analysis

- 元数据（Metadata），又称中介数据、中继数据，为描述数据的数据（Data about data），主要是描述数据属性（property）的信息，用来支持如指示存储位置、历史数据、资源查找、文件记录等功能。





## Cases

- breakin-ctf-2017_misc_Mysterious-GIF：gif文件中分离出zip，zip中分离出多个小zip，解压得到partxx.enc，在gif的元数据comment中找到私钥，对.enc文件进行RSA解密，连接成一个图片文件





# Traffic Packet Analysis





#### PcapPlusPlus Build on Linux

> installation case on Fedora30

```python
git clone https://github.com/seladb/PcapPlusPlus.git
cd PcapPlusPlus/
./configure-linux.sh --default
make all
sudo make install
```





# Compressed Package Analysis

> 压缩包分析







# Audio Steganography

> 音频隐写

与音频相关的 CTF 题目主要使用了隐写的策略，主要分为 MP3 隐写，LSB 隐写，波形隐写，频谱隐写等等







# Disk Memory Analysis

> 磁盘内存分析





# Other





## pyc File