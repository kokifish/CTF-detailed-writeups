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

> 信息搜集技术   社会工程学相关的题目也列在这



# Code Analysis

> 编码有关的分析

## Coding in the Communication

电话拨号编码：1-9 分别使用 1-9 个脉冲，0 则表示使用 10 个脉冲

### Morse编码

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/Misc_morse.jpg)

> 莫尔斯编码在线转换 http://www.zhongguosou.com/zonghe/moErSiCodeConverter.aspx
>
> 音频morse解码 https://morsecode.world/international/decoder/audio-decoder-adaptive.html

**字母**

| 字符 | 电码符号 | 字符 | 电码符号 | 字符 | 电码符号 | 字符 | 电码符号 |
| ---- | -------- | ---- | -------- | ---- | -------- | ---- | -------- |
| A    | ．━      | B    | ━．．．  | C    | ━ ．━．  | D    | ━ ．．   |
| E    | ．       | F    | ．．━．  | G    | ━ ━．    | H    | ．．．． |
| I    | ．．     | J    | ．━ ━ ━  | K    | ━ ．━    | L    | ．━．．  |
| M    | ━ ━      | N    | ━．      | O    | ━ ━ ━    | P    | ．━ ━．  |
| Q    | ━ ━．━   | R    | ．━ ．   | S    | ．．．   | T    | ━        |
| U    | ．．━    | V    | ．．．━  | W    | ．━ ━    | X    | ━ ．．━  |
| Y    | ━．━ ━   | Z    | ━ ━ ．． |      |          |      |          |

**数字长码**

| 字符 | 电码符号   | 字符 | 电码符号   | 字符 | 电码符号  | 字符 | 电码符号  |
| ---- | ---------- | ---- | ---------- | ---- | --------- | ---- | --------- |
| 0    | ━ ━ ━ ━ ━  | 1    | ．━ ━ ━ ━  | 2    | ．．━ ━ ━ | 3    | ．．．━ ━ |
| 4    | ．．．．━  | 5    | ．．．．． | 6    | ━．．．． | 7    | ━ ━．．． |
| 8    | ━ ━ ━ ．． | 9    | ━ ━ ━ ━ ． |      |           |      |           |

**标点符号**

| 字符 | 电码符号    | 字符 | 电码符号    | 字符 | 电码符号      | 字符 | 电码符号    |
| ---- | ----------- | ---- | ----------- | ---- | ------------- | ---- | ----------- |
| .    | ．━．━ ．━  | :    | ━ ━ ━．．． | ,    | ━ ━．．━ ━    | ;    | ━．━ ．━．  |
| ?    | ．．━ ━．． | =    | ━ ．．．━   | '    | ．━ ━ ━ ━ ．  | /    | ━．．━ ．   |
| !    | ━．━ ．━ ━  | ━    | ━．．．．━  | _    | ．．━ ━．━    | "    | ．━ ．．━． |
| (    | ━ ．━ ━ ．  | )    | ━．━ ━．━   | $    | ．．．━ ．．━ | &    | ．．．．    |
| @    | ．━ ━．━ ． | +    | ．━．━．    |      |               |      |             |





敲击码

曼彻斯特编码

格雷编码





## Computer Related Coding



### ASCII编码

![](ascii_table_black.png)

### Base编码

> 转码  https://gchq.github.io/CyberChef/

### 核心价值观编码
http://www.hiencode.com/cvencode.html

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

> 生活中常用的编码

### 条形码

- 在线识别  https://online-barcode-reader.inliteresearch.com/

### QR Code

二维码(QR Code, UR Code)

* 条形码与二维码在线识别  https://online-barcode-reader.inliteresearch.com/

## Other Code/Language/Algorithm

https://www.dangermouse.net/esoteric/

* npiet语言：使用图像进行编程  ``2021红帽杯初赛colorful code``

### 零宽隐写
* 零宽度字符
零宽度字符是一种字节宽度为0的不可打印的Unicode字符, 在浏览器等环境不可见, 但是真是存在, 获取字符串长度时也会占位置, 表示某一种控制功能的字符。

```unicode
零宽空格（zero-width space, ZWSP）用于可能需要换行处。
    Unicode: U+200B  HTML: &#8203;
零宽不连字 (zero-width non-joiner，ZWNJ)放在电子文本的两个字符之间，抑制本来会发生的连字，而是以这两个字符原本的字形来绘制。
    Unicode: U+200C  HTML: &#8204;
零宽连字（zero-width joiner，ZWJ）是一个控制字符，放在某些需要复杂排版语言（如阿拉伯语、印地语）的两个字符之间，使得这两个本不会发生连字的字符产生了连字效果。
    Unicode: U+200D  HTML: &#8205;
左至右符号（Left-to-right mark，LRM）是一种控制字符，用于计算机的双向文稿排版中。
    Unicode: U+200E  HTML: &lrm; &#x200E; 或&#8206;
右至左符号（Right-to-left mark，RLM）是一种控制字符，用于计算机的双向文稿排版中。
    Unicode: U+200F  HTML: &rlm; &#x200F; 或&#8207;
字节顺序标记（byte-order mark，BOM）常被用来当做标示文件是以UTF-8、UTF-16或UTF-32编码的标记。
    Unicode: U+FEFF
```
在010editor中打开常见的字符为`E2 80 8D`和`E2 80 8C`

* 原理不知道没太大关系，真正要深入的时候再深入也不迟，首先要知道怎样玩
https://330k.github.io/misc_tools/unicode_steganography.html



---

# Forensic Steganography

> 隐写取证   由于隐写取证分析过程与目标载体关联较大，将按照载体来列举隐写取证的知识与案例

任何要求检查一个静态数据文件从而获取隐藏信息的都可以被认为是隐写取证题（除非单纯地是密码学的知识），一些低分的隐写取证又常常与古典密码学结合在一起，而高分的题目则通常用与一些较为复杂的现代密码学知识结合在一起。









# Image Analysis

- 元数据（Metadata），又称中介数据、中继数据，为描述数据的数据（Data about data），主要是描述数据属性（property）的信息，用来支持如指示存储位置、历史数据、资源查找、文件记录等功能。
- 常用图像隐写套路
  https://blog.csdn.net/u012486730/article/details/82016706
  
- 常见ctf图像隐写工具
    - Stegsolve 
    - F5-steganography

- 文件格式查询网站
https://www.fileformat.info/format/cloud.htm

## PNG

  文件格式：
1. http://www.libpng.org/pub/png/spec/1.2/PNG-Contents.html
2. https://www.fileformat.info/format/png/egff.htm
    - 常见隐写：图像宽度；图像数据块IDAT（衣服图片可能有多个块进行信息隐藏）；LSB信息隐藏



**Cases**

- 2021DASCTF实战精英夏令营暨DASCTF July X CBCTF 4th, ezSteganography: 用stegsolve打开后，从red通道lsb看到提示；然后stegsolve -> Analyse -> Data Extract -> 只勾选Green 0，点save bin，出来的是个png图像，打开后可以看到flag的上半部分；用QIM quantization(step=20)对图片做提取，得到水印图，得到剩下的一半flag





## JPEG

1. https://www.cnblogs.com/senior-engineer/p/9548347.html
2. https://www.fileformat.info/format/jpeg/egff.htm
    - 隐写软件：Stegdetect；JPHS；SilentEye

**Cases**

- information_hiding_2021chunqiubei_fungame_snowww 把jpg文件中隐藏的信息先提取，然后发现是原图加上水印程序，我们需要写出逆向的水印函数就可以把水印恢复出来，水印就是flag。



## GIF
> https://www.fileformat.info/format/gif/egff.htm

- gif图片隐写方案：**空间轴**(由于 GIF 的动态特性，由一帧帧的图片构成，所以每一帧的图片，多帧图片间的结合，都成了隐藏信息的一种载体)； **时间轴**(GIF 文件每一帧间的时间间隔也可以作为信息隐藏的载体)



## SVG
- SVG(Scalable Vector Graphics)是一种基于XML的二维矢量图格式，和我们平常用的jpg/png等图片格式所不同的是SVG图像在放大或改变尺寸的情况下其图形质量不会有所损失，并且我们可以使用任何的文本编辑器打开SVG图片并且编辑它，目前主流的浏览器都已经支持SVG图片的渲染。
- 可以向svg图片里插入一个JavaScript代码或进行XSS


**Cases**

- breakin-ctf-2017_misc_Mysterious-GIF：gif文件中分离出zip，zip中分离出多个小zip，解压得到partxx.enc，在gif的元数据comment中找到私钥，对.enc文件进行RSA解密，连接成一个图片文件



# Audio Steganography

> 音频隐写
>
> https://www.sqlsec.com/2018/01/ctfwav.html
>
> https://ctf-wiki.org/misc/audio/introduction/

与音频相关的 CTF 题目主要使用了隐写的策略，主要分为：

* MP3 隐写 （工具： Mp3Stego http://www.petitcolas.net/steganography/mp3stego/）
* LSB 隐写 （工具： Silenteye）
* 波形隐写 （工具：**AutoStitch**(较简单) 或 Adobe Audition）
* 频谱隐写
* 等等





# Compressed Package Analysis

> 压缩包分析

## ZIP

CTF中ZIP压缩包的考察一般都是把压缩包进行加密，然后尝试把ZIP的加密给破解。

> 主要攻击

* 爆破
  * Windows下的神器 **ARCHPR** http://www.downcc.com/soft/130539.html
  * Linux 下的命令行工具 **fcrackzip** https://github.com/hyc/fcrackzip
  * **Advanced Zip Password Recovery** http://down.40huo.cn/misc/AZPR_4.0.zip
* CRC32
  * 表示的是冗余校验码，长为32bit，在png和zip文件中常见。然而在zip文件中的crc32使用的是明文做的校验码，因此当zip文件的（明文非常短，密码非常长）的时候可以直接爆破求解zip的明文。
* 已知明文攻击
  * 要求：一个加密的压缩文件；已知压缩工具及加密算法；**已知压缩包里某个文件的部分连续内容 (至少 12 字节)**
  * 攻击步骤：首先获得已知明文的信息，其次确定压缩算法，然后使用下述工具进行明文攻击。
  * 工具：
    * Windows： **ARCHPR** http://www.downcc.com/soft/130539.html
    * Linux：**PKCrack** http://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack.html
* 伪加密
  * 原理：在上文 ZIP 格式中的核心目录区中，有个通用位标记 (General purpose bit flag) 的 2 字节，不同比特位有着不同的含义。有些zip文件没有加密但是把这个标记设置成加密，这就是伪加密。
  * 破解
    * 16 进制下修改通用位标记
    * ``binwalk -e`` 无视伪加密
    * 在 Mac OS 及部分 Linux(如 Kali ) 系统中，可以直接打开伪加密的 ZIP 压缩包
    * 检测伪加密的小工具 ``ZipCenOp.jar``
    * 有时候用 ``WinRar`` 的修复功能（此方法有时有奇效，不仅针对伪加密）

## RAR

RAR 文件主要由标记块，压缩文件头块，文件头块，结尾块组成。详细格式见：https://forensicswiki.xyz/wiki/index.php?title=RAR

> 主要攻击

* 爆破
  * Linux 下的 **RarCrack** http://rarcrack.sourceforge.net/
  * **Advanced Rar Password Recovery** http://down.40huo.cn/misc/AdvancedRARPassword.zip
* 伪加密
  * 在RAR文件的``File Header``中，第三个字段为``HEAD_FLAGS``，有2字节，这两个字节中的第三个bit表示的是是否加密。有时候RAR文件没有加密但会把此bit设置为加密，这就是伪加密。破解伪加密只要把字段去除即可。



# Office: Docx, Xlsx, Pdf, etc

- xctf-2020-huaweictf misc:s34hunka: 一个xls以单元格背景颜色保存的图片，看起来像是图像隐写，实际上主要是信息检索，使用网上的原版与给出的、转为图片后的版本进行对照，像素差异处则为flag。



# Network

> 网址查IP: https://www.ipaddress.com/   改host时可以在这里查ip。还有Whois Lookup等

## Traffic Packet Analysis

通常比赛中会提供一个包含流量数据的 PCAP 文件，有时候也会需要选手们先进行修复或重构传输文件后，再进行分析。

* 流量包修复工具：
    * https://f00l.de/hacking/pcapfix.php   **PcapFix Online**
    * https://github.com/Rup0rt/pcapfix/tree/devel  **PcapFix**

* 常用流量包分析工具
    * tshark （tshark 作为 wireshark 的命令行版, 高效快捷是它的优点, 配合其余命令行工具 (awk,grep) 等灵活使用, 可以快速定位, 提取数据从而省去了繁杂的脚本编写）
    * PcapPlusPlus (后面有介绍)

### USB Traffic Analysis

> https://blog.csdn.net/qq_43625917/article/details/107723635 USB流量，含键盘鼠标

- 文件类型一般为pcap

分析步骤：

1. 提取capdata: `tshark -r usb.pcap -T fields -e usb.capdata > usbdata.txt`
   `tshark -r usb.pcap -T fields -e usb.capdata | sed '/^\s*$/d' > usbdata.txt ` (提取并去除空行)
2. 使用脚本加上冒号
3. 提取键盘信息

```python
# 加上冒号
f=open('usbdata.txt','r')
fi=open('out.txt','w')
while 1:
    a=f.readline().strip()
    if a:
        if len(a)==16: # 鼠标流量的话len改为8
            out=''
            for i in range(0,len(a),2):
                if i+2 != len(a):
                    out+=a[i]+a[i+1]+":"
                else:
                    out+=a[i]+a[i+1]
            fi.write(out)
            fi.write('\n')
    else:
        break
fi.close()
```

```python
# 还原键盘信息的脚本
normalKeys = {
    "04":"a", "05":"b", "06":"c", "07":"d", "08":"e",
    "09":"f", "0a":"g", "0b":"h", "0c":"i", "0d":"j",
     "0e":"k", "0f":"l", "10":"m", "11":"n", "12":"o",
      "13":"p", "14":"q", "15":"r", "16":"s", "17":"t",
       "18":"u", "19":"v", "1a":"w", "1b":"x", "1c":"y",
        "1d":"z","1e":"1", "1f":"2", "20":"3", "21":"4",
         "22":"5", "23":"6","24":"7","25":"8","26":"9",
         "27":"0","28":"<RET>","29":"<ESC>","2a":"<DEL>", "2b":"\t",
         "2c":"<SPACE>","2d":"-","2e":"=","2f":"[","30":"]","31":"\\",
         "32":"<NON>","33":";","34":"'","35":"<GA>","36":",","37":".",
         "38":"/","39":"<CAP>","3a":"<F1>","3b":"<F2>", "3c":"<F3>","3d":"<F4>",
         "3e":"<F5>","3f":"<F6>","40":"<F7>","41":"<F8>","42":"<F9>","43":"<F10>",
         "44":"<F11>","45":"<F12>"}
shiftKeys = {
    "04":"A", "05":"B", "06":"C", "07":"D", "08":"E",
     "09":"F", "0a":"G", "0b":"H", "0c":"I", "0d":"J",
      "0e":"K", "0f":"L", "10":"M", "11":"N", "12":"O",
       "13":"P", "14":"Q", "15":"R", "16":"S", "17":"T",
        "18":"U", "19":"V", "1a":"W", "1b":"X", "1c":"Y",
         "1d":"Z","1e":"!", "1f":"@", "20":"#", "21":"$",
          "22":"%", "23":"^","24":"&","25":"*","26":"(","27":")",
          "28":"<RET>","29":"<ESC>","2a":"<DEL>", "2b":"\t","2c":"<SPACE>",
          "2d":"_","2e":"+","2f":"{","30":"}","31":"|","32":"<NON>","33":"\"",
          "34":":","35":"<GA>","36":"<","37":">","38":"?","39":"<CAP>","3a":"<F1>",
          "3b":"<F2>", "3c":"<F3>","3d":"<F4>","3e":"<F5>","3f":"<F6>","40":"<F7>",
          "41":"<F8>","42":"<F9>","43":"<F10>","44":"<F11>","45":"<F12>"}
output = []
keys = open('out.txt')
for line in keys:
    try:
        if line[0]!='0' or (line[1]!='0' and line[1]!='2') or line[3]!='0' or line[4]!='0' or line[9]!='0' or line[10]!='0' or line[12]!='0' or line[13]!='0' or line[15]!='0' or line[16]!='0' or line[18]!='0' or line[19]!='0' or line[21]!='0' or line[22]!='0' or line[6:8]=="00":
             continue
        if line[6:8] in normalKeys.keys():
            output += [[normalKeys[line[6:8]]],[shiftKeys[line[6:8]]]][line[1]=='2']
        else:
            output += ['[unknown]']
    except:
        pass

keys.close()

flag=0
print("".join(output))
for i in range(len(output)):
    try:
        a=output.index('<DEL>')
        del output[a]
        del output[a-1]
    except:
        pass

for i in range(len(output)):
    try:
        if output[i]=="<CAP>":
            flag+=1
            output.pop(i)
            if flag==2:
                flag=0
        if flag!=0:
            output[i]=output[i].upper()
    except:
        pass

print ('output :' + "".join(output))
```





# Disk Memory Analysis

> 磁盘内存分析 (取证)

常用工具 
* EasyRecovery 
    * 支持从各种存储介质恢复删除、格式化或者丢失的文件，支持的媒体介质包括：硬盘驱动器、光驱、闪存、以及其它多媒体移动设备。无论文件是被命令行方式删除，还是被应用程序或者文件系统删除，EasyRecovery都能实现恢复，甚至能重建丢失的RAID。
* FTK（司法智能分析软件）电子物证分析软件，执行自动、完整、彻底的计算机电子取证检查
    * 官网 https://accessdata.com/
    * 可以去下破解版
* Elcomsoft Forensic Disk Decryptor 
    * http://down.40huo.cn/misc/efdd_setup_en.msi
    * http://down.40huo.cn/misc/Elcomsoft.Forensic.Disk.Decryptor.CracKed.By.Hmily.LCG.rar
* Volatility (内存取证)
* NTFS 流文件 **Alternate Stream View** http://down.40huo.cn/misc/alternatestreamview.zip

> 常见磁盘格式
Windows: FAT12 -> FAT16 -> FAT32 -> NTFS
Linux: EXT2 -> EXT3 -> EXT4
删除文件：目录表中文件名第一字节 e5。

> VMDK文件

VMDK 文件本质上是物理硬盘的虚拟版，也会存在跟物理硬盘的分区和扇区中类似的填充区域，我们可以利用这些填充区域来把我们需要隐藏的数据隐藏到里面去，这样可以避免隐藏的文件增加了 VMDK 文件的大小（如直接附加到文件后端），也可以避免由于 VMDK 文件大小的改变所带来的可能导致的虚拟机错误。而且 VMDK 文件一般比较大，适合用于隐藏大文件。



## Volatility内存取证

> 这里提供快速入门和常用的命令

Volatility是一款开源的内存取证分析工具，由python编写，支持各种操作系统。
下载地址：https://www.volatilityfoundation.org/26
这里只介绍release版本的用法，在kali系统上下载volatility的Linux版本，得到的是一个可执行文件。因此通过volatility进行内存取证的时候就需要该可执行文件进行帮助。我们把该文件命名为volatility。

Document：https://github.com/volatilityfoundation/volatility 官网和文档都在里面，不使用release版本可以直接下载源代码，make后根据文档介绍来使用。

这里给出
**Usage**：这是volatility使用的格式
`volatility [command option] [image] [plugin]`
`volatility -f [image] --profile=[profile] [plugin]`
命令行选项决定volatility要做什么，`image`表示需要审计的镜像文件，`profile`指定镜像文件的操作系统，`plugin`代表一系列代码，表示的是对镜像文件执行某个`plugin`关联的代码，并给出执行后的结果。

* `volatility -h` 查看帮助文档
* `volatility [plugin] -h` 查看某个`plugin`的帮助文档
* `volatility -f 1.raw imageinfo` `-f`选项后跟一个需要进行审计的镜像文件，再后面跟着的是插件`[plugin]`的名称，表示对`1.raw`文件执行`imageinfo`插件的逻辑。这里`imageinfo`插件表示的是查看镜像系统的信息，一般用来确定当前镜像文件的系统。
* `volatility -f 1.raw --profile=Win7SP0x86 volshell` 把`1.raw`文件指定为Win7SP0x86系统的文件(默认profile设置的就是这个，但是也有可能通过`imageinfo`查到的是别的系统)，然后执行在镜像文件中打开shell。
* `volatility -f 1.raw --profile=Win7SP0x86 pslist` 列出`1.raw`正在运行的进程。

以上是内存取证最常用的步骤，下面再介绍一些常用的插件，插件的具体细节使用`volatility [plugin] -h`命令查看

* `memdump` 转储进程的可寻址内存，用`-p`参数指定进程号，`-D`指定dump出来的文件的本地存储位置。
* `hivelist` 列举注册表
* `iehistory` 查看浏览器浏览记录
* `filescan` 扫描内存中所有文件
* `dumpfiles` 提取文件，可以用`-Q`参数指定文件的内存地址
* `cmdscan` 查看cmd中命令的使用情况
* `cmdline` Display process command-line arguments

参考题目：祥云杯 2021 考古






# Git Leak

> git 泄露

- 工具：scrabble

# Other





## pyc File

> 该部分内容在reverse.md内的`.pyc`章节内





# Tools Lookup Table

- StegSolve: jave app，可查看LSB隐写，提取各层数据，查看各通道各层的二值图。
- binwalk: Linux命令行工具，可识别文件中隐藏的其他文件格式(特征字串匹配)
- ctftools.com:   https://ctftools.com/down/   大杂烩，编码、web、隐写、漏洞扫描什么的都有，大多提供的是软件下载
- CyberChef: https://gchq.github.io/CyberChef/   编码、隐写、格式、压缩包、流量等