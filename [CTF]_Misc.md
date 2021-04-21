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

### Morse编码

![](https://raw.githubusercontent.com/hex-16/pictures/master/CTF_pic/Misc_morse.jpg)

> 莫尔斯编码在线转换 http://www.zhongguosou.com/zonghe/moErSiCodeConverter.aspx

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

> 生活中常用的编码

条形码

二维码(UR Code)

# Forensic Steganography

> 隐写取证

任何要求检查一个静态数据文件从而获取隐藏信息的都可以被认为是隐写取证题（除非单纯地是密码学的知识），一些低分的隐写取证又常常与古典密码学结合在一起，而高分的题目则通常用与一些较为复杂的现代密码学知识结合在一起





## Cases

- xctf-2020-huaweictf misc:s34hunka: 一个以单元格背景颜色保存的图片，看起来像是图像隐写，实际上主要是信息检索，使用网上的原版与给出的、转为图片后的版本进行对照，像素差异处则为flag。





# Image Analysis

- 元数据（Metadata），又称中介数据、中继数据，为描述数据的数据（Data about data），主要是描述数据属性（property）的信息，用来支持如指示存储位置、历史数据、资源查找、文件记录等功能。





## Cases

- breakin-ctf-2017_misc_Mysterious-GIF：gif文件中分离出zip，zip中分离出多个小zip，解压得到partxx.enc，在gif的元数据comment中找到私钥，对.enc文件进行RSA解密，连接成一个图片文件





# Traffic Packet Analysis



## USB Traffic Analysis

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





## PcapPlusPlus

> https://pcapplusplus.github.io/docs/tutorials/intro

- PcapPlusPlus is built of 3 libraries: Common++, Packet++ and Pcap++.

### Packet++

- 解析、创建、编辑多种支持的协议的包的库
- 可以独立运行，不依赖于Pcap++, libpcap/WinPcap/Npcap等

主要类与功能:

1. `RawPacket`: 表示从网络捕获的原始数据
2. `Layer`: 所有协议层的基类。每个协议层负责解析属于该协议的数据包中的特定字节
3. `Packet` - representing a packet that was parsed by the different PcapPlusPlus protocol parsers and contains the different protocol layers
4. Protocol layers (e.g. `EthLayer, IPv4Layer, IPv6Layer, TcpLayer, UdpLayer, DnsLayer, HttpRequestLayer, HttpResponseLayer, PayloadLayer`, etc.) - classes representing specific protocol parsers. 都继承了 `Layer` class
5. `PacketUtils`: 包含多种常用功能的类。e.g. 计算5元组/2元组的哈希值
6. `TcpReassembly`: TCP重组(a.k.a TCP reconstruction) of TCP streams
7. `IPv4Reassembly` - a class for providing IPv4 reassembly (a.k.a IPv4 de-fragmentation) of IPv4 packets

### Pcap++

- 拦截、发送数据包，提供网络、网卡信息，统计数据等的库
- 主要是包捕获引擎(libpcap, WinPcap, Npcap, DPDK, PF_RING...)的c++包装器，但也提供了这些引擎中不存在的一些独特特性和功能

主要类与功能:

1. `PcapLiveDevice`:表示Linux/MacOS/FreeBSD网络接口，并允许捕获和发送数据包以及检索接口信息
2. `WinPcapLiveDevice`: 表示一个Windows网络接口，并包含' PcapLiveDevice '中暴露的所有功能。这个类实际上继承了' PcapLiveDevice '并为WinPcap/Npcap和Windows操作系统做了相关的调整
3. `DpdkDevice`: 表示一个支持DPDK的网络接口，并封装了用于捕获和发送数据包以及检索接口信息的DPDK基本功能
4. `PfRingDevice`: 表示启用PF_RING的网络接口，并封装用于捕获和发送数据包以及检索接口信息的PF_RING功能
5. `PcapRemoteDevice`: 表示远程机器上的网络接口，并允许使用rpcap协议在该接口上捕获和发送数据包。这个类实际上封装了WinPcap的远程捕获功能，因此只能在Windows上使用
6. pcap and pcap-ng file readers and writers (`PcapFileReaderDevice, PcapFileWriterDevice, PcapNgFileReaderDevice, PcapNgFileWriterDevice, IFileReaderDevice, IFileWriterDevice`)
7. 数据包过滤引擎 Packet filtering engine - a C++ API for the [BPF (Berkeley Packet Filter)](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter) format for easy-to-use packet filtering from a network interface or pcap/pcap-ng file
8. `NetworkUtils` - 包含需要网络交互的公共和基本操作的类。e.g. 通过发送ARP请求发现远程机器的MAC地址, 通过主机名(通过发送DNS请求)发现IPv4地址...



### Common++

- 包含`Packet++`和`Pcap++`使用的公共代码实用程序和类的库

主要类与功能:

1. `IPv4Address, IPv6Address`: 表示IPv4/IPv6地址的类
2. `MacAddress`: 表示MAC(以太网)地址的类
3. `IpUtils.h`: 各种有用的网络工具
4. `LoggerPP`: PcapPlusPlus中广泛使用的一个简单的日志基础设施
5. `SystemUtils.h`: 几个用于与操作系统交互的实用工具



原始数据仅在RawPacket对象中存一次，不同层仅指向对应数据开始的地方。e.g. UDP Layer指向UDP开始的地方

![](https://raw.githubusercontent.com/hex-16/pictures/master/Code_pic/PcapPlusPlus_LayersAndRawData.png)



### PcapPlusPlus Build on Linux

> installation case on Fedora33, build from source

```python
git clone https://github.com/seladb/PcapPlusPlus.git
cd PcapPlusPlus/
./configure-linux.sh --default
make all
sudo make install
```



### Cases



```cpp
// author: hyhuang1024@outlook.com
// 小的pcap文件生成方式： editcap -i 60 ./data/202010041400.pcap small.pcap
#include <pcap.h>
#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "stdlib.h"

int main(int argc, char* argv[]) {
    // open a pcap file for reading
    pcpp::PcapFileReaderDevice reader("small_00000_20201004130000.pcap");
    if (!reader.open()) {
        printf("Error opening the pcap file\n");
        return 1;
    }

    // read the first (and only) packet from the file
    pcpp::RawPacket rawPacket;
    if (!reader.getNextPacket(rawPacket)) {
        printf("Couldn't read the first packet in the file\n");
        return 1;
    }

    // parse the raw packet into a parsed packet
    pcpp::Packet parsedPacket(&rawPacket);

    // verify the packet is IPv4
    if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
        // extract source and dest IPs
        pcpp::IPv4Address srcIP =
            parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress();
        pcpp::IPv4Address destIP =
            parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress();
        printf("Source IP is '%s'; Dest IP is '%s'\n", srcIP.toString().c_str(),
               destIP.toString().c_str());  // print source and dest IPs
    }

    while (reader.getNextPacket(rawPacket)) {
    }
    pcpp::IPcapDevice::PcapStats stats;
    reader.getStatistics(stats);
    printf("Read %lu packets successfully and %lu packets could not be read\n",
           stats.packetsRecv, stats.packetsDrop);

    reader.close();  // close the file
}
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

> 该部分内容在reverse.md内的`.pyc`章节内





# Tools

- stegsolve 可查看LSB隐写