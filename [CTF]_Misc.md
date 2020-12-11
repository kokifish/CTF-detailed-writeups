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

> 生活中常用的编码

条形码

二维码(UR Code)

# Forensic Steganography

> 隐写

任何要求检查一个静态数据文件从而获取隐藏信息的都可以被认为是隐写取证题（除非单纯地是密码学的知识），一些低分的隐写取证又常常与古典密码学结合在一起，而高分的题目则通常用与一些较为复杂的现代密码学知识结合在一起



# Image Analysis

- 元数据（Metadata），又称中介数据、中继数据，为描述数据的数据（Data about data），主要是描述数据属性（property）的信息，用来支持如指示存储位置、历史数据、资源查找、文件记录等功能。





## Cases

- breakin-ctf-2017_misc_Mysterious-GIF：gif文件中分离出zip，zip中分离出多个小zip，解压得到partxx.enc，在gif的元数据comment中找到私钥，对.enc文件进行RSA解密，连接成一个图片文件





# Traffic Packet Analysis





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