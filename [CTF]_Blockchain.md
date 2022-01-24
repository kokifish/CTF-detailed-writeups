- Writer: github.com/peidongg   date: from 2021

# Blockchain

## Build Environment

* 参考资料：
  * [https://ethereum.org](https://ethereum.org/)   官网
  * https://www.cnblogs.com/little-kwy/p/10394299.html
  * https://blog.csdn.net/u013096666/article/details/78647509
  * https://www.cnblogs.com/wanghui-garcia/p/10256520.html  geth参数

> ps:很多参考资料由于版本问题稍微有点过时，这里重新写一个能用的

### 1.如何运行+创建用户和创世块

获取geth镜像
`sudo docker pull ethereum/client-go`

运行docker
`sudo docker run -it --name eth ethereum/client-go`

创建专门用于ethereum的docker网络
`sudo docker network create -d bridge --subnet=172.19.0.0/16 ethnet`

运行docker并指定工作目录为`/home`，绑定网络`ethnet`，指定网络ip为`172.19.0.8`
`sudo docker run -it --rm --network ethnet --ip 172.19.0.8 -v /home:/home --entrypoint /bin/sh ethereum/client-go`

在容器内的`/home`目录创建如下目录结构和文件，也可以在外部创建，因为已经挂载了，直接在外部操作文件相当于在容器内部操作
```bash
dapp/
dapp/miner/
dapp/data/
dapp/genesis.json
```

在容器内创建以太坊账户
`geth -datadir /home/dapp/miner/data account new`
假设创建了两个账户，公钥分别为`0x91C3415B468b43410591c72a402C7AD5236Aa6E2`和`0xdD7Cce6534168032E15524E30F70f453607c9222`。

在`genesis.json`文件中配置创世块，某些版本的创世块在部署合约的时候会出现`transact to ERC20Token.MyToken errored: Error: Returned error: invalid opcode: SHR`这个错误，用下方的创世块可以解决这个问题：
```json
{
  "config": {
    "chainId": 88,
    "homesteadBlock": 0,
    "eip150Block": 0,
    "eip150Hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "ethash": {}
  },
  "alloc"      : {
    "0x91C3415B468b43410591c72a402C7AD5236Aa6E2": {"balance": "1000000000000000000000"},
    "0xdD7Cce6534168032E15524E30F70f453607c9222": {"balance": "10000000000000000000"}
  },
  "coinbase"   : "0x0000000000000000000000000000000000000000",
  "difficulty" : "0x800",
  "extraData"  : "0x0000000000000000000000000000000000000000000000000000000000000000",
  "gasLimit"   : "0x2fefd8",
  "nonce"      : "0x0",
  "mixhash"    : "0x0000000000000000000000000000000000000000000000000000000000000000",
  "parentHash" : "0x0000000000000000000000000000000000000000000000000000000000000000",
  "timestamp"  : "0x0",
  "coinbase"   : "0x0000000000000000000000000000000000000000",
  "number"     : "0x0",
  "gasUsed"    : "0x0"
}
```

创建完创世块之后，首先要初始化私链，即生成一些初始的文件。如果在每次生成容器的时候才进行初始化，就会导致每次的节点信息不一样，不方便配置静态节点。
`geth -datadir /home/dapp/data/ init /home/dapp/genesis.json`

### 2. 让以太坊运行起来

说明：
1. 下面的地址由于是主机的`home`挂载容器的`\home`，因此凡是出现`\home`的都是指同样的目录。
2. `-v` 选项下用的都是绝对路径，这里写相对路径只是方便，实际操作的时候都要改成绝对路径。


> 这里先参照第二个参考资料进行复现，我们需要使用一个持久性容器作为主矿工。

* 它会自动读取genesis.json文件，并初始化以太坊网络
* 它能够连接其它节点（容器）
* 它能够接受各种rpc调用，并能够部署合约
* 它已经配置好挖矿账户，可以一键挖矿

* 创建一个文件`/home/dapp/init.sh`并授予至少775权限
> 该脚本的功能是让以太坊节点（容器）自动初始化以太坊网络，并且接受一个自动运行脚本作为输入。

**这里的`-datadir`字段的目录不能是挂载的目录，因为是分布式存储，挂载的目录只能被用一次，否则geth就会报`Failed to create the protocol stack: datadir already used by another process`错误**

```bash
#!/bin/sh
geth -datadir /run/data/ init /home/dapp/genesis.json

if [  $# -lt 1 ]; then 
  exec "/bin/sh"
else
  exec /bin/sh -c "$@"
fi
```

* 注意事项
> geth 1.10.7及以下版本把所有`--http`改为`--rpc`，以上使用第二个，参考https://geth.ethereum.org/docs/rpc/server
* --rpc => --http
* --rpcapi => --http.api
* --rpcaddr => --http.addr
* --rpcport => --http.port
* --rpccorsdomain => --http.corsdomain

> `--etherbase `已弃用，使用`--miner.etherbase`代替。`--allow-insecure-unlock`因为出于安全考虑，默认禁止了HTTP通道解锁账户，因此需要加上这个选项。

* 在`/home/dapp/miner/`目录下创建`password.txt`文件，里面存储账户`0x91C3415B468b43410591c72a402C7AD5236Aa6E2`所对应的密码，之后解锁的时候就不需要输入密码。

创建一个文件`/home/dapp/mine.sh`并授予至少775权限，它包含容器中需要执行的命令，主要是文件拷贝和私链的启动：
```bash
#!/bin/sh
cp -r /home/dapp/miner/data/keystore/* /run/data/keystore/  # 拷贝链上的账户信息
cp -r /home/dapp/data/geth/* /run/data/geth                 # 拷贝固定的初始化链节点文件
geth -datadir /run/data/ --networkid 88 --http --http.corsdomain '*' --http.addr "172.19.0.7" --http.api admin,eth,miner,web3,personal,net,txpool,debug --password="/home/dapp/miner/password.txt" --unlock "0x91C3415B468b43410591c72a402C7AD5236Aa6E2" --miner.etherbase "0x91C3415B468b43410591c72a402C7AD5236Aa6E2" --allow-insecure-unlock --ipcdisable --snapshot=false console
```
其中
`--networkid`指定链的序号；`--http.corsdomain '*'`指定了任意地方可以访问这个rpc接口；`--http`定义rpc接口；`--ipcdisable`关闭ipc接口；`--snapshot=false`关闭snapshot。

* 接下来就可以创建主矿工的容器了
```bash
sudo docker run -it --rm --name=miner --network ethnet --ip 172.19.0.7 -p 8545:8545 --hostname eth-node -v /home/:/home --entrypoint /home/dapp/init.sh ethereum/client-go /home/dapp/mine.sh
```

然后在容器中运行```admin.nodeInfo.enode```获取主节点的节点信息。
```
"enode://752b4f3d53233c6bb80d2fb29d1d61503fde9cfc9a8da14896af15ade3da9bd449f623a87527ff8bf267273f6f4e23c2155037de768dba926c90c74b57a54431@127.0.0.1:30303"
```
然后最后的字段要改成当前容器的ip(`172.19.0.7`)和端口(默认`30303`)。

### 3.只会挖矿的矿工

现在已经配置好了一个节点了，然后我们需要进行多节点的配置。

在`/home/dapp/`目录下创建一个名为`static-nodes.json`的文件，用来存储上一步的静态节点，从而进行节点发现。
```
[
  "enode://752b4f3d53233c6bb80d2fb29d1d61503fde9cfc9a8da14896af15ade3da9bd449f623a87527ff8bf267273f6f4e23c2155037de768dba926c90c74b57a54431@172.19.0.7:30303"
]
```

然后在`/home/dapp/`目录下创建一个名为`only_mine.sh`的文件并授予至少775权限，它包含容器中需要执行的命令，主要是文件拷贝和私链的进入：
```bash
#!/bin/sh
cp -r /home/dapp/miner/data/keystore/* /run/data/keystore/
mkdir /run/data/geth
cp /home/dapp/static-nodes.json /run/data/    # 需要把static-nodes.json文件拷贝到-datadir的目录下
geth -datadir /run/data/ --ipcdisable --networkid 88 console
```

* 接下来就可以创建**只会挖矿的矿工**的容器了，需要注意的是这些容器的名称最好进行区分，然后分配的ip需要不一样，如果在一台机器上那么端口就要不一样。下面是两个创建容器的例子：
  * 容器一：
  ```sh
  sudo docker run -it --rm -d --name=node1 --network ethnet --ip 172.19.0.10 --hostname node1 -v home/:/home --entrypoint /home/dapp/init.sh ethereum/client-go /home/dapp/only_mine.sh
  ```
  * 容器二：
  ```sh
  sudo docker run -it --rm -d --name=node2 --network ethnet --ip 172.19.0.11 --hostname node2 -v home/:/home --entrypoint /home/dapp/init.sh ethereum/client-go /home/dapp/only_mine.sh
  ```

当运行两个容器之后，在主矿工中应该就能通过`admin.peers`命令看到已经有两个节点加入，表示节点发现成功。

### 4. 挖矿

`miner.start(1)`：开始挖矿，参数表示挖矿的线程数，首次挖矿会生成DAG。
`miner.stop()`：停止挖矿。

成功出块的标志是log中有个锤子的标志。

### 5. 部署与调用合约



> 这里用到的是Remix(http://remix.ethereum.org/)。我们的目标是使用Remix连接容器中的rpc接口，然后做到在我们的私链上进行合约的部署和调用。

> 这里有个神坑，ubuntu18.04中不知道为什么使用Chrome浏览器无法连接私链，而使用Firefox就能成功连上。

如果之前的步骤没有出错，那么参考https://remix-ide.readthedocs.io/en/latest/run.html#more-about-web3-provider 。选择`Web3 Provider`然后endnode输入`http://172.19.0.7:8545`就成功连上我们的私链。

要进行合约的部署调用，需要有节点一直在挖矿。我们可以使用主或者辅助节点运行`miner.start(1)`就行。然后在`remix`中进行合约的编辑、编译、部署、调用就不在这里详细说明，网上有很多资料。


* 玩到这里，终于开始开始用自己的私链进行练习了。


### 6. 一键部署3个节点的私链 TODO

---

## Solidity 一些必要的基础知识

### 合约转账相关

#### 金额的存储

以太坊中的账户有固定账户的地址。在Solidity中使用`address`类型进行表示，该类型允许和`byte20`、`uint160`、`int`、`uint`以及合约类型进行转换。

地址类型有两种：`address`和`address payable`。其区别是`address payable`多了`transfer`和`send`成员。但有时候直接是`address`也有`transfer`和`send`成员。

Solidity里的每个`address`类型的变量可以看成一个对象，对象里面存着一个成员变量(金额`balance`)。然后该对象有下面几个方法，具体见**Solidity文档**：
- `transfer`：向地址转钱(失败会fallback)
- `send`：向地址转钱(失败不会fallback，会返回false)
- `call`,`delegatecall`,`staticcall`：与不符合 (ABI) 的合约交互，慎用，低级函数。常见后面会跟随`.gas`或者`.value`两个函数。

其中`public`和`externel`的函数有三个成员。
- `.selector` 返回 ABI 函数选择器
- `.gas(uint)` 返回一个可调用的函数对象，当被调用时，它将指定函数运行的gas。
- `.value(uint)` 返回一个可调用的函数对象，当被调用时，它将向目标函数发送指定数量的以太币（单位 wei）。

因此在重入攻击中见到的`msg.sender.call.value(12345)()`就表示向`msg.sender`发送12345个wei。

* 注：在合约中执行`address1.send()`,`address1.transfer()`,`address1.call.value(12345)()`表示的是当前合约向`address1`这个地址转账。



#### 转账的三种方式
1. 部署时转账。
   1. 需要在合约的**构造函数**定义中加`payable`修饰符，例：``constructor() public payable{}``。
   2. 在构造交易创建合约的时候`to`字段写上金额，单位是`wei`。
2. 合约函数内部转账给别人
   在合约内部函数转账给其它地址时，需要在函数中加上`payable`修饰符。
3. 接收别人直接给合约转账
   若别人转账给当前合约，当前合约的`fallback`函数中需要加上`payable`修饰符，或者实现`receive`函数。如果两个函数都没有实现，那么其它账户或合约给该合约转账的时候会抛出异常。




### 智能合约基础

#### 合约调用合约

##### 同一个`.sol`文件中
如果两个合约在同一个合约中，那么A合约要调用B合约的方法：
* 通过继承B使得A合约继承B合约的方法
* 在A合约中创建B合约的对象，然后使用对象调用B合约的方法

##### 不在同一个`.sol`文件中
如果两个合于不在同一个文件中（也是经常见的情况），那么A合约要调用B合约的方法：
1. 在A合约的`.sol`文件中创建一个B合约的接口`B_interface`，参考官方文档中的接口。
2. 然后在A合约中创建`B_interface`的对象，然后使用该对象调用B合约中的方法。
3. **可以在创建`B_interface`的对象的时候传入一个已部署在链上的B合约的地址，这样调用的时候就指定调用该合约。**

#### 合约相关
* `this`: 表示当前合约的地址
* `selfdestruct(address payable recipient)`: 销毁合约，并把余额**强制**发送到指定 **地址**.

---

## Blockchain Security

CTF 中关于区块链安全的内容，目前为止，涉及到最多的便是 Ethereum 安全。CTF 中有关于 Ethereum Security 还是比较简单的，主要涉及到的是 Solidity Security。 （**From ctf-wiki**）


* 参考资料：
  * https://ctf-wiki.org/blockchain/introduction/
  * https://docs.soliditylang.org/en/v0.6.8/index.html  **Solidity document**
  * https://learnblockchain.cn/docs/solidity/index.html **Solidity 中文文档**
  * https://web3py.readthedocs.io/en/stable/ **Web3py document** (for python development)
  * https://www.qikegu.com/docs/4811 Solidity入门1
  * https://www.cnblogs.com/blockchainnote/p/11691499.html Solidity入门2

### Some detail about solidity

solidity智能合约编译后主要有abi (Application Binary Interface，应用二进制接口) 和 二进制数据。二进制数据表示的是编译后的合约数据，也是会存储在链上的。但是ABI是不会存储在链上的，需要我们自己来保存。下面介绍一下生成ABI的主要方法：
* 使用`solc`编译器编译生成
* 使用`remix`编译合约生成，然后合约部署后remix会帮我们在浏览器里面生成ABI

* 在调用合约的函数的时候需要通过函数选择器进行选择函数，然后根据Solidity的参数编码方式进行编码，详细可见solidity的官方文档。


### 账户地址相关 About Account Address
1. 生成固定前缀或后缀的地址。参考下方的网站，给出公钥的固定前缀或后缀，生成相应的账户的私钥，用此私钥可以在以太坊中创建公钥(账户地址)满足某些条件的账户。
   * https://vanity-eth.tk/


### 函数调用 Function Call

* 参考资料： https://blog.csdn.net/weixin_43343144/article/details/85240235

#### 外部函数调用

* `sendTransaction` 创建并发送一个交易调用该函数
* `call` 一个本地调用，不会向区块链广播任何东西，不消耗gas
* `[合约函数名]()` 由于有constant标识的方法不会修改状态变量，所以它不会被编译器执行。所以，如果testFunc() 有constant标识，它并不会被编译器执行，web3.js会执行call()的本地操作。相反如果没有constant标识，会执行sendTransaction()操作。

#### 内部函数调用

* `CALL`:是在 **被调用者** 的上下文中执行,只能修改被调用者的storage，即运行代码的时候是在该函数的合约的环境中。
* `CALLCODE`: 是在 **调用者** 的上下文中执行, 可以修改调用者的storage，即运行代码在调用的人的合约环境中。
* `DELEGATECALL`: 运行代码在调用的人的合约环境中，且**固定在调用者的合约环境中**。
  * 例1：在A的函数中,B.callcode(c的函数): c看到msg.sender是B;
  * 例2：在A的函数中,B.delegatecall(c的函数): c看到msg.sender是A;



---

## JSON RPC API

* 参考资料
  * https://geth.ethereum.org/docs/rpc/server
  * http://cw.hubwiz.com/card/c/ethereum-json-rpc-api/1/3/17/

> 官网上的是按照命名进行划分，这里按照功能进行划分，方便寻找，也方便入门。这里仅列举一些较为常用的API，要全面学习则见官网。

### 查看节点信息
* `admin.nodeInfo.enode` 查看**当前节点信息**
* `admin.peers` 查看当前**已建立连接的节点的信息**
* `net.peerCount` 返回当前客户端所连接的对端**节点数量**

### 账户相关

#### 账户操作
* `personal.newAccount(str[password])` **创建**一个账户
* `personal.importRawKey(str[privateKey], str[password])` **根据椭圆曲线私钥导入**一个账户
  * `web3py`中使用`web3.geth.personal.import_raw_key(str[privateKey], str[password])` 进行导入，返回值是其公钥，也是**账户地址**。

#### 查看账户信息
* `eth.accounts` 查看客户端持有的**账户地址列表**。(上下两个一样)
* `personal.listAccounts` 查看客户端持有的账户地址列表。(上下两个一样)
* `eth.getBlance(hex_str[address])` 指定地址**账户（或合约）的余额**

### 挖矿
* `miner.start(1)` 开始挖矿，参数表示挖矿的线程数，首次挖矿会生成DAG。
* `miner.stop()` 停止挖矿。

### 网络相关
* `net.version` 查看链（网络）的ID

### 交易相关
* `eth.sendTransaction(...)` **发送交易**。参数是一个json对象，返回交易的hash值，详见参考资料，这里仅给出例子：
  * `eth.sendTransaction({from:eth.accounts[0], to:eth.accounts[1], value:100000000})`
  * `web3`发的交易是异步执行的，因此该交易无法获得调用的合约的函数的返回值(只有同步执行才能有返回值)。**可以通过触发事件的方式把结果输出到日志， 然后通过订阅事件获取结果**
* `eth.signTransaction(...)` **对一个交易进行签名**（离线签名）。参数是一个交易对象。返回值是一串已签名的交易数据，例子：
  * `eth.signTransaction({from:eth.accounts[0], to:eth.accounts[1], value:100000000}) ==> "0xf86205640a94d..."`
* `eth.sendRawTransaction(...)` **发送一个被签名的交易的raw数据**。既然都说了是被签名的，就表示需要有一个交易，然后这个交易需要签名，然后再发送签名后的信息。因此参数是签名后的数据，例子：
  * `eth.sendRawTransaction("0xf86205640a94d...")`
* `eth.call(...)` **立刻执行一个新的消息调用**，无需在区块链上创建交易。参数是一个json对象：to表示的是合约地址，data表示的是调用的函数（solidity使用函数的哈希的前4 byte来表示），返回值是所执行合约的返回值。例子：
  * `eth.call({to:"0x5BbCF2D662A83Ca49CE1D5726b0cbF0f858945c8", data:"0x2e64cec1"})`


### 查看链上的信息

#### 查看区块信息
* `eth.blockNumber` **返回区块的数量**
* `eth.getBlockByHash(...)` **返回具有指定哈希的块**。输入的参数是区块的hash(32Byte)，输出是块的对象。
* `eth.getBlockByNumber(...)` **返回指定编号的块。** 输入的参数是块的序号，输出是块的对象。

#### 查看交易信息
* `eth.getTransaction(...)` 等价于`eth.getTransactionByHash` 输入交易的Hash，**返回交易对象**。这里在发出交易的时候就能看得到(**在交易池中**)，若是部署合约的交易则有合约的详细内容。
* `eth.getTransactionReceipt(...)` 输入交易的HASH，**返回交易对象**。需要在**交易被确认**后才能找到，里面有合约地址。
* `eth.getTransactionFromBlock(...)` 输入区块的Hash，**返回交易的对象**



### 小技巧
* geth 中如何只挖一个块
  `miner.start(1);admin.sleepBlocks(1);miner.stop();`

* 以太坊中的交易里面的`gas`字段，意思就是交易的`gasLimit`


# 开发工具
[Solidity 智能合约开发工具准备第一篇](https://blog.csdn.net/qq_36764089/article/details/81867947?utm_medium=distribute.pc_relevant.none-task-blog-2~default~baidujs_baidulandingword~default-8.highlightwordscore&spm=1001.2101.3001.4242.5)
**以太坊开发工具指南** https://zhuanlan.zhihu.com/p/316741673


### 以太坊浏览器 Ethereum browser

比较常用的浏览器：http://ethscan.hubwiz.com/#/
可以根据需求查看某个区块，某个交易，某个用户的信息(比如只看某个用户的区块或交易信息)
































---

# 暂时先把题目写在这里

### 2019 强网杯babybank （重入攻击 Re-Entrancy）

* 题目内容位于： https://github.com/ctf-wiki/ctf-challenges/tree/master/blockchain

题目共分为三个挑战，其题解如下：

1. 首先构造一个特定结尾的账户地址，使用https://vanity-eth.tk/ 生成

2. 然后查找区块信息，查询owner调用set_secret函数的区块，从而得知它的secret。难点在于如何去查。

3. 使用重入攻击和uint溢出使得babybank合约中的balance字段变成一个非常大的数。
   1. 首先需要`selfdestruct`强制转账给babybank，因为babybank本身没有钱(eth)
   2. 创建重入攻击的合约`C`。用第一步生成的账户调用babybank合约的`transfer`方法令`balance[address(C)]=2`。
   3. 调用合约`C`的重入攻击方法，最终的目的是使得`balance[address(C)]=-2`为一个很大的数。
   4. 合约`C`调用babybank合约的payForFlag方法得到flag。