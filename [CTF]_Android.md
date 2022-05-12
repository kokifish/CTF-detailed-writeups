要想逆向，首先学正向的开发！！！

# Android

> https://xmsg.org/wordpress/2017/02/%E5%90%BE%E7%88%B1%E7%A0%B4%E8%A7%A3%E5%AE%89%E5%8D%93%E9%80%86%E5%90%91%E5%85%A5%E9%97%A8%E6%95%99%E7%A8%8B/

apk实际是zip压缩包，改apk后缀为zip后解压可以看到内部结构。但不完全？用AndroidKiller可以完全解开







apk组成

子目录: 

- assets: 资源目录。assets目录下的资源文件不需要生成索引，Java代码中用AssetManager访问
- lib: .so库目录
- META-INF: 存放工程属性文件. e.g. Manifest.MF
- res: 资源目录2。编译时会自动生成索引文件（R.java），在Java代码中用R.xxx.yyy来引用

根目录文件: 

- AndroidManifest.xml: Android工程的基础配置属性文件
- classes.dex: Java代码编译得到的 Dalvik VM 能直接执行的文件
- resources.arsc: 对res 目录下的资源的一个索引文件，保存了原工程中 strings.xml等文件内容



## Dalvik

Dalvik 是 google 专门为 Android 操作系统设计的一个虚拟机，经过深度优化。虽然 Android 上的程序是使用 java 来开发的，但是 Dalvik 和标准的 java 虚拟机 JVM 还是两回事。Dalvik VM 是基于寄存器的，而 JVM 是基于栈的；Dalvik有专属的文件执行格式 dex （dalvik executable），而 JVM 则执行的是 java 字节码。Dalvik VM 比 JVM 速度更快，占用空间更少。
通过 Dalvik 的字节码我们不能直接看到原来的逻辑代码，这时需要借助如 Apktool 或 dex2jar+jd-gui 工具来帮助查看。但是，我们最终修改 APK 需要操作的文件是 .smali 文件，而不是导出来的 Java 文件重新编译



## Smali







# Anti-Debug







## ptrace tracerid

```cpp
long ptrace(enum __ptrace_request request,pid_t pid,void *addr,void *data);
```

```
PTRACE_TRACEME,   本进程被其父进程所跟踪。其父进程应该希望跟踪子进程
PTRACE_PEEKTEXT,  从内存地址中读取一个字节，内存地址由addr给出
PTRACE_PEEKDATA,  同上
PTRACE_PEEKUSER,  可以检查用户态内存区域(USER area),从USER区域中读取一个字节，偏移量为addr
PTRACE_POKETEXT,  往内存地址中写入一个字节。内存地址由addr给出
PTRACE_POKEDATA,  往内存地址中写入一个字节。内存地址由addr给出
PTRACE_POKEUSER,  往USER区域中写入一个字节，偏移量为addr
PTRACE_GETREGS,    读取寄存器
PTRACE_GETFPREGS,  读取浮点寄存器
PTRACE_SETREGS,  设置寄存器
PTRACE_SETFPREGS,  设置浮点寄存器
PTRACE_CONT,    重新运行
PTRACE_SYSCALL,  重新运行
PTRACE_SINGLESTEP,  设置单步执行标志
PTRACE_ATTACH，追踪指定pid的进程
PTRACE_DETACH，  结束追踪
```

调ptrace可以尝试跟踪某个进程，如果失败则说明目标进程可能已经被附加调试器了

`/proc/pid/status`中会存储tracerid，表示哪个pid在跟踪这个进程



# **ADB** Debug

> https://developer.android.com/studio/releases/platform-tools  SDK Platform-Tools

ADB: **A**ndroid **D**ebug **B**ridge



windows可以正常识别设备，拷贝文件，开启USB调试，但adb devices无法发现真机设备，可能原因是缺少对应的驱动程序。（LG G8X会出现）



```bash
adb -s LMG850UMc4ed5fb5 forward tcp:23946 tcp:23946# 指定设备 端口转发 # 前：本地端口，后：安卓端口
adb push \path\to\local_file /data/local/tmp # 本地推文件到安卓 前面的是本地文件的路径 后面是安卓设备的路径
adb pull /device/file C:\path\to\store # 安卓拉取文件到本地
adb shell # 
```

> 在windows PS/cmd已经改成UTF-8(chcp: 65001)时，adb shell中`ls`仍然出现类似于` [1;36mbin [0m`的乱码，则可能是ANSI转义序列，adb shell中执行`alias ls="ls --color=never"`可解决，也可以用`sudo ls`代替`ls`



# Tools

> https://www.androiddevtools.cn/ 工具导航
>
> 



## IDA Pro

> 注意本地打开的so版本与远程执行的so版本是否相同。如果打开的so和调试的so版本不同(如armeabi, armeabi-v7a)，attach后不要点same，不然本地so的i64就会被改掉，备注什么的都没了。

远程调试，雷电模拟器+IDA Pro 7.6远程调试配置过程：

1. 把IDA对应的server(在IDA目录下)推到模拟器中并运行：`adb -s device_sn push path\IDAPro7.6\dbgsrv\android_server /data/local/tmp; adb -s device_sn shell; sudo; cd /data/local/tmp; chmod 755 ./android_server ; ./android_server `
2. shell run: `adb forward tcp:23946 tcp:23946`，前面的是本机端口，后面的是设备端口
3. IDA中选择Remote ARM Linux/Android debugger, 如果是本机则IP填127.0.0.1, Port=23946; 
4. 然后Debugger->Attach to Process

> http://www.4k8k.xyz/article/freeking101/106701908 动态调试 普通调试 debug调试
>
> FFFFFFFF: got SIGILL signal (Illegal instruction) (exc.code 5, tid 1234). 这个错误的原因疑似为模拟器是x86结构，so程序是ARM架构。雷电模拟器+IDA会报这种错。houdini是Intel研发的ARM binary translator，可以让arm运行在x86架构的cpu上，为业界x86的兼容性方案。
>
> IDA无法在apk中的.so下断的原因（大概）：IDA下断在arm的.so的地址上，模拟器在加载so之后，so中指令实际上被转成了x86，但IDA中看到的指令仍是translate前的arm指令，并非实际执行的x86指令。解决方案：arm服务器运行arm模拟器，无指令集兼容问题；qemu运行arm镜像，但速度很慢；root的真机，google系最佳。M1也有兼容性问题，原因：TBD

> 如果attach后进程显示不完整（e.g.只有一个进程），则可能是`dbg_server`不是运行在root权限的，LG G8X+magisk，授权shell root权限后，在运行`dbg_server`前sudo可以解决进程显示不全的问题



## apktool

```bash
apktool.jar d andra.apk # 然后会出现一个文件夹 andra 保存经过了解压的apk里面的文件
apktool.jar d -r andra.apk -o andra # 与上面一样 
```







### Installation

> test in 2020.3, Kali20.04, apktool 2.5   https://ibotpeaches.github.io/Apktool/install/

1. Download Linux [wrapper script](https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool) (Right click, Save Link As `apktool`)
2. Download apktool-2 ([find newest here](https://bitbucket.org/iBotPeaches/apktool/downloads/))
3. Rename downloaded jar to `apktool.jar`
4. Move both files (`apktool.jar` & `apktool`) to `/usr/local/bin` (root needed)
5. Make sure both files are executable (`chmod +x`)
6. Try running apktool via cli. (actually, use apktool.jar)



## jeb

https://forum.reverse4you.org/t/cracked-jeb-3-24-anti-blm-edition-by-dimitarserg/11768 JEB 3.24 demo

https://rextester.com/DYRN51380 online keygen

打开后，Bytecode/Disassembly前面几行的 `# Main Activity: xxx (SplashActivity)` 中的xxx一般就是APP一开始运行时打开的activity。点蓝色可以跳转过去，然后在跳转过去的地方右键，点解析(或按tab)可以看到java代码



## AndroidKiller

win GUI app，可以完全解开apk，



## Frida

python+javascript的hook框架，适用于android/ios/linux/win/osx等平台。动态代码执行功能在核心引擎Gum中用C实现





### Cases

- hook libc.so的strcmp函数，输出调用时的参数

```python
import frida
import sys
import time

def on_message(message, data):
    print(message)

# 定义用来hook的js代码
jscode = """
var str_name_so = "libc.so";
var funcname = "strcmp";         //要hook的函数在函数里面的偏移
var ptr_func = Module.findExportByName(str_name_so, funcname);

console.log("ptr_func :", ptr_func);

Interceptor.attach(ptr_func,
    {
        onEnter: function (args) {
            console.log('strcmp:', ptr(args[0]).readCString(), "::", ptr(args[1]).readCString());
            // console.log("hook on enter no exp");
        },
        onLeave: function (retval) {
            // console.log("hook on Leave no exp");
        }
    });
"""

device = frida.get_usb_device()  # 得到设备 # 如果获取不到 考虑使用 get_remote_device
p1 = device.spawn(["com.yzdd.crackme"])
process = device.attach(p1)  # 劫持进程
script = process.create_script(jscode)  # 创建js脚本
script.on('message', on_message)  # 加载回调函数，
print('[*] Running')
device.resume(p1)
script.load()  # 加载脚本
sys.stdin.read()
```





### Installation

> https://www.cnblogs.com/aWxvdmVseXc0/p/12463319.html#autoid-0-1-0

安装案例：雷电模拟器(Android7)+frida15.1.10

1. `pip install frida; pip install frida-tools`
2. 在 https://github.com/frida/frida/releases 下载目标机上的frida-server二进制，注意要对应平台、指令集。例如雷电模拟器要用的是`frida-server-15.1.10-android-x86`。`adb shell; cat /proc/cpuinfo`的方法在雷电模拟器上行不通，cpu会显示host的
3. 把frida-server二进制push到模拟器并运行：`adb push path/to/frida-server-15.1.10-android-x86 \data\local\tmp; adb shell; cd /data/local/tmp; chmod +x frida-server-15.1.10-android-x86; ./frida-server-15.1.10-android-x86`
4. 在宿主机中查看模拟器进程`frida-ps -U`

