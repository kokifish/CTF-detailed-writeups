import frida
import sys
import time


def on_message(message, data):
    print(message)


# 定义用来hook的js代码
jscode = """
Java.perform(function () { // perform是frida的main，所有脚本都应放在这里
    // 获取将要被hook的函数 #  获取MainActivity类
    var MainActivity  = Java.use('com.jerry.live.tv.App'); 
    // hook decoder函数，用js自己实现
    MainActivity.decoder.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function (arg1, arg2, arg3) {
        console.log('arg1: ' + arg1);
        console.log('arg2: ' + arg2);
        console.log('arg3: ' + arg3);
        var retval = this.decoder(arg1, arg2, arg3);
        console.log('retval: ' + retval);
        
        return retval;
    };
});
"""

device = frida.get_usb_device()  # 得到设备 # 如果获取不到 考虑使用get_remote_device
p1 = device.spawn(["com.jerry.livehd"])
process = device.attach(p1)  # 劫持进程
script = process.create_script(jscode)  # 创建js脚本
script.on('message', on_message)  # 加载回调函数，
print('[*] Running')
script.load()  # 加载脚本

device.resume(p1)
sys.stdin.read()
