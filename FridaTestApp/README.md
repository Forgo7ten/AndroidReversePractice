# FridaTestApp 学习Frida过程中的代码

[Frida document frida.re/docs/home](https://frida.re/docs/home/)

# Frida简单使用

## Frida简单Hook

1.   编写MainActivity，添加按钮`btnMethodHooked`

2.   为其注册点击监听，编写HookedObject类，调用其中的方法

3.   运行

     ```bash
     btnMethodHooked: 9
     btnMethodHooked: helloFridahelloFrida
     btnMethodHooked: 20
     ```

4.   编写Frida脚本

5.   运行

     ```bash
     frida -H 192.168.0.104:8888 -f com.db.translate.app -l test.js
     ```

```javascript
function main() {
    Java.perform(function () {
            // 先查找HookedObject类，然后hook其的stringTwo方法
            Java.use("com.forgotten.fridatestapp.HookedObject").stringTwo.implementation = function (arg) {
              // this为当前实例，获得原方法执行的结果
              var result = this.stringTwo(arg);
              // 打印参数和原方法结果
              console.log("stringTwo arg,result: ", arg, result);
              // 对方法的结果进行修改（相当于重写了该方法）
              return Java.use("java.lang.String").$new("hhello");
            };

        // hook addNumber方法 function参数列表可以什么都不填
        Java.use("com.forgotten.fridatestapp.HookedObject").addNumber.overload("int", "int").implementation = function () {
            // 内置有变量[argument]，为方法的参数列表
            for (var i = 0; i < arguments.length; i++) {
                console.log("addNumber arguments[" + i + "]=" + arguments[i]);
            }
            var result = this.addNumber(arguments[0], arguments[1]);
            console.log("addNumber arg,result: ", arguments, result);
            return 99;
        };
    });
}
// Frida一附加上，就执行函数
setImmediate(main);
```



-   对于内部类，通过`类名$内部类名`去use或者choose

## Frida访问方法及变量

-   方法调用

    -   静态方法使用`Java.use`获得**类**后直接调用

    -   非静态方法需要使用`Java.choose`查找到**类实例**后进行调用
    -   构造方法为`$init`

-   静态/非静态变量

    -   设置成员变量的值，写法是`[field_name].value = [value]`，其他方面和函数一样。
    -   如果有一个成员变量和成员函数的名字相同，则在其前面加一个`_`，如`_[field_name].value = [value]`



```javascript
function invoke() {
    Java.perform(function () {
        // 在内存中搜索类的实例
        Java.choose("com.forgotten.fridatestapp.HookedObject", {
            // 如果匹配上执行回调，参数为类实例
            onMatch: function (instance) {
                console.log("Found `HookedObject` instance:", instance);
                // 打印私有成员变量的值，需要[field].value
                console.log("instance.score =", instance.score.value);
                // 打印静态成员变量的值
                console.log("HookedObject.msg =", Java.use("com.forgotten.fridatestapp.HookedObject").msg.value);
                // 修改成员变量的值
                instance.score.value = Java.use("java.lang.Integer").parseInt("-900");
                // 打印修改之后的值
                console.log("instance.score =", instance.score.value);
                // 与方法同名的成员变量，需前面加_
                console.log("instance.stringTwo =", instance._stringTwo.value);
            },
            // 搜索完成执行回调
            onComplete: function () {
                console.log("Found Completed");
            },
        });
    });
}
// Frida附加上后延迟5秒执行，期间由于逻辑问题需要主动点击按钮来实例化对象
setTimeout(invoke, 5000);

```



### Frida构造打印对象

#### array数组`[Object Object]`

```javascript
Java.perform(function () {
    // Hook Arrays.toString方法 重载char[]
    Java.use("java.util.Arrays").toString.overload("[C").implementation = function () {
        // 打印参数
        console.log("arg = ", arguments[0]);
        /* 手动构造一个Java array：参数一为类型，参数二为数组 */
        var arg = Java.array("char", ["上", "山", "打", "老", "虎"]);
        var result = this.toString(arg);
        console.log("[NEW]arg,result = ", arg, result);
        return result;
    };
});
Java.perform(function () {
    // Java.use("java.util.Arrays").toString.overload("[B").implementation = function () {
    /* `.toString`方法同时也可用`["toString"]`替代，这两种形式等价 */
    Java.use("java.util.Arrays")["toString"].overload("[B").implementation = function () {
        var result = this.toString(arguments[0]);
        console.log('["toString"] arg,result = ', arguments[0], result);
        return result;
    };
});
```

#### Map

```javascript
Java.perform(function () {
    // 在内存中查找ConstructoredObject类的实例
    Java.choose("com.forgotten.fridatestapp.construct.ConstructoredObject", {
        onMatch: function (instance) {
            // 找到后获取实例field map的值，尝试转为HashMap类型
            var vmap = Java.cast(instance.map.value, Java.use("java.util.HashMap"));
            console.log("vmap:", vmap);
            console.log("vmap.toString():", vmap.toString());
        },
        onComplete: function () {
            console.log("vmap: search completed");
        },
    });
});
```



#### 枚举类型

```javascript
Java.perform(function () {
    Java.choose("com.forgotten.fridatestapp.construct.ConstructoredObject", {
        onMatch: function (instance) {
            // 找到后获取实例field map的值，尝试转为自定义Enum Signal类型
            var venum = Java.cast(instance.color.value, Java.use("com.forgotten.fridatestapp.construct.ConstructoredObject$Signal"));
            console.log("venum:", venum);
            // 调用Enum的方法
            console.log("venum.name():", venum.name());
        },
        onComplete: function () {
            console.log("venum: search completed");
        },
    });
});
```





#### 转型

可以通过`getClass().getName().toString()`来查看当前实例的类型。
找到一个instance，通过`Java.cast`来强制转换对象的类型。

向上转型

**不能将父类对象转为子类类型**

```javascript
Java.perform(function () {
    Java.choose("com.forgotten.fridatestapp.construct.ConstructoredObject", {
        onMatch: function (instance) {
            // 获取成员变量wJuice的值，并明确类型为父类Water
            var wJuice = Java.cast(instance.wJuice.value, Java.use("com.forgotten.fridatestapp.construct.Water"));
            // 调用父类Water的still()方法
            console.log("wJuice.still():", wJuice.still(wJuice));
            // 明确类型为子类Juice，调用其方法
            console.log("wJuice.fillEnergy():", Java.cast(wJuice, Java.use("com.forgotten.fridatestapp.construct.Juice")).fillEnergy());
        },
        onComplete: function () {
            console.log("wJuice: search completed");
        },
    });
});
```



#### 编写自定义类

```javascript
Java.perform(function () {
    // 新建类实现的接口，先获取其类
    var face = Java.use("com.forgotten.fridatestapp.construct.CheerInterface");
    // 创建一个类
    var beer = Java.registerClass({
        // 类的名称，小写就可
        name: "com.forgotten.fridatestapp.beer",
        // 实现的接口数组，多个来写[a, b]
        implements: [face],
        // 类中含有的方法
        methods: {
            cheer: function () {
                console.log("Cheer!!!");
            },
        },
        /**
         * 其余的可写属性：`super` 父类；`protocols` 该类遵循的协议数组？
         */
    });
    console.log("beer:", beer);
    // 调用一下自己编写的类的方法
    beer.$new().cheer();
});
```



#### Frida加载dex中类到内存

```javascript
Java.perform(function () {
    // 从本机路径加载一个dex进入内存
    Java.openClassFile("/data/local/tmp/r0gson.dex").load();
    // 使用该dex中的gson类
    const gson = Java.use("com.r0ysue.gson.Gson");
    Java.choose("com.forgotten.fridatestapp.construct.ConstructoredObject", {
        onMatch: function (instance) {
            // 使用gson打印该实例
            console.log("gson ObjectStr:", gson.$new().toJson(instance));
        },
        onComplete: function () {
            console.log("search completed");
        },
    });
});
```



### 不可见函数名hook

```javascript
Java.perform(
    function x() {
        // 定义目标类
        var targetClass = "com.example.hooktest.MainActivity";
        var hookCls = Java.use(targetClass);
        // 获得目标类的所有方法
        var methods = hookCls.class.getDeclaredMethods();
        // 遍历所有方法名
        for (var i in methods) {
            console.log(methods[i].toString());
            console.log(encodeURIComponent(methods[i].toString().replace(/^.*?\.([^\s\.\(\)]+)\(.*?$/, "$1")));
        }
        // 如果有等于不可见字符类的
        hookCls[decodeURIComponent("%D6%8F")]
            .implementation = function (x) {
                console.log("original call: fun(" + x + ")");
                var result = this[decodeURIComponent("%D6%8F")](900);
                return result;
            }
    }
)
```





#### Frida hook 动态加载class

对于调用时动态加载的类，遍历ClassLoader然后找到能加载该类的ClassLoader；然后将Frida的默认classloader为设置为找到的这个ClassLoader；再使用`Java.use`来加载该类

```javascript
// 枚举内存中的 类加载器
Java.enumerateClassLoaders({
    onMatch:function(loader){
        try{
            // 如果找到的类加载器 能加载的类有[class_name]
            if(loader.findClass("[class_name]")){
                console.log("Successfully found loader")
                console.log(loader);
                // 设置 java默认的classloader
                Java.classFactory.loader = loader ;
            }
        }
        catch(error){
            console.log("find error:" + error)
        }
    },
    onComplete: function () {
        console.log("End")
    }
})
// 再 使用该类
Java.use("[class_name]")
```

## Frida hook装入的类

需hook的类有很多并且有一定特征的话，可以枚举所有装入的类，然后批量hook

```javascript
// 枚举装入的类
Java.enumerateLoadedClasses({
    onMatch: function (name, handle) {

        // 类名进行匹配，如果包含的话 进行hook
        if (name.indexOf("[class_name]") != -1) {
            console.log("name:" + name + " handle:" + handle)
            Java.use(name).check.implementation = function () {
                return true
            }
        }
    },
    onComplete: function () {
        console.log("end")
    }
})
```



## Frida 打印栈回溯

```
function printStack(name) {
    Java.perform(function () {
        var Exception = Java.use("java.lang.Exception");
        var ins = Exception.$new("Exception");
        var straces = ins.getStackTrace();
        if (straces != undefined && straces != null) {
            var strace = straces.toString();
            var replaceStr = strace.replace(/,/g, "\\n");
            console.log("=============================" + name + " Stack strat=======================");
            console.log(replaceStr);
            console.log("=============================" + name + " Stack end=======================\r\n");
            Exception.$dispose();
        }
    });
}
```



# Frida高级使用

## Frida RPC(Remote procedure call)

### RPC主动调用

**rpc.exports导出名不可以有大写字母或者下划线**

```javascript
function invoke() {
    Java.perform(function () {
        // 搜索HookedObject类实例
        Java.choose("com.forgotten.fridatestapp.HookedObject", {
            onMatch: function (instance) {
                console.log("found HookedObject:", instance);
                // 查找到实例后主动调用方法
                console.log("ho.getPasswd():", instance.getPasswd("123 ABC"));
            },
            onComplete: function () {
                console.log("HookedObject: search complete.");
            },
        });
    });
}
/* 测试函数 */
function test() {
    console.log("I'm Frida_rpc.js!");
}
/* 导出函数列表(可供py调用的) py函数映射和实际函数名 */
rpc.exports = {
    invokefunc: invoke,
    testfunc: test,
};

```

```python
import time
import frida

## handler | script脚本信息交互函数
def my_message_handler(message,payload):
    print(message)
    print(payload)

# 通过Usb连接设备
# device = frida.get_usb_device()

# 通过ip:port 连接设备
device = frida.get_device_manager().add_remote_device("192.168.0.104:8888")
################ 通过spawn方式启动 ###########################
pid = device.spawn(["com.forgotten.fridatestapp"])
device.resume(pid)
time.sleep(1)
session = device.attach(pid)
##### <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# session = device.attach("com.forgotten.fridatestapp")
################ 通过attach现有进程方式启动 ###################
with open("./frida_rpc.js") as f:
    # 创建一个新脚本
    script = session.create_script(f.read())
# 加载信息交互handler函数
script.on("message",my_message_handler)
# 加载脚本
script.load()

command = ""
while True:
    command = input("Enter Command(y/t/n): ")
    if command=="y":
        script.exports.invokefunc()
    elif command=="t":
        script.exports.testfunc()
    elif command=="n":
        break
```

### rpc动态修改

```javascript
Java.perform(function () {
    Java.use("com.forgotten.fridatestapp.HookedObject").getPasswd.implementation = function () {
        // 需要发送给python的字符串：由函数的参数和结果拼接而成
        var string_to_send = arguments[0] + ":" + this.getPasswd(arguments[0]);
        var string_to_recv;
        // 发送到python程序
        send(string_to_send);
        // 同时调用.wait()来 阻塞运行，等待接收消息
        recv(function (received_json_objection) {
            // 接收来的json字符串
            console.log("recv in js:",JSON.stringify(received_json_objection))
            // 打印json的`my_data`,json串来自python
            string_to_recv = received_json_objection.my_data;
            console.log("string_to_recv:", string_to_recv);
        }).wait();
        // 将接收到的字符串当作被hook函数的结果返回回去
        var result = Java.use("java.lang.String").$new(string_to_recv);
        return result;
    };
});

```

```python
import time
import frida


## handler | script脚本信息交互函数
def my_message_handler(message, payload):
    print(message)  # 打印得到的信息
    print(payload)  # 输出的为`none`?
    # 如果`type`字段为"send" 则是js发来的消息
    if message["type"] == "send":
        # 打印json的`payload`内容(js发送过来的内容)
        print(message["payload"])
        # 向script发送消息，格式为字典
        script.post({"my_data": "Hello"})


# 通过Usb连接设备
# device = frida.get_usb_device()

# 通过ip:port 连接设备
device = frida.get_device_manager().add_remote_device("192.168.0.104:8888")
################ 通过spawn方式启动 ###########################
pid = device.spawn(["com.forgotten.fridatestapp"])
device.resume(pid)
time.sleep(1)
session = device.attach(pid)
##### <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# session = device.attach("com.forgotten.fridatestapp")
################ 通过attach现有进程方式启动 ###################
with open("./frida_rpc.js") as f:
    # 创建一个新脚本
    script = session.create_script(f.read())
# 加载信息交互handler函数
script.on("message", my_message_handler)
# 加载脚本
script.load()

command = ""
while True:
    command = input("Enter `n` for leave: ")
    if command == "n":
        break

```



## Frida native Hook

### hook用户函数

#### hook静态注册(或导出)函数

```javascript
function main0() {
    /* hook 可导出的native函数 */
    Java.perform(function () {
        // 寻找模块so的地址
        var lib_fridatestapp_addr = Module.findBaseAddress("libfridatestapp.so");
        console.log("native_lib_addr -> ", lib_fridatestapp_addr);
        // 寻找导出函数的地址
        var staticString_addr = Module.findExportByName("libfridatestapp.so", "Java_com_forgotten_fridatestapp_MainActivity_staticString");
        console.log("staticString() addr -> ", staticString_addr);
        // 对函数进行attach
        Interceptor.attach(staticString_addr, {
            // 函数进入时，参数为函数的参数
            onEnter: function (args) {
                /* 打印native函数调用栈，有Backtracer.ACCURATE和Backtracer.FUZZY两种模式切换 */
                console.log("CCCryptorCreate called from:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n") + "\n");

                // 打印三个参数地址
                console.log("Interceptor.attach staticString() args:", args[0], args[1], args[2]);
                // 将 参数三传进去的jstring字符串，转换为char*再用readCString()得到JavaScript字符串来输出
                console.log("jstring is", Java.vm.getEnv().getStringUtfChars(args[2], null).readCString());

                // 可以对参数进行修改
                var new_arg2 = Java.vm.getEnv().newStringUtf("new arg2 from Frida");
                args[2] = new_arg2;
            },
            // 函数执行完的时候，参数为函数的返回值
            onLeave: function (reval) {
                console.log("Interceptor.attach staticString() retval", reval);
                console.log("Interceptor.attach staticString() retval", Java.vm.getEnv().getStringUtfChars(reval, null).readCString());

                // 对函数的返回值进行替换
                var new_reval = Java.vm.getEnv().newStringUtf("HaHa Frida!!!");
                reval.replace(new_reval);
            },
        });
    });
}
```

#### 主动调用静态注册(或导出)函数

```javascript
function main1() {
    /* 主动调用 可导出的native函数 */
    Java.perform(function invoke_justAdd_func() {
        // 寻找模块so的地址
        var lib_fridatestapp_addr = Module.findBaseAddress("libfridatestapp.so");
        console.log("native_lib_addr -> ", lib_fridatestapp_addr);
        // 寻找导出函数的地址
        var justAdd_addr = Module.findExportByName("libfridatestapp.so", "_Z7justAddii");
        console.log("justAdd() addr -> ", justAdd_addr);
        // 新建一个Native函数，参数分别为 已存在函数地址，函数返回值类型，函数参数列表
        var justAdd_func = new NativeFunction(justAdd_addr, "int", ["int", "int"]);
        // 执行函数，获得函数返回值
        var justAdd_result = justAdd_func(10, 2);
        console.log("invoke justAdd(10,2) result-> ", justAdd_result);
    });

    Java.perform(function invoke_nativeString_func() {
        /* 大部分代码同 hook函数中的 */
        // 寻找模块so的地址
        var lib_fridatestapp_addr = Module.findBaseAddress("libfridatestapp.so");
        console.log("native_lib_addr -> ", lib_fridatestapp_addr);
        // 寻找导出函数的地址
        var staticString_addr = Module.findExportByName("libfridatestapp.so", "Java_com_forgotten_fridatestapp_MainActivity_staticString");
        console.log("staticString() addr -> ", staticString_addr);

        /* 声明该native函数，返回值和参数env、jobject等都是"pointer" */
        var nativeString_func = new NativeFunction(staticString_addr, "pointer", ["pointer", "pointer", "pointer"]);

        // 对函数进行attach
        Interceptor.attach(staticString_addr, {
            // 函数进入时，参数为函数的参数
            onEnter: function (args) {
                // 打印三个参数地址
                console.log("Interceptor.attach staticString() args:", args[0], args[1], args[2]);
                // 将 参数三传进去的jstring字符串，转换为char*再用readCString()得到JavaScript字符串来输出
                console.log("jstring is", Java.vm.getEnv().getStringUtfChars(args[2], null).readCString());

                /* 主动调用方法，打印函数结果 */
                console.log("==> invoke stringfunc(): ", Java.vm.getEnv().getStringUtfChars(nativeString_func(args[0], args[1], args[2]), null).readCString());

                // 可以对参数进行修改
                var new_arg2 = Java.vm.getEnv().newStringUtf("new arg2 from Frida");
                args[2] = new_arg2;
            },
            // 函数执行完的时候，参数为函数的返回值
            onLeave: function (reval) {
                console.log("Interceptor.attach staticString() retval", reval);
                console.log("Interceptor.attach staticString() retval", Java.vm.getEnv().getStringUtfChars(reval, null).readCString());

                // 对函数的返回值进行替换
                var new_reval = Java.vm.getEnv().newStringUtf("HaHa Frida!!!");
                reval.replace(new_reval);
            },
        });
    });
}
```

#### 替换掉静态注册(或导出)函数

```javascript
function main2() {
    /* 替换 justAdd函数 */
    Java.perform(function replace_func() {
        // 寻找模块so的地址
        var lib_fridatestapp_addr = Module.findBaseAddress("libfridatestapp.so");
        console.log("native_lib_addr -> ", lib_fridatestapp_addr);
        // 寻找导出函数的地址
        var justAdd_addr = Module.findExportByName("libfridatestapp.so", "_Z7justAddii");
        console.log("justAdd() addr -> ", justAdd_addr);
        // 对原native函数进行替换，参数1为替换的地址，参数2为一个NativeCallback
        Interceptor.replace(
            justAdd_addr,
            new NativeCallback(
                // 参数分别为，替换执行的函数，返回值类型，参数类型列表
                function (a, b) {
                    console.log("justAdd args: ", a, b);
                    var result = a * (b + 5);
                    console.log("new Func Result: ", result);
                    return result;
                },
                "int",
                ["int", "int"]
            )
        );
    });
}
```

#### 通过地址偏移操作未导出函数

通过ida找到函数偏移

```java
function main3() {
    /* 靠地址偏移hook未导出函数  */
    Java.perform(function () {
        // 寻找模块so的地址
        var lib_fridatestapp_addr = Module.findBaseAddress("libfridatestapp.so");
        console.log("native_lib_addr -> ", lib_fridatestapp_addr);
        // 通过函数偏移+模块的地址，得到函数的地址
        var dynamicString_addr = lib_fridatestapp_addr.add(0xa48);
        console.log("dynamicString() addr -> ", dynamicString_addr);
        // 对函数进行attach
        Interceptor.attach(dynamicString_addr, {
            // 函数进入时，参数为函数的参数
            onEnter: function (args) {
                /* 打印native函数调用栈，有Backtracer.ACCURATE和Backtracer.FUZZY两种模式切换 */
                // console.log("CCCryptorCreate called from:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n") + "\n");

                // 打印三个参数地址
                console.log("Interceptor.attach dynamicString() args:", args[0], args[1], args[2]);
                // 将 参数三传进去的jstring字符串，转换为char*再用readCString()得到JavaScript字符串来输出
                // console.log("jstring is", Java.vm.getEnv().getStringUtfChars(args[2], null).readCString());

                // 可以对参数进行修改
                var new_arg2 = Java.vm.getEnv().newStringUtf("new arg2 from Frida");
                args[2] = new_arg2;
            },
            // 函数执行完的时候，参数为函数的返回值
            onLeave: function (reval) {
                console.log("Interceptor.attach dynamicString() retval", reval);
                console.log("Interceptor.attach dynamicString() retval", Java.vm.getEnv().getStringUtfChars(reval, null).readCString());

                // 对函数的返回值进行替换
                var new_reval = Java.vm.getEnv().newStringUtf("HaHa Frida!!!");
                // reval.replace(new_reval);
            },
        });
    });
}
```



### 模块相关操作

#### 枚举出所有模块的所有导出符号

```javascript
/* 枚举出所有模块的所有导出符号 */
function EnumerateAllExports() {
    var modules = Process.enumerateModules();
    //print all modules
    //console.log("Process.enumerateModules->",JSON.stringify(modules));
    for (var i = 0; i < modules.length; i++) {
        var module = modules[i];
        var module_name = modules[i].name;
        var exports = module.enumerateExports();
        console.log("module.enumerateeExports", JSON.stringify(exports));
    }
}
```



#### 遍历某模块符号/导出/导入

```javascript
function look_module(module_name){
    // 根据模块名称寻找地址；根据地址找到模块返回Module对象
    var native_lib_addr = Process.findModuleByAddress(Module.findBaseAddress(module_name));
    console.log("native_lib_addr => ",JSON.stringify(native_lib_addr));
    // 遍历模块的所有Symbols
    console.log("enumerateImports=>",JSON.stringify(native_lib_addr.enumerateSymbols()));

}
look_module("linker64");
```



### JNI框架层的利用

#### JNI框架hook：

```javascript
/* hook jni函数GetStringUTFChars */
function hook_getStringUTFChars_func() {
    var GetStringUTFChars_addr = null;
    // 该函数在这个so里面，遍历里面的所有符号
    var symbools = Process.findModuleByName("libart.so").enumerateSymbols();
    //console.log(JSON.stringify(symbool));
    for (var i = 0; i < symbools.length; i++) {
        // 取到符号的name
        var symbol = symbools[i].name;
        // 过滤一下，因为还有一个checkjni类中有该函数
        if (symbol.indexOf("CheckJNI") == -1 && symbol.indexOf("JNI") >= 0) {
            if (symbol.indexOf("GetStringUTFChars") >= 0) {
                console.log("finally found GetStringUTFChars name:", symbol);
                // 保存该函数的地址
                GetStringUTFChars_addr = symbools[i].address;
                console.log("finally found GetStringUTFChars address :", GetStringUTFChars_addr);
            }
        }
    }
    /* 开始附加该函数 */
    Interceptor.attach(GetStringUTFChars_addr, {
        onEnter: function (args) {
            console.log("art::JNI::GetStringUTFChars(_JNIEnv*,_jstring*,unsigned char*)->", args[0], Java.vm.getEnv().getStringUtfChars(args[1], null).readCString(), args[2]);
            // 打印栈回溯
            // console.log("CCCryptoCreate called from:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n") + "\n");
        },
        onLeave: function (retval) {
            // 打印返回值，为c字符串
            console.log("retval is->", retval.readCString());
        },
    });
}
```

#### JNI框架replace：

```javascript
/* 对NewStringUTF函数进行replace操作 */
function replace_NewStringUTF_func() {
    /* 同上 */
    var NewStringUTF_addr = null;
    // 该函数在这个so里面，遍历里面的所有符号
    var symbools = Process.findModuleByName("libart.so").enumerateSymbols();
    //console.log(JSON.stringify(symbool));
    for (var i = 0; i < symbools.length; i++) {
        // 取到符号的name
        var symbol = symbools[i].name;
        // 过滤一下，因为还有一个checkjni类中有该函数
        if (symbol.indexOf("CheckJNI") == -1 && symbol.indexOf("JNI") >= 0) {
            if (symbol.indexOf("NewStringUTF") >= 0) {
                console.log("finally found NewStringUTF_name:", symbol);
                // 保存该函数的地址
                NewStringUTF_addr = symbools[i].address;
                console.log("finally found NewStringUTF_address :", NewStringUTF_addr);
            }
        }
    }

    // new一个NewStringUTF的NativeFunction
    /* static jstring NewStringUTF(JNIEnv* env, const char* utf) */
    var NewStringUTF = new NativeFunction(NewStringUTF_addr, "pointer", ["pointer", "pointer"]);
    // 然后执行替换
    Interceptor.replace(
        NewStringUTF_addr,
        new NativeCallback(
            function (arg1, arg2) {
                // 打印原本的参数
                console.log("NewStringUTF arg1,arg2->", arg1, arg2.readCString());
                // new一个char*字符串
                var newARG2 = Memory.allocUtf8String("newPARG2");
                /* 将参数替换，然后执行原函数并返回结果
        var result=NewStringUTF(arg1,newARG2); // 不能随意修改，会导致崩溃*/
                var result = NewStringUTF(arg1, arg2);
                return result;
            },
            "pointer",
            ["pointer", "pointer"]
        )
    );
}
```

