function main0() {
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
// setTimeout(invoke, 5000);

function main1() {
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

    Java.perform(function () {
        // 在内存中查找ConstructoredObject类的实例
        Java.choose("com.forgotten.fridatestapp.ConstructoredObject", {
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

    Java.perform(function () {
        Java.choose("com.forgotten.fridatestapp.ConstructoredObject", {
            onMatch: function (instance) {
                // 找到后获取实例field map的值，尝试转为自定义Enum Signal类型
                var venum = Java.cast(instance.color.value, Java.use("com.forgotten.fridatestapp.ConstructoredObject$Signal"));
                console.log("venum:", venum);
                // 调用Enum的方法
                console.log("venum.name():", venum.name());
            },
            onComplete: function () {
                console.log("venum: search completed");
            },
        });
    });

    Java.perform(function () {
        Java.choose("com.forgotten.fridatestapp.ConstructoredObject", {
            onMatch: function (instance) {
                // 获取成员变量wJuice的值，并明确类型为父类Water
                var wJuice = Java.cast(instance.wJuice.value, Java.use("com.forgotten.fridatestapp.Water"));
                // 调用父类Water的still()方法
                console.log("wJuice.still():", wJuice.still(wJuice));
                // 明确类型为子类Juice，调用其方法
                console.log("wJuice.fillEnergy():", Java.cast(wJuice, Java.use("com.forgotten.fridatestapp.Juice")).fillEnergy());
            },
            onComplete: function () {
                console.log("wJuice: search completed");
            },
        });
    });

    Java.perform(function () {
        // 新建类实现的接口，先获取其类
        var face = Java.use("com.forgotten.fridatestapp.CheerInterface");
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

    Java.perform(function () {
        // 从本机路径加载一个dex进入内存
        Java.openClassFile("/data/local/tmp/r0gson.dex").load();
        // 使用该dex中的gson类
        const gson = Java.use("com.r0ysue.gson.Gson");
        Java.choose("com.forgotten.fridatestapp.ConstructoredObject", {
            onMatch: function (instance) {
                // 使用gson打印该实例
                console.log("gson ObjectStr:", gson.$new().toJson(instance));
            },
            onComplete: function () {
                console.log("search completed");
            },
        });
    });
}

function main2() {}

// Frida一附加上，就执行函数
setImmediate(main1);
