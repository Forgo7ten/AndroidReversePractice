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

/* hook RegisterNatives函数  */
function hook_RegisterNatives() {
    var RegisterNatives_addr = null;
    var symbols = Process.findModuleByName("libart.so").enumerateSymbols();
    //console.log(JSON.stringify(symbols))
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i].name;
        if (symbol.indexOf("CheckJNI") == -1 && symbol.indexOf("JNI") >= 0) {
            if (symbol.indexOf("RegisterNatives") >= 0) {
                console.log("finally found RegisterNatives_name :", symbol);
                RegisterNatives_addr = symbols[i].address;
                console.log("finally found RegisterNatives_addr :", RegisterNatives_addr);
            }
        }
    }

    if (RegisterNatives_addr != null) {
        Interceptor.attach(RegisterNatives_addr, {
            onEnter: function (args) {
                console.log("[RegisterNatives]method counts :", args[3]);
                var env = args[0];
                var jclass = args[1];
                var class_name = Java.vm.tryGetEnv().getClassName(jclass);
                var methods_ptr = ptr(args[2]);
                var method_count = parseInt(args[3]);
                for (var i = 0; i < method_count; i++) {
                    var name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3));
                    var sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize));
                    var fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));
                    var name = Memory.readCString(name_ptr);
                    var sig = Memory.readCString(sig_ptr);
                    var find_module = Process.findModuleByAddress(fnPtr_ptr);
                    console.log(
                        "[RegisterNatives] java_class:",
                        class_name,
                        "name:",
                        name,
                        "sig:",
                        sig,
                        "fnPtr:",
                        fnPtr_ptr,
                        "module_name:",
                        find_module.name,
                        "module_base:",
                        find_module.base,
                        "offset:",
                        ptr(fnPtr_ptr).sub(find_module.base)
                    );
                }
            },
            onLeave: function (retval) {},
        });
    } else {
        console.log("didn`t found RegisterNatives address");
    }
}

setImmediate(main3);