# FirstXposed

Xposed基础项目搭建参见：[Android(0) Xposed 模块开发一 环境搭建 | Forgo7ten'blog](https://forgo7ten.github.io/AndroidReverse/2021/2021071201/)

## Hook方法

编写`HookMethod`类，实现`IXposedHookLoadPackage`接口

### hook构造方法

编写`hookConstructorTest()`方法

首先需要获取到要hook的类

1.   通过java反射获取

     ```java
     try {
         // 使用java反射 类加载器.loadClass方式来加载一个类
         Class<?> HookedObjectClass = mLpparam.classLoader.loadClass("com.forgotten.fridatestapp.HookedObject");
     } catch (ClassNotFoundException e) {
         e.printStackTrace();
     }
     ```

2.   通过XposedHelpers.findClass来加载

     ```java
     // 通过XposedHelpers.findClass来加载一个类
     Class<?> HookedObjectClass = XposedHelpers.findClass("com.forgotten.fridatestapp.HookedObject", mLpparam.classLoader);
     ```

即可开始hook，使用`XposedHelpers.findAndHookConstructor`方法

>方法原型
>
>```java
>public static XC_MethodHook.Unhook findAndHookMethod (Class<?> clazz, String methodName, Object... parameterTypesAndCallback);
>
>public static XC_MethodHook.Unhook findAndHookMethod (String className, ClassLoader classLoader, String methodName, Object... parameterTypesAndCallback);  
>```
>

1.   使用第一种重载对无参构造方法进行hook

     ```java
     // 对构造方法进行hook
     XposedHelpers.findAndHookConstructor(HookedObjectClass, new XC_MethodHook() {
         @Override
         protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
             super.beforeHookedMethod(param);
             /*
              * param.args 参数列表
              * param.thisObject 当前方法的类对象
              * param.getResult() 获得函数返回值
              */
             XposedBridge.log("HookedObject_init_beforeHook1:" + param.thisObject);
     
         }
     
         @Override
         protected void afterHookedMethod(MethodHookParam param) throws Throwable {
             super.afterHookedMethod(param);
             XposedBridge.log("HookedObject_init_afterHook1");
     
         }
     });
     ```

2.   使用第二种重载对无参构造方法进行hook

     ```java
     XposedHelpers.findAndHookConstructor("com.forgotten.fridatestapp.HookedObject", mLpparam.classLoader, new XC_MethodHook() {
         @Override
         protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
             super.beforeHookedMethod(param);
             XposedBridge.log("HookedObject_init_beforeHook2:" + param.thisObject);
     
         }
     
         @Override
         protected void afterHookedMethod(MethodHookParam param) throws Throwable {
             super.afterHookedMethod(param);
             XposedBridge.log("HookedObject_init_afterHook2");
         }
     });
     ```

得到结果：

```log
20:00:41.359 27583-27583/com.forgotten.fridatestapp I/LSPosed-Bridge: HookedObject_init_beforeHook2:com.forgotten.fridatestapp.HookedObject@3d84803
20:00:41.360 27583-27583/com.forgotten.fridatestapp I/LSPosed-Bridge: HookedObject_init_beforeHook1:com.forgotten.fridatestapp.HookedObject@3d84803
20:00:41.361 27583-27583/com.forgotten.fridatestapp I/LSPosed-Bridge: HookedObject_init_afterHook1
20:00:41.362 27583-27583/com.forgotten.fridatestapp I/LSPosed-Bridge: HookedObject_init_afterHook2
```

可以得到结论：

1.   **Xposed代码执行是在目标app的进程之中**的，因为log打印就是在目标进程之中；同理，代码所需的权限也在目标app中

2.   hook代码执行顺序特点

     1.   当有一个hook该方法时

          ```bash
          firstHook.beforeHookedMethod()
          	method()
          firstHook.afterHookedMethod()
          ```

     2.   当有两个方法一前一后hook该方法时，多层依次类推

          ```bash
          SecondHook.beforeHookedMethod()
              firstHook.beforeHookedMethod()
                  method()
              firstHook.afterHookedMethod()
          SecondHook.afterHookedMethod()



Hook有参方法即，在*``XC_MethodHook`回调参数前*，插入参数的类型

-   如Hook`init(String a,int b, float c)`；

    ```java
    XposedHelpers.findAndHookConstructor(clazz,String.class, int.class, float.class, new XC_MethodHook(){});
    ```



### hook方法

适用于

-   共有、私有方法
-   静态、实例方法
-   JNI Java层方法



编写`hookMethodTest()`方法

首先通过反射或`XposedHelpers`来加载类

之后通过`XposedHelpers.findAndHookMethod()`方法进行hook

>   方法原型
>
>   ```java
>   public static XC_MethodHook.Unhook findAndHookMethod (Class<?> clazz, String methodName, Object... parameterTypesAndCallback);
>   public static XC_MethodHook.Unhook findAndHookMethod (String className, ClassLoader classLoader, String methodName, Object... parameterTypesAndCallback);
>   ```

同构造方法，只不过多了一个参数`methodName`

```java
/**
 * 对方法的hook测试
 */
private void hookMethodTest() {
    XposedHelpers.findAndHookMethod("com.forgotten.fridatestapp.HookedObject", mLpparam.classLoader, "stringTwo",String.class, new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            super.beforeHookedMethod(param);
            /* param.args 为方法的参数列表 */
            XposedBridge.log("HookedObject.stringTwo_before param: "+param.args[0]);

            /*// 对参数进行修改
            param.args[0] = "param from Xposed";*/

        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            super.afterHookedMethod(param);
            /* param.getResult() 获得方法的返回值 */
            XposedBridge.log("HookedObject.stringTwo_after: result: "+param.getResult());

            /*// 对返回值进行修改
            param.setResult("I'm from Xposed.");*/
        }

    });
}
```

其中被hook的方法稍微修改了一下

```java
public String stringTwo(String hello) {
    String temp = msg+hello + hello;
    Log.d("stringTwo", "stringTwo: temp="+temp);
    return temp;
}
```

得到结果

```bash
21:04:01.345 30364-30364/com.forgotten.fridatestapp I/LSPosed-Bridge: HookedObject.stringTwo_before param: helloFrida
21:04:01.350 30364-30364/com.forgotten.fridatestapp D/stringTwo: stringTwo: temp=你好helloFridahelloFrida
21:04:01.351 30364-30364/com.forgotten.fridatestapp I/LSPosed-Bridge: HookedObject.stringTwo_after: result: 你好helloFridahelloFrida
```



### Hook内部类/匿名内部类

通过smali来查看类的名字，

如`com.forgotten.fridatestapp.MainActivity$$ExternalSyntheticLambda0`，`MainActivity`的第一个`onClick`匿名内部类

```java
/** hookMethodTest() **/

/** hook匿名内部类onClick的方法 **/
XposedHelpers.findAndHookMethod("com.forgotten.fridatestapp.MainActivity$$ExternalSyntheticLambda0", mLpparam.classLoader, "onClick", android.view.View.class, new XC_MethodHook() {
    @Override
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
        super.beforeHookedMethod(param);
        XposedBridge.log("MainActivity.onClick0_before");

    }

    @Override
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
        super.afterHookedMethod(param);
        XposedBridge.log("MainActivity.onClick0_after");
    }

});
```

log输出

```bash
21:16:10.230 31705-31705/com.forgotten.fridatestapp I/LSPosed-Bridge: MainActivity.onClick0_before
21:16:10.236 31705-31705/com.forgotten.fridatestapp D/FridaTestApp: btnMethodHooked: 9
21:16:10.236 31705-31705/com.forgotten.fridatestapp I/LSPosed-Bridge: HookedObject.stringTwo_before param: helloFrida
21:16:10.240 31705-31705/com.forgotten.fridatestapp D/stringTwo: stringTwo: temp=你好helloFridahelloFrida
21:16:10.240 31705-31705/com.forgotten.fridatestapp I/LSPosed-Bridge: HookedObject.stringTwo_after: result: 你好helloFridahelloFrida
21:16:10.242 31705-31705/com.forgotten.fridatestapp D/FridaTestApp: btnMethodHooked: 你好helloFridahelloFrida
21:16:10.242 31705-31705/com.forgotten.fridatestapp D/FridaTestApp: btnMethodHooked: 22
21:16:10.242 31705-31705/com.forgotten.fridatestapp I/LSPosed-Bridge: MainActivity.onClick0_after
```



### 此外

-   对于一些app内部独有的类，hook时如果需要这样的类的类型，则需要通过`XposedHelpers.findClass()`来得到参数的类型



## 获取/修改对象属性

编写`accessFieldTest()`方法

### 获取属性

#### 通过反射

```java
// 反射方式获取static Field
Field msgField = obj.getClass().getDeclaredField("msg");
// 私有属性，需要取消 Java 语言访问检查
msgField.setAccessible(true);
// static属性，获得值时传入null
String msgValue = (String) msgField.get(null);

// 反射方式获取Object Field
Field scoreField = obj.getClass().getDeclaredField("score");
scoreField.setAccessible(true);
int scoreValue = (int) scoreField.get(obj);

XposedBridge.log("reflection Filed-> msg="+msgValue+" score="+scoreValue);
```

log输出

```bash
21:49:35.351 952-952/com.forgotten.fridatestapp I/LSPosed-Bridge: reflection Filed-> msg=你好 score=9
```



#### 通过`XposedHelpers`

```java
String msg2Value = (String) XposedHelpers.getStaticObjectField(obj.getClass(), "msg");
int score2Value = (int)XposedHelpers.getIntField(obj,"score");
XposedBridge.log("XposedHelpers Filed-> msg="+msg2Value+" score="+score2Value);
```

log输出

```bash
21:49:35.354 952-952/com.forgotten.fridatestapp I/LSPosed-Bridge: XposedHelpers Filed-> msg=你好 score=9
```



>   相应api
>
>   ```java
>   // 获取静态属性
>   public static Object getStaticObjectField(Class<?> clazz, String fieldName);
>   public static boolean getStaticBooleanField(Class<?> clazz, String fieldName);
>   public static byte getStaticByteField(Class<?> clazz, String fieldName);
>   public static char getStaticCharField(Class<?> clazz, String fieldName);
>   public static double getStaticDoubleField(Class<?> clazz, String fieldName);
>   public static float getStaticFloatField(Class<?> clazz, String fieldName);
>   public static int getStaticIntField(Class<?> clazz, String fieldName);
>   public static long getStaticLongField(Class<?> clazz, String fieldName);
>   public static short getStaticShortField(Class<?> clazz, String fieldName);
>   
>   // 获取一般属性
>   public static Object getObjectField(Object obj, String fieldName);
>   public static boolean getBooleanField(Object obj, String fieldName);
>   同...
>   ```





### 修改属性

#### 通过反射

```java
/** 获取Field同上 **/

/* 通过反射设置属性值 */
msgField.set(null,"from reflection");
scoreField.set(obj,99);

msg2Value = (String) XposedHelpers.getStaticObjectField(obj.getClass(), "msg");
score2Value = (int)XposedHelpers.getIntField(obj,"score");
XposedBridge.log("reflection setFiled-> msg="+msg2Value+" score="+score2Value);
```

log输出

```bash
21:59:27.225 1386-1386/com.forgotten.fridatestapp I/LSPosed-Bridge: reflection setFiled-> msg=from reflection score=99
```



#### 通过`XposedHelpers`

```java
/*通过Helpers设置属性值*/
XposedHelpers.setStaticObjectField(obj.getClass(),"msg","from helpers");
XposedHelpers.setIntField(obj,"score",888);

msg2Value = (String) XposedHelpers.getStaticObjectField(obj.getClass(), "msg");
score2Value = (int)XposedHelpers.getIntField(obj,"score");
XposedBridge.log("XposedHelpers setFiled-> msg="+msg2Value+" score="+score2Value);
```

log输出

```bash
21:59:27.226 1386-1386/com.forgotten.fridatestapp I/LSPosed-Bridge: XposedHelpers setFiled-> msg=from helpers score=888
```



>   相应api
>
>   ```java
>   // 设置静态属性
>   public static void setStaticObjectField(Class<?> clazz, String fieldName, Object value);
>   ...
>   
>   // 设置一般属性
>   public static void setObjectField(Object obj, String fieldName, Object value);
>   ...
>   ```
>
>   



## 主动调用方法

编写`invokeMethodTest()`方法

### 通过反射

```java
/*通过反射调用静态方法*/
// 获得静态Method 有一个参数String
Method getStringLengthMethod = obj.getClass().getDeclaredMethod("getStringLength",String.class);
/* 如果为private同样需要取消权限控制 */
int lengthValue = (int) getStringLengthMethod.invoke(obj.getClass(),"123");
// 获得实例方法
Method addNumberMethod = obj.getClass().getDeclaredMethod("addNumber", int.class, int.class, int.class);
double addNumberResult = (double) addNumberMethod.invoke(obj, 7, 8, 9);
XposedBridge.log("reflection invoke -> length=" + lengthValue + " addNumberResult=" + addNumberResult);
```

log输出

```bash
22:24:38.246 2757-2757/com.forgotten.fridatestapp I/LSPosed-Bridge: reflection invoke -> length=3 addNumberResult=24.0
```



### 通过XposedHelpers

```java
/*通过Helpers调用实例方法*/
int length2Value = (int) XposedHelpers.callStaticMethod(obj.getClass(), "getStringLength","12345");
Class[] parameterTypes = {int.class, int.class, int.class};
double addNumber2Result = (double) XposedHelpers.callMethod(obj, "addNumber", parameterTypes, 4, 5, 6);
/*
// 也可以这么写
double addNumber2Result = (double) XposedHelpers.callMethod(obj, "addNumber", new Class[]{int.class, int.class, int.class}, 4, 5, 6);*/
double addNumber3Result = (double) XposedHelpers.callMethod(obj, "addNumber", 3, 4, 5);
XposedBridge.log("Helpers invoke -> length=" + length2Value + " addNumberResult=" + addNumber2Result + "/" + addNumber3Result);
```

log输出

```bash
22:24:38.255 2757-2757/com.forgotten.fridatestapp I/LSPosed-Bridge: Helpers invoke -> length=5 addNumberResult=15.0/12.0
```



>   相应api
>
>   ```java
>   static Object	callMethod(Object obj, String methodName, Class[]<?> parameterTypes, Object... args)
>   Calls an instance or static method of the given object.
>   static Object	callMethod(Object obj, String methodName, Object... args)
>   Calls an instance or static method of the given object
>   
>   static Object	callStaticMethod(Class<?> clazz, String methodName, Class[]<?> parameterTypes, Object... args)
>   Calls a static method of the given class.
>   static Object	callStaticMethod(Class<?> clazz, String methodName, Object... args)
>   Calls a static method of the given class.
>   ```



-   其中任选一种即可，若没有填写参数类型数组参数、Xposed也会给补上去



## 对加壳App的处理

从52pojie上随便找了一个百度壳的app：[Xposed对壳的处理：testBDApp-蓝奏下载](https://wwe.lanzouy.com/iERHiz964cb)

找到壳的`Application`，Hook其`onCreate()`方法，在结束(修正`ClassLoader`)后，获取到真正的`ClassLoader`，之后可以正常Hook

```java
/** 在handleLoadPackage()下的逻辑 **/

/** 对加壳app的处理 **/
if("com.xekvhaDYe.androie".equals(lpparam.packageName)){
mLpparam = lpparam;
// getClassloaderAllClasses(mLpparam.classLoader);
XposedHelpers.findAndHookMethod("com.baidu.protect.StubApplication", mLpparam.classLoader, "onCreate", new XC_MethodHook() {
    @Override
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
        super.beforeHookedMethod(param);
        XposedBridge.log("com.baidu.protect.StubApplication onCreate has hooked");
    }

    @Override
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
        super.afterHookedMethod(param);
        XposedBridge.log("com.baidu.protect.StubApplication AFTERonCreate");
        ClassLoader finalClr = getClassloader();
        // getClassloaderAllClasses(finalClr);
        Class<?> aClass = XposedHelpers.findClass("com.xekvhaDYu.android.a.MainActivity", finalClr);
        Method[] declaredMethods = aClass.getDeclaredMethods();
        for (Method m : declaredMethods) {
            XposedBridge.log("method:"+m.toString());
            /* 可以打印出里面有onCreate()方法 */
        }

        /*
        // 正常开始hook相应方法
        XposedHelpers.findAndHookMethod("com.xekvhaDYu.android.a.MainActivity", finalClr, "onCreate",Bundle.class, null);
        // 这个方法为native函数，找不到实现，就不演示
        */
    }
});
```

用到的两个方法

```java

/**
 * 获得当前线程的ClassLoader
 * @return 返回当前ClassLoader
 */
public static ClassLoader getClassloader(){
    ClassLoader resultClr = null;
    Class<?> ActivityThreadClazz = null;
    try {
        ActivityThreadClazz = Class.forName("android.app.ActivityThread");
        Object currentActivityThread = XposedHelpers.callStaticMethod(ActivityThreadClazz, "currentActivityThread");
        Object mBoundApplication = XposedHelpers.getObjectField(currentActivityThread, "mBoundApplication");
        Application mInitialApplication = (Application) XposedHelpers.getObjectField(currentActivityThread,"mInitialApplication");
        Object info = XposedHelpers.getObjectField(mBoundApplication, "info");
        Application mApplication = (Application) XposedHelpers.getObjectField(info,"mApplication");
        resultClr = mApplication.getClassLoader();
    } catch (ClassNotFoundException e) {
        e.printStackTrace();
    }
    return resultClr;

}

/**
 * 获得ClassLoader可以加载的所有的类列表并打印
 * @param clr 传入的ClassLoader
 */
public static void getClassloaderAllClasses(ClassLoader clr){
    if(clr.toString().contains("BootClassLoader")){
        /* BootClassLoader没有这样的方法 */
        XposedBridge.log("getClassloaderAllClasses warning: is BootClassLoader, return...");
        return;
    }
    XposedBridge.log("getClassloaderAllClasses start -----> "+clr);

    Object pathListObj = XposedHelpers.getObjectField(clr, "pathList");
    Object[] dexElementsObj = (Object[]) XposedHelpers.getObjectField(pathListObj,"dexElements");
    for(Object dexElementObj:dexElementsObj){
        Object dexFileObj = XposedHelpers.getObjectField(dexElementObj, "dexFile");
        Object mCookieObj = XposedHelpers.getObjectField(dexFileObj, "mCookie");
        String[] classNameList = (String[]) XposedHelpers.callStaticMethod(dexFileObj.getClass(), "getClassNameList", mCookieObj);
        for (String cName : classNameList) {
            XposedBridge.log ("--> "+cName);
        }

    }
    XposedBridge.log("getClassloaderAllClasses end -----> "+clr);
}
```



此时打印最终的ClassLoader可以发现，加载的有内存中的DexFile，dump出来可以达到脱壳的目的？

```bash
Found finalClassLoader: dalvik.system.PathClassLoader[DexPathList[[zip file "/data/app/com.xekvhaDYe.androie-e7-oKrRen8eNa_JLqVnQog==/base.apk", dex file "InMemoryDexFile[cookie=[0, 3816653808]]", dex file "InMemoryDexFile[cookie=[0, 3816653888]]", dex file "InMemoryDexFile[cookie=[0, 3816653968]]", dex file "/data/app/com.xekvhaDYe.androie-e7-oKrRen8eNa_JLqVnQog==/base.apk"],nativeLibraryDirectories=[/data/app/com.xekvhaDYe.androie-e7-oKrRen8eNa_JLqVnQog==/lib/arm, /data/app/com.xekvhaDYe.androie-e7-oKrRen8eNa_JLqVnQog==/base.apk!/lib/armeabi-v7a, /system/lib, /vendor/lib]]]
```



### 另外一种处理

```java
// 被hook的app的包名
String hookedPackageName = "com.xekvhaDYe.androie";
// app里面的Activity
String hookedActivityName = "com.xekvhaDYu.android.a.MainActivity";
if (hookedPackageName.equals(lpparam.packageName)) {
    XposedBridge.log("has hooked...");
    XposedBridge.log("inner  => " + lpparam.processName);
    Class ActivityThread = XposedHelpers.findClass("android.app.ActivityThread", lpparam.classLoader);
    XposedBridge.hookAllMethods(ActivityThread, "performLaunchActivity", new XC_MethodHook() {
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            super.afterHookedMethod(param);
            Object mInitialApplication = (Application) XposedHelpers.getObjectField(param.thisObject, "mInitialApplication");
            ClassLoader finalCL = (ClassLoader) XposedHelpers.callMethod(mInitialApplication, "getClassLoader");
            XposedBridge.log("found classload is => " + finalCL.toString());
            Class BabyMain = (Class) XposedHelpers.callMethod(finalCL, "findClass", hookedActivityName);
            XposedBridge.log("found final class is => " + BabyMain.getName().toString());
        }
    });
}
```



## 多dex的处理

例如某个加载器在代码中加载了另一个dex：hook软件的自定义`ClassLoader`的构造方法，在构造方法结束后得到真正的`ClassLoader`对象

## 对so层的处理

Xposed并不支持对so层的Hook，但是可以通过xposed来hook`System.loadLibrary()`方法来判断加载的so文件，当加载到指定so文件时候，自身也加载预先编写的so用C/C++来hook软件的so文件。

但是hook`System.loadLibrary()`方法会导致加载时使用的`ClassLoader`被替换成`Xposed`的`ClassLoader`；所以查看`System.loadLibrary()`的源码来调用更深层次的，在Android8.1调用的是`Runtime.loadLibrary0(ClassLoader loader, String libname)`；根据系统各有不同，稍作修改即可。

Xposed加载逻辑

```java
// hook so
XposedHelpers.findAndHookMethod("java.lang.Runtime", lpparam.classLoader, "loadLibrary0",ClassLoader.class,String.class, new XC_MethodHook() {
    @Override
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
        super.beforeHookedMethod(param);
        String soName = (String) param.args[1];
        XposedBridge.log("beforeHookedMethod System.load("+soName+")");
    }

    @Override
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
        super.afterHookedMethod(param);
        String soName = (String) param.args[1];
        XposedBridge.log("afterHookedMethod System.load("+soName+")");
        // 被hook的so名字
        String hookedSo = "native-libXXXXX";
        if(soName.contains(hookedSo)){
            // 如果加载到了需要被hook的so，则加载自己用于hook的so文件
            System.load("/data/data/[packagename]/files/myHook.so");
        }
    }
});
```



可以通过以下来编写hook代码

-   [ele7enxxh/Android-Inline-Hook: thumb16 thumb32 arm32 inlineHook in Android (github.com)](https://github.com/ele7enxxh/Android-Inline-Hook)



@TODO





