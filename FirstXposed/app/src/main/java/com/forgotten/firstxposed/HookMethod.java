package com.forgotten.firstxposed;

import android.app.Application;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * @ClassName HookMethod
 * @Description hook方法测试
 * @Author Palmer
 * @Date 2022/1/24
 **/
public class HookMethod implements IXposedHookLoadPackage {
    // 保存到全局的lpparam变量
    XC_LoadPackage.LoadPackageParam mLpparam;

    /**
     * 获得当前线程的ClassLoader
     *
     * @return 返回当前ClassLoader
     */
    public static ClassLoader getClassloader() {
        ClassLoader resultClr = null;
        Class<?> ActivityThreadClazz = null;
        try {
            ActivityThreadClazz = Class.forName("android.app.ActivityThread");
            Object currentActivityThread = XposedHelpers.callStaticMethod(ActivityThreadClazz, "currentActivityThread");
            Object mBoundApplication = XposedHelpers.getObjectField(currentActivityThread, "mBoundApplication");
            Application mInitialApplication = (Application) XposedHelpers.getObjectField(currentActivityThread, "mInitialApplication");
            Object info = XposedHelpers.getObjectField(mBoundApplication, "info");
            Application mApplication = (Application) XposedHelpers.getObjectField(info, "mApplication");
            resultClr = mApplication.getClassLoader();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return resultClr;

    }

    /**
     * 获得ClassLoader可以加载的所有的类列表并打印
     *
     * @param clr 传入的ClassLoader
     */
    public static void getClassloaderAllClasses(ClassLoader clr) {
        if (clr.toString().contains("BootClassLoader")) {
            /* BootClassLoader没有这样的方法 */
            XposedBridge.log("getClassloaderAllClasses warning: is BootClassLoader, return...");
            return;
        }
        XposedBridge.log("getClassloaderAllClasses start -----> " + clr);

        Object pathListObj = XposedHelpers.getObjectField(clr, "pathList");
        Object[] dexElementsObj = (Object[]) XposedHelpers.getObjectField(pathListObj, "dexElements");
        for (Object dexElementObj : dexElementsObj) {
            Object dexFileObj = XposedHelpers.getObjectField(dexElementObj, "dexFile");
            Object mCookieObj = XposedHelpers.getObjectField(dexFileObj, "mCookie");
            String[] classNameList = (String[]) XposedHelpers.callStaticMethod(dexFileObj.getClass(), "getClassNameList", mCookieObj);
            for (String cName : classNameList) {
                XposedBridge.log("--> " + cName);
            }

        }
        XposedBridge.log("getClassloaderAllClasses end -----> " + clr);
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        // 打印日志，打印加载过的app的包名
        XposedBridge.log("Xposed has " + lpparam.packageName);
        if ("com.forgotten.fridatestapp".equals(lpparam.packageName)) {
            // 根据包名过滤app

            // 保存lpparam到成员变量
            mLpparam = lpparam;
            // 对构造方法hook
            hookConstructorTest();
            // 对方法进行hook
            // hookMethodTest();
            // 获取/修改对象属性
            // accessFieldTest();
            // 主动调用静态、实例方法
            invokeMethodTest();
        }


        /** 对加壳app的处理 **/
        if ("com.xekvhaDYe.androie".equals(lpparam.packageName)) {
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
                    XposedBridge.log("Found finalClassLoader: " + finalClr);
                    // getClassloaderAllClasses(finalClr);
                    Class<?> aClass = XposedHelpers.findClass("com.xekvhaDYu.android.a.MainActivity", finalClr);
                    Method[] declaredMethods = aClass.getDeclaredMethods();
                    for (Method m : declaredMethods) {
                        XposedBridge.log("method:" + m.toString());
                        /* 可以打印出里面有onCreate()方法 */
                    }

                    /*
                    // 正常开始hook相应方法
                    XposedHelpers.findAndHookMethod("com.xekvhaDYu.android.a.MainActivity", finalClr, "onCreate",Bundle.class, null);
                    // 这个方法为native函数，找不到实现，就不演示
                    */
                }
            });
        }


/*        // 被hook的app的包名
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
        }*/


/*        // hook so
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
        });*/
    }

    /**
     * 主动调用方法
     */
    private void invokeMethodTest() {
        XposedHelpers.findAndHookMethod("com.forgotten.fridatestapp.HookedObject", mLpparam.classLoader, "stringTwo", String.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                Object obj = param.thisObject;
                /*通过反射调用静态方法*/
                // 获得静态Method 有一个参数String
                Method getStringLengthMethod = obj.getClass().getDeclaredMethod("getStringLength", String.class);
                /* 如果为private同样需要取消权限控制 */
                int lengthValue = (int) getStringLengthMethod.invoke(obj.getClass(), "123");
                // 获得实例方法
                Method addNumberMethod = obj.getClass().getDeclaredMethod("addNumber", int.class, int.class, int.class);
                double addNumberResult = (double) addNumberMethod.invoke(obj, 7, 8, 9);
                XposedBridge.log("reflection invoke -> length=" + lengthValue + " addNumberResult=" + addNumberResult);

                /*通过Helpers调用实例方法*/
                int length2Value = (int) XposedHelpers.callStaticMethod(obj.getClass(), "getStringLength", "12345");
                Class[] parameterTypes = {int.class, int.class, int.class};
                double addNumber2Result = (double) XposedHelpers.callMethod(obj, "addNumber", parameterTypes, 4, 5, 6);
                /*
                // 也可以这么写
                double addNumber2Result = (double) XposedHelpers.callMethod(obj, "addNumber", new Class[]{int.class, int.class, int.class}, 4, 5, 6);*/
                double addNumber3Result = (double) XposedHelpers.callMethod(obj, "addNumber", 3, 4, 5);
                XposedBridge.log("Helpers invoke -> length=" + length2Value + " addNumberResult=" + addNumber2Result + "/" + addNumber3Result);

            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
            }
        });
    }

    /**
     * 获取/修改对象字段
     */
    private void accessFieldTest() {
        XposedHelpers.findAndHookMethod("com.forgotten.fridatestapp.HookedObject", mLpparam.classLoader, "stringTwo", String.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                XposedBridge.log("accessField() HookedObject.stringTwo_before param: " + param.args[0]);

                // 可以通过 param.thisObject 来获取到当前对象
                Object obj = param.thisObject;


                /*反射方式获取static Field*/
                Field msgField = obj.getClass().getDeclaredField("msg");
                // 私有属性，需要取消 Java 语言访问检查
                msgField.setAccessible(true);
                // static属性，获得值时传入null
                String msgValue = (String) msgField.get(null);

                /*反射方式获取Object Field*/
                Field scoreField = obj.getClass().getDeclaredField("score");
                scoreField.setAccessible(true);
                int scoreValue = (int) scoreField.get(obj);

                XposedBridge.log("reflection Filed-> msg=" + msgValue + " score=" + scoreValue);

                String msg2Value = (String) XposedHelpers.getStaticObjectField(obj.getClass(), "msg");
                int score2Value = XposedHelpers.getIntField(obj, "score");
                XposedBridge.log("XposedHelpers Filed-> msg=" + msg2Value + " score=" + score2Value);


                /* 通过反射设置属性值 */
                msgField.set(null, "from reflection");
                scoreField.set(obj, 99);

                msg2Value = (String) XposedHelpers.getStaticObjectField(obj.getClass(), "msg");
                score2Value = XposedHelpers.getIntField(obj, "score");
                XposedBridge.log("reflection setFiled-> msg=" + msg2Value + " score=" + score2Value);


                /*通过Helpers设置属性值*/
                XposedHelpers.setStaticObjectField(obj.getClass(), "msg", "from helpers");
                XposedHelpers.setIntField(obj, "score", 888);

                msg2Value = (String) XposedHelpers.getStaticObjectField(obj.getClass(), "msg");
                score2Value = XposedHelpers.getIntField(obj, "score");
                XposedBridge.log("XposedHelpers setFiled-> msg=" + msg2Value + " score=" + score2Value);

            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                /* param.getResult() 获得方法的返回值 */
                XposedBridge.log("accessField() HookedObject.stringTwo_after: result: " + param.getResult());
            }

        });
    }


    /**
     * 对方法的hook测试
     */
    private void hookMethodTest() {
        XposedHelpers.findAndHookMethod("com.forgotten.fridatestapp.HookedObject", mLpparam.classLoader, "stringTwo", String.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                /* param.args 为方法的参数列表 */
                XposedBridge.log("HookedObject.stringTwo_before param: " + param.args[0]);

                /*// 对参数进行修改
                param.args[0] = "param from Xposed";*/

            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                /* param.getResult() 获得方法的返回值 */
                XposedBridge.log("HookedObject.stringTwo_after: result: " + param.getResult());

                /*// 对返回值进行修改
                param.setResult("I'm from Xposed.");*/
            }

        });

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

    }

    /**
     * 对构造方法的hook测试
     */
    private void hookConstructorTest() {

        /*try {
            // 使用java反射 类加载器.loadClass方式来加载一个类
            Class<?> HookedObjectClass = mLpparam.classLoader.loadClass("com.forgotten.fridatestapp.HookedObject");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }*/

        // 通过XposedHelpers.findClass来加载一个类
        Class<?> HookedObjectClass = XposedHelpers.findClass("com.forgotten.fridatestapp.HookedObject", mLpparam.classLoader);
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

    }
}