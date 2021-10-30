package com.forgotten.actlyloadnocomp;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import dalvik.system.DexClassLoader;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 调用方法
        onLoadDex(this.getApplicationContext(), "/data/local/tmp/NoComponent.dex");
    }


    public void onLoadDex(Context context, String dexFilePath) {
        File optfile = context.getDir("opt_dex", 0);
        File libfile = context.getDir("lib_path", 0);
        ClassLoader parentClassloader = MainActivity.class.getClassLoader();
        ClassLoader tmpClassloader = context.getClassLoader();
        // 加载相应的dex文件
        DexClassLoader dexClassLoader = new DexClassLoader(dexFilePath, optfile.getAbsolutePath(), libfile.getAbsolutePath(), MainActivity.class.getClassLoader());
        /**
         参数：
         String dexPath: 加载目标dex所在的路径，装载器将从路径中寻找指定目标类
         String optimizedDirectory: dex在apk或者jar文件中，在装载前需要先解压出dex文件，这个路径是解压出来的dex文件存放的路径
         String librarySearchPath: 目标类中使用的C/C++库
         ClassLoader parent: 该类装载器的父装载器，一般为当前执行类的装载器
         **/
        Class<?> clazz = null;
        try {
            // 加载相应的类文件
            clazz = dexClassLoader.loadClass("NoComponent");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        // 如果成功加载到了相应的类
        if (clazz != null) {
            try {
                // 获得构造方法
                Constructor<?> Cons = clazz.getConstructor();
                // 获得实例
                Object object = Cons.newInstance();
                // 得到sum方法
                Method method = clazz.getMethod("sum", int.class, int.class);
                // 进行调用
                int sum = (int) method.invoke(object, 2, 3);
                Log.d("onLoadDex", "sum: " + sum);
            } catch (NoSuchMethodException e) {
                e.printStackTrace();
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            } catch (InstantiationException e) {
                e.printStackTrace();
            } catch (InvocationTargetException e) {
                e.printStackTrace();
            }
        }


    }

}