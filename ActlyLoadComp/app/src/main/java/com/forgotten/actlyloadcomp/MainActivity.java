package com.forgotten.actlyloadcomp;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.ArrayMap;
import android.view.View;
import android.widget.Button;

import androidx.appcompat.app.AppCompatActivity;

import java.io.File;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import dalvik.system.DexClassLoader;

public class MainActivity extends AppCompatActivity {
    private static final String dexPath = "/data/local/tmp/TestApp.dex";
    private Button btnOne;
    private Button btnTwo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        btnOne = findViewById(R.id.btn_one);
        btnTwo = findViewById(R.id.btn_two);

        btnOne.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivityOne(getApplicationContext(), dexPath);
            }
        });

        btnTwo.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivityTwo(getApplicationContext(), dexPath);
            }
        });
    }


    public void replaceClassLoader(ClassLoader classLoader) {
        try {
            // 加载 android.app.ActivityThread 类
            Class<?> ActivityThreadClazz = classLoader.loadClass("android.app.ActivityThread");
            // 获得方法 currentActivityThread
            Method currentActivityThreadMethod = ActivityThreadClazz.getMethod("currentActivityThread");
            // 设置可访问
            currentActivityThreadMethod.setAccessible(true);
            // 执行currentActivityThread方法得到唯一的activityThread对象
            Object activityThreadObj = currentActivityThreadMethod.invoke(null);
            // 找到mPackages字段
            Field mPackagesField = ActivityThreadClazz.getDeclaredField("mPackages");
            mPackagesField.setAccessible(true);
            // 获得activityThread对象的mPackages字段
            ArrayMap mPackagesObj = (ArrayMap) mPackagesField.get(activityThreadObj);
            // 根据当前包名，查找到相应的loadedApk对象
            WeakReference wr = (WeakReference) mPackagesObj.get(this.getPackageName());
            Object loadedApkObj = wr.get();
            // 加载loadedAPk类
            Class<?> loadedApkClazz = classLoader.loadClass("android.app.LoadedApk");
            // 找到loadedApk类的mClassLoader字段
            Field mClassLoaderFiled = loadedApkClazz.getDeclaredField("mClassLoader");
            mClassLoaderFiled.setAccessible(true);
            // 将找到的loadedAPk的mClassLoader字段设置为自己新建的classLoader
            mClassLoaderFiled.set(loadedApkObj, classLoader);

        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
    }

    public void startActivityOne(Context context, String dexfilePath) {
        File optfile = context.getDir("opt_dex", 0);
        File libfile = context.getDir("lib_path", 0);
        ClassLoader parentClassloader = MainActivity.class.getClassLoader();
        ClassLoader tmpClassloader = context.getClassLoader();
        // 加载相应的dex文件
        DexClassLoader dexClassLoader = new DexClassLoader(dexfilePath, optfile.getAbsolutePath(), libfile.getAbsolutePath(), MainActivity.class.getClassLoader());
        replaceClassLoader(dexClassLoader);

        Class<?> clazz = null;
        try {
            // 加载相应的类文件
            clazz = dexClassLoader.loadClass("com.forgotten.actlyloadcomptestapp.TestOneActivity");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        // 启动MainActivity类
        context.startActivity(new Intent(context, clazz));

    }


    public void startActivityTwo(Context context, String dexfilePath) {
        File optfile = context.getDir("opt_dex", 0);
        File libfile = context.getDir("lib_path", 0);

        ClassLoader pathClassloader = MainActivity.class.getClassLoader();
        ClassLoader bootClassloader = MainActivity.class.getClassLoader().getParent();
        // 加载相应的dex文件
        DexClassLoader dexClassLoader = new DexClassLoader(dexfilePath, optfile.getAbsolutePath(), libfile.getAbsolutePath(), bootClassloader);

        try {
            Field parentField = ClassLoader.class.getDeclaredField("parent");
            parentField.setAccessible(true);
            // 将pathClassLoader的父类修改为DexClassLoader
            parentField.set(pathClassloader, dexClassLoader);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }

        Class<?> clazz = null;
        try {
            // 加载相应的类文件
            clazz = dexClassLoader.loadClass("com.forgotten.actlyloadcomptestapp.TestTwoActivity");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        // 启动MainActivity类
        context.startActivity(new Intent(MainActivity.this, clazz));

    }
}