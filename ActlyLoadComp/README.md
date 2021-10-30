# 主动加载dex（调用组件）



### 实验步骤

环境 Pixel sailfish 8.1.0

#### 1. 编写被调组件

新建一个AS项目

##### 1.1 编写TestOneActivity

Activity代码

```java
package com.forgotten.actlyloadcomptestapp;

import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

public class TestOneActivity extends AppCompatActivity {
    private static final String TAG = "ActlyLoadComp";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_test_one);
        Log.d(TAG, "onCreate: TestOneActivity");
        Toast.makeText(getApplicationContext(), "TestOneActivity", Toast.LENGTH_SHORT).show();

    }
}
```

activity_test_one

```xml
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    tools:context=".TestOneActivity">
    <TextView
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="TestOneActivity"
        android:textSize="48sp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintLeft_toLeftOf="parent"
        app:layout_constraintRight_toRightOf="parent"
        app:layout_constraintTop_toTopOf="parent" />
</androidx.constraintlayout.widget.ConstraintLayout>
```

##### 1.2 编写TestTwoActiviy

将提示由`TestOne`修改为`TestTwo`

其中activity代码变为继承`Activity`类

```java
public class TestTwoActivity extends Activity{
    
}
```

其余同

#### 2. 调用环境配置

##### 2.1 生成dex

AS中，菜单栏 `Build` → `Build Bundle(s)/APK(s)` → `Build APK(s)`生成APK

之后打开APK压缩包，提取出包含TestActivity的dex

##### 2.2 将dex放入设备

```bash
adb push TestApp.dex /data/local/tmp
```



##### 2.3 赋予dex相应权限

```bash
adb shell
su
cd /data/local/tmp
chmod 777 TestApp.dex
```



#### 3. 编写调用app

##### 3.1 编写MainActivity

详见代码

##### 3.2 修改AndroidManifest.xml

###### 3.2.1 添加读写权限

```xml
<!--    在<manifest>节点下添加相应权限 -->
	<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
```

###### 3.2.2 注册被调用Activity

```xml
  <activity
            android:name="com.forgotten.actlyloadcomptestapp.TestTwoActivity"
            android:exported="true" />
        <activity
            android:name="com.forgotten.actlyloadcomptestapp.TestOneActivity"
            android:exported="true" />
```



##### 3.3 拷贝TestActivity布局文件

将两个`TestActivity`的布局文件放入调用app的`layout`文件夹中；若不这样做，则需要注释掉`setContentView`行



#### 4. 编译运行调用app

点击按钮即可看到效果

