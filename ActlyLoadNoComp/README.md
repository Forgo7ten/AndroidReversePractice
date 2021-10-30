# 主动加载dex（调用非组件）



### 实验步骤

环境 Pixel sailfish 8.1.0



#### 1. 生成被调用dex

##### 1.1 源码

```java
public class NoComponent {
    public static void main(String[] args) {
        System.out.println("NoComponent:main");
    }

    public int sum(int a, int b) {
        System.out.println("NoComponent:sum");
        return a + b;
    }
}
```

##### 1.2 生成`.class`文件

命令

```bash
javac NoComponent.java
```

##### 1.3 生成`.dex`文件

命令

```bash
dx.bat --dex --output NoComponent.dex NoComponent.class
```



#### 2. 调用环境配置

##### 2.2 将dex放入设备

```bash
adb push NoComponent.dex /data/local/tmp
```

##### 2.3 赋予dex权限

```bash
adb shell
su
cd /data/local/tmp
chmod 777 NoComponent.dex
```



#### 3. 编写app

##### 3.1 编写MainActivity.java

##### 3.2 在AndroidManifest.xml中添加读写权限

```xml
<!--    在<manifest>节点下添加相应权限 -->
	<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
```



#### 4. 安装运行app

得到Log日志

```bash
2021-10-30 20:41:35.225 14292-14292/com.forgotten.actlyloadnocomp D/onLoadDex: sum: 5
```

