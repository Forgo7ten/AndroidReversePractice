---
title:  ES FileExplorer修改记录

tags:
  - 会员解锁
  - 签名校验
  - 去除更新
  - 去除广告
author: Forgo7ten
updated: '2022/01/09 00:03:00'
categories:
  - Crack
date: 2022-01-01 00:03:00

---



# ES FileExplorer修改

官网：[ES APP GROUP (estrongs.com)](http://www.estrongs.com/)

version 4.2.8.1



-   解锁会员
-   去除包名签名校验
-   去除更新
-   删除百度广告

## 效果展示

![n1](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842.png)

![n2](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-1.png)

![n3](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-2.png)

## 分析过程

### 会员功能解锁

#### 分析

官网下载，没有加固

刚开始通过搜索vip，查找到了AccountInfo.toString方法

然后hook了getIsVip()，发现没有被调用。

![image-20220109143829888](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-3.png)

然后找一个触发vip开通的地方，来到了vip功能 侧边栏管理

开启monitor的`Start Method Profiling`功能，点击保存，跳转到了开通会员界面

此时停止记录，搜搜`onClick`

![image-20220109144048736](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-4.png)

前往查看

![image-20220109144319810](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-5.png)

前往`a.H1(`)方法，H1直接调用了`this.J1()`方法，查看`J1()`

![image-20220109144338972](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-6.png)

发现有两个if判断，先查看最外层的if判断的else代码`ChinaMemberActivity.x1(this, "nav_manage");`；启动的正好是开通Vip的Activity

通过直接hook s()方法，返回true，确实未登录会员功能已经解锁，

主题按钮由【解锁】变为了【下载】；侧边栏管理旁的会员皇冠标志也消失不见

但是我还想追更深

于是前往c50.m().s()方法：`return o.E0().r2();`

前往o.E0().r2()方法：`return this.p2();`

前往p2()方法

```java
public boolean p2(){
   return PreferenceManager.getDefaultSharedPreferences(FexApplication.o()).getBoolean(b50.d, false);
}
```



p2是使用getDefaultSharedPreferences取出了一个Boolean值，也就是将vip状态存在了SharedPreferences中，但是我使用grep找了并没有找到，可能是登录才会写入这些信息？没有登录测试

其中b50.d的值为

![image-20220109144626867](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-7.png)

同样找到了在p2同类的j4方法，这里将vip状态存入本地文件；hook了一下，没有被调用，可能登录才会调用吧

```java
public void J4(boolean p0){
   PreferenceManager.getDefaultSharedPreferences(FexApplication.o()).edit().putBoolean("already_shown_register_dialog", p0).apply();
}
```



#### 修改

##### Frida hook

所以说直接hook `p2()`方法返回true，即可

```javascript
function main() {
    Java.perform(function () {
        Java.use("com.estrongs.android.pop.o").p2.implementation = function () {
            console.log("p2 hooked.");
            return true;
        };
    });
}

setImmediate(main);
```

![image-20220109145120810](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-8.png)

##### 修改Smali

```smali
.method public p2()Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method
```



### 去除校验

#### 分析

重新打包安装后提示盗版，同时会员失效

![daoban](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-9.png)

![image-20220109151145363](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-10.png)

找到这个弹窗来自`pop.view.e`

![image-20220109151632823](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-11.png)

hook这几个方法，打印栈回溯

发现正常的值为

```
e.c()  true
e.d()  false
e.e()  false
```

##### c3$a

而这几个方法都是由`FileExplorerActivity$c3$a.run()`方法调用的，`e.c()`也有`utils.p.a()`来调用

![image-20220109153959997](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-12.png)

可以看到验证了包名，或者`e.c()==false`都会执行`FileExplorerActivity$c3$a$a.run()`回调，而在这调用了`e.f()`方法弹出盗版弹窗

所以只要让`e.c()`恒为`true`即可去除盗版验证

##### e.c

而`e.c()`调用了`e.d()`，若`e.d()`成立则直接返回`true`，不判断接下来的apk签名

##### e.d

`e.d()`在其中验证了一些`android.os.Build`的信息；若相同则不判断签名和包名直接返回`true`

验证的信息为

```java
return Build.MANUFACTURER.equals("Amazon")  &&
    ( 
    Build.MODEL.equals("Kindle Fire") || Build.MODEL.startsWith("KF")
);
```

##### e.e

`e.e()`的返回值感觉并没有什么作用，先是查询本地SharedPreferences，查到了并且值通过验证就返回`false`，未查到就写入验证的值，然后返回`true`；感觉像是安装后判断第一次打开之类的

判断是否相等的值`10141`是版本号

```java
public static String H1(Context p0){
   return PreferenceManager.getDefaultSharedPreferences(p0).getString("fex_version", "0");
}
public static void m5(Context p0,String p1){
   SharedPreferences$Editor uEditor = PreferenceManager.getDefaultSharedPreferences(p0).edit();
   uEditor.putString("fex_version", p1);
   uEditor.commit();
}
```



#### 修改

e.c()和e.d() 任意一方法返回`true`即可，我这里就都改了

```smali
.method public static c()Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method

.method public static d()Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method
```



### 去除自动更新

其实可以通过开关自动检测来实现；还是禁止更新好，于是分析一下

先分析布局找到控件的资源ID

![image-20220109161959607](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-13.png)

根据ID找到弹出弹窗的方法为`ec.m10.l()`（更新数据解析类`es.l10$b.b(JSONObject p0)`），交叉引用找到`ec.m10.c()`方法

其中int i对应的是`“upgrade_nat_error”`，修改时候返回下面的`upgrade_is_latest`即可提示最新版

![image-20220109163858577](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-14.png)

#### 修改



```
.method private static c(Landroid/app/Activity;ZZ)V
    .locals 1
    .annotation build Landroidx/annotation/UiThread;
    .end annotation

    const v0, 0x7f110c8c
    invoke-static {v0}, Lcom/estrongs/android/ui/view/v;->b(I)V
    return-void
    
.end method
```

这样每次都是弹出提示最新版了，缺点是没有找到真正发送更新信息的地方；抓包抓了一下，没有抓到版本请求，虽然仔细看了这个c方法没感觉有网络请求的操作……

打包完发现这个方法控制的是显示，上述那样改还是每次打开会弹出一个Toast。想关闭的话把下图中的自动检测关掉（因为每次打开都会检测新版本），或者上面修改的2678四行代码删掉就可以了，懒得搞了

![img](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-15.png)



### 去除百度广告

虽然会员已经没有广告了，但根据版规还是去除一下广告，搜索关键字发现了百度广告

根据芽衣大佬的方法[【新手教程】安卓 穿山甲广告（字节跳动）、腾讯广告和百度广告 通用去除教程](https://www.52pojie.cn/thread-1213695-1-1.html)

![image-20220109172021531](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-16.png)



删除jar后，却找不到`addEventListener()`方法

![image-20220109172308703](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-17.png)

只好自力更生了

先删除`assets/bdxadsdk.jar`

然后去把两处调用删除

![image-20220109172938998](https://gitee.com/Forgo7ten/images-bed/raw/master/2022/01/20220110000842-18.png)

看代码有异常捕获了，应该不出问题

然后把`bdxadsdk.jar`字符串都替换成了`bdxadsdk_crack.jar`（纯粹多此一举）



打包签名安装，MIUI12没有出问题