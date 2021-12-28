#include <jni.h>
#include <string>
#include <android/log.h>
#include <pthread.h>

/**
 * JNI初尝试
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_forgotten_firstjni_MainActivity_stringFromHello(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from Hello";
    return env->NewStringUTF(hello.c_str());
}


/**
 * 使用类的静态Field
 */
extern "C" JNIEXPORT void JNICALL Java_com_forgotten_firstjni_MainActivity_useObjectStaticField(
        JNIEnv *env,
        jobject /* this */) {
    // 查找该类
    jclass person_clazz = env->FindClass("com/forgotten/firstjni/Person");
    // 查找(公共)静态字段ID
    jfieldID number_fieldID = env->GetStaticFieldID(person_clazz, "sNumber", "I");
    // 获取该字段的值
    jint number = env->GetStaticIntField(person_clazz, number_fieldID);
    __android_log_print(ANDROID_LOG_DEBUG, "useObjectStaticField", "before sNumber=%d", number);
    env->SetStaticIntField(person_clazz, number_fieldID, 999);
    __android_log_print(ANDROID_LOG_DEBUG, "useObjectStaticField", "after sNumber=%d", number);
    // 查找(私有)静态字段ID  同公有 | jni中不分公私
    jfieldID country_fieldID = env->GetStaticFieldID(person_clazz, "country", "Ljava/lang/String;");
    // 进行显式类型转换 除了基本类型一律是object
    jstring country_jstr = static_cast<jstring>(env->GetStaticObjectField(person_clazz,
                                                                          country_fieldID));
    // 将jstring转为char*
    const char *country_chars = env->GetStringUTFChars(country_jstr, nullptr);
    __android_log_print(ANDROID_LOG_DEBUG, "useObjectStaticField", "country=%s", country_chars);
}

/**
 * 实例化对象方法一
 */
extern "C" JNIEXPORT void JNICALL Java_com_forgotten_firstjni_MainActivity_useObjectField1(
        JNIEnv *env,
        jobject /* this */) {
    // 查找该类
    jclass person_clazz = env->FindClass("com/forgotten/firstjni/Person");
    // 查找构造方法的methodID，构造方法名为<init>
    jmethodID constructID1 = env->GetMethodID(person_clazz, "<init>", "()V");
    // 进行对象的实例化
    jobject person1 = env->NewObject(person_clazz, constructID1);
    // 查找到字段name的fieldID
    jfieldID nameID = env->GetFieldID(person_clazz, "mName", "Ljava/lang/String;");
    // 通过对象和fieldID获取存储的值
    jstring name_jstr = static_cast<jstring>(env->GetObjectField(person1, nameID));
    // 将jstring转换为char×类型
    const char *name_chars = env->GetStringUTFChars(name_jstr, nullptr);
    __android_log_print(ANDROID_LOG_DEBUG, "useObjectField1", "name=%s", name_chars);

    // 使用完需要释放掉该字符串  不确定是否这么用
    env->ReleaseStringUTFChars(name_jstr, name_chars);
    __android_log_print(ANDROID_LOG_DEBUG, "useObjectField1", "name=%s", name_chars);
    // 好像释放了后还是可以用…… 晕

    jmethodID constructID2 = env->GetMethodID(person_clazz, "<init>", "(Ljava/lang/String;)V");
    // 给有参构造函数设置参数并执行获得对象
    jobject person2 = env->NewObject(person_clazz, constructID2, env->NewStringUTF("Hello"));
    jstring name_jstr2 = static_cast<jstring>(env->GetObjectField(person2, nameID));
    __android_log_print(ANDROID_LOG_DEBUG, "useObjectField1", "param name=%s",
                        env->GetStringUTFChars(name_jstr2, nullptr));

}

/**
 * 实例化对象方法二
 */
extern "C" JNIEXPORT void JNICALL Java_com_forgotten_firstjni_MainActivity_useObjectField2(
        JNIEnv *env,
        jobject /* this */) {
    // 查找该类
    jclass person_clazz = env->FindClass("com/forgotten/firstjni/Person");
    // 查找构造方法的methodID
    jmethodID constructID = env->GetMethodID(person_clazz, "<init>", "()V");
    // 新建一个对象，但没有进行初始化
    jobject person_obj = env->AllocObject(person_clazz);
    // 对对象进行初始化，第四个参数为 params...
    env->CallNonvirtualVoidMethod(person_obj, person_clazz, constructID);
    // 查找到字段name的fieldID
    jfieldID nameID = env->GetFieldID(person_clazz, "mName", "Ljava/lang/String;");
    jstring name_jstr2 = static_cast<jstring>(env->GetObjectField(person_obj, nameID));
    __android_log_print(ANDROID_LOG_DEBUG, "useObjectField2", "name=%s",
                        env->GetStringUTFChars(name_jstr2, nullptr));

}

/**
 * 使用array数组
 */
extern "C" JNIEXPORT void JNICALL Java_com_forgotten_firstjni_MainActivity_useArray(
        JNIEnv *env,
        jobject /* this */) {
    // 查找该类
    jclass person_clazz = env->FindClass("com/forgotten/firstjni/Person");
    // 查找(公共)静态字段ID
    jfieldID array_fieldID = env->GetStaticFieldID(person_clazz, "testArray", "[I");
    jintArray tarray = static_cast<jintArray>(env->GetStaticObjectField(person_clazz,
                                                                        array_fieldID));
    // 获得array的长度
    int length = env->GetArrayLength(tarray);
    // 获得指向array的int指针
    int *p = env->GetIntArrayElements(tarray, nullptr);
    for (int i = 0; i < length; ++i) {
        // 循环打印array
        __android_log_print(ANDROID_LOG_DEBUG, "useArray", "array[%d]=%d", i, p[i]);
    }
    int newarr[length];
    for (int i = 0; i < length; ++i) {
        newarr[i] = 100 - i;
    }
    // 对数组中的值进行修改
    env->SetIntArrayRegion(tarray, 0, length, newarr);
}


/**
 * JNI调用静态与非静态方法
 */
extern "C"
JNIEXPORT void JNICALL
Java_com_forgotten_firstjni_MainActivity_useMethod(JNIEnv *env, jobject thiz) {
    // 查找该类
    jclass person_clazz = env->FindClass("com/forgotten/firstjni/Person");
    // 找到相应的构造方法
    jmethodID constructID = env->GetMethodID(person_clazz, "<init>", "(Ljava/lang/String;)V");
    jstring hello_js = env->NewStringUTF("Hello");
    // 给有参构造函数设置参数并执行获得对象
    jobject person_obj = env->NewObject(person_clazz, constructID, hello_js);

    // 获得Person类中的静态方法ID
    jmethodID sMethod_mid = env->GetStaticMethodID(person_clazz, "sMethod",
                                                   "(Ljava/lang/String;)I");
    // 相应的方法还有CallStaticIntMethodA,CallStaticIntMethodV 只是传递的参数形式不同
    // 中间的int是返回值，如果方法的返回值为void时，则应调用CallVoidMethod()
    int hello_len = env->CallStaticIntMethod(person_clazz, sMethod_mid, hello_js);
    __android_log_print(ANDROID_LOG_DEBUG, "useMethod", "hello_len=%d", hello_len);

    // 获得Person类中的非静态方法ID
    jmethodID mMethod_mid = env->GetMethodID(person_clazz, "mMethod", "(Ljava/lang/String;)I");
    int hello_2len = env->CallIntMethod(person_obj, mMethod_mid, hello_js);
    __android_log_print(ANDROID_LOG_DEBUG, "useMethod", "hello_2len=%d", hello_2len);
}


// 保存vm的全局变量
JavaVM *global_vm = nullptr;
// 保存全局ClassLoader
jobject gClassLoader = nullptr;

/**
 * 加载类函数封装
 * @param env Env
 * @param name 加载类全类名
 * @return
 */
jclass loadClass(JNIEnv *env, const char *name) {
    jclass result = nullptr;
    if (env) {
        // 首先通过env->FindClass()来加载类
        result = env->FindClass(name);
        // 尝试捕获异常，如果加载失败会捕获到异常
        jthrowable exception = env->ExceptionOccurred();
        if (exception) {
            // 如果有异常，证明加载失败，此时先清除异常
            env->ExceptionClear();
            // 使用全局ClassLoader的方式来加载类
            jclass ClassLoader_Clazz = env->FindClass("java/lang/ClassLoader");
            jmethodID loadClass_MID = env->GetMethodID(ClassLoader_Clazz, "loadClass",
                                                       "(Ljava/lang/String;)Ljava/lang/Class;");
            return static_cast<jclass>(env->CallObjectMethod(gClassLoader, loadClass_MID,
                                                             env->NewStringUTF(name)));
        }
    }
    return result;
}

/**
 * 获取env
 * @return
 */
JNIEnv *getEnv() {
    JNIEnv *env = nullptr;
    // 先尝试通过GetEnv获取env
    int status = global_vm->GetEnv((void **) &env, JNI_VERSION_1_6);
    if (status < 0) {
        // 如果获取失败，尝试通过附加进程来获取env
        status = global_vm->AttachCurrentThread(&env, NULL);
        if (status < 0) {
            return nullptr;
        }
    }
    return env;
}

void thread_method2();

/**
 * 线程初尝试
 * @param args
 * @return
 */
void *thread_method(void *args) {
    JNIEnv *thread_env = nullptr;
    // 附加当前进程
    if (global_vm->AttachCurrentThread(&thread_env, nullptr) == JNI_OK) {
        __android_log_print(ANDROID_LOG_DEBUG, "thread_method", "get env=%p", &thread_env);
    }
    // 取消附加当前进程
    global_vm->DetachCurrentThread();

    thread_method2();

    pthread_exit(0);
}

void thread_method2() {
    JNIEnv *env = getEnv();
    // 加载类并构造对象
    jclass Person_clazz = loadClass(env, "com/forgotten/firstjni/Person");
    jmethodID construct_MID = env->GetMethodID(Person_clazz, "<init>", "()V");
    jobject person_obj = env->NewObject(Person_clazz, construct_MID);
    // 调用toString方法
    jmethodID toString_MID = env->GetMethodID(Person_clazz, "toString", "()Ljava/lang/String;");
    jstring person_s = static_cast<jstring>(env->CallObjectMethod(person_obj, toString_MID));
    // 打印方法的结果
    const char *s = env->GetStringUTFChars(person_s, nullptr);
    __android_log_print(ANDROID_LOG_DEBUG, "thread_method2", "personString = %s", s);
}



/**
 * JNI_OnLoad初尝试
 * @param vm
 * @param reserved
 * @return
 */
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    // JNI版本号
    jint result = JNI_VERSION_1_6;
    // 通过vm来获取env
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, result) == JNI_OK) {
        JavaVM *evm = nullptr;
        // 通过env获得vm
        env->GetJavaVM(&evm);
        if (evm == vm) {
            __android_log_print(ANDROID_LOG_DEBUG, "JNI_OnLoad", "evm == vm");
        } else {
            __android_log_print(ANDROID_LOG_DEBUG, "JNI_OnLoad", "evm != vm");
        }
    }

    /** 获取ClassLoader并保存到全局 **/
    // 随意获取一个类class对象
    jclass Person_clazz = env->FindClass("com/forgotten/firstjni/Person");
    // 查找getClassLoader方法
    jclass Class_clazz = env->FindClass("java/lang/Class");
    jmethodID getClassLoader_MID = env->GetMethodID(Class_clazz, "getClassLoader",
                                                    "()Ljava/lang/ClassLoader;");
    // 调用方法，获得ClassLoader
    jobject localClassLoader = env->CallObjectMethod(Person_clazz, getClassLoader_MID);
    // *转换为全局引用保存到全局*
    gClassLoader = env->NewWeakGlobalRef(localClassLoader);


    /** Thread获取env **/
    global_vm = vm;
    pthread_t thread;
    pthread_create(&thread, nullptr, thread_method, nullptr);
    pthread_join(thread, nullptr);

    return result;
}


jstring global_hello = nullptr;
/**
 * 测试局部引用、全局引用、弱全局引用
 */
extern "C"
JNIEXPORT void JNICALL
Java_com_forgotten_firstjni_MainActivity_testLGRef(JNIEnv *env, jobject thiz) {
    jstring hello = env->NewStringUTF("Hello");
//    env->DeleteLocalRef(hello); // 被删除了后就不能使用了
    __android_log_print(ANDROID_LOG_DEBUG, "testLGRef", "hello=%s", env->GetStringUTFChars(hello,
                                                                                           nullptr));
    // 如果JNI有10个引用的位置(可以定义10个引用变量)则if成立
    if (env->EnsureLocalCapacity(10) == 0) {
        __android_log_print(ANDROID_LOG_DEBUG, "testLGRef", "has 10 yes");
    } else {
        __android_log_print(ANDROID_LOG_DEBUG, "testLGRef", "has 10 no");
    }

    // 定义一个全局引用 可跨进程跨函数访问 拒绝被回收
    //    global_hello = static_cast<jstring>(env->NewGlobalRef(hello));
    // 定义一个弱全局引用，不同之处在于可以被回收
    //    global_hello = static_cast<jstring>(env->NewWeakGlobalRef(hello));

    // 生成一个长度为10的引用堆栈，接下来的10个局部引用都归堆栈管理
    if (env->PushLocalFrame(10) == 0) {
        jstring s1 = env->NewStringUTF("s1");
        jstring s2 = env->NewStringUTF("s2");

        // 销毁栈中的引用
        // env->PopLocalFrame(nullptr);

        // 销毁栈中的引用 保留s2并作为结果
        jobject res = env->PopLocalFrame(s2);
    } else {
        // 空间不足
    }
}