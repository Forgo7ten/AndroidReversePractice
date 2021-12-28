#include <jni.h>
#include <android/log.h>

// constructor(num)为优先级，越小优先级越高越先执行；可连同括号一起省略
__attribute__ ((constructor(2), visibility("hidden"))) void initarray_2(void) {
    __android_log_print(ANDROID_LOG_DEBUG, "nactivity", "initarray_2");

}

extern "C" void _init(void) {
    __android_log_print(ANDROID_LOG_DEBUG, "nactivity", "_init()");
}

__attribute__ ((constructor(1), visibility("hidden"))) void initarray_1(void) {
    __android_log_print(ANDROID_LOG_DEBUG, "nactivity", "initarray_1");

}

__attribute__ ((constructor(3), visibility("hidden"))) void initarray_3(void) {
    __android_log_print(ANDROID_LOG_DEBUG, "nactivity", "initarray_3");

}

//extern "C"
//JNIEXPORT void JNICALL
//Java_com_forgotten_firstjni_NativeActivity_onCreate(JNIEnv *env, jobject thiz,
//                                                    jobject Bundle_obj) {
//    // super.onCreate(savedInstanceState);
//    jclass AppCompatAcitvity_jclazz = env->FindClass("androidx/appcompat/app/AppCompatActivity");
//    jmethodID onCreate_mid = env->GetMethodID(AppCompatAcitvity_jclazz, "onCreate",
//                                              "(Landroid/os/Bundle;)V");
//    /**
//     * 调用父类的方法（1.当前对象;2.父类的clazz;3.方法mid;4.方法参数列表
//     */
//    env->CallNonvirtualVoidMethod(thiz, AppCompatAcitvity_jclazz, onCreate_mid, Bundle_obj);
//
//    // 打印 Log.d("NativeActivity","onCreate run..");
//    jclass Log_clazz = env->FindClass("android/util/Log");
//    jmethodID Log_d_mid = env->GetStaticMethodID(Log_clazz, "d",
//                                                 "(Ljava/lang/String;Ljava/lang/String;)I");
//    jstring tag = env->NewStringUTF("NativeActivity");
//    jstring info = env->NewStringUTF("onCreate run..");
//    env->CallStaticIntMethod(Log_clazz, Log_d_mid, tag, info);
//}


void RegisterNatives(JNIEnv *env);

extern "C"
JNIEXPORT void JNICALL
Java_com_forgotten_firstjni_NativeActivity_onCreate(JNIEnv *env, jobject thiz,
                                                    jobject Bundle_obj) {
    /** super.onCreate(savedInstanceState); **/
    // 根据对象获得类clazz
    jclass NativeActivity_clazz = env->GetObjectClass(thiz);
    // 根据子类获取父类
    jclass AppCompatAcitivity_clazz = env->GetSuperclass(NativeActivity_clazz);
    // 获取父类的onCreate方法ID
    jmethodID supper_onCreate_mid = env->GetMethodID(AppCompatAcitivity_clazz, "onCreate",
                                                     "(Landroid/os/Bundle;)V");
    // 执行方法 | 执行父类方法用CallNonvirtual 执行自身方法(包括重写方法)用Call...Method
    env->CallNonvirtualVoidMethod(thiz, AppCompatAcitivity_clazz, supper_onCreate_mid, Bundle_obj);


    /** setContentView(R.id.activity_native); **/
    // 获取setContentView的方法ID
    jmethodID setContentView_mid = env->GetMethodID(NativeActivity_clazz, "setContentView", "(I)V");
    jclass R_layout_clazz = env->FindClass("com/forgotten/firstjni/R$layout");
    jfieldID activity_native_fid = env->GetStaticFieldID(R_layout_clazz, "activity_native", "I");
    // 获取到布局ID值
    jint activity_native_value = env->GetStaticIntField(R_layout_clazz, activity_native_fid);
    env->CallVoidMethod(thiz, setContentView_mid, activity_native_value);

    /** showText=findViewById(R.id.show_text); **/
    jclass R_id_clazz = env->FindClass("com/forgotten/firstjni/R$id");
    jmethodID findViewById_mid = env->GetMethodID(NativeActivity_clazz, "findViewById",
                                                  "(I)Landroid/view/View;");
    jfieldID showText_fid = env->GetStaticFieldID(R_id_clazz, "show_text", "I");
    jint showText_value = env->GetStaticIntField(R_id_clazz, showText_fid);
    jobject showText = env->CallObjectMethod(thiz, findViewById_mid, showText_value);

    /** showText.setText("From nactivity.cpp") **/
    jclass TextView_clazz = env->FindClass("android/widget/TextView");
    jmethodID setText_mid = env->GetMethodID(TextView_clazz, "setText",
                                             "(Ljava/lang/CharSequence;)V");
    jstring text_s = env->NewStringUTF("From nactivity.cpp");
    env->CallVoidMethod(showText, setText_mid, text_s);

    /** Log.d("NativeActivity","onCreate run.."); **/
    jclass Log_clazz = env->FindClass("android/util/Log");
    jmethodID Log_d_mid = env->GetStaticMethodID(Log_clazz, "d",
                                                 "(Ljava/lang/String;Ljava/lang/String;)I");
    jstring tag = env->NewStringUTF("NativeActivity");
    jstring info = env->NewStringUTF("onCreate run..");
    env->CallStaticIntMethod(Log_clazz, Log_d_mid, tag, info);

    // 执行javaOnCreate方法
    jmethodID javaOnCreate_mid = env->GetMethodID(NativeActivity_clazz, "javaOnCreate", "()V");
    env->CallVoidMethod(thiz, javaOnCreate_mid);
}

jint dynamic_one(JNIEnv *env, jobject thiz, jstring str) {
    const char *s = env->GetStringUTFChars(str, nullptr);
    __android_log_print(ANDROID_LOG_DEBUG, "dynamic", "str: %s", s);
    int len = env->GetStringUTFLength(str);
    return len;
}

// 可以使名称不导出
__attribute__ ((visibility ("hidden"))) void dynamic_two(JNIEnv *env, jobject thiz, jint num) {
    for (int i = 0; i < num; i++) {
        __android_log_print(ANDROID_LOG_DEBUG, "dynamic", "i=%d", i);
    }
}


/**
 * 动态注册函数
 * @param env
 */
JNIEXPORT void RegisterNatives(JNIEnv *env) {
    // 先获取需要注册函数的类
    jclass clazz = env->FindClass("com/forgotten/firstjni/NativeActivity");
    if (nullptr != clazz) {
        // 初始化需要动态注册的列表
        JNINativeMethod methods[] = {
                // 1:java native方法 2:方法签名 3:要绑定的函数
                {"dynamicGetLen",   "(Ljava/lang/String;)I", (void *) dynamic_one},
                {"dynamicPrintNum", "(I)V",                  (void *) dynamic_two}
        };
        // 动态注册方法，为clazz类注册，方法列表为methods，长度为个数
        env->RegisterNatives(clazz, methods, sizeof(methods) / sizeof(JNINativeMethod));
    }
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    // JNI版本号
    jint result = JNI_VERSION_1_6;
    // 通过vm来获取env
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, result) == JNI_OK) {
        RegisterNatives(env);
    }

    return result;
}