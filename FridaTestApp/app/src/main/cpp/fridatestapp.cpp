#include "jni.h"
#include <android/log.h>
#include <string.h>

int justAdd(jint a, jint b);

// 可以使名称不导出
__attribute__ ((visibility ("hidden"))) jstring
funcString(JNIEnv *env, jobject thiz, jstring argstr) {
    const char *s = env->GetStringUTFChars(argstr, nullptr);
    char msg[50] = "Your input: ";
    strcat(msg, s);
    jstring result = env->NewStringUTF(msg);
    return result;
}


/**
 * 动态注册函数
 * @param env
 */
JNIEXPORT void RegisterNatives(JNIEnv *env) {
    // 先获取需要注册函数的类
    jclass clazz = env->FindClass("com/forgotten/fridatestapp/MainActivity");
    if (nullptr != clazz) {
        // 初始化需要动态注册的列表
        JNINativeMethod methods[] = {
                // 1:java native方法 2:方法签名 3:要绑定的函数
                {"dynamicString", "(Ljava/lang/String;)Ljava/lang/String;", (void *) funcString}
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

extern "C"
JNIEXPORT jstring JNICALL
Java_com_forgotten_fridatestapp_MainActivity_staticString(JNIEnv *env, jobject thiz,
                                                          jstring input) {

    justAdd(90,1);

    const char *s = env->GetStringUTFChars(input, nullptr);
    char msg[50] = "Your input: ";
    strcat(msg, s);
    jstring result = env->NewStringUTF(msg);
    return result;
}

int justAdd(jint a, jint b) {
    for(int i=0;i<10;i++){
        a+=b;
    }
    __android_log_print(ANDROID_LOG_DEBUG, "native", "a = %d",a);
    return a;
}