#include <jni.h>
#include <string>
#include <netdb.h>
#include <arpa/inet.h>
#include <android/log.h>
#include "elfhook/elfhook.h"

#define ELFHOOK_DEBUG 1

extern "C"
JNIEXPORT jstring

JNICALL
Java_com_mingyuans_hook_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

void print_gethostbyname() {
    gethostbyname("www.mingyuans.me");
}

struct hostent	*my_gethostbyname(const char * domain) {
    __android_log_print(android_LogPriority::ANDROID_LOG_INFO,"androidHook","my_gethostbyname called! %s",domain);
    return NULL;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mingyuans_hook_MainActivity_doElfHookByLinkView(JNIEnv *env, jobject instance) {
    struct hostent	*(*system_gethostbyname)(const char *) = NULL;
    size_t  result = elfhook_s("native-lib", "gethostbyname", (void *) my_gethostbyname,
                               (void **) &system_gethostbyname);

    print_gethostbyname();

    struct hostent * hostent_ptr = system_gethostbyname("www.baidu.com");
    if (hostent_ptr != NULL) {
        __android_log_print(android_LogPriority::ANDROID_LOG_INFO, "androidHook", "domain ips: %s",
                            inet_ntoa(*((struct in_addr *) hostent_ptr->h_addr)));
    } else {
        __android_log_print(android_LogPriority::ANDROID_LOG_INFO, "androidHook", "%s", "domain ips: null");
    }
    return result;
}