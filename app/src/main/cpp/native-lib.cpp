#include <jni.h>
#include <string>
#include <netdb.h>
#include <arpa/inet.h>
#include <android/log.h>
#include "elfhook/elfhook.h"

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
    uint  result = elfhook_s("native-lib", "gethostbyname", (void *) my_gethostbyname,
                               (void **) &system_gethostbyname);

    print_gethostbyname();

    struct hostent * hostent_ptr = system_gethostbyname("www.baidu.com");
    if (hostent_ptr != NULL) {
        __android_log_print(android_LogPriority::ANDROID_LOG_INFO, "androidHook", "domain ips: %s",
                            inet_ntoa(*((struct in_addr *) hostent_ptr->h_addr)));
    } else {
        __android_log_print(android_LogPriority::ANDROID_LOG_INFO, "androidHook", "%s", "domain ips: null");
    }

    if (result != 0) {
        elfhook_stop("native-lib", result, (void **) &system_gethostbyname);
    }
    print_gethostbyname();

    return result;
}


extern "C"
JNIEXPORT jint JNICALL
Java_com_mingyuans_hook_MainActivity_doElfHookByExecutableView(JNIEnv *env, jobject instance) {
    struct hostent	*(*system_gethostbyname)(const char *) = NULL;
    size_t  result = elfhook_p("native-lib", "gethostbyname", (void *) my_gethostbyname,
                               (void **) &system_gethostbyname);

    print_gethostbyname();

    if (system_gethostbyname != NULL) {
        struct hostent * hostent_ptr = system_gethostbyname("www.baidu.com");
        if (hostent_ptr != NULL) {
            __android_log_print(android_LogPriority::ANDROID_LOG_INFO, "androidHook", "domain ips: %s",
                                inet_ntoa(*((struct in_addr *) hostent_ptr->h_addr)));
        } else {
            __android_log_print(android_LogPriority::ANDROID_LOG_INFO, "androidHook", "%s", "domain ips: null");
        }
    } else {
        __android_log_print(android_LogPriority::ANDROID_LOG_INFO,"androidHook","system gethostbyname is null!");
    }
    return result;


}

int (*global_system_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;

int my_getaddrinfo(const char *hostname, const char *service, const struct addrinfo * hints, struct addrinfo **result) {
    __android_log_print(android_LogPriority::ANDROID_LOG_INFO,"androidHook","hostname:%s",hostname);
    if (global_system_getaddrinfo != NULL) {
        __android_log_print(android_LogPriority::ANDROID_LOG_INFO,"androidHook","do system_getaddrinfo");
        return global_system_getaddrinfo(hostname,service,hints,result);
    }
    return 0;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_mingyuans_hook_MainActivity_hookWebViewDns(JNIEnv *env, jobject instance) {
    int (*system_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
    int hookResultCode = elfhook_p("WebViewGoogle.apk","getaddrinfo", (void *) my_getaddrinfo,
              (void **) &system_getaddrinfo);
    global_system_getaddrinfo = system_getaddrinfo;
    __android_log_print(android_LogPriority::ANDROID_LOG_INFO,"androidHook","system_getaddirinfo: 0x%x",system_getaddrinfo);

    return hookResultCode;
}