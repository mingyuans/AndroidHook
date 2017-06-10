//
// Created by yanxq on 17/6/10.
//

#include <android/log.h>

#ifndef ANDROIDHOOK_ELF_LOG_H
#define ANDROIDHOOK_ELF_LOG_H

#define ELFHOOK_DEBUG 1

#ifndef ELFHOOK_TAG
#define ELFHOOK_TAG "elfHook"
#endif

#ifdef ELFHOOK_DEBUG
#define LOGI(...) __android_log_print(android_LogPriority::ANDROID_LOG_INFO,ELFHOOK_TAG,__VA_ARGS__)
#define LOGW(...) __android_log_print(android_LogPriority::ANDROID_LOG_WARN,ELFHOOK_TAG,__VA_ARGS__)
#define LOGE(...) __android_log_print(android_LogPriority::ANDROID_LOG_ERROR,ELFHOOK_TAG,__VA_ARGS__)
#else
#define LOGI(...) while(0){}
#define LOGE(...) while(0){}
#define LOGW(...) while(0){}
#endif

#endif //ANDROIDHOOK_ELF_LOG_H
