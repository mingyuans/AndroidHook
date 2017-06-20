/**
 *
 * 这里代码只要来自 https://github.com/boyliang/AllHookInOne ;
 *
 *  Created by yanxq on 17/6/10.
 */
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include "elf_log.h"


#define PAGE_START(addr) (~(getpagesize() - 1) & (addr))

static int modify_memory_access(void *addr, int prots){
    void *page_start_addr = (void *)PAGE_START((uint32_t)addr);
    return mprotect(page_start_addr, getpagesize(), prots);
}

static int clear_cache(void *addr, size_t len){
    void *end = (uint8_t *)addr + len;
    syscall(0xf0002, addr, end);
    return 1;
}

/**
 *
 * @param fun_addr_ptr
 * @param new_func_addr
 * @param origin_func_addr_ptr
 * @return 0--fail else symbol offset at .got
 */
uint replace_function(void **fun_addr_ptr, void *new_func_addr, void **origin_func_addr_ptr) {
    if (*fun_addr_ptr == new_func_addr) {
        LOGI("The function has replaced before!");
        return 1;
    }

    if (origin_func_addr_ptr != NULL && !*origin_func_addr_ptr) {
        *origin_func_addr_ptr = *fun_addr_ptr;
    } else {
        LOGW("origin_func_addr_ptr == NULL or content != NULL ");
    }

    //需要先修改该内存端的访问权限，跟 Java 反射中setAccessible 有点像; PROT_EXEC | PROT_READ |
    if (modify_memory_access(fun_addr_ptr,  PROT_READ | PROT_WRITE)) {
        LOGE("Modify memory access failed! address: %x, reason: %d",fun_addr_ptr,errno);
        return 0;
    }

    *fun_addr_ptr = new_func_addr;
    clear_cache(fun_addr_ptr, getpagesize());
    return (uint) fun_addr_ptr;
}

void substring(char * str, char start_char,char *buf,int size) {
    int index = 0;
    int current_length = 0;
    bool isSubStarted = false;
    char current_char;
    while ((current_char = *(str + index++)) != '\0') {
        if (!isSubStarted && current_char == start_char) {
            isSubStarted = true;
        }

        if (isSubStarted) {
            if (current_char == '\n') {
                break;
            }

            if (current_length < (size-1)) {
                buf[current_length++] = current_char;
            }
            if (current_length == (size -1)) {
                break;
            }
        }
    }
    buf[current_length] = '\0';
}

static inline bool is_line_end_with_so(const char *string, const char *suffix) {
    int str_len = strlen(string);
    int suffix_len = strlen(suffix);
    return str_len >= suffix_len
           //line 本身有 \n 的结尾，这里加载该字符位移
           && (0 == memcmp(string + (str_len-suffix_len-1), suffix,suffix_len));
}

/**
 * 查找soname的基址，如果为NULL，则为当前进程基址
 */
void *find_so_base(const char *soname, char *path, int path_size) {
    FILE *fd = fopen("/proc/self/maps", "r");
    char line[256];
    void *base = 0;

    while (fd != NULL && fgets(line, sizeof(line), fd) != NULL) {
        //检查了下，该项特点是会具有执行权限;
        if (soname == NULL || (strstr(line,"xp") && is_line_end_with_so(line, soname))) {
            if (path) {
                substring(line,'/',path,path_size);
            }

            line[8] = '\0';
            base = (void *) strtoul(line, NULL, 16);
            break;
        }
    }

    if (fd == NULL) {
        LOGW("Process maps open failed! %d", errno);
    } else {
        fclose(fd);
    }

    return base;
}

