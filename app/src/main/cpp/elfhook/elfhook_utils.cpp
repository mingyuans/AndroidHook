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
 * @return 1--success, 0--fail
 */
int replace_function(void **fun_addr_ptr, void *new_func_addr, void **origin_func_addr_ptr) {
    if (*fun_addr_ptr == new_func_addr) {
        return 1;
    }

    if (origin_func_addr_ptr != NULL) {
        *origin_func_addr_ptr = *fun_addr_ptr;
    }

    //需要先修改该内存端的访问权限，跟 Java 反射中setAccessible 有点像;
    if (modify_memory_access(fun_addr_ptr, PROT_EXEC | PROT_READ | PROT_WRITE)) {
        return 0;
    }

    *fun_addr_ptr = new_func_addr;
    clear_cache(fun_addr_ptr, getpagesize());
    return 1;
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

/**
 * 查找soname的基址，如果为NULL，则为当前进程基址
 */
void *find_so_base(const char *soname, char *path, int path_size) {
    FILE *fd = fopen("/proc/self/maps", "r");
    char line[256];
    void *base = 0;

    while (fgets(line, sizeof(line), fd) != NULL) {
        //检查了下，该项特点是会具有执行权限;
        if (soname == NULL || (strstr(line, soname) && strstr(line,"xp"))) {
            if (path) {
                substring(line,'/',path,path_size);
            }

            line[8] = '\0';
            base = (void *) strtoul(line, NULL, 16);
            break;
        }
    }

    fclose(fd);
    return base;
}

