//
// Created by yanxq on 17/6/10.
//

#ifndef ANDROIDHOOK_ELFHOOK_UTILS_H
#define ANDROIDHOOK_ELFHOOK_UTILS_H

int replace_function(void **fun_addr_ptr, void *new_func_addr, void **origin_func_addr_ptr);

void *find_so_base(const char *soname, char *path, int path_size);


#endif //ANDROIDHOOK_ELFHOOK_UTILS_H
