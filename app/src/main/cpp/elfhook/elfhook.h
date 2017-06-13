//
// Created by yanxq on 17/6/10.
//

#ifndef ANDROIDHOOK_ELFHOOK_H
#define ANDROIDHOOK_ELFHOOK_H

#define ELFHOOK_DEBUG 1

/**
 * Do elf hook by exec view
 * @param so_name target so
 * @param symbol function_name
 * @param new_func_addr new_function_address
 * @param origin_func_addr_ptr  origin function address
 * @return 0--fail else symbol offset at .got
 */
uint elfhook_p(const char *so_name,const char *symbol, void *new_func_addr,void **origin_func_addr_ptr);

/**
 * Do elf hook by link view;
 *
 * see more: http://ele7enxxh.com/Android-Shared-Library-Hook-With-GOT.html
 *
 * @param so_name target so
 * @param symbol function_name
 * @param new_func_addr new_function_address
 * @param origin_func_addr_ptr  origin function address
 * @return 0--fail else symbol offset at .got
 */
uint elfhook_s(const char *so_name,const char *symbol, void *new_func_addr,void **origin_func_addr_ptr);

/**
 *
 * @param symbol_offset elfhook_s or elfhook_p return;
 * @param origin_func_addr_ptr
 * @return
 */
uint elfhook_stop(uint symbol_offset,void **origin_func_addr_ptr);

#endif //ANDROIDHOOK_ELFHOOK_H
