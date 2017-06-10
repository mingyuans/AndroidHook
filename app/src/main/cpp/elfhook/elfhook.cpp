//
// Created by yanxq on 17/6/10.
//
#include <string>
#include <fcntl.h>
#include <elf.h>
#include "elfhook_utils.h"
#include "elf_log.h"

int elfhook_p(const char *so_name,const char *symbol, void *new_func_addr,void **origin_func_addr_ptr) {

}


inline void read_data_form_fd(int fd, uint32_t seek,void * ptr, size_t size) {
    lseek(fd, seek, SEEK_SET);
    read(fd, ptr, size);
}

int elfhook_s(const char *so_name,const char *symbol, void *new_func_addr,void **origin_func_addr_ptr) {
    char so_path[256] = {0};
    uint8_t * elf_base_address = (uint8_t *) find_so_base(so_name, so_path, sizeof(so_path));

    //section 信息需要从 SO 文件中读取，因为该链接视图仅在 编译链接阶段有用，在执行中无用，
    //因此加载到内存后不一定有 section 段;
    int fd = open(so_path, O_RDONLY);

    //读取 ELF HEADER
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *) malloc(sizeof(Elf32_Ehdr));
    read(fd, ehdr, sizeof(Elf32_Ehdr));

    //查找 .shstrtab section，这个 section 存放各个 section 的名字，
    //我们需要通过它来找到我们需要的 section。
    uint32_t shdr_base = ehdr->e_shoff;
    uint16_t shnum = ehdr->e_shnum;
    uint32_t shstr_base = shdr_base + ehdr->e_shstrndx * sizeof(Elf32_Shdr);
    Elf32_Shdr *shstr = (Elf32_Shdr *) malloc(sizeof(Elf32_Shdr));
    read_data_form_fd(fd,shstr_base,shstr, sizeof(Elf32_Shdr));

    //定位 shstrtab 中  section name 字符的首地址
    char *shstrtab = (char *) malloc(shstr->sh_size);
    read_data_form_fd(fd,shstr->sh_offset,shstrtab,shstr->sh_size);

    //跳转到 section 开头，我们开始 section 遍历，通过 section 的 sh_name 可以在
    //shstrtab 中对照找到该 section 的名字，然后判断是不是我们需要的 section.
    Elf32_Shdr *shdr = (Elf32_Shdr *) malloc(sizeof(Elf32_Shdr));
    lseek(fd, shdr_base, SEEK_SET);

    /**
     * .rel.plt 保存外部符号的重定位信息, .dynsym 保存所有符号信息，
     * .dynstr 保存有符号的对应字符串表示;
     *
     * 我们需要修改目标符号在 .rel.plt 的重定位，但首先我们需要知道 .rel.plt 中哪一条是在说明目标符号的;
     * 定位的方法是，遍历 .rel.plt 的每一条，逐条拿出来查找它在 .dynsym 的对应详细信息，
     * .dynsym 的符号详细信息可以指引我们在 .dynstr 找到该符号的 name，通过比对 name 就能判断 .rel.plt 的条目是不是在说明我们目标符号的重定位;
     */
    char *sh_name = NULL;
    Elf32_Shdr *relplt_shdr = (Elf32_Shdr *) malloc(sizeof(Elf32_Shdr));
    Elf32_Shdr *dynsym_shdr = (Elf32_Shdr *) malloc(sizeof(Elf32_Shdr));
    Elf32_Shdr *dynstr_shdr = (Elf32_Shdr *) malloc(sizeof(Elf32_Shdr));
    for (uint16_t i = 0; i < shnum; ++i) {
        read(fd, shdr, sizeof(Elf32_Shdr));
        sh_name = shstrtab + shdr->sh_name;
        if (strcmp(sh_name, ".dynsym") == 0)
            memcpy(dynsym_shdr, shdr, sizeof(Elf32_Shdr));
        else if (strcmp(sh_name, ".dynstr") == 0)
            memcpy(dynstr_shdr, shdr, sizeof(Elf32_Shdr));
        else if (strcmp(sh_name, ".rel.plt") == 0)
            memcpy(relplt_shdr, shdr, sizeof(Elf32_Shdr));
    }

    //读取字符表
    char *dynstr = (char *) malloc(sizeof(char) * dynstr_shdr->sh_size);
    lseek(fd, dynstr_shdr->sh_offset, SEEK_SET);
    if (read(fd, dynstr, dynstr_shdr->sh_size) != dynstr_shdr->sh_size)
        return 0;

    //读取符号表
    Elf32_Sym *dynsymtab = (Elf32_Sym *) malloc(dynsym_shdr->sh_size);
    printf("dynsym_shdr->sh_size\t0x%x\n", dynsym_shdr->sh_size);
    lseek(fd, dynsym_shdr->sh_offset, SEEK_SET);
    if (read(fd, dynsymtab, dynsym_shdr->sh_size) != dynsym_shdr->sh_size)
        return 0;

    //读取重定位表
    Elf32_Rel *rel_ent = (Elf32_Rel *) malloc(sizeof(Elf32_Rel));
    lseek(fd, relplt_shdr->sh_offset, SEEK_SET);
    if (read(fd, rel_ent, sizeof(Elf32_Rel)) != sizeof(Elf32_Rel))
        return 0;

    LOGI("ELF 表准备完成, 开始查找符号%s的 got 表重定位地址...",symbol);

    Elf32_Addr *offset = 0;
    for (uint16_t i = 0; i < relplt_shdr->sh_size / sizeof(Elf32_Rel); i++) {
        uint16_t ndx = ELF32_R_SYM(rel_ent->r_info);
        LOGI("ndx = %d, str = %s", ndx, dynstr + dynsymtab[ndx].st_name);
        if (strcmp(dynstr + dynsymtab[ndx].st_name, symbol) == 0) {
            LOGI("符号%s在got表的偏移地址为: 0x%x", symbol, rel_ent->r_offset);
            offset = &rel_ent->r_offset;
            break;
        }
        if (read(fd, rel_ent, sizeof(Elf32_Rel)) != sizeof(Elf32_Rel)) {
            LOGI("获取符号%s的重定位信息失败", symbol);
            return 0;
        }
    }

    if (offset == 0) {
        LOGE("符号%s地址获取失败", symbol);
        return 0;
    }

    LOGI("符号获取成功，进行符号地址修改...");
    void * function_addr_ptr = (elf_base_address + *offset);
    return replace_function((void **) function_addr_ptr,
                     new_func_addr, origin_func_addr_ptr);
}