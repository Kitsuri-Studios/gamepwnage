/**
 Gamepwnage -- Cross Platform Game Hacking API(s)

 Copyright (c) 2024-2025 bitware. All rights reserved.
 Copyright (c) 2026-ONWARDS Kitsuri Studio. All rights reserved.

 "Gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
https://github.com/Kitsuri-Studios/gamepwnage
*/
#ifdef GPWN_USING_BUILD_CONFIG
#include "config.h"
#else
#ifndef GPWNAPI
#define GPWNAPI
#endif
#ifndef GPWN_BKND
#define GPWN_BKND
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#if defined(__linux__) && defined(__GLIBC__)
#ifndef __USE_GNU
#define __USE_GNU
#endif
#endif
#include <link.h>
#include <dlfcn.h>

#include "plthook.h"
#include "mem.h"

struct dl_linkdata {
    ElfW(Addr) baseaddr;
    ElfW(Dyn) *dynaddr;
};

#ifdef __USE_GNU
GPWN_BKND int get_linkdata_by_handle(void *dlhandle,
    struct dl_linkdata *linkdata);
#endif
GPWN_BKND int get_linkdata_by_libname(char *libname,
    struct dl_linkdata *linkdata);

GPWNAPI plthook_handle *hook_plt(
    const char *libname, const char *symname,
    void *fake, void **original
) {
    ElfW(Addr) baddr = 0;
    ElfW(Dyn) *dyn = 0;
    ElfW(Sym) *symtab = 0;
    char *strtab = 0;
    ElfW(Rela) *rela_plt = 0;
    size_t rela_plt_size = 0;

    if(libname && *libname != '\0') {
        // lib is specified
        struct dl_linkdata linkdata;
#ifdef __USE_GNU
        void *dlhandle = dlopen(libname, RTLD_NOLOAD | RTLD_LAZY);
        if(!dlhandle) {
#ifdef GPWN_DEBUG
            fprintf(stderr, "hook_plt() failed : no such library"
                "\"%s\" failed\n", libname);
#endif
            return 0;
        }
        if(!get_linkdata_by_handle(dlhandle, &linkdata)) {
#ifdef GPWN_DEBUG
            fprintf(stderr, "hook_plt() failed :"
                " dlinfo() couldn't retrive link_map\n");
#endif
            dlclose(dlhandle);
            return 0;
        }
        dlclose(dlhandle);
#else
        if(!get_linkdata_by_libname((char*) libname, &linkdata)) {
#ifdef GPWN_DEBUG
            fprintf(stderr, "hook_plt() failed : couldn't retrive linkdata\n");
#endif
            return 0;
        }
#endif
        baddr = linkdata.baseaddr;
        dyn = linkdata.dynaddr;
    } else {
        // lib not specified
#if defined __linux__ && defined __GLIBC__
        struct link_map *lmap = _r_debug.r_map;
        baddr = lmap->l_addr;
        dyn = lmap->l_ld;
#else
        return 0;
#endif
    }
    // retrive .dynamic contents
    for (; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_SYMTAB)
            symtab = (ElfW(Sym) *)dyn->d_un.d_ptr;
        if (dyn->d_tag == DT_STRTAB)
            strtab = (char *)dyn->d_un.d_ptr;
        if (dyn->d_tag == DT_JMPREL)
            rela_plt = (ElfW(Rela) *)dyn->d_un.d_ptr;
        if (dyn->d_tag == DT_PLTRELSZ)
            rela_plt_size = dyn->d_un.d_val;
    }
    if(!symtab || !strtab || !rela_plt || !rela_plt_size) {
#ifdef GPWN_DEBUG
        fprintf(stderr, "hook_plt() failed :"
            " couldn't retrive .dynamic contents\n");
#endif
        return 0;
    }
#ifdef __ANDROID__
    symtab = (ElfW(Sym)*) ((ElfW(Addr)) symtab + (ElfW(Addr)) baddr);
    strtab = (char*) ((ElfW(Addr)) strtab + (ElfW(Addr)) baddr);
    rela_plt = (ElfW(Rela)*) ((ElfW(Addr)) rela_plt + (ElfW(Addr)) baddr);
#endif
// #ifdef GPWN_DEBUG
    // printf("symtab\t: %p\n", symname);
    // printf("strtab\t: %p\n", strtab);
    // printf("rela_plt\t: %p\n", rela_plt);
    // printf("rela_pltsz\t: %p\n", rela_plt_size);
// #endif
    // iterate through relocation table
    void **r_addr = 0;
    for (size_t i = 0; i < rela_plt_size / sizeof(ElfW(Rela)); i++) {
        ElfW(Rela) *rel = &rela_plt[i];
#ifdef __LP64__
        uint32_t sym_idx = ELF64_R_SYM(rel->r_info);   // index
#else
        uint32_t sym_idx = ELF32_R_SYM(rel->r_info);   // index
#endif
        ElfW(Sym) *sym = &symtab[sym_idx];
        const char *_symname = &strtab[sym->st_name];

        if (strncmp(_symname, symname, strlen(symname)) == 0 &&
            (_symname[strlen(symname)] == '\0' || _symname[strlen(symname)] == '@')
        )
            r_addr =  (void **) (rel->r_offset + baddr);
    }
    if(!r_addr) {
#ifdef GPWN_DEBUG
        fprintf(stderr, "hook_plt() failed : no such symbol as"
                " \"%s\" in \"%s\"\n", symname, libname);
#endif
        return 0;
    }
// #ifdef GPWN_DEBUG
//     printf("%s@%s : %p\n", symname, libname, r_addr);
// #endif
    plthook_handle *handle = malloc(sizeof(plthook_handle));
    if(!handle) {
#ifdef GPWN_DEBUG
        fprintf(stderr, "hook_plt() failed : malloc() failed\n");
#endif
        return 0;
    }
    handle->addr = r_addr;
    handle->original = *r_addr;

    if(original)
        *original = *r_addr;
    // *r_addr = fake;
    void *fakeaddr = fake;
    if(!write_mem(r_addr, &fakeaddr, sizeof(void*))) {
#ifdef GPWN_DEBUG
        fprintf(stderr, "hook_plt() failed : write_mem() failed\n");
#endif
        free(handle);
        return 0;
    }
    return handle;
}

GPWNAPI void rm_hook_plt(plthook_handle *handle) {
    if(handle) {
        // *handle->addr = handle->original;
        write_mem(handle->addr, &handle->original, sizeof(handle->original));
        free(handle);
    }
}

struct dl_iterate_data {
    char *libname;
    struct dl_linkdata *linkdata;
};

GPWN_BKND int dl_iterate_cb(struct dl_phdr_info *info, size_t size, void *data) {
    // callback for dl_iterate_phdr
    struct dl_iterate_data *cb_data = data;
    if(!info->dlpi_addr || !strstr(info->dlpi_name, cb_data->libname))
        return 0;
    for(size_t i = 0; i < info->dlpi_phnum; i++) {
        if(info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            cb_data->linkdata->baseaddr = info->dlpi_addr;
            cb_data->linkdata->dynaddr =
                (ElfW(Dyn)*) (info->dlpi_phdr[i].p_vaddr + info->dlpi_addr);
            return 1;
        }
    }
    return 0;
}
GPWN_BKND int get_linkdata_by_libname(
    char *libname, struct dl_linkdata *linkdata
) {
    if(!libname || *libname == '\0')
        return 0;
    struct dl_iterate_data cb_data;
    cb_data.libname = libname;
    cb_data.linkdata = linkdata;
    return dl_iterate_phdr(dl_iterate_cb, (void*) &cb_data);
}

#ifdef __USE_GNU
GPWN_BKND int get_linkdata_by_handle(
    void *dlhandle, struct dl_linkdata *linkdata
) {
    if(!dlhandle)
        return 0;
    struct link_map *lmap = 0;
    if(dlinfo(dlhandle, RTLD_DI_LINKMAP, &lmap)) {
        return 0;
    }
    linkdata->baseaddr = lmap->l_addr;
    linkdata->dynaddr = lmap->l_ld;
    return 1;
}
#endif
