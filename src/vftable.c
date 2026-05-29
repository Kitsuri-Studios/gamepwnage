/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2026 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
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
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <link.h>

#include "vftable.h"
#include "dynlib.h"
#include "mem.h"

typedef struct {
    uintptr_t start;
    size_t size;
    int writable;
} gpwn_seg;

typedef struct {
    const char *libname;
    gpwn_seg segs[32];
    size_t seg_count;
    int found;
} gpwn_libscan_ctx;

static int gpwn_vft_iterate_cb(struct dl_phdr_info *info, size_t size, void *arg) {
    gpwn_libscan_ctx *ctx = (gpwn_libscan_ctx *)arg;
    (void)size;

    if (!info || !info->dlpi_name)
        return 0;

    size_t want_len = strlen(ctx->libname);
    size_t name_len = strlen(info->dlpi_name);

    int match = 0;
    if (name_len >= want_len && strcmp(info->dlpi_name + name_len - want_len, ctx->libname) == 0)
        match = 1;
    if (strcmp(info->dlpi_name, ctx->libname) == 0)
        match = 1;

    if (!match)
        return 0;

    ctx->found = 1;

    for (ElfW(Half) i = 0; i < info->dlpi_phnum && ctx->seg_count < 32; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD)
            continue;
        if (!(ph->p_flags & PF_R))
            continue;
        if (!ph->p_memsz)
            continue;

        gpwn_seg *seg = &ctx->segs[ctx->seg_count++];
        seg->start = (uintptr_t)(info->dlpi_addr + ph->p_vaddr);
        seg->size = (size_t)ph->p_memsz;
        seg->writable = ((ph->p_flags & PF_W) != 0);
    }

    return 1;
}

static uintptr_t gpwn_find_zts(gpwn_libscan_ctx *ctx, const char *classname) {
    size_t len = strlen(classname) + 1;
    for (size_t i = 0; i < ctx->seg_count; i++) {
        gpwn_seg *seg = &ctx->segs[i];
        if (seg->writable)
            continue;

        void *p = memmem((void *)seg->start, seg->size, classname, len);
        if (p)
            return (uintptr_t)p;
    }
    return 0;
}

static uintptr_t gpwn_find_ptr_ref(gpwn_libscan_ctx *ctx, uintptr_t target) {
    for (size_t i = 0; i < ctx->seg_count; i++) {
        gpwn_seg *seg = &ctx->segs[i];

        for (size_t off = 0; off + sizeof(uintptr_t) <= seg->size; off += sizeof(uintptr_t)) {
            uintptr_t *p = (uintptr_t *)(seg->start + off);
            if (*p == target)
                return (uintptr_t)p;
        }
    }
    return 0;
}

static void **gpwn_scan_vftable(const char *libname, const char *classname) {
    gpwn_libscan_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.libname = libname;

    if (!dl_iterate_phdr(gpwn_vft_iterate_cb, &ctx) || !ctx.found)
        return 0;

    uintptr_t zts = gpwn_find_zts(&ctx, classname);
    if (!zts)
        return 0;

    uintptr_t zts_ref = gpwn_find_ptr_ref(&ctx, zts);
    if (!zts_ref)
        return 0;

    uintptr_t zti = zts_ref - sizeof(uintptr_t);

    uintptr_t zti_ref = gpwn_find_ptr_ref(&ctx, zti);
    if (!zti_ref)
        return 0;

    void **vt = (void **)(zti_ref + sizeof(uintptr_t));
    uintptr_t *meta = (uintptr_t *)vt;

 /* if (meta[-2] != 0)
        return 0; */

    return vt;
}

GPWNAPI void **get_vftable_ptr(const char *libname, const char *classname) {
    char sym[4096];
    size_t class_len;

    if (!libname || !*libname || !classname || !*classname)
        return 0;

    class_len = strnlen(classname, 4096);
    if (class_len >= 4096 - 7)
        return 0;   // symbol too long

    snprintf(sym, sizeof(sym), "_ZTV%zu%s", class_len, classname);

    void *vtable_addr = gpwn_dlsym(libname, sym);
    if (vtable_addr)
        return (void **)((uintptr_t)vtable_addr + 2 * sizeof(void *));

    return gpwn_scan_vftable(libname, classname);
}

GPWNAPI void *hook_vft(void **vftable, size_t idx, void *newfunc) {
    void *old_func;

    if (!vftable || !newfunc)
        return 0;

    old_func = vftable[idx];

    if (!write_mem((void *)&vftable[idx], (void *)&newfunc, sizeof(void *)))
        return 0;

    return old_func;
}