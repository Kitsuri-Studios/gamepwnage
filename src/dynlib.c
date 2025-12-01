/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <link.h>
#include <dlfcn.h>
#include <elf.h>

// SysV hash algorithm
static uint32_t sysv_hash(const uint8_t *name) {
    uint32_t h = 0, g;
    while (*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

// GNU hash algorithm
static uint32_t gnu_hash(const uint8_t *name) {
    uint32_t h = 5381;
    while (*name) {
        h += (h << 5) + *name++;
    }
    return h;
}

// Find symbol using SysV hash table
static ElfW(Sym) *find_sym_sysv(
        ElfW(Sym) *symtab, const char *strtab,
        const uint32_t *buckets, uint32_t buckets_cnt,
        const uint32_t *chains, uint32_t chains_cnt,
        const char *sym_name) {
    uint32_t hash = sysv_hash((const uint8_t *)sym_name);

    for (uint32_t i = buckets[hash % buckets_cnt]; 0 != i; i = chains[i]) {
        if (i >= chains_cnt) break;
        ElfW(Sym) *sym = symtab + i;
        if (0 != strcmp(strtab + sym->st_name, sym_name)) continue;
        return sym;
    }
    return NULL;
}

// Find symbol using GNU hash table
static ElfW(Sym) *find_sym_gnu(
        ElfW(Sym) *symtab, const char *strtab,
        const uint32_t *buckets, uint32_t buckets_cnt,
        const uint32_t *chains, uint32_t symoffset,
        const ElfW(Addr) *bloom, uint32_t bloom_cnt,
        uint32_t bloom_shift,
        const char *sym_name) {
    uint32_t hash = gnu_hash((const uint8_t *)sym_name);

    // Bloom filter check
    static uint32_t elfclass_bits = sizeof(ElfW(Addr)) * 8;
    size_t word = bloom[(hash / elfclass_bits) % bloom_cnt];
    size_t mask = 0 | (size_t)1 << (hash % elfclass_bits) |
                  (size_t)1 << ((hash >> bloom_shift) % elfclass_bits);

    if ((word & mask) != mask) return NULL;

    uint32_t i = buckets[hash % buckets_cnt];
    if (i < symoffset) return NULL;

    // Chain traversal
    while (1) {
        ElfW(Sym) *sym = symtab + i;
        uint32_t sym_hash = chains[i - symoffset];

        if ((hash | 1) == (sym_hash | 1)) {
            if (0 == strcmp(strtab + sym->st_name, sym_name)) {
                return sym;
            }
        }

        if (sym_hash & 1) break;
        i++;
    }

    return NULL;
}

struct find_lib_data {
    const char *libname;
    ElfW(Addr) load_bias;
    ElfW(Dyn) *dynamic;
};

// Callback for dl_iterate_phdr
static int iterate_cb(struct dl_phdr_info *info, size_t size, void *arg) {
    struct find_lib_data *d = (struct find_lib_data *)arg;
    (void)size;

    if (!info->dlpi_addr || !info->dlpi_name) return 0;

    const char *name = info->dlpi_name;
    size_t libname_len = strlen(d->libname);
    size_t name_len = strlen(name);

    // Match by suffix or exact name
    int match = 0;
    if (name_len >= libname_len) {
        if (strcmp(name + name_len - libname_len, d->libname) == 0) {
            match = 1;
        }
    }
    if (strcmp(name, d->libname) == 0) {
        match = 1;
    }

    if (!match) return 0;

    // fputs("found library\n", stderr);

    d->load_bias = info->dlpi_addr;

    // Find PT_DYNAMIC segment
    for (size_t i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            d->dynamic = (ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            return 1;
        }
    }
    return 0;
}

// Main function: resolve symbol from library
void *gpwn_dlsym(const char *libname, const char *symname) {
    if (!libname || !*libname || !symname || !*symname) {
        // fputs("gpwn_dlsym: invalid arguments\n", stderr);
        return NULL;
    }

    // fputs("gpwn_dlsym: looking for symbol\n", stderr);

    struct find_lib_data data = {libname, 0, NULL};

    if (!dl_iterate_phdr(iterate_cb, &data)) {
        // fputs("gpwn_dlsym: library not found\n", stderr);
        return NULL;
    }

    if (!data.dynamic) {
        // fputs("gpwn_dlsym: no PT_DYNAMIC segment\n", stderr);
        return NULL;
    }

    ElfW(Addr) load_bias = data.load_bias;
    ElfW(Dyn) *dynamic = data.dynamic;

    // Parse dynamic section
    ElfW(Sym) *symtab = NULL;
    const char *strtab = NULL;
    const uint32_t *sysv_buckets = NULL;
    uint32_t sysv_buckets_cnt = 0;
    const uint32_t *sysv_chains = NULL;
    uint32_t sysv_chains_cnt = 0;
    const uint32_t *gnu_buckets = NULL;
    uint32_t gnu_buckets_cnt = 0;
    const uint32_t *gnu_chains = NULL;
    uint32_t gnu_symoffset = 0;
    const ElfW(Addr) *gnu_bloom = NULL;
    uint32_t gnu_bloom_cnt = 0;
    uint32_t gnu_bloom_shift = 0;

    for (ElfW(Dyn) *dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_SYMTAB:
                symtab = (ElfW(Sym) *)(load_bias + dyn->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = (const char *)(load_bias + dyn->d_un.d_ptr);
                break;
            case DT_HASH: {
                const uint32_t *hash_ptr = (const uint32_t *)(load_bias + dyn->d_un.d_ptr);
                sysv_buckets_cnt = hash_ptr[0];
                sysv_chains_cnt = hash_ptr[1];
                sysv_buckets = &hash_ptr[2];
                sysv_chains = &sysv_buckets[sysv_buckets_cnt];
                break;
            }
            case DT_GNU_HASH: {
                const uint32_t *gnu_hash_ptr = (const uint32_t *)(load_bias + dyn->d_un.d_ptr);
                gnu_buckets_cnt = gnu_hash_ptr[0];
                gnu_symoffset = gnu_hash_ptr[1];
                gnu_bloom_cnt = gnu_hash_ptr[2];
                gnu_bloom_shift = gnu_hash_ptr[3];
                gnu_bloom = (const ElfW(Addr) *)(&gnu_hash_ptr[4]);
                gnu_buckets = (const uint32_t *)(&gnu_bloom[gnu_bloom_cnt]);
                gnu_chains = (const uint32_t *)(&gnu_buckets[gnu_buckets_cnt]);
                break;
            }
        }
    }

    if (!symtab || !strtab) {
        // fputs("gpwn_dlsym: symtab or strtab not found\n", stderr);
        return NULL;
    }

    ElfW(Sym) *sym = NULL;

    // Try GNU hash first
    if (gnu_buckets_cnt > 0) {
        // fputs("gpwn_dlsym: using GNU hash\n", stderr);
        sym = find_sym_gnu(
                symtab, strtab, gnu_buckets, gnu_buckets_cnt,
                gnu_chains, gnu_symoffset, gnu_bloom, gnu_bloom_cnt, gnu_bloom_shift, symname);
    }

    // Fallback to SysV hash
    if (!sym && sysv_buckets_cnt > 0) {
        // fputs("gpwn_dlsym: using SYSV hash\n", stderr);
        sym = find_sym_sysv(
                symtab, strtab, sysv_buckets, sysv_buckets_cnt,
                sysv_chains, sysv_chains_cnt, symname);
    }

    if (!sym) {
        // fputs("gpwn_dlsym: symbol not found\n", stderr);
        return NULL;
    }

    if (sym->st_shndx == SHN_UNDEF) {
        // fputs("gpwn_dlsym: symbol is undefined\n", stderr);
        return NULL;
    }

    void *addr = (void *)(load_bias + sym->st_value);
    // fputs("gpwn_dlsym: found symbol\n", stderr);
    return addr;
}