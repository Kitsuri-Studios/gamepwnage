/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2026 bitware. All rights reserved.
 Made by xzelleiv

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <pthread.h>
#include <dlfcn.h>

#include "multihook.h"
#include "inlinehook.h"
#include "mem.h"
#include "proc.h"
#include "dynlib.h"

typedef struct gpwn_hook_node {
    void *fake_func;
    void **user_old_func;
    struct gpwn_hook_node *next;
    struct gpwn_hook_node *prev;
    bool is_active;
} gpwn_hook_node_t;

typedef struct gpwn_hook_chain {
    void *target_addr;
    hook_handle *base_hook;
    gpwn_hook_node_t *head;
    void *original_trampoline;
    void *dispatch_stub;
    size_t stub_size;
    bool is_branch_hook;
    uint32_t original_instruction;
    void *landing_pad;
    size_t landing_pad_size;
    struct gpwn_hook_chain *next;
} gpwn_hook_chain_t;

typedef struct gpwn_pending_hook {
    char *libname;
    char *symname;
    void *fake_func;
    void **user_old_func;
    struct gpwn_pending_hook *next;
} gpwn_pending_hook_t;

static gpwn_hook_chain_t *g_hook_chains = NULL;
static gpwn_pending_hook_t *g_pending_hooks = NULL;
static pthread_mutex_t g_registry_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *(*g_old_dlopen)(const char *filename, int flags) = NULL;
static gpwn_hook_t g_dlopen_hook = NULL;

static void *my_dlopen(const char *filename, int flags);

static void *create_dispatch_stub(void *target_addr, void *initial_dest, size_t *out_size) {
    size_t size = 0;
    uint8_t temp[32];
    memset(temp, 0, sizeof(temp));

#if defined(__aarch64__)
    uint32_t stub_arm64[] = {
        0x58000050, // ldr x16, #8
        0xd61f0200, // br x16
        0x00000000,
        0x00000000
    };
    *(uint64_t*)&stub_arm64[2] = (uintptr_t)initial_dest;
    size = sizeof(stub_arm64);
    memcpy(temp, stub_arm64, size);

#elif defined(__arm__)
    uint32_t stub_arm32[] = {
        0xe59fc000, // ldr ip, [pc]
        0xe12fff1c, // bx ip
        0x00000000
    };
    stub_arm32[2] = (uint32_t)(uintptr_t)initial_dest;
    size = sizeof(stub_arm32);
    memcpy(temp, stub_arm32, size);

#elif defined(__x86_64__) || defined(__amd64__)
    uint8_t stub_x64[] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    *(uint64_t*)&stub_x64[6] = (uintptr_t)initial_dest;
    size = sizeof(stub_x64);
    memcpy(temp, stub_x64, size);
#endif

    if (size == 0) {
        return NULL;
    }

    void *stub_mem = mmap_near(target_addr, size, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (!stub_mem) {
        return NULL;
    }

    if (!write_mem(stub_mem, temp, size)) {
        munmap(stub_mem, size);
        return NULL;
    }

#if defined(__arm__) || defined(__aarch64__)
    __builtin___clear_cache((char*)stub_mem, (char*)stub_mem + size);
#endif

    *out_size = size;
    return stub_mem;
}

static bool update_dispatch_stub(void *stub_mem, void *new_dest) {
    bool res = false;
#if defined(__aarch64__)
    res = write_mem((void*)((uintptr_t)stub_mem + 8), &new_dest, sizeof(void*));
    if (res) {
        __builtin___clear_cache((char*)stub_mem, (char*)stub_mem + 16);
    }
#elif defined(__arm__)
    uint32_t val = (uint32_t)(uintptr_t)new_dest;
    res = write_mem((void*)((uintptr_t)stub_mem + 8), &val, sizeof(uint32_t));
    if (res) {
        __builtin___clear_cache((char*)stub_mem, (char*)stub_mem + 12);
    }
#elif defined(__x86_64__) || defined(__amd64__)
    res = write_mem((void*)((uintptr_t)stub_mem + 6), &new_dest, sizeof(void*));
#else
    (void)stub_mem;
    (void)new_dest;
#endif
    return res;
}

static void rebuild_chain_pointers(gpwn_hook_chain_t *chain) {
    gpwn_hook_node_t *curr = chain->head;
    gpwn_hook_node_t *first_active = NULL;
    gpwn_hook_node_t *prev_active = NULL;

    while (curr) {
        if (curr->is_active) {
            if (!first_active) {
                first_active = curr;
            }
            if (prev_active) {
                void *next_target = curr->fake_func;
                __atomic_store_n(prev_active->user_old_func, next_target, __ATOMIC_RELEASE);
            }
            prev_active = curr;
        }
        curr = curr->next;
    }

    if (prev_active) {
        void *orig = chain->original_trampoline;
        __atomic_store_n(prev_active->user_old_func, orig, __ATOMIC_RELEASE);
    }

    void *stub_target = first_active ? first_active->fake_func : chain->original_trampoline;
    update_dispatch_stub(chain->dispatch_stub, stub_target);
}

GPWNAPI gpwn_hook_t gpwn_hook(void *target_addr, void *fake_func, void **old_func) {
    if (!target_addr || !fake_func || !old_func) {
        return NULL;
    }

    pthread_mutex_lock(&g_registry_mutex);

    gpwn_hook_chain_t *chain = g_hook_chains;
    while (chain) {
        if (chain->target_addr == target_addr) {
            break;
        }
        chain = chain->next;
    }

    gpwn_hook_node_t *node = malloc(sizeof(gpwn_hook_node_t));
    if (!node) {
        pthread_mutex_unlock(&g_registry_mutex);
        return NULL;
    }
    node->fake_func = fake_func;
    node->user_old_func = old_func;
    node->is_active = true;
    node->next = NULL;
    node->prev = NULL;

    if (!chain) {
        chain = malloc(sizeof(gpwn_hook_chain_t));
        if (!chain) {
            free(node);
            pthread_mutex_unlock(&g_registry_mutex);
            return NULL;
        }
        memset(chain, 0, sizeof(gpwn_hook_chain_t));
        chain->target_addr = target_addr;
        chain->head = node;
        chain->next = g_hook_chains;

        size_t stub_size = 0;
        chain->dispatch_stub = create_dispatch_stub(target_addr, fake_func, &stub_size);
        if (!chain->dispatch_stub) {
            free(chain);
            free(node);
            pthread_mutex_unlock(&g_registry_mutex);
            return NULL;
        }
        chain->stub_size = stub_size;

        chain->base_hook = gpwn_raw_inline_hook(target_addr, chain->dispatch_stub, &chain->original_trampoline);
        if (!chain->base_hook) {
            munmap(chain->dispatch_stub, chain->stub_size);
            free(chain);
            free(node);
            pthread_mutex_unlock(&g_registry_mutex);
            return NULL;
        }

        *old_func = chain->original_trampoline;
        g_hook_chains = chain;
    } else {
        // chain exists. build links before exposing to live threads
        gpwn_hook_node_t *old_head = chain->head;
        node->next = old_head;
        
        void *old_target = old_head ? old_head->fake_func : chain->original_trampoline;
        
        // stage user's old func pointer first
        __atomic_store_n(old_func, old_target, __ATOMIC_RELEASE);
        
        if (old_head) {
            old_head->prev = node;
        }
        
        // redirect dispatch stub first, then switch list head
        update_dispatch_stub(chain->dispatch_stub, fake_func);
        
        // publish new head to registry
        __atomic_store_n(&chain->head, node, __ATOMIC_RELEASE);
    }

    pthread_mutex_unlock(&g_registry_mutex);
    return (gpwn_hook_t)node;
}

GPWNAPI gpwn_hook_t gpwn_hook_branch(void *branch_addr, void *fake_func, void **old_func) {
    if (!branch_addr || !fake_func || !old_func) {
        return NULL;
    }

    pthread_mutex_lock(&g_registry_mutex);

    gpwn_hook_chain_t *chain = g_hook_chains;
    while (chain) {
        if (chain->target_addr == branch_addr) {
            break;
        }
        chain = chain->next;
    }

    gpwn_hook_node_t *node = malloc(sizeof(gpwn_hook_node_t));
    if (!node) {
        pthread_mutex_unlock(&g_registry_mutex);
        return NULL;
    }
    node->fake_func = fake_func;
    node->user_old_func = old_func;
    node->is_active = true;
    node->next = NULL;
    node->prev = NULL;

    if (!chain) {
        void *original_dest = NULL;
        bool is_thumb = false;
        
#if defined(__aarch64__)
        uint32_t inst = *(uint32_t*)branch_addr;
        if ((inst & 0xFC000000) == 0x94000000) { // bl
            int64_t imm26 = inst & 0x03FFFFFF;
            if (imm26 & 0x02000000) {
                imm26 |= ~0x03FFFFFF;
            }
            int64_t offset = imm26 * 4;
            original_dest = (void*)((uintptr_t)branch_addr + offset);
        }
#elif defined(__arm__)
        uint16_t hw1 = *(uint16_t*)branch_addr;
        uint16_t hw2 = *(uint16_t*)((uintptr_t)branch_addr + 2);
        if ((hw1 & 0xF800) == 0xF000 && ((hw2 & 0xF800) == 0xF800 || (hw2 & 0xF000) == 0xE000)) {
            is_thumb = true;
            int32_t s = (hw1 >> 10) & 1;
            int32_t j1 = (hw2 >> 13) & 1;
            int32_t j2 = (hw2 >> 11) & 1;
            int32_t imm10 = hw1 & 0x3FF;
            int32_t imm11 = hw2 & 0x7FF;
            int32_t i1 = !(j1 ^ s);
            int32_t i2 = !(j2 ^ s);
            int32_t imm32 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
            if (s) {
                imm32 |= ~0x1FFFFFF;
            }
            int32_t offset = imm32 + 4;
            original_dest = (void*)(((uintptr_t)branch_addr + offset) | 1);
        } else {
            uint32_t inst = *(uint32_t*)branch_addr;
            if ((inst & 0x0F000000) == 0x0B000000) { // bl
                int32_t imm24 = inst & 0x00FFFFFF;
                if (imm24 & 0x00800000) {
                    imm24 |= ~0x00FFFFFF;
                }
                int32_t offset = (imm24 * 4) + 8;
                original_dest = (void*)((uintptr_t)branch_addr + offset);
            } else if ((inst & 0xFE000000) == 0xFA000000) { // blx
                int32_t imm24 = inst & 0x00FFFFFF;
                int32_t h = (inst >> 24) & 1;
                if (imm24 & 0x00800000) {
                    imm24 |= ~0x00FFFFFF;
                }
                int32_t offset = (imm24 * 4) + (h * 2) + 8;
                original_dest = (void*)(((uintptr_t)branch_addr + offset) | 1);
            }
        }
#endif

        if (!original_dest) {
            free(node);
            pthread_mutex_unlock(&g_registry_mutex);
#ifdef GPWN_DEBUG
            fprintf(stderr, "gpwn_hook_branch() failed: target is not a direct branch instruction\n");
#endif
            return NULL;
        }

        chain = malloc(sizeof(gpwn_hook_chain_t));
        if (!chain) {
            free(node);
            pthread_mutex_unlock(&g_registry_mutex);
            return NULL;
        }
        memset(chain, 0, sizeof(gpwn_hook_chain_t));
        chain->target_addr = branch_addr;
        chain->head = node;
        chain->original_trampoline = original_dest;
        chain->is_branch_hook = true;
        chain->original_instruction = *(uint32_t*)branch_addr;

        size_t stub_size = 0;
        chain->dispatch_stub = create_dispatch_stub(branch_addr, fake_func, &stub_size);
        if (!chain->dispatch_stub) {
            free(chain);
            free(node);
            pthread_mutex_unlock(&g_registry_mutex);
            return NULL;
        }
        chain->stub_size = stub_size;

        void *patch_target = chain->dispatch_stub;
        bool patch_success = false;

#if defined(__aarch64__)
        int64_t offset = (uintptr_t)patch_target - (uintptr_t)branch_addr;
        if (offset >= -134217728 && offset <= 134217724) {
            uint32_t new_inst = 0x94000000 | (((int64_t)offset / 4) & 0x03FFFFFF);
            patch_success = write_mem(branch_addr, &new_inst, sizeof(uint32_t));
            if (patch_success) {
                __builtin___clear_cache((char*)branch_addr, (char*)branch_addr + sizeof(uint32_t));
            }
        } else {
            size_t lp_size = 0;
            chain->landing_pad = create_dispatch_stub(branch_addr, patch_target, &lp_size);
            if (chain->landing_pad) {
                chain->landing_pad_size = lp_size;
                int64_t lp_offset = (uintptr_t)chain->landing_pad - (uintptr_t)branch_addr;
                uint32_t new_inst = 0x94000000 | (((int64_t)lp_offset / 4) & 0x03FFFFFF);
                patch_success = write_mem(branch_addr, &new_inst, sizeof(uint32_t));
                if (patch_success) {
                    __builtin___clear_cache((char*)branch_addr, (char*)branch_addr + sizeof(uint32_t));
                }
            }
        }
#elif defined(__arm__)
        if (is_thumb) {
            int32_t offset = (uintptr_t)patch_target - ((uintptr_t)branch_addr + 4);
            if (offset >= -16777216 && offset <= 16777214) {
                int32_t s = (offset >> 24) & 1;
                int32_t i1 = (offset >> 23) & 1;
                int32_t i2 = (offset >> 22) & 1;
                int32_t imm10 = (offset >> 12) & 0x3FF;
                int32_t imm11 = (offset >> 1) & 0x7FF;
                uint16_t hw1 = 0xF000 | (s << 10) | imm10;
                uint16_t hw2 = 0xF800 | (i1 << 13) | (i2 << 11) | imm11;
                uint32_t new_inst = hw1 | (hw2 << 16);
                patch_success = write_mem(branch_addr, &new_inst, sizeof(uint32_t));
                if (patch_success) {
                    __builtin___clear_cache((char*)branch_addr, (char*)branch_addr + sizeof(uint32_t));
                }
            } else {
                size_t lp_size = 0;
                chain->landing_pad = create_dispatch_stub(branch_addr, patch_target, &lp_size);
                if (chain->landing_pad) {
                    chain->landing_pad_size = lp_size;
                    int32_t lp_offset = (uintptr_t)chain->landing_pad - ((uintptr_t)branch_addr + 4);
                    int32_t s = (lp_offset >> 24) & 1;
                    int32_t i1 = (lp_offset >> 23) & 1;
                    int32_t i2 = (lp_offset >> 22) & 1;
                    int32_t imm10 = (lp_offset >> 12) & 0x3FF;
                    int32_t imm11 = (lp_offset >> 1) & 0x7FF;
                    uint16_t hw1 = 0xF000 | (s << 10) | imm10;
                    uint16_t hw2 = 0xF800 | (i1 << 13) | (i2 << 11) | imm11;
                    uint32_t new_inst = hw1 | (hw2 << 16);
                    patch_success = write_mem(branch_addr, &new_inst, sizeof(uint32_t));
                    if (patch_success) {
                        __builtin___clear_cache((char*)branch_addr, (char*)branch_addr + sizeof(uint32_t));
                    }
                }
            }
        } else {
            int32_t offset = (uintptr_t)patch_target - ((uintptr_t)branch_addr + 8);
            if (offset >= -33554432 && offset <= 33554428) {
                uint32_t new_inst = 0xEB000000 | (((int32_t)offset / 4) & 0x00FFFFFF);
                patch_success = write_mem(branch_addr, &new_inst, sizeof(uint32_t));
                if (patch_success) {
                    __builtin___clear_cache((char*)branch_addr, (char*)branch_addr + sizeof(uint32_t));
                }
            } else {
                size_t lp_size = 0;
                chain->landing_pad = create_dispatch_stub(branch_addr, patch_target, &lp_size);
                if (chain->landing_pad) {
                    chain->landing_pad_size = lp_size;
                    int32_t lp_offset = (uintptr_t)chain->landing_pad - ((uintptr_t)branch_addr + 8);
                    uint32_t new_inst = 0xEB000000 | (((int32_t)lp_offset / 4) & 0x00FFFFFF);
                    patch_success = write_mem(branch_addr, &new_inst, sizeof(uint32_t));
                    if (patch_success) {
                        __builtin___clear_cache((char*)branch_addr, (char*)branch_addr + sizeof(uint32_t));
                    }
                }
            }
        }
#endif

        if (!patch_success) {
            if (chain->landing_pad) {
                munmap(chain->landing_pad, chain->landing_pad_size);
            }
            munmap(chain->dispatch_stub, chain->stub_size);
            free(chain);
            free(node);
            pthread_mutex_unlock(&g_registry_mutex);
            return NULL;
        }

        *old_func = chain->original_trampoline;
        chain->next = g_hook_chains;
        g_hook_chains = chain;
    } else {
        node->next = chain->head;
        chain->head->prev = node;
        __atomic_store_n(&chain->head, node, __ATOMIC_RELEASE);
        rebuild_chain_pointers(chain);
    }

    pthread_mutex_unlock(&g_registry_mutex);
    return (gpwn_hook_t)node;
}

GPWNAPI bool gpwn_hook_enable(gpwn_hook_t hook) {
    if (!hook) {
        return false;
    }

    pthread_mutex_lock(&g_registry_mutex);

    gpwn_hook_node_t *target_node = (gpwn_hook_node_t *)hook;
    gpwn_hook_chain_t *chain = g_hook_chains;
    bool found = false;

    while (chain) {
        gpwn_hook_node_t *curr = chain->head;
        while (curr) {
            if (curr == target_node) {
                found = true;
                break;
            }
            curr = curr->next;
        }
        if (found) {
            target_node->is_active = true;
            rebuild_chain_pointers(chain);
            break;
        }
        chain = chain->next;
    }

    pthread_mutex_unlock(&g_registry_mutex);
    return found;
}

GPWNAPI bool gpwn_hook_disable(gpwn_hook_t hook) {
    if (!hook) {
        return false;
    }

    pthread_mutex_lock(&g_registry_mutex);

    gpwn_hook_node_t *target_node = (gpwn_hook_node_t *)hook;
    gpwn_hook_chain_t *chain = g_hook_chains;
    bool found = false;

    while (chain) {
        gpwn_hook_node_t *curr = chain->head;
        while (curr) {
            if (curr == target_node) {
                found = true;
                break;
            }
            curr = curr->next;
        }
        if (found) {
            target_node->is_active = false;
            rebuild_chain_pointers(chain);
            break;
        }
        chain = chain->next;
    }

    pthread_mutex_unlock(&g_registry_mutex);
    return found;
}

GPWNAPI bool gpwn_hook_delete(gpwn_hook_t hook) {
    if (!hook) {
        return false;
    }

    pthread_mutex_lock(&g_registry_mutex);

    gpwn_hook_node_t *target_node = (gpwn_hook_node_t *)hook;
    gpwn_hook_chain_t *chain = g_hook_chains;
    gpwn_hook_chain_t *prev_chain = NULL;
    bool found = false;

    while (chain) {
        gpwn_hook_node_t *curr = chain->head;
        while (curr) {
            if (curr == target_node) {
                found = true;
                break;
            }
            curr = curr->next;
        }

        if (found) {
            target_node->is_active = false;

            if (target_node->prev) {
                target_node->prev->next = target_node->next;
            } else {
                __atomic_store_n(&chain->head, target_node->next, __ATOMIC_RELEASE);
            }

            if (target_node->next) {
                target_node->next->prev = target_node->prev;
            }

            rebuild_chain_pointers(chain);
            free(target_node);

            if (!chain->head) {
                if (chain->is_branch_hook) {
                    write_mem(chain->target_addr, &chain->original_instruction, sizeof(uint32_t));
#if defined(__arm__) || defined(__aarch64__)
                    __builtin___clear_cache((char*)chain->target_addr, (char*)chain->target_addr + sizeof(uint32_t));
#endif
                    if (chain->landing_pad) {
                        munmap(chain->landing_pad, chain->landing_pad_size);
                    }
                } else {
                    rm_hook(chain->base_hook);
                }
                munmap(chain->dispatch_stub, chain->stub_size);

                if (prev_chain) {
                    prev_chain->next = chain->next;
                } else {
                    g_hook_chains = chain->next;
                }
                free(chain);
            }
            break;
        }
        prev_chain = chain;
        chain = chain->next;
    }

    pthread_mutex_unlock(&g_registry_mutex);
    return found;
}

GPWNAPI int gpwn_hook_get_count(void *target_addr) {
    if (!target_addr) {
        return 0;
    }

    pthread_mutex_lock(&g_registry_mutex);

    gpwn_hook_chain_t *chain = g_hook_chains;
    int count = 0;

    while (chain) {
        if (chain->target_addr == target_addr) {
            gpwn_hook_node_t *curr = chain->head;
            while (curr) {
                if (curr->is_active) {
                    count++;
                }
                curr = curr->next;
            }
            break;
        }
        chain = chain->next;
    }

    pthread_mutex_unlock(&g_registry_mutex);
    return count;
}

GPWNAPI void *gpwn_hook_get_orig_func(gpwn_hook_t hook) {
    if (!hook) {
        return NULL;
    }

    pthread_mutex_lock(&g_registry_mutex);

    gpwn_hook_node_t *target_node = (gpwn_hook_node_t *)hook;
    gpwn_hook_chain_t *chain = g_hook_chains;
    void *orig = NULL;

    while (chain) {
        gpwn_hook_node_t *curr = chain->head;
        while (curr) {
            if (curr == target_node) {
                orig = chain->original_trampoline;
                break;
            }
            curr = curr->next;
        }
        if (orig) {
            break;
        }
        chain = chain->next;
    }

    pthread_mutex_unlock(&g_registry_mutex);
    return orig;
}

GPWNAPI void *gpwn_hook_get_old_func(gpwn_hook_t hook) {
    if (!hook) {
        return NULL;
    }

    pthread_mutex_lock(&g_registry_mutex);

    gpwn_hook_node_t *target_node = (gpwn_hook_node_t *)hook;
    gpwn_hook_chain_t *chain = g_hook_chains;
    void *old_val = NULL;

    while (chain) {
        gpwn_hook_node_t *curr = chain->head;
        while (curr) {
            if (curr == target_node) {
                old_val = __atomic_load_n(target_node->user_old_func, __ATOMIC_ACQUIRE);
                break;
            }
            curr = curr->next;
        }
        if (old_val) {
            break;
        }
        chain = chain->next;
    }

    pthread_mutex_unlock(&g_registry_mutex);
    return old_val;
}

static void *my_dlopen(const char *filename, int flags) {
    void *handle = g_old_dlopen(filename, flags);
    if (filename && handle) {
        pthread_mutex_lock(&g_registry_mutex);

        gpwn_pending_hook_t *curr = g_pending_hooks;
        gpwn_pending_hook_t *prev = NULL;
        while (curr) {
            if (strstr(filename, curr->libname)) {
                void *addr = gpwn_dlsym(curr->libname, curr->symname);
                if (addr) {
                    gpwn_hook(addr, curr->fake_func, curr->user_old_func);

                    gpwn_pending_hook_t *to_free = curr;
                    if (prev) {
                        prev->next = curr->next;
                    } else {
                        g_pending_hooks = curr->next;
                    }
                    curr = curr->next;
                    free(to_free->libname);
                    free(to_free->symname);
                    free(to_free);
                    continue;
                }
            }
            prev = curr;
            curr = curr->next;
        }

        pthread_mutex_unlock(&g_registry_mutex);
    }
    return handle;
}

GPWNAPI gpwn_hook_t gpwn_hook_by_name(const char *libname, const char *symname, void *fake_func, void **old_func) {
    if (!libname || !symname || !fake_func || !old_func) {
        return NULL;
    }

    pthread_mutex_lock(&g_registry_mutex);

    void *addr = gpwn_dlsym(libname, symname);
    if (addr) {
        gpwn_hook_t h = gpwn_hook(addr, fake_func, old_func);
        pthread_mutex_unlock(&g_registry_mutex);
        return h;
    }

    gpwn_pending_hook_t *pending = malloc(sizeof(gpwn_pending_hook_t));
    if (!pending) {
        pthread_mutex_unlock(&g_registry_mutex);
        return NULL;
    }
    pending->libname = strdup(libname);
    pending->symname = strdup(symname);
    pending->fake_func = fake_func;
    pending->user_old_func = old_func;
    pending->next = g_pending_hooks;
    g_pending_hooks = pending;

    if (!g_dlopen_hook) {
        void *dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
        if (dlopen_addr) {
            g_dlopen_hook = gpwn_hook(dlopen_addr, my_dlopen, (void**)&g_old_dlopen);
        }
    }

    pthread_mutex_unlock(&g_registry_mutex);
    return (gpwn_hook_t)pending;
}
