/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

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
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "mem.h"
#include "proc.h"

GPWNAPI bool write_mem(void *dest, void *src, size_t len)
{
   // Get the system page size
    size_t page_size = sysconf(_SC_PAGESIZE);

    // Calculate the aligned address and size
    uintptr_t addr = (uintptr_t)dest;
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = ((addr + len + page_size - 1)
        & ~(page_size - 1)) - aligned_addr;
    // get the current protection
    int old_protection = get_prot(aligned_addr);
    if(old_protection == -1)
    {
#ifdef GPWN_DEBUG
        fprintf(stderr, "write_mem() failed at address %p :"
            " couldn't retrive memory protection.\n", addr);
#endif
        return false;
    }

    if (mprotect((void *)aligned_addr, aligned_size,
            old_protection | PROT_WRITE) == -1) {
#ifdef GPWN_DEBUG
        fprintf(stderr, "write_mem() failed at address %p :"
            " could't set memory protection.\n", addr);
#endif
        return false;
    }
    memcpy(dest, src, len);
    // Restore the original memory protection
    if((old_protection & PROT_WRITE) != PROT_WRITE) {
        if (mprotect((void *)aligned_addr, aligned_size, old_protection) == -1) {
#ifdef GPWN_DEBUG
            fprintf(stderr, "write_mem() warning at address %p :"
                " could't restore memory protection.\n", addr);
#endif
        }
    }
    return true;
}
GPWNAPI bool read_mem(void *dest, void *src, size_t len)
{
   // Get the system page size
    size_t page_size = sysconf(_SC_PAGESIZE);

    // Calculate the aligned address and size
    uintptr_t addr = (uintptr_t)src;
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = ((addr + len + page_size - 1) & ~(page_size - 1)) - aligned_addr;
    // get the current protection
    int old_protection = get_prot(aligned_addr);
    if(old_protection == -1)
    {
#ifdef GPWN_DEBUG
        fprintf(stderr, "read_mem() failed at address %p :"
            " couldn't retrive memory protection.\n", addr);
#endif
        return false;
    }
    if (mprotect((void *)aligned_addr, aligned_size,
            old_protection | PROT_READ) == -1) {
#ifdef GPWN_DEBUG
            fprintf(stderr, "read_mem() failed at address %p :"
                " could't set memory protection.\n", addr);
#endif
        return false;
    }
    memcpy(dest, src, len);
    // restore the original memory protection
    if((old_protection & PROT_READ) != PROT_READ) {
        if (mprotect((void *)aligned_addr, aligned_size, old_protection) == -1) {
#ifdef GPWN_DEBUG
            fprintf(stderr, "read_mem() warning at address %p :"
                " could't restore memory protection.\n", addr);
#endif
        }
    }
    return true;
}
GPWNAPI uintptr_t get_addr(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset)
{

    int i = 0;
    uintptr_t Address = Baseaddr; // Get the base address from the parameters

    do
    {
        Address = *((uintptr_t *)Address); // Dereferance current address
        if (Address == (uintptr_t)NULL)
        {
            return 0;
        } // If address = NULL then return 0;

        Address += offsets[i]; // Address = Address + offset
        i++;

    } while (i < TotalOffset);

    return Address; // Return Final Address
}
GPWNAPI void *mmap_near(void *hint, size_t size, int prot) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t target = (uintptr_t)hint;
    size = (size + page_size - 1) & ~(page_size - 1);
    uintptr_t min_addr = (target > 128 * 1024 * 1024) ? (target - 128 * 1024 * 1024) : page_size;
    uintptr_t max_addr = target + 128 * 1024 * 1024 - page_size;
    FILE *fd = fopen("/proc/self/maps", "r");
    if (!fd) {
        return NULL;
    }
    char line[1024];
    uintptr_t prev_end = 0;
    void *allocated = NULL;
    while (fgets(line, sizeof(line), fd) != NULL) {
        uintptr_t start = 0, end = 0;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) {
            continue;
        }
        if (start > prev_end) {
            uintptr_t overlap_start = (prev_end > min_addr) ? prev_end : min_addr;
            uintptr_t overlap_end = (start < max_addr) ? start : max_addr;
            overlap_start = (overlap_start + page_size - 1) & ~(page_size - 1);
            overlap_end = overlap_end & ~(page_size - 1);
            if (overlap_end > overlap_start && (overlap_end - overlap_start) >= size) {
                uintptr_t candidate;
                if (target <= overlap_start) {
                    candidate = overlap_start;
                } else if (target >= overlap_end) {
                    candidate = overlap_end - size;
                } else {
                    candidate = target & ~(page_size - 1);
                    if (candidate < overlap_start) {
                        candidate = overlap_start;
                    } else if (candidate + size > overlap_end) {
                        candidate = overlap_end - size;
                    }
                }
                void *addr = mmap((void*)candidate, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (addr != MAP_FAILED) {
                    uintptr_t addr_val = (uintptr_t)addr;
                    int64_t diff = (int64_t)addr_val - (int64_t)target;
                    if (diff >= -134217728 && diff <= 134217724) {
                        allocated = addr;
                        break;
                    } else {
                        munmap(addr, size);
                    }
                }
            }
        }
        prev_end = end;
    }
    fclose(fd);
    if (!allocated && max_addr > prev_end) {
        uintptr_t overlap_start = (prev_end > min_addr) ? prev_end : min_addr;
        overlap_start = (overlap_start + page_size - 1) & ~(page_size - 1);
        uintptr_t overlap_end = max_addr & ~(page_size - 1);
        if (overlap_end > overlap_start && (overlap_end - overlap_start) >= size) {
            uintptr_t candidate = overlap_start;
            void *addr = mmap((void*)candidate, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (addr != MAP_FAILED) {
                uintptr_t addr_val = (uintptr_t)addr;
                int64_t diff = (int64_t)addr_val - (int64_t)target;
                if (diff >= -134217728 && diff <= 134217724) {
                    allocated = addr;
                } else {
                    munmap(addr, size);
                }
            }
        }
    }
    if (!allocated) {
        void *addr = mmap(hint, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr != MAP_FAILED) {
            uintptr_t addr_val = (uintptr_t)addr;
            int64_t diff = (int64_t)addr_val - (int64_t)target;
            if (diff >= -134217728 && diff <= 134217724) {
                allocated = addr;
            } else {
                munmap(addr, size);
            }
        }
    }
    return allocated;
}

GPWNAPI bool gpwn_patch_nop(void *addr, size_t len) {
    if (!addr || len == 0) {
        return false;
    }
#if defined(__aarch64__)
    if (len % 4 != 0 || ((uintptr_t)addr % 4) != 0) return false;
#elif defined(__arm__)
    bool is_thumb = ((uintptr_t)addr & 1) != 0;
    void *patch_target = (void *)((uintptr_t)addr & ~1);
    if (is_thumb) {
        if (len % 2 != 0) return false;
    } else {
        if (len % 4 != 0 || ((uintptr_t)patch_target % 4) != 0) return false;
    }
#else
    void *patch_target = addr;
#endif
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t aligned_addr = (uintptr_t)addr & ~(page_size - 1);
    size_t aligned_size = (((uintptr_t)addr + len + page_size - 1) & ~(page_size - 1)) - aligned_addr;
    if (mprotect((void *)aligned_addr, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        return false;
    }
#if defined(__aarch64__)
    uint32_t nop_inst = 0xd503201f;
    for (size_t i = 0; i < len / 4; i++) {
        ((uint32_t *)addr)[i] = nop_inst;
    }
#elif defined(__arm__)
    if (is_thumb) {
        uint16_t nop_inst = 0x46c0;
        for (size_t i = 0; i < len / 2; i++) {
            ((uint16_t *)patch_target)[i] = nop_inst;
        }
    } else {
        uint32_t nop_inst = 0xe1a00000;
        for (size_t i = 0; i < len / 4; i++) {
            ((uint32_t *)patch_target)[i] = nop_inst;
        }
    }
#elif defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__x86__)
    memset(addr, 0x90, len);
#else
    (void)addr;
    (void)len;
#endif
#if defined(__arm__) || defined(__aarch64__)
    uintptr_t clean_start = (uintptr_t)addr & ~1;
    __builtin___clear_cache((char *)clean_start, (char *)clean_start + len);
#endif
    mprotect((void *)aligned_addr, aligned_size, PROT_READ | PROT_EXEC);
    return true;
}

GPWNAPI bool gpwn_patch_ret(void *addr) {
    if (!addr) {
        return false;
    }
#if defined(__aarch64__)
    uint32_t ret_inst = 0xd65f03c0;
    return gpwn_patch_nop(addr, sizeof(uint32_t)) ?
           (memcpy(addr, &ret_inst, sizeof(uint32_t)), __builtin___clear_cache((char*)addr, (char*)addr + 4), true) : false;
#elif defined(__arm__)
    bool is_thumb = ((uintptr_t)addr & 1) != 0;
    void *patch_target = (void *)((uintptr_t)addr & ~1);
    if (is_thumb) {
        uint16_t ret_inst = 0x4770;
        return gpwn_patch_nop(addr, sizeof(uint16_t)) ?
               (memcpy(patch_target, &ret_inst, sizeof(uint16_t)), __builtin___clear_cache((char*)patch_target, (char*)patch_target + 2), true) : false;
    } else {
        uint32_t ret_inst = 0xe12fff1e;
        return gpwn_patch_nop(addr, sizeof(uint32_t)) ?
               (memcpy(patch_target, &ret_inst, sizeof(uint32_t)), __builtin___clear_cache((char*)patch_target, (char*)patch_target + 4), true) : false;
    }
#elif defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__x86__)
    uint8_t ret_inst = 0xc3;
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t aligned_addr = (uintptr_t)addr & ~(page_size - 1);
    mprotect((void *)aligned_addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    *(uint8_t *)addr = ret_inst;
    mprotect((void *)aligned_addr, page_size, PROT_READ | PROT_EXEC);
    return true;
#else
    (void)addr;
    return false;
#endif
}
