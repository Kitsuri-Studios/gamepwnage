/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#pragma once

#ifdef GPWN_USING_BUILD_CONFIG
#include "config.h"
#else
#ifndef GPWNAPI
#define GPWNAPI
#endif
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

GPWNAPI bool write_mem(void *dest, void *src, size_t len);
GPWNAPI bool read_mem(void *dest, void *src, size_t len);

GPWNAPI uintptr_t get_addr(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset);
GPWNAPI void *mmap_near(void *hint, size_t size, int prot);

GPWNAPI bool gpwn_patch_nop(void *addr, size_t len);
GPWNAPI bool gpwn_patch_ret(void *addr);

#ifdef __cplusplus
}
#endif
