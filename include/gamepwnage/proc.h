/**
 Gamepwnage -- Cross Platform Game Hacking API(s)

 Copyright (c) 2024-2025 bitware. All rights reserved.
 Copyright (c) 2026-ONWARDS Kitsuri Studio. All rights reserved.

 "Gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
https://github.com/Kitsuri-Studios/gamepwnage
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
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uintptr_t start; /* starting addr of the map */
    uintptr_t end;   /* ending addr of the map   */
    int prot;        /* protection of the map    */
} proc_map;

GPWNAPI unsigned int get_proc_map_count(const char *module);
GPWNAPI unsigned int get_proc_map(const char *module, proc_map *map_array, unsigned int max_map_count);
GPWNAPI void *get_module_addr(char *_module, char *_permissions);
GPWNAPI int get_prot(uintptr_t addr);
GPWNAPI void *find_unmapped(void *target, size_t size);

#ifdef __cplusplus
}
#endif
