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
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include "proc.h"

GPWNAPI unsigned int get_proc_map_count(const char *module) {
    FILE* fd = fopen("/proc/self/maps", "r");
    if (!fd) {
        //perror("Can't open map...");
        return 0;
    }

    char line[1024];
    unsigned int idx = 0;
    while (fgets(line, sizeof(line), fd) != NULL) {
        if (module) {
            if (!strstr(line, module))
                continue;
        }
        idx++;
    }
    fclose(fd);
    return idx;
}
GPWNAPI unsigned int get_proc_map(const char *module,
    proc_map *map_array, unsigned int max_map_count)  {
    FILE* fd = fopen("/proc/self/maps", "r");
    if (!fd) {
        //perror("Can't open map...");
        return 0;
    }

    char line[1024];
    unsigned int idx = 0;
    char prot_str[5];
    while (fgets(line, sizeof(line), fd) != NULL && idx < max_map_count) {
        if (module) {
            if (!strstr(line, module))
                continue;
        }
        // <start_addr>-<end_addr> rwxp ....
        sscanf(line, "%zx-%zx %4s", &map_array[idx].start, &map_array[idx].end, prot_str);
        map_array[idx].prot = 0;
        if (prot_str[0] == 'r')
            map_array[idx].prot |= PROT_READ;
        if (prot_str[1] == 'w')
            map_array[idx].prot |= PROT_WRITE;
        if (prot_str[2] == 'x')
            map_array[idx].prot |= PROT_EXEC;
        idx++;
    }
    fclose(fd);
    return idx;
}
GPWNAPI void *get_module_addr(
    char *_module, char *_permissions)
{
    unsigned int map_count = get_proc_map_count(_module);
    if(!map_count)
        return 0;    // map wth module name not found
    proc_map *maps = calloc(map_count, sizeof(proc_map));
    if(!maps)
        return 0;    // calloc failed
    map_count = get_proc_map(_module, maps, map_count);
    uintptr_t addr = 0;
    if(!_permissions || strlen(_permissions) < 3) {
        addr = maps[0].start;    // select the first map if nothing specified
    } else {
        int prot = 0;
        if(_permissions[0] == 'r')
            prot |= PROT_READ;
        if(_permissions[1] == 'w')
            prot |= PROT_WRITE;
        if(_permissions[3] == 'x')
            prot |= PROT_EXEC;
        for(unsigned int i = 0; i < map_count; i++) {
            if(maps[i].prot == prot) {
                addr = maps[i].start;
                break;
            }
        }
    }
    free(maps);
    return (void*) addr;
}
GPWNAPI int get_prot(uintptr_t addr)
{
    unsigned int map_count = get_proc_map_count(0);
    if(!map_count)
        return 0;    // map wth module name not found
    proc_map *maps = calloc(map_count, sizeof(proc_map));
    if(!maps)
        return 0;    // calloc failed
    map_count = get_proc_map(0, maps, map_count);
    int prot = 0;
    for(unsigned int i = 0; i < map_count; i++) {
        if(addr >= maps[i].start
        && addr < maps[i].end) {
            prot = maps[i].prot;
            break;
        }
    }
    free(maps);
    return prot;
}
GPWNAPI void* find_unmapped(void *target, size_t size) {
    unsigned int map_count = get_proc_map_count(0);
    proc_map *maps = calloc(map_count, sizeof(proc_map));
    if(!maps) {
        // calloc() failed
        return 0;
    }
    unsigned int rd_map_count = get_proc_map(0, maps, map_count);
    unsigned int target_index = -1;
    // get the target's index
    for(unsigned int i = 0; i < rd_map_count; i++) {
        if((uintptr_t) target >= maps[i].start &&
            (uintptr_t) target < maps[i].end
        ) {
            target_index = i;
            break;
        }
    }
    if(target_index == -1) {
        // target map not found
        free(maps);
        return 0;
    }
    uintptr_t nearest_pos = 0, nearest_neg = 0;
    if(target_index < rd_map_count) {
        // find positive
        for(unsigned int i = target_index; i < rd_map_count; i++) {
            if(maps[i+1].start - maps[i].end >= size) {
                nearest_pos = maps[i].end;
                break;
            }
        }
    } else {
        nearest_pos = maps[target_index].end;
    }
    if(target_index > 0) {
        // find negative
        for(unsigned int i = target_index - 1; i == 0; i--) {
            if(maps[i+1].start - maps[i].end >= size) {
                nearest_neg = maps[i].end;
                break;
            }
        }
    } else if (maps[target_index].start >= size) {
        nearest_neg = maps[target_index].start - size;
    }
    free(maps);
    if(nearest_pos - (uintptr_t) target <= (uintptr_t) target - nearest_neg)
    {
        return (void*) nearest_pos;
    } else {
        return (void*) nearest_neg;
    }
}
