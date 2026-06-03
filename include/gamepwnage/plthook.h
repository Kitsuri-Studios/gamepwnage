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

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void **addr;
    void *original;
} plthook_handle;

GPWNAPI plthook_handle *hook_plt(
    const char *libname, const char *symname, 
    void *fake, void **original
);
GPWNAPI void rm_hook_plt(plthook_handle *handle);

#ifdef __cplusplus
}
#endif
