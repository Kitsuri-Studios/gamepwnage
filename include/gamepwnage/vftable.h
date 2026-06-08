/*
 * gamepwnage -- Cross Platform Game Hacking API(s)
 * Copyright (c) 2024-2026 bitware. All rights reserved.
 *
 * "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 * Go to the project home page for more info:
 * https://github.com/bitwaree/gamepwnage
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

GPWNAPI void **get_vftable_ptr(const char *libname, const char *classname);
GPWNAPI void *hook_vft(void **vftable, size_t idx, void *newfunc);

#ifdef __cplusplus
}
#endif
