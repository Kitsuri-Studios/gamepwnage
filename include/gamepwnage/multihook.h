/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2026 bitware. All rights reserved.
 Made by xzelleiv

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

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* gpwn_hook_t;

GPWNAPI gpwn_hook_t gpwn_hook(void *target_addr, void *fake_func, void **old_func);
GPWNAPI gpwn_hook_t gpwn_hook_branch(void *branch_addr, void *fake_func, void **old_func);

GPWNAPI bool gpwn_hook_enable(gpwn_hook_t hook);
GPWNAPI bool gpwn_hook_disable(gpwn_hook_t hook);
GPWNAPI bool gpwn_hook_delete(gpwn_hook_t hook);

GPWNAPI int gpwn_hook_get_count(void *target_addr);
GPWNAPI void *gpwn_hook_get_orig_func(gpwn_hook_t hook);
GPWNAPI void *gpwn_hook_get_old_func(gpwn_hook_t hook);

#ifdef __cplusplus
}
#endif
