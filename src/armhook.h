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

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__aarch64__)
// For 64 bit armhook: requires 28 bytes minimum
GPWNAPI uintptr_t arm_hook64(uintptr_t addr, uintptr_t branchaddr, size_t len);
#elif defined(__arm__)
//For 32 bit armhook: requires 20 bytes minimum
GPWNAPI uintptr_t arm_hook32(uintptr_t addr, uintptr_t branchaddr, size_t len);
#endif

#ifdef __cplusplus
}
#endif
