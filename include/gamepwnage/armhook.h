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

#if defined(__aarch64__)
// For 64 bit armhook: requires 20 bytes minimum
GPWNAPI uintptr_t arm64_detour(uintptr_t addr, uintptr_t branchaddr, size_t len);
#elif defined(__arm__)
//For 32 bit armhook: requires 12 bytes minimum
GPWNAPI uintptr_t arm32_detour(uintptr_t addr, uintptr_t branchaddr, size_t len);
#endif

#ifdef __cplusplus
}
#endif
