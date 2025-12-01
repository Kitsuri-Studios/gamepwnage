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

#ifdef __cplusplus
extern "C" {
#endif

 // Resolve a symbol from a library using ELF dynamic linking Works across namespaces on Android (maybe :freaklaugh:)
GPWNAPI void *gpwn_dlsym(const char *libname, const char *symname);

#ifdef __cplusplus
}
#endif