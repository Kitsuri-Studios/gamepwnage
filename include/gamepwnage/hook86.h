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
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
x86_32 hook -- atleast 5 bytes required to place a hook
            -- no gp registers will be modified

RETURNS     -- the address where the hook should jmp back
*/
GPWNAPI uintptr_t hook_x86(void *AddresstoHook, void *hookFunAddr, size_t len);


#ifdef __cplusplus
}
#endif
