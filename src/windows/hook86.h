/**
 Gamepwnage -- Cross Platform Game Hacking API(s)

 Copyright (c) 2024-2025 bitware. All rights reserved.
 Copyright (c) 2026-ONWARDS Kitsuri Studio. All rights reserved.

 "Gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
https://github.com/Kitsuri-Studios/gamepwnage
*/
#pragma once
#include <stdint.h>
#include <stdbool.h>

/*
x86_32 hook -- atleast 5 bytes required to place a hook
            -- no gp registers will be modified

RETURNS     -- the address where the hook should jmp back
*/
uintptr_t hook_x86(void *AddresstoHook, void *hookFunAddr, size_t len);

/*
x86_64 hook -- atleast 16 bytes required to place a hook
            -- "%rax" will be modified,
               needs to be poped in the first of the code
            -- "%rsp" will be modified as well

RETURNS     -- the address where the hook should jmp back
*/
#if defined(__x86_64__) || defined(__amd64__)
uintptr_t hook_x64(void *AddresstoHook, void *hookFunAddr, size_t len);
#endif
