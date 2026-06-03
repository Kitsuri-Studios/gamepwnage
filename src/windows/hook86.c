/**
 Gamepwnage -- Cross Platform Game Hacking API(s)

 Copyright (c) 2024-2025 bitware. All rights reserved.
 Copyright (c) 2026-ONWARDS Kitsuri Studio. All rights reserved.

 "Gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
https://github.com/Kitsuri-Studios/gamepwnage
*/
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include "mem.h"

uintptr_t hook_x86(void *AddresstoHook, void *hookFunAddr, size_t len)
{
    if (len < 5)
    {
        return 0;
    }
    // Change Permission
    DWORD oldProtection, tempProtection;
    if (!VirtualProtect(AddresstoHook, len, PAGE_EXECUTE_READWRITE, &oldProtection))
    {
        // fprintf(stderr, "error changing memory protection.\n", );
        return 0;
    }
    // patch nops
    memset(AddresstoHook, 0x90, len);

    uint32_t RelativeAddress = ((uintptr_t)hookFunAddr - ((uintptr_t)AddresstoHook + 5)); // get the relative address

    *((unsigned char *) AddresstoHook) = 0xE9;        // copy jmp instruction
    memcpy((void *)((uintptr_t)AddresstoHook + 1), &RelativeAddress, sizeof(uint32_t));
    // Restore the previous permisssion
    VirtualProtect(AddresstoHook, len, oldProtection, &tempProtection);
    return ((uintptr_t) AddresstoHook + len);
}

uintptr_t hook_x64(void *AddresstoHook, void *hookFunAddr, size_t len)
{
    unsigned char jmp_sample[14] = {  
        0x50, 0x48, 0xb8, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12, 0xff,
        0xe0, 0x58
    };
    
    if (len < 14)
    {
        return 0;
    }
    // Change Permission
    DWORD oldProtection, tempProtection;
    if (!VirtualProtect(AddresstoHook, len, PAGE_EXECUTE_READWRITE, &oldProtection))
    {
        // fprintf(stderr, "error changing memory protection.\n", );
        return 0;
    }
    // patch nops
    memset(AddresstoHook, 0x90, len);

    // copy sample jmp instruction
    memcpy((void*)AddresstoHook, (void*) jmp_sample, sizeof(jmp_sample));
    //copy the addressss to jmp
    memcpy((void *)((uintptr_t)AddresstoHook + 3), &hookFunAddr, sizeof(void*));
    // Restore the previous permisssion
    VirtualProtect(AddresstoHook, len, oldProtection, &tempProtection);
    return ((uintptr_t)AddresstoHook + 0xD);    //Return the jumpback address
}
