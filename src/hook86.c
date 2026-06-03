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
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>

#include "hook86.h"
#include "proc.h"

/*
x86_32 hook -- atleast 5 bytes required to place a hook
            -- no gp registers will be modified

RETURNS     -- the address where the hook should jmp back
*/
GPWNAPI uintptr_t hook_x86(void *AddresstoHook, void *hookFunAddr, size_t len)
{
    if (len < 5)
    {
        // not enough bytes
        // fprintf(stderr, "hook_x86() error: not enough memory to place a hook\n");
        return 0;
    }

    // Get the system page size
    size_t page_size = sysconf(_SC_PAGESIZE);
    // Calculate the aligned address and size
    uintptr_t addr = (uintptr_t)AddresstoHook;
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = ((addr + len + page_size - 1) & ~(page_size - 1)) - aligned_addr;
    // the the current protection
    int old_protection;
    old_protection = get_prot(aligned_addr);
    // Change memory protection to allow reading, writing, and executing
    if (mprotect((void *) aligned_addr, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        // perror("Error changing memory protection");
        return 0;
    }
    // patch nops
    memset(AddresstoHook, 0x90, len);

    uint32_t RelativeAddress = ((uintptr_t)hookFunAddr - ((uintptr_t)AddresstoHook + 5)); // get the relative address

    *(unsigned char *)AddresstoHook = 0xE9; // copy jmp instruction
    memcpy((void *)((uintptr_t)AddresstoHook + 1), &RelativeAddress, 4);
    // Restore the previous permisssion
    if (mprotect((void *) aligned_addr, len, old_protection) == -1)
    {
        // perror("Error changing memory protection");
        // won't returns "0" as hook already placed
    }
    return (uintptr_t)AddresstoHook + len;
}
