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

bool write_mem(void *Dest, void *Src, size_t len)
{

    DWORD oldProtect;

    if(!VirtualProtect(Dest, len, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        // fprintf(stderr, "error changing memory protection.\n", );
        return FALSE;
    }

    memcpy(Dest, Src, len);
    VirtualProtect(Dest, len, oldProtect, &oldProtect);

    return TRUE;
}

bool read_mem(void *Dest, void *Src, size_t len)
{

    DWORD oldProtect;

    if(!VirtualProtect(Src, len, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        // fprintf(stderr, "error changing memory protection.\n", );
        return FALSE;
    }
    memcpy(Dest, Src, len);
    VirtualProtect(Src, len, oldProtect, &oldProtect);

    return TRUE;
}

uintptr_t get_addr(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset)
{

    int i = 0;
    uintptr_t Address = Baseaddr; // Get the base address from the parameters

    do
    {
        Address = *((uintptr_t *)Address); // Dereferance current address
        if (Address == (uintptr_t) NULL)
        {
            return 0;
        } // If address = NULL then return 0;

        Address += offsets[i]; // Address = Address + offset
        i++;

    } while (i < TotalOffset);

    return Address; // Return Final Address
}
