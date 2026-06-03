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
#include <stdbool.h>
#include <windows.h>
#include "nop.h"

bool patch_nop(void *Address, size_t len)
{
    DWORD oldProtect, temp;

    if(!VirtualProtect(Address, len, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        // fprintf(stderr, "error changing memory protection.\n", );
        return FALSE;
    }
    memset(Address, 0x90, len);
    VirtualProtect(Address, len, oldProtect, &temp);

    return TRUE;
}
