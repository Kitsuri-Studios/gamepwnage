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

bool patch_nop_winex(void *Address, size_t len, HANDLE hProcess)
{
    unsigned char *pseudomemory = (unsigned char *) malloc(len);
    if(!pseudomemory) {
        return false;
    }
    memset(pseudomemory, 0x90, len);
    SIZE_T BytesRead = 0;
    if (!WriteProcessMemory(hProcess, (LPVOID)Address, (LPCVOID)pseudomemory, len, (SIZE_T*)&BytesRead)) {
        // fprintf(stderr, "patch_nop_winex() failed, couldn't allocate memory.\n");
        free(pseudomemory);
        return false;
    }
    free(pseudomemory);
    return true;
}
