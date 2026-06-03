/**
 Gamepwnage -- Cross Platform Game Hacking API(s)

 Copyright (c) 2024-2025 bitware. All rights reserved.
 Copyright (c) 2026-ONWARDS Kitsuri Studio. All rights reserved.

 "Gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
https://github.com/Kitsuri-Studios/gamepwnage
*/
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include "mem.h"

bool write_mem_winex(void* Dest, void* Src, size_t len, HANDLE hProcess)
{
    SIZE_T BytesRead = 0;
    if (!WriteProcessMemory(hProcess, (LPVOID)Dest, (LPCVOID)Src, len, (SIZE_T*)&BytesRead))
    {
        // fprintf(stderr, "write_mem_winex() failed at address %p
        //  , error code: %d\n", (long) Dest, GetLastError());
        return FALSE;
    }
    return TRUE;
}

bool read_mem_winex(void* Dest, void* Src, size_t len, HANDLE hProcess)
{
    SIZE_T BytesWritten = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)Src, (LPVOID)Dest, len, (SIZE_T*)&BytesWritten))
    {
        // fprintf(stderr, "read_mem_winex() failed at address %p
        //  , error code: %d\n", (long) Src, GetLastError());
        return FALSE;
    }
    return TRUE;
}

uintptr_t get_addr_winex(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset, HANDLE hProcess)
{
    int i = 0;
    uintptr_t Address = Baseaddr; // Get the base address from the parameters
    uintptr_t AddrBak = 0;

    SIZE_T BytesRead = 0;
    BOOL ifRead;

    do {
        AddrBak = Address;

        ifRead = ReadProcessMemory(hProcess, (LPCVOID)AddrBak, (LPVOID)&Address, sizeof(void*), (SIZE_T*)&BytesRead); // Dereferance current address
        if (!Address || BytesRead != sizeof(void*) || !ifRead)
        {
            return 0;
        } // If address = NULL then return 0;

        Address += offsets[i]; // Address = Address + offset
        i++;

    } while (i < TotalOffset);

    return Address; // Return Final Address
}
