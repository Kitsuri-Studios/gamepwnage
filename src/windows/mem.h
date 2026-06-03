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

// implementations for internal use
bool write_mem(void *Dest, void *Src, size_t len);
bool read_mem(void *Dest, void *Src, size_t len);
uintptr_t get_addr(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset);

// implementations for external use
#include <windows.h>
bool write_mem_winex(void* Dest, void* Src, size_t len, HANDLE hProcess);
bool read_mem_winex(void* Dest, void* Src, size_t len, HANDLE hProcess);
uintptr_t get_addr_winex(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset, HANDLE hProcess);
