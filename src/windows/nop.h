/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#pragma once
#include <stdint.h>
#include <stdbool.h>

// implementations for internal use
bool patch_nop(void *Address, size_t len);
// implementations for external use
#include <windows.h>
bool patch_nop_winex(void *Address, size_t len, HANDLE hProcess);
