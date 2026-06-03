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

#include "nop.h"
#include "proc.h"

GPWNAPI bool patch_nop(void *Address, size_t len)
{
// check architecture and set-up as required
#if defined(__x86_64__) || defined(__amd64__)
    // Code specific to x86_64
    static const unsigned char nopBytes[1] = {0x90};
    static const size_t nopBytes_len = 1;
#elif defined(__i386__) || defined(__i686__) || defined (__x86__)
    // Code specific to x86 (32-bit)
    static const unsigned char nopBytes[1] = {0x90};
    static const size_t nopBytes_len = 1;
#elif defined(__aarch64__)
    // Code specific to AArch64
    static const unsigned char nopBytes[4] = {0x1f, 0x20, 0x03, 0xd5};
    static const size_t nopBytes_len = 4;
#elif defined(__arm__)
    // Code specific to 32-bit ARM
    static const unsigned char nopBytes[4] = {0x00, 0xF0, 0x20, 0xE3};
    static const size_t nopBytes_len = 4;
#else
    #error "Unsupported architecture."
#endif

    if((len % nopBytes_len) != 0)
    {
        //If invalid length
        // fprintf(stderr, "[!] %s@%s: Invalid nop length specified at address 0x%lX! (must be a multiple of %d)", 
        //     "PatchNop", "gamepwnage", (uintptr_t)Address, (int)nopBytes_len);
        return false;
    }
    
   // Get the system page size
    size_t page_size = sysconf(_SC_PAGESIZE);
    
    // Calculate the aligned address and size
    uintptr_t addr = (uintptr_t)Address;
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = ((addr + len + page_size - 1) & ~(page_size - 1)) - aligned_addr;

    int old_protection = get_prot(aligned_addr);

    // Change memory protection to allow reading, writing, and executing
    if (mprotect((void *)aligned_addr, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        // perror("[X] PatchNop: Error changing memory protection");
        return false;
    }

    for (int n=0; n < (len/nopBytes_len); n++)
    {
        //copy nop bytes
        // memcpy(Address, nopBytes, nopBytes_len);
        // avoid calling memcpy as it might take extra cpu cycles
        for (int j=0; j < nopBytes_len; j++)
        {
            ((unsigned char*)Address)[j] = nopBytes[j];
        }
        Address += nopBytes_len;
    }

    // Restore the original memory protection
    if (mprotect((void *)aligned_addr, aligned_size, old_protection) == -1)
    {
        // perror("[X] PatchNop: Error restoring memory protection");
        return false;
    }

    return true;
}
