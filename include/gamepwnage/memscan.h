/**
 Gamepwnage -- Cross Platform Game Hacking API(s)

 Copyright (c) 2024-2025 bitware. All rights reserved.
 Copyright (c) 2026-ONWARDS Kitsuri Studio. All rights reserved.

 "Gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
https://github.com/Kitsuri-Studios/gamepwnage
*/
#pragma once

#ifdef GPWN_USING_BUILD_CONFIG
#include "config.h"
#else
#ifndef GPWNAPI
#define GPWNAPI
#endif
#endif

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char byte;
typedef struct {
    int flags;                // flags
    void *next;               // next address
    size_t sig_size;          // signature length
    byte* sig;                // signature bytes
    byte* mask;               // mask bytes
    char *libname;            // library name
} sigscan_handle;

// flags
#define GPWN_SIGSCAN_XMEM       1
#define GPWN_SIGSCAN_WMEM       1 << 1
#define GPWN_SIGSCAN_FORCEMODE  1 << 3

/*
Note:
(*) If no flags are specified during setup, scanner will go through all readable
    memory regions. And if (GPWN_SIGSCAN_XMEM | GPWN_SIGSCAN_WMEM) used as flags,
    it will only scan memory regions with both read and write protections.
(*) If GPWN_SIGSCAN_FORCEMODE used, it will attempt overriding protection before
    reading.
*/
GPWNAPI sigscan_handle *sigscan_setup(const char *signature_str,
    const char *libname, int flags);
GPWNAPI sigscan_handle *sigscan_setup_raw(byte *sigbyte, byte *mask,
    size_t sig_size, const char *libname, int flags);
GPWNAPI void sigscan_cleanup(sigscan_handle *handle);
GPWNAPI void *get_sigscan_result(sigscan_handle *handle);

#ifdef __cplusplus
}
#endif
