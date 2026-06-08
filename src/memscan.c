/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
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
#include <ctype.h>
#include <string.h>
#include <sys/mman.h>
#include "proc.h"
#include "memscan.h"
GPWN_BKND size_t parse_sigpattern(const char *in_pattern,
    byte **sigbyte, byte **mask);
GPWN_BKND size_t search_sigpattern4(uint32_t *data, size_t data_len,
    uint32_t *sigbyte, uint32_t *mask, size_t sig_len);
GPWN_BKND size_t search_sigpattern_hybrid(byte *data, size_t data_len,
    byte *sigbyte, byte *mask, size_t sig_len, size_t block_size);
GPWNAPI sigscan_handle *sigscan_setup(const char *signature_str,
    const char *libname, int flags) {
    sigscan_handle *handle = malloc(sizeof(sigscan_handle));
    if(!handle) {
#ifdef GPWN_DEBUG
        fputs("sigscan_setup() failed : "
            "malloc() couldn't allocate memory\n", stderr);
#endif
        return 0;
    }
    handle->flags = flags;
    handle->next = 0;
    if(libname)
        handle->libname = strdup(libname);
    else
        handle->libname = 0;
    handle->sig_size = parse_sigpattern(signature_str, &handle->sig, &handle->mask);
    if(handle->sig_size == (size_t)-1) {
#ifdef GPWN_DEBUG
        fputs("sigscan_setup() failed : "
            "invalid signature string\n", stderr);
#endif
        if(handle->libname)
            free(handle->libname);
        free(handle);
        return 0;
    }
    return handle;
}
GPWNAPI sigscan_handle *sigscan_setup_raw(byte *sigbyte, byte *mask,
    size_t sig_size, const char *libname, int flags) {
    sigscan_handle *handle = malloc(sizeof(sigscan_handle));
    if(!handle) {
#ifdef GPWN_DEBUG
        fputs("sigscan_setup_raw() failed : "
            "malloc() couldn't allocate memory\n", stderr);
#endif
        return 0;
    }
    handle->flags = flags;
    handle->next = 0;
    if(libname)
        handle->libname = strdup(libname);
    else
        handle->libname = 0;
    handle->sig = malloc(sig_size);
    if(!handle->sig) {
#ifdef GPWN_DEBUG
        fputs("sigscan_setup_raw() failed : "
            "malloc() couldn't allocate memory\n", stderr);
#endif
        if(handle->libname)
            free(handle->libname);
        free(handle);
        return 0;
    }
    handle->mask = malloc(sig_size);
    if(!handle->mask) {
#ifdef GPWN_DEBUG
        fputs("sigscan_setup_raw() failed : "
            "malloc() couldn't allocate memory\n", stderr);
#endif
        free(handle->sig);
        if(handle->libname)
            free(handle->libname);
        free(handle);
        return 0;
    }
    memcpy(handle->sig, sigbyte, sig_size);
    memcpy(handle->mask, mask, sig_size);
    for(size_t i = 0; i < sig_size; i++) {
        if(!handle->mask[i])
            handle->sig[i] = 0;
    }
    handle->sig_size = sig_size;
    return handle;
}
GPWNAPI void sigscan_cleanup(sigscan_handle *handle) {
    if(!handle)
        return;
    if(handle->libname)
        free(handle->libname);
    free(handle->sig);
    free(handle->mask);
    free(handle);
}
GPWNAPI void *get_sigscan_result(sigscan_handle *handle) {
    if(!handle || handle->next == (void*)-1)
        return (void*)-1;
    int required_prot = PROT_READ;
    int block_size = 1;
    if(handle->flags & GPWN_SIGSCAN_WMEM)
        required_prot |= PROT_WRITE;
    if(handle->flags & GPWN_SIGSCAN_XMEM) {
        required_prot |= PROT_EXEC;
#if defined(__aarch64__) || defined(__arm__)
        block_size = 4;
#endif
    }
    unsigned int map_count = get_proc_map_count(handle->libname);
    if(!map_count) {
#ifdef GPWN_DEBUG
        fputs("get_sigscan_result() failed : "
            "couldn't retrieve map_count.\n", stderr);
#endif
        return (void*) -1;
    }
    proc_map *maps = calloc(map_count, sizeof(proc_map));
    if(!maps) {
#ifdef GPWN_DEBUG
        fputs("get_sigscan_result() failed : "
            "calloc() couldn't allocate memory\n", stderr);
#endif
        return (void*) -1;
    }
    map_count = get_proc_map(handle->libname, maps, map_count);
    if(!map_count) {
#ifdef GPWN_DEBUG
        fputs("get_sigscan_result() failed : "
            "couldn't retrieve memory map.\n", stderr);
#endif
        free(maps);
        return (void*) -1;
    }
    for(unsigned int i = 0; i < map_count; i++) {
        size_t map_len = maps[i].end - maps[i].start;
        if(map_len < handle->sig_size)
            continue;
        if((handle->flags & GPWN_SIGSCAN_FORCEMODE)
            && (maps[i].prot & required_prot) != required_prot) {
            if(mprotect(
                    (void*) maps[i].start,
                    map_len,
                    maps[i].prot | required_prot) == 0)
                maps[i].prot |= required_prot;
        }
        if((maps[i].prot & required_prot) != required_prot)
            continue;
        byte *data;
        size_t data_len;
        size_t offset;
        if(!handle->next || (uintptr_t) handle->next < maps[i].start) {
            data = (byte*) maps[i].start;
            data_len = map_len;
        } else if (
            (uintptr_t) handle->next >= maps[i].start
            && maps[i].end >= handle->sig_size
            && (uintptr_t) handle->next <= maps[i].end - handle->sig_size
        ) {
            data = (byte*) handle->next;
            data_len = maps[i].end - (size_t) handle->next;
        } else {
            continue;
        }
        offset = search_sigpattern_hybrid(data, data_len,
            handle->sig, handle->mask, handle->sig_size, block_size);
        if(offset != (size_t)-1) {
            handle->next = data + offset + 1;
            free(maps);
            return data + offset;
        }
    }
    handle->next = (void*)-1;
    free(maps);
    return (void*) -1;
}
static inline uint8_t hextonib(char hex) {
    if(hex >= '0' && hex <= '9')
        return hex - '0';
    else if(hex >= 'a' && hex <= 'f')
        return hex - 'a' + 0xa;
    else if(hex >= 'A' && hex <= 'F')
        return hex - 'A' + 0xa;
    return 0;
}
GPWN_BKND size_t parse_sigpattern(const char *in_pattern,
    byte **sigbyte, byte **mask) {
    size_t pat_len = strlen(in_pattern);
    *sigbyte = malloc((pat_len / 2) + 1);
    *mask    = malloc((pat_len / 2) + 1);
    if(!*sigbyte || !*mask) {
        free(*sigbyte);
        free(*mask);
        return (size_t)-1;
    }
    memset(*sigbyte, 0, (pat_len / 2) + 1);
    memset(*mask,    0, (pat_len / 2) + 1);
    size_t head   = 0;
    int    nibble = 0;
    for(size_t i = 0; i < pat_len; i++) {
        char c = in_pattern[i];
        if(c == ' ' || c == '\n') {
            if(nibble) {
                free(*sigbyte);
                free(*mask);
                return (size_t)-1;
            }
            continue;
        }
        if(c == '?') {
            if(nibble) {
                free(*sigbyte);
                free(*mask);
                return (size_t)-1;
            }
            if(i + 1 < pat_len && in_pattern[i + 1] == '?')
                i++;
            (*sigbyte)[head] = 0x00;
            (*mask)[head]    = 0x00;
            head++;
            continue;
        }
        if(isxdigit((unsigned char)c)) {
            if(!nibble) {
                (*sigbyte)[head] |= hextonib(c) << 4;
                (*mask)[head]    |= 0xf0;
            } else {
                (*sigbyte)[head] |= hextonib(c) & 0x0f;
                (*mask)[head]    |= 0x0f;
                head++;
            }
            nibble = !nibble;
            continue;
        }
        free(*sigbyte);
        free(*mask);
        return (size_t)-1;
    }
    if(nibble) {
        free(*sigbyte);
        free(*mask);
        return (size_t)-1;
    }
    return head;
}
GPWN_BKND size_t search_sigpattern4(uint32_t *data, size_t data_len,
    uint32_t *sigbyte, uint32_t *mask, size_t sig_len) {
    if(sig_len == 0 || data_len < sig_len)
        return (size_t)-1;
    if((sig_len & 3) || (data_len & 3))
        return (size_t)-1;
    data_len /= 4;
    sig_len  /= 4;
    for(size_t i = 0; i <= (data_len - sig_len); i++) {
        for(size_t j = 0; j < sig_len; j++) {
            if((data[i+j] & mask[j]) != (sigbyte[j] & mask[j]))
                break;
            if(j+1 == sig_len)
                return i * 4;
        }
    }
    return (size_t)-1;
}
#if defined(USING_AVX2)
#include <immintrin.h>
static inline char cmp256(__m256i *data, __m256i *sig, __m256i *mask) {
    __m256i diff = _mm256_xor_si256(
        _mm256_and_si256(_mm256_loadu_si256(data), _mm256_loadu_si256(mask)),
        _mm256_loadu_si256(sig)
    );
    return _mm256_testz_si256(diff, diff);
}
static inline char cmp128(__m128i *data, __m128i *sig, __m128i *mask) {
    __m128i diff = _mm_xor_si128(
        _mm_and_si128(_mm_loadu_si128(data), _mm_loadu_si128(mask)),
        _mm_loadu_si128(sig)
    );
    return _mm_testz_si128(diff, diff);
}
#elif defined(USING_NEON)
#include <arm_neon.h>
static inline char cmp128(uint64x2_t *data, uint64x2_t *sig, uint64x2_t *mask) {
    uint64x2_t diff = veorq_u64(
        vandq_u64(vld1q_u64((uint64_t*)data), vld1q_u64((uint64_t*)mask)),
        vld1q_u64((uint64_t*)sig)
    );
    return (vgetq_lane_u64(diff, 0) | vgetq_lane_u64(diff, 1)) == 0;
}
#endif
typedef struct {
    size_t anchor_idx;
    size_t right_idx;
    byte anchor_byte;
    int has_anchor;
    int use_bmh;
    uint8_t bmh_skip[256];
} sigscan_ctx;
static int sig_has_partial_mask(const byte *mask, size_t sig_len) {
    for(size_t i = 0; i < sig_len; i++) {
        if(mask[i] != 0 && mask[i] != 0xff)
            return 1;
    }
    return 0;
}
static uint8_t sig_anchor_score(byte b) {
    if(b == 0x00 || b == 0xff)
        return 0;

    // 256-bit table (4×u64): bit N set -> byte N is a rare/good anchor. 0x00, 0xFF and common opcodes/prefixes cleared.
    static const uint64_t hot_mask[4] = {
        0x000200070380fffeULL,
        0x001e070601100703ULL,
        0x0001070000920001ULL,
        0x2200008300400000ULL
    };
    if((hot_mask[b >> 6] >> (b & 63)) & 1)
        return 16;
    return 220;
}
static void sigscan_ctx_init(sigscan_ctx *ctx, const byte *sig, const byte *mask,
    size_t sig_len) {
    ctx->has_anchor = 0;
    ctx->use_bmh = 0;
    ctx->anchor_idx = 0;
    ctx->right_idx = 0;
    ctx->anchor_byte = 0;
    if(!sig_len)
        return;
    size_t fixed = 0;
    size_t first_fixed = 0;
    int have_first = 0;
    size_t best_i = 0;
    uint8_t best_r = 0;
    int have_best = 0;
    for(size_t i = 0; i < sig_len; i++) {
        if(mask[i] != 0xff)
            continue;
        fixed++;
        ctx->right_idx = i;
        if(!have_first) {
            first_fixed = i;
            have_first = 1;
        }
        uint8_t r = sig_anchor_score(sig[i]);
        if(!have_best || r > best_r || (r == best_r && i < best_i)) {
            best_r = r;
            best_i = i;
            have_best = 1;
        }
    }
    if(have_best && best_r > 0) {
        ctx->has_anchor = 1;
        ctx->anchor_idx = best_i;
        ctx->anchor_byte = sig[best_i];
    } else if(have_first) {
        ctx->has_anchor = 1;
        ctx->anchor_idx = first_fixed;
        ctx->anchor_byte = sig[first_fixed];
    }
    if(sig_has_partial_mask(mask, sig_len))
        return;
    if(fixed < 2 || sig_len < 4)
        return;
    uint8_t def = (ctx->right_idx >= 255) ? 255 : (uint8_t)(ctx->right_idx + 1);
    for(int i = 0; i < 256; i++)
        ctx->bmh_skip[i] = def;
    for(size_t i = 0; i < ctx->right_idx; i++) {
        if(mask[i] != 0xff)
            continue;
        uint8_t shift = (uint8_t)(ctx->right_idx - i);
        if(shift < 1)
            shift = 1;
        ctx->bmh_skip[sig[i]] = shift;
    }
    ctx->use_bmh = 1;
}
static int sig_matches(const byte *data, const byte *sigbyte, const byte *mask,
    size_t sig_len) {
    size_t j = 0;
#if defined(USING_AVX2)
    for(; j + 32 <= sig_len; j += 32) {
        if(!cmp256(
                (__m256i*)(data + j),
                (__m256i*)(sigbyte + j),
                (__m256i*)(mask + j)))
            return 0;
    }
    for(; j + 16 <= sig_len; j += 16) {
        if(!cmp128(
                (__m128i*)(data + j),
                (__m128i*)(sigbyte + j),
                (__m128i*)(mask + j)))
            return 0;
    }
#elif defined(USING_NEON)
    for(; j + 16 <= sig_len; j += 16) {
        if(!cmp128(
                (uint64x2_t*)(data + j),
                (uint64x2_t*)(sigbyte + j),
                (uint64x2_t*)(mask + j)))
            return 0;
    }
#endif
#ifdef __LP64__
    for(; j + 8 <= sig_len; j += 8) {
        uint64_t dv, sv, mv;
        __builtin_memcpy(&dv, data + j, 8);
        __builtin_memcpy(&sv, sigbyte + j, 8);
        __builtin_memcpy(&mv, mask + j, 8);
        if((dv & mv) != (sv & mv))
            return 0;
    }
#endif
    for(; j + 4 <= sig_len; j += 4) {
        uint32_t dv, sv, mv;
        __builtin_memcpy(&dv, data + j, 4);
        __builtin_memcpy(&sv, sigbyte + j, 4);
        __builtin_memcpy(&mv, mask + j, 4);
        if((dv & mv) != (sv & mv))
            return 0;
    }
    for(; j < sig_len; j++) {
        if((data[j] & mask[j]) != (sigbyte[j] & mask[j]))
            return 0;
    }
    return 1;
}
static size_t sigscan_bmh_shift(const sigscan_ctx *ctx, const byte *data,
    size_t off) {
    uint8_t shift = ctx->bmh_skip[data[off + ctx->right_idx]];
    return shift ? shift : 1;
}
GPWN_BKND size_t search_sigpattern_hybrid(byte *data, size_t data_len,
    byte *sigbyte, byte *mask, size_t sig_len, size_t block_size) {
    if(block_size == 0 || sig_len == 0 || data_len < sig_len)
        return (size_t)-1;

    sigscan_ctx ctx;
    sigscan_ctx_init(&ctx, sigbyte, mask, sig_len);

    if(ctx.has_anchor) {
        const byte *p = data;
        const byte *anchor_end = data + data_len - sig_len + ctx.anchor_idx + 1;
        size_t alignment_mask = block_size - 1;

        while(p < anchor_end) {
            size_t search_len = (size_t)(anchor_end - p);
            const byte *hit = memchr(p, ctx.anchor_byte, search_len);
            if(!hit)
                break;

            p = hit;
            size_t pos = (size_t)(p - data);
            if(pos < ctx.anchor_idx) {
                p++;
                continue;
            }

            size_t off = pos - ctx.anchor_idx;
            if(off + sig_len > data_len) {
                p++;
                continue;
            }

            if(block_size > 1 && (off & alignment_mask) != 0) {
                size_t next_aligned_off = (off + block_size) & ~alignment_mask;
                const byte *next_p = data + next_aligned_off + ctx.anchor_idx;
                p = next_p > hit + 1 ? next_p : hit + 1;
                continue;
            }

            if(sig_matches(data + off, sigbyte, mask, sig_len))
                return off;

            if(ctx.use_bmh) {
                size_t min_off = off + sigscan_bmh_shift(&ctx, data, off);
                const byte *bmh_p = data + min_off + ctx.anchor_idx;
                p = bmh_p > hit + 1 ? bmh_p : hit + 1;
            } else {
                p = hit + 1;
            }
        }
        return (size_t)-1;
    }

    for(size_t i = 0; i <= data_len - sig_len; i += block_size) {
        if(sig_matches(data + i, sigbyte, mask, sig_len))
            return i;
    }
    return (size_t)-1;
}