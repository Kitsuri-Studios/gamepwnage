/*
gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "mem.h"

#define RELOC64_OUT_WORDS 128 /* relocated insn buffer */
#define RELOC64_SRC_WORDS 32  /* max src instructions */

static inline int64_t reloc_signext(uint64_t val, unsigned bits) {
    uint64_t m = 1ULL << (bits - 1);
    return (int64_t)((val ^ m) - m);
}

static inline bool reloc_emit_u32(uint32_t** op, uint32_t* end, uint32_t v) {
    if(*op >= end)
        return false;
    **op = v;
    (*op)++;
    return true;
}

static inline bool reloc_emit_u64(uint32_t** op, uint32_t* end, uint64_t v) {
    return reloc_emit_u32(op, end, (uint32_t)v)
        && reloc_emit_u32(op, end, (uint32_t)(v >> 32));
}

static inline bool reloc_emit_ldr_u64(uint32_t** op, uint32_t* end, unsigned reg,
    uint64_t value) {
    if(!reloc_emit_u32(op, end, 0x58000000u | (reg & 0x1fu) | (2u << 5)))
        return false;
    if(!reloc_emit_u32(op, end, 0x14000002u))
        return false;
    return reloc_emit_u64(op, end, value);
}

static inline bool reloc_emit_branch_abs(uint32_t** op, uint32_t* end,
    uintptr_t target, int with_link) {
    unsigned reg = 17u;
    if(!reloc_emit_ldr_u64(op, end, reg, (uint64_t)target))
        return false;
    return reloc_emit_u32(op, end, with_link ? 0xd63f0220u : 0xd61f0220u);
}

static inline bool reloc_emit_cond_branch_abs(uint32_t** op, uint32_t* end,
    uint32_t insn, uintptr_t target) {
    uint32_t cond = insn & 0xfu;
    int64_t off = reloc_signext((uint64_t)((insn >> 5) & 0x7ffffu) << 2, 21);
    if(!reloc_emit_u32(op, end, 0x54000000u | (cond ^ 1u) | (5u << 5)))
        return false;
    return reloc_emit_branch_abs(op, end, target, 0);
}

static inline bool reloc_emit_literal_load(uint32_t** op, uint32_t* end,
    uint32_t insn, uintptr_t pool_addr) {
    uint32_t rd = insn & 0x1fu;
    uint32_t opc = (insn >> 30) & 3u;
    uint32_t ldr;
    if(opc == 3u)
        return reloc_emit_u32(op, end, 0xd503201fu);
    if(opc == 0u)
        ldr = 0x18000000u | rd | (2u << 5);
    else if(opc == 1u)
        ldr = 0x58000000u | rd | (2u << 5);
    else
        ldr = 0x98000000u | rd | (2u << 5);
    if(!reloc_emit_u32(op, end, ldr))
        return false;
    if(!reloc_emit_u32(op, end, 0x14000002u))
        return false;
    return reloc_emit_u64(op, end, (uint64_t)pool_addr);
}

/* min-max byte steal; extends past trailing adrp */
static inline size_t aarch64_steal_byte_count(const uint32_t *insns, size_t insn_words,
    size_t min_bytes, size_t max_bytes) {
    if(!insns || min_bytes == 0 || max_bytes < min_bytes
        || (min_bytes & 3u) || (max_bytes & 3u))
        return 0;
    size_t max_n = max_bytes / 4u;
    if(insn_words < max_n)
        max_n = insn_words;
    size_t n = 0;
    while(n < max_n) {
        n++;
        if(n * 4u >= min_bytes) {
            uint32_t last = insns[n - 1u];
            if((last & 0x9f000000u) != 0x90000000u)
                break;
        }
    }
    if(n * 4u < min_bytes)
        return 0;
    return n * 4u;
}

static inline bool aarch64_insn_is_pc_relative(uint32_t insn) {
    if((insn & 0xfc000000u) == 0x14000000u)
        return true;
    if((insn & 0xfc000000u) == 0x94000000u)
        return true;
    if((insn & 0xff000010u) == 0x54000000u)
        return true;
    if((insn & 0xff000010u) == 0x56000000u)
        return true;
    if((insn & 0x7e000000u) == 0x34000000u)
        return true;
    if((insn & 0x7e000000u) == 0x36000000u)
        return true;
    if((insn & 0x9f000000u) == 0x90000000u)
        return true;
    if((insn & 0x9f000000u) == 0x10000000u)
        return true;
    if((insn & 0x3b000000u) == 0x18000000u)
        return true;
    return false;
}

static int reloc_insn(uint32_t** op, uint32_t* end, uintptr_t pc, uint32_t insn) {

    if((insn & 0xfc000000u) == 0x14000000u) {
        int64_t off = reloc_signext((uint64_t)(insn & 0x03ffffffu) << 2, 28);
        if(!reloc_emit_branch_abs(op, end, (uintptr_t)((int64_t)pc + off), 0))
            return 1;
        return -1;
    }

    if((insn & 0xfc000000u) == 0x94000000u) {
        int64_t off = reloc_signext((uint64_t)(insn & 0x03ffffffu) << 2, 28);
        if(!reloc_emit_branch_abs(op, end, (uintptr_t)((int64_t)pc + off), 1))
            return 1;
        return 0;
    }

    if((insn & 0xff000010u) == 0x54000000u) {
        int64_t off = reloc_signext((uint64_t)((insn >> 5) & 0x7ffffu) << 2, 21);
        if(!reloc_emit_cond_branch_abs(op, end, insn, (uintptr_t)((int64_t)pc + off)))
            return 1;
        return 0;
    }

    if((insn & 0xff000010u) == 0x56000000u) {
        int64_t off = reloc_signext((uint64_t)((insn >> 5) & 0x7ffffu) << 2, 21);
        if(!reloc_emit_cond_branch_abs(op, end, insn, (uintptr_t)((int64_t)pc + off)))
            return 1;
        return 0;
    }

    if((insn & 0x7e000000u) == 0x34000000u) {
        uint32_t rt = insn & 0x1fu;
        uint32_t sf = insn >> 31;
        uint32_t cb_op = (insn >> 24) & 1u;
        int64_t off = reloc_signext((uint64_t)((insn >> 5) & 0x7ffffu) << 2, 21);
        uintptr_t target = (uintptr_t)((int64_t)pc + off);
        if(!reloc_emit_u32(op, end, (sf << 31) | ((cb_op ^ 1u) << 24) | 0x34000000u | (5u << 5) | rt))
            return 1;
        if(!reloc_emit_branch_abs(op, end, target, 0))
            return 1;
        return 0;
    }

    if((insn & 0x7e000000u) == 0x36000000u) {
        uint32_t rt = insn & 0x1fu;
        uint32_t tb_op = (insn >> 24) & 1u;
        uint32_t b40 = (insn >> 19) & 0x1fu;
        uint32_t sf = (insn >> 31) & 1u;
        int64_t off = reloc_signext((uint64_t)((insn >> 5) & 0x3fffu) << 2, 16);
        uintptr_t target = (uintptr_t)((int64_t)pc + off);
        if(!reloc_emit_u32(op, end, (sf << 31) | ((tb_op ^ 1u) << 24) | 0x36000000u | (b40 << 19) | (5u << 5) | rt))
            return 1;
        if(!reloc_emit_branch_abs(op, end, target, 0))
            return 1;
        return 0;
    }

    if((insn & 0x9f000000u) == 0x90000000u) {
        uint32_t rd = insn & 0x1fu;
        int64_t immlo = (insn >> 29) & 0x3;
        int64_t immhi = (insn >> 5) & 0x7ffff;
        int64_t imm = reloc_signext((uint64_t)((immhi << 2) | immlo) << 12, 33);
        uintptr_t target = (uintptr_t)((pc & ~0xfffull) + (uint64_t)imm);
        if(!reloc_emit_ldr_u64(op, end, rd, (uint64_t)target))
            return 1;
        return 0;
    }

    if((insn & 0x9f000000u) == 0x10000000u) {
        uint32_t rd = insn & 0x1fu;
        int64_t immlo = (insn >> 29) & 0x3;
        int64_t immhi = (insn >> 5) & 0x7ffff;
        int64_t imm = reloc_signext((uint64_t)((immhi << 2) | immlo), 21);
        uintptr_t target = (uintptr_t)((int64_t)pc + imm);
        if(!reloc_emit_ldr_u64(op, end, rd, (uint64_t)target))
            return 1;
        return 0;
    }

    if((insn & 0x3b000000u) == 0x18000000u) {
        int64_t off = reloc_signext((uint64_t)((insn >> 5) & 0x7ffffu) << 2, 21);
        uintptr_t pool = (uintptr_t)((pc & ~3ull) + (uint64_t)off);
        if(!reloc_emit_literal_load(op, end, insn, pool))
            return 1;
        return 0;
    }

    if(!reloc_emit_u32(op, end, insn))
        return 1;
    return 0;
}

static bool relocate_prologue(void* dst, void* src, size_t count) {
    if(!count || count > RELOC64_SRC_WORDS)
        return false;
    uint32_t insns[RELOC64_SRC_WORDS];
    if(!read_mem(insns, src, count * sizeof(uint32_t)))
        return false;
    uint32_t out[RELOC64_OUT_WORDS];
    uint32_t* op = out;
    uint32_t* const oend = out + RELOC64_OUT_WORDS;
    for(size_t i = 0; i < count; i++) {
        uintptr_t pc = (uintptr_t)src + i * 4;
        int r = reloc_insn(&op, oend, pc, insns[i]);
        if(r == 1)
            return false;
        if(r == -1)
            goto done;
    }
    {
        uintptr_t ret_target = (uintptr_t)src + count * 4;
        if(!reloc_emit_branch_abs(&op, oend, ret_target, 0))
            return false;
    }
done:
    return write_mem(dst, out, (size_t)(op - out) * sizeof(uint32_t));
}
