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

#define RELOC64_OUT_WORDS 64
#define RELOC64_SRC_WORDS 16

static void write_u32(uint32_t** p, uint32_t v) {
    **p = v;
    (*p)++;
}

static void write_u64(uint32_t** p, uint64_t v) {
    write_u32(p, (uint32_t)(v));
    write_u32(p, (uint32_t)(v >> 32));
}

static int reloc_insn(uint32_t** out, uintptr_t pc, uint32_t insn) {

    if ((insn & 0xFC000000) == 0x14000000) {
        int64_t off = (int64_t)(((uint64_t)(insn & 0x03FFFFFF) << 2) << 36) >> 36;
        uintptr_t target = pc + off;
        write_u32(out, 0x58000051);
        write_u32(out, 0xD61F0220);
        write_u64(out, target);
        return -1;
    }

    if ((insn & 0xFC000000) == 0x94000000) {
        int64_t off = (int64_t)(((uint64_t)(insn & 0x03FFFFFF) << 2) << 36) >> 36;
        uintptr_t target = pc + off;
        write_u32(out, 0x58000071);
        write_u32(out, 0xD63F0220);
        write_u64(out, target);
        return 0;
    }

    if ((insn & 0xFF000010) == 0x54000000) {
        uint32_t cond = insn & 0xF;
        int64_t off = (int64_t)(((uint64_t)((insn >> 5) & 0x7FFFF) << 2) << 43) >> 43;
        uintptr_t target = pc + off;
        write_u32(out, 0x54000000 | (cond ^ 1) | (5 << 5));
        write_u32(out, 0x58000051);
        write_u32(out, 0xD61F0220);
        write_u64(out, target);
        return 0;
    }

    if ((insn & 0x7E000000) == 0x34000000) {
        uint32_t rt = insn & 0x1F;
        uint32_t sf = insn >> 31;
        uint32_t op = (insn >> 24) & 1;
        int64_t off = (int64_t)(((uint64_t)((insn >> 5) & 0x7FFFF) << 2) << 43) >> 43;
        uintptr_t target = pc + off;
        write_u32(out, (sf << 31) | (op << 24) | 0x34000000 | (5 << 5) | rt);
        write_u32(out, 0x58000051);
        write_u32(out, 0xD61F0220);
        write_u64(out, target);
        return 0;
    }

    if ((insn & 0x7E000000) == 0x36000000) {
        uint32_t rt  = insn & 0x1F;
        uint32_t op  = (insn >> 24) & 1;
        uint32_t b40 = (insn >> 19) & 0x1F;
        uint32_t sf  = (insn >> 31) & 1;
        int64_t off  = (int64_t)(((uint64_t)((insn >> 5) & 0x3FFF) << 2) << 48) >> 48;
        uintptr_t target = pc + off;
        write_u32(out, (sf << 31) | (op << 24) | 0x36000000 | (b40 << 19) | (5 << 5) | rt);
        write_u32(out, 0x58000051);
        write_u32(out, 0xD61F0220);
        write_u64(out, target);
        return 0;
    }

    if ((insn & 0x9F000000) == 0x90000000) {
        uint32_t rd   = insn & 0x1F;
        int64_t immlo = (insn >> 29) & 0x3;
        int64_t immhi = (insn >> 5) & 0x7FFFF;
        int64_t imm   = ((immhi << 2) | immlo) << 12;
        imm = (imm << 11) >> 11;
        uintptr_t target = (pc & ~0xFFFULL) + imm;
        write_u32(out, 0x58000000 | rd | (2 << 5));
        write_u32(out, 0x14000002);
        write_u64(out, target);
        return 0;
    }

    if ((insn & 0x9F000000) == 0x10000000) {
        uint32_t rd   = insn & 0x1F;
        int64_t immlo = (insn >> 29) & 0x3;
        int64_t immhi = (insn >> 5) & 0x7FFFF;
        int64_t imm   = (immhi << 2) | immlo;
        imm = (imm << 43) >> 43;
        uintptr_t target = pc + imm;
        write_u32(out, 0x58000000 | rd | (2 << 5));
        write_u32(out, 0x14000002);
        write_u64(out, target);
        return 0;
    }

    write_u32(out, insn);
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
    for(size_t i = 0; i < count; i++) {
        uintptr_t pc = (uintptr_t)src + i * 4;
        if(reloc_insn(&op, pc, insns[i]) == -1)
            goto done;
    }
    {
        uintptr_t ret_target = (uintptr_t)src + count * 4;
        write_u32(&op, 0x58000051);
        write_u32(&op, 0xD61F0220);
        write_u64(&op, ret_target);
    }
done:
    if((size_t)(op - out) > RELOC64_OUT_WORDS)
        return false;
    return write_mem(dst, out, (size_t)(op - out) * sizeof(uint32_t));
}
