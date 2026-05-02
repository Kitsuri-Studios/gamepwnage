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

static void write_u32(uint32_t** p, uint32_t v) {
    **p = v;
    (*p)++;
}

static void write_u64(uint32_t** p, uint64_t v) {
    write_u32(p, (uint32_t)(v));
    write_u32(p, (uint32_t)(v >> 32));
}

// returns -1 if terminator (unconditional branch), 0 otherwise
static int reloc_insn(uint32_t** out, uintptr_t pc, uint32_t insn) {

    // B (unconditional) - terminator
    if ((insn & 0xFC000000) == 0x14000000) {
        int64_t off = (int64_t)(((uint64_t)(insn & 0x03FFFFFF) << 2) << 36) >> 36;
        uintptr_t target = pc + off;
        write_u32(out, 0x58000051); // LDR x17, #8
        write_u32(out, 0xD61F0220); // BR x17
        write_u64(out, target);
        return -1;
    }

    // BL
    if ((insn & 0xFC000000) == 0x94000000) {
        int64_t off = (int64_t)(((uint64_t)(insn & 0x03FFFFFF) << 2) << 36) >> 36;
        uintptr_t target = pc + off;
        write_u32(out, 0x58000071); // LDR x17, #8 (x17 for BLR)
        write_u32(out, 0xD63F0220); // BLR x17
        write_u64(out, target);
        return 0;
    }

    // B.cond
    if ((insn & 0xFF000010) == 0x54000000) {
        uint32_t cond = insn & 0xF;
        int64_t off = (int64_t)(((uint64_t)((insn >> 5) & 0x7FFFF) << 2) << 43) >> 43;
        uintptr_t target = pc + off;
        // B.invcond +20 (5 words forward, skips LDR+BR+u64)
        write_u32(out, 0x54000000 | (cond ^ 1) | (5 << 5));
        write_u32(out, 0x58000051); // LDR x17, #8
        write_u32(out, 0xD61F0220); // BR x17
        write_u64(out, target);
        return 0;
    }

    // CBZ / CBNZ
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

    // TBZ / TBNZ
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

    // ADRP
    if ((insn & 0x9F000000) == 0x90000000) {
        uint32_t rd   = insn & 0x1F;
        int64_t immlo = (insn >> 29) & 0x3;
        int64_t immhi = (insn >> 5) & 0x7FFFF;
        int64_t imm   = ((immhi << 2) | immlo) << 12;
        imm = (imm << 11) >> 11; // sign extend 33 bits
        uintptr_t target = (pc & ~0xFFFULL) + imm;
        write_u32(out, 0x58000000 | rd | (2 << 5)); // LDR rd, #8
        write_u32(out, 0x14000002);                  // B +8 (skip literal)
        write_u64(out, target);
        return 0;
    }

    // ADR
    if ((insn & 0x9F000000) == 0x10000000) {
        uint32_t rd   = insn & 0x1F;
        int64_t immlo = (insn >> 29) & 0x3;
        int64_t immhi = (insn >> 5) & 0x7FFFF;
        int64_t imm   = (immhi << 2) | immlo;
        imm = (imm << 43) >> 43; // sign extend 21 bits
        uintptr_t target = pc + imm;
        write_u32(out, 0x58000000 | rd | (2 << 5));
        write_u32(out, 0x14000002);
        write_u64(out, target);
        return 0;
    }

    // everything else: copy as-is
    write_u32(out, insn);
    return 0;
}

// dst must have at least count*5 + 4 words of space
static void relocate_prologue(void* dst, void* src, size_t count) {
    uint32_t* out = (uint32_t*)dst;
    for (size_t i = 0; i < count; i++) {
        uintptr_t pc   = (uintptr_t)src + i * 4;
        uint32_t  insn = ((uint32_t*)src)[i];
        if (reloc_insn(&out, pc, insn) == -1)
            return;
    }
    // tail jump back to original after stolen bytes
    uintptr_t ret_target = (uintptr_t)src + count * 4;
    write_u32(&out, 0x58000051); // LDR x17, #8
    write_u32(&out, 0xD61F0220); // BR x17
    write_u64(&out, ret_target);
}