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
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>

#include "mem.h"
#include "nop.h"
#include "proc.h"
#include "inlinehook.h"

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__x86__)
#include "hook86.h"
#elif defined(__arm__) || defined (__aarch64__)
#include "armhook.h"
#include "reloc64.h"
#endif

#ifdef __aarch64__
#define AARCH64_LEGACY_HOOKBYTES_LEN 20
#define AARCH64_MICRO_HOOKBYTES_LEN  12
#define AARCH64_NANO_HOOKBYTES_LEN    4
#define MAX_BUFFERLEN AARCH64_LEGACY_HOOKBYTES_LEN

static inline uint32_t encode_adrp(int64_t offset) {
    // 32 bits signed
    if(offset <= -((int64_t)1 << 32) ||
        offset >= (((int64_t)1 << 32) - 1))
        return 0; // out of range
    // page number 4K
    int64_t page_offset = offset >> 12;
    // immlo (bits [30:29] in instruction)
    uint32_t immlo = (page_offset & 0x3) << 29;
    // extract immhi (bits [23:5] in instruction)
    uint32_t immhi = ((page_offset >> 2) & 0x7FFFF) << 5;
    // ADRP base opcode: 1 00 10000 (fixed bits)
    uint32_t base_opcode = 0x90000000;
    // assemble : base_opcode + immhi + immlo + Rd
    return base_opcode | immhi | immlo | 17;
}
static inline uint32_t encode_b(int32_t offset) {
    // 26 bits signed
    if(offset < -((int32_t)1 << 27) ||
        offset >= ((int32_t)1 << 27))
        return 0; // out of range
    // convert offset to 26-bit immediate (divide by 4)
    int32_t imm26 = (int32_t)(offset >> 2);
    // mask to 26 bits (ensures proper handling of negative values)
    uint32_t imm26_masked = (uint32_t)imm26 & 0x03FFFFFF;
    // B instruction opcode: 000101 (fixed bits)
    return 0x14000000 | imm26_masked;
}
#elif defined(__arm__)
#define ARM_LEGACY_HOOKBYTES_LEN 12
#define ARM_NANO_HOOKBYTES_LEN    4
#define MAX_BUFFERLEN ARM_LEGACY_HOOKBYTES_LEN

static inline uint32_t encode_b(int32_t offset) {
    // calculate the offset in words (divide by 4)
    int32_t word_offset = (offset - 8) >> 2;
    if (word_offset < -0x800000 || word_offset > 0x7FFFFF)
        return 0; // out of range
    // mask to 24 bits (signed)
    word_offset &= 0x00FFFFFF;
    return 0xEA000000 | word_offset;
}
#elif defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__x86__)
#define X86_HOOKBYTES_LEN 16
#define MAX_BUFFERLEN X86_HOOKBYTES_LEN

#if defined(__x86_64__) || defined(__amd64__)
#define LONGJMP_BUF_LEN
#endif

static inline size_t x86_instruction_length(const uint8_t *code, size_t max_len, int is_64bit) {
    if (!code || max_len == 0) return 0;

    size_t offset = 0;
    uint8_t byte;
    int has_66 = 0, has_67 = 0;

    // Legacy prefixes (can have multiple)
    int has_rex = 0;
    while (offset < max_len) {
        byte = code[offset];

        // REX prefix (64-bit mode only, 0x40-0x4F)
        if (is_64bit && (byte >= 0x40 && byte <= 0x4F)) {
            has_rex = 1;
            offset++;
            continue;
        }

        // Legacy prefixes
        if (byte == 0xF0 || byte == 0xF2 || byte == 0xF3 ||  // LOCK, REPNE, REP
            byte == 0x2E || byte == 0x36 || byte == 0x3E ||  // Segment overrides
            byte == 0x26 || byte == 0x64 || byte == 0x65) {
            offset++;
        continue;
            }

            if (byte == 0x66) { has_66 = 1; offset++; continue; }  // Operand size
            if (byte == 0x67) { has_67 = 1; offset++; continue; }  // Address size

            break;
    }

    if (offset >= max_len) return 0;

    // Read opcode
    byte = code[offset++];
    uint8_t opcode = byte;

    // Two-byte opcode (0x0F escape)
    int two_byte = 0;
    int three_byte = 0;
    if (byte == 0x0F) {
        if (offset >= max_len) return 0;
        two_byte = 1;
        byte = code[offset++];
        opcode = byte;

        // Three-byte opcode (0x0F 0x38 or 0x0F 0x3A)
        if (byte == 0x38 || byte == 0x3A) {
            if (offset >= max_len) return 0;
            three_byte = 1;
            byte = code[offset++];
            opcode = byte;
        }
    }

    // Determine if we need ModR/M byte
    int has_modrm = 0;
    int imm_size = 0;  // Size of immediate value

    if (three_byte) {
        has_modrm = 1;  // Three-byte opcodes typically have ModR/M
    } else if (two_byte) {
        // Most two-byte opcodes have ModR/M, except some special ones
        if (opcode == 0x01 || opcode == 0x02 || opcode == 0x05 ||
            opcode == 0x06 || opcode == 0x08 || opcode == 0x09 ||
            opcode == 0x0B || opcode == 0x30 || opcode == 0x31 ||
            opcode == 0x32 || opcode == 0x33 || opcode == 0x34 ||
            opcode == 0xA0 || opcode == 0xA1 || opcode == 0xA8 ||
            opcode == 0xA9 || opcode == 0xC8 || opcode == 0xC9) {
            has_modrm = 0;
            } else {
                has_modrm = 1;
            }

            // Handle immediates for two-byte opcodes
            if ((opcode >= 0x80 && opcode <= 0x8F) ||  // Jcc near
                opcode == 0xA4 || opcode == 0xAC ||     // shld/shrd with imm8
                opcode == 0xBA) {                        // bt/bts/btr/btc with imm8
                    if (opcode >= 0x80 && opcode <= 0x8F) {
                        imm_size = 4;  // 32-bit displacement for conditional jumps
                    } else {
                        imm_size = 1;  // imm8
                    }
                }
    } else {
        // One-byte opcodes
        // Opcodes that have ModR/M
        if ((opcode >= 0x00 && opcode <= 0x03) || (opcode >= 0x08 && opcode <= 0x0B) ||
            (opcode >= 0x10 && opcode <= 0x13) || (opcode >= 0x18 && opcode <= 0x1B) ||
            (opcode >= 0x20 && opcode <= 0x23) || (opcode >= 0x28 && opcode <= 0x2B) ||
            (opcode >= 0x30 && opcode <= 0x33) || (opcode >= 0x38 && opcode <= 0x3B) ||
            (opcode >= 0x62 && opcode <= 0x63) || (opcode >= 0x80 && opcode <= 0x8F) ||
            (opcode >= 0xC0 && opcode <= 0xC1) || (opcode >= 0xC4 && opcode <= 0xC7) ||
            (opcode >= 0xD0 && opcode <= 0xD3) || (opcode >= 0xF6 && opcode <= 0xF7) ||
            (opcode >= 0xFE && opcode <= 0xFF) || opcode == 0x69 || opcode == 0x6B) {
            has_modrm = 1;
            }

            // Immediate size determination for one-byte opcodes
            if (opcode >= 0xB0 && opcode <= 0xB7) {
                imm_size = 1;  // MOV reg8, imm8
            } else if (opcode >= 0xB8 && opcode <= 0xBF) {
                imm_size = is_64bit ? 8 : 4;  // MOV reg, imm (can be 64-bit in 64-bit mode with REX.W)
                if (has_rex && is_64bit) {
                    // Check REX.W bit - but we'd need to track the actual REX byte
                    // For simplicity, assume 64-bit if REX is present
                    imm_size = 8;
                } else if (has_66) {
                    imm_size = 2;  // 16-bit operand size
                } else {
                    imm_size = 4;  // 32-bit default
                }
            } else if (opcode == 0xE8 || opcode == 0xE9) {
                imm_size = 4;  // CALL/JMP near (rel32)
            } else if (opcode == 0xEB || opcode == 0x70 || opcode == 0x71 ||
                opcode == 0x72 || opcode == 0x73 || opcode == 0x74 ||
                opcode == 0x75 || opcode == 0x76 || opcode == 0x77 ||
                opcode == 0x78 || opcode == 0x79 || opcode == 0x7A ||
                opcode == 0x7B || opcode == 0x7C || opcode == 0x7D ||
                opcode == 0x7E || opcode == 0x7F || opcode == 0xE0 ||
                opcode == 0xE1 || opcode == 0xE2 || opcode == 0xE3) {
                imm_size = 1;  // Short jumps/loops (rel8)
                } else if (opcode == 0xC2 || opcode == 0xCA) {
                    imm_size = 2;  // RET imm16
                } else if (opcode == 0x6A || opcode == 0xCD) {
                    imm_size = 1;  // PUSH imm8, INT imm8
                } else if (opcode == 0x68) {
                    imm_size = has_66 ? 2 : 4;  // PUSH imm16/imm32
                } else if (opcode == 0xA0 || opcode == 0xA1 || opcode == 0xA2 || opcode == 0xA3) {
                    // MOV moffs (direct memory offset)
                    imm_size = (is_64bit && !has_67) ? 8 : 4;
                } else if (opcode == 0x04 || opcode == 0x0C || opcode == 0x14 ||
                    opcode == 0x1C || opcode == 0x24 || opcode == 0x2C ||
                    opcode == 0x34 || opcode == 0x3C) {
                    imm_size = 1;  // ALU ops with AL, imm8
                    } else if (opcode == 0x05 || opcode == 0x0D || opcode == 0x15 ||
                        opcode == 0x1D || opcode == 0x25 || opcode == 0x2D ||
                        opcode == 0x35 || opcode == 0x3D) {
                        imm_size = has_66 ? 2 : 4;  // ALU ops with AX/EAX, imm16/imm32
                        }

                        // Group opcodes with ModR/M that also have immediates
                        if (has_modrm) {
                            if (opcode == 0x80 || opcode == 0x82 || opcode == 0xC6) {
                                imm_size = 1;  // Group 1/11 with imm8
                            } else if (opcode == 0x81 || opcode == 0xC7) {
                                imm_size = has_66 ? 2 : 4;  // Group 1/11 with imm16/imm32
                            } else if (opcode == 0x83) {
                                imm_size = 1;  // Group 1 with imm8 (sign-extended)
                            } else if (opcode == 0x69) {
                                imm_size = has_66 ? 2 : 4;  // IMUL with imm16/imm32
                            } else if (opcode == 0x6B) {
                                imm_size = 1;  // IMUL with imm8
                            } else if (opcode == 0xC0 || opcode == 0xC1) {
                                imm_size = 1;  // Shift/rotate with imm8
                            }
                        }
    }

    // Parse ModR/M and SIB if present
    if (has_modrm) {
        if (offset >= max_len) return 0;
        uint8_t modrm = code[offset++];

        uint8_t mod = (modrm >> 6) & 0x3;
        uint8_t rm = modrm & 0x7;

        // Check if SIB byte is present
        if (mod != 3 && rm == 4) {
            if (offset >= max_len) return 0;
            uint8_t sib = code[offset++];
            uint8_t base = sib & 0x7;

            // Special case: SIB with base=5 and mod=0 means disp32
            if (mod == 0 && base == 5) {
                offset += 4;  // disp32
            } else if (mod == 1) {
                offset += 1;  // disp8
            } else if (mod == 2) {
                offset += 4;  // disp32
            }
        } else {
            // Displacement based on mod
            if (mod == 1) {
                offset += 1;  // disp8
            } else if (mod == 2) {
                offset += 4;  // disp32
            } else if (mod == 0 && rm == 5) {
                offset += 4;  // disp32 (RIP-relative in 64-bit)
            }
        }
    }

    // Add immediate bytes
    offset += imm_size;

    if (offset > max_len) return 0;

    return offset;
}

#endif

GPWNAPI hook_handle* hook_addr(void *address, void *fake, void **original_func, int flags) {
    hook_handle *handle = malloc(sizeof(hook_handle));
    if(!handle) {
        // perror("malloc() failed.");
        return 0;
    }
    handle->address = address;
    handle->fake = fake;
    handle->flags = 0;
    handle->rbyte_len = MAX_BUFFERLEN;
    size_t page_size = (size_t) sysconf(_SC_PAGESIZE);
    void *aligned_addr = (void*) ((uintptr_t) address & ~(page_size - 1));
    // allocate the trampoline
    handle->trampoline_addr = mmap_near(aligned_addr, page_size, PROT_EXEC | PROT_READ | PROT_WRITE);
    if(handle->trampoline_addr == MAP_FAILED) {
        // perror("mmap() failed.");
        free(handle);
        return 0;
    }
    // read the bytes
    uint8_t mem_buffer[MAX_BUFFERLEN];
    if(!read_mem(mem_buffer, address, MAX_BUFFERLEN)) {
        // fputs("read_mem() failed.\n", stderr);
        munmap(handle->trampoline_addr, page_size);
        free(handle);
        return 0;
    }
#ifdef __aarch64__
    if(
        (handle->trampoline_addr - address) >= -(1 << 27) &&
        (handle->trampoline_addr - address) < ((1 << 27) - 1) &&
        (!flags || (flags & GPWN_AARCH64_NANOHOOK) == GPWN_AARCH64_NANOHOOK)
    ) {
        // nano hook
        if(!arm64_detour((uintptr_t) handle->trampoline_addr, (uintptr_t) fake,
                AARCH64_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm64_detour() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!write_mem(handle->trampoline_addr + AARCH64_LEGACY_HOOKBYTES_LEN,
                mem_buffer, AARCH64_NANO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!arm64_detour( (uintptr_t)(handle->trampoline_addr +
                AARCH64_LEGACY_HOOKBYTES_LEN + AARCH64_NANO_HOOKBYTES_LEN),
            (uintptr_t) (address + AARCH64_NANO_HOOKBYTES_LEN),
            AARCH64_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm64_detour() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        uint32_t b_opcode = encode_b(handle->trampoline_addr - address);
        if(!write_mem(address, &b_opcode, 4)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        handle->flags |= GPWN_AARCH64_NANOHOOK;
        *original_func = handle->trampoline_addr + AARCH64_LEGACY_HOOKBYTES_LEN;
        return handle;
    }
    if (
        (handle->trampoline_addr - address) >= -((int64_t)1 << 32) &&
        (handle->trampoline_addr - address) < (((int64_t)1 << 32) - 1) &&
        !flags || (flags & GPWN_AARCH64_MICROHOOK) == GPWN_AARCH64_MICROHOOK
    ) {
        // micro hook
        uint32_t hook_bytes[3];
        hook_bytes[0] = encode_adrp(((int64_t)handle->trampoline_addr & ~((int64_t)0xfff))
        - ((int64_t) address &  ~((int64_t)0xfff)));
        hook_bytes[1] = 0xf9400231;
        hook_bytes[2] = 0xd61f0220;
        if(!write_mem(handle->trampoline_addr, &fake, 8)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!write_mem(handle->trampoline_addr + 8, mem_buffer,
                AARCH64_MICRO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!arm64_detour(
            (uintptr_t) (handle->trampoline_addr + 8 + AARCH64_MICRO_HOOKBYTES_LEN),
            (uintptr_t) (address + AARCH64_MICRO_HOOKBYTES_LEN),
            AARCH64_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm64_detour() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!write_mem(address, &hook_bytes, AARCH64_MICRO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        handle->flags |= GPWN_AARCH64_MICROHOOK;
        *original_func = handle->trampoline_addr + 8;
        return handle;
    }
    if ((!flags || (flags & GPWN_AARCH64_LEGACYHOOK) == GPWN_AARCH64_LEGACYHOOK)) {
        relocate_prologue(
            handle->trampoline_addr,
            address,
            AARCH64_LEGACY_HOOKBYTES_LEN / 4
        );
        mprotect(handle->trampoline_addr, page_size, PROT_EXEC | PROT_READ);
        __builtin___clear_cache(
            (char*)handle->trampoline_addr,
            (char*)handle->trampoline_addr + page_size
        );
        if (!arm64_detour((uintptr_t)address,
                (uintptr_t)fake, AARCH64_LEGACY_HOOKBYTES_LEN)) {
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
                }
        handle->flags |= GPWN_AARCH64_LEGACYHOOK;
        *original_func = handle->trampoline_addr;
        return handle;
    }
#elif defined(__arm__)
    if(
        (handle->trampoline_addr - address) >= -(1 << 27) &&
        (handle->trampoline_addr - address) < ((1 << 27) - 1) &&
        (!flags || (flags & GPWN_ARM_NANOHOOK) == GPWN_ARM_NANOHOOK)
    ) {
        // nano hook
        if(!arm32_detour((uintptr_t) handle->trampoline_addr, (uintptr_t) fake,
                ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm32_detour() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!write_mem(handle->trampoline_addr + ARM_LEGACY_HOOKBYTES_LEN,
                mem_buffer, ARM_NANO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if (!arm32_detour((uintptr_t)(handle->trampoline_addr +
                ARM_LEGACY_HOOKBYTES_LEN + ARM_NANO_HOOKBYTES_LEN),
                (uintptr_t)(address + ARM_NANO_HOOKBYTES_LEN),
                ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm32_detour() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        uint32_t b_opcode = encode_b(handle->trampoline_addr - address);
        if(!write_mem(address, &b_opcode, 4)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        handle->flags |= GPWN_ARM_NANOHOOK;
        *original_func = handle->trampoline_addr + ARM_LEGACY_HOOKBYTES_LEN;
        return handle;
    }
    if ((!flags || (flags & GPWN_ARM_LEGACYHOOK) == GPWN_ARM_LEGACYHOOK)) {
        if(!write_mem(handle->trampoline_addr,
                mem_buffer, ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if (!arm32_detour(
                (uintptr_t)handle->trampoline_addr + ARM_LEGACY_HOOKBYTES_LEN,
                (uintptr_t)address + ARM_LEGACY_HOOKBYTES_LEN,
                ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm32_detour() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if (!arm32_detour((uintptr_t)address, (uintptr_t)fake,
                ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm32_detour() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        handle->flags |= GPWN_ARM_LEGACYHOOK;
        *original_func = handle->trampoline_addr;
        return handle;
    }
#elif defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__x86__)
    size_t inst_len = 0;
    if(
        (address - handle->trampoline_addr >  2147483647) ||
        (address - handle->trampoline_addr < -2147483648)
    ) {
        // fputs("memory isn't in range, hook failed.\n", stderr);
        munmap(handle->trampoline_addr, page_size);
        free(handle);
        return 0;
    }
    if(
        (fake - address - 5 < (intptr_t)  2147483647) &&
        (fake - address - 5 > (intptr_t) -2147483648)
    ) {
        // in range for short hook
        do {
#if defined(__x86_64__) || defined(__amd64__)
            inst_len += x86_instruction_length(mem_buffer + inst_len, MAX_BUFFERLEN, 1);
#else
            inst_len += x86_instruction_length(mem_buffer + inst_len, MAX_BUFFERLEN, 0);
#endif
        } while(inst_len < 5);
        handle->rbyte_len = inst_len; // override

        handle->flags = GPWN_X86_SHORTHOOK;
        if(!write_mem((void*) handle->trampoline_addr, (void*) mem_buffer, inst_len)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!hook_x86((void*) (handle->trampoline_addr + inst_len), (void*) (address + inst_len), 5)) {
            // fputs("hook_x86() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!hook_x86(address, fake, inst_len)) {
            // fputs("hook_x86() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        *original_func = handle->trampoline_addr;
        return handle;
    }
#if defined(__x86_64__) || defined(__amd64__)
    else {
        // use longhook
        do {
            inst_len += x86_instruction_length(mem_buffer + inst_len, MAX_BUFFERLEN, 1);
        } while(inst_len < 6);
        handle->rbyte_len = inst_len; // override

        handle->flags = GPWN_X86_64_LONGHOOK;
        if(!write_mem(handle->trampoline_addr, (void*) &fake, sizeof(void*))) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!write_mem(handle->trampoline_addr+sizeof(void*), mem_buffer, inst_len)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!hook_x86(handle->trampoline_addr+sizeof(void*)+inst_len, address+inst_len, 5)) {
            // fputs("hook_x86() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        // custom hook
        uint8_t jmprel[6] = {0xFF, 0x25, 0, 0, 0, 0};
        *(int32_t*)(jmprel+2) = (uintptr_t) (handle->trampoline_addr) - (uintptr_t)(address + 6);
        patch_nop(address, inst_len);
        write_mem(address, jmprel, sizeof(jmprel));
        *original_func = handle->trampoline_addr + sizeof(void*);
        return handle;
    }
#endif
#endif
    munmap(handle->trampoline_addr, page_size);
    free(handle);
    return 0;
}

GPWNAPI bool rm_hook(hook_handle *handle) {
    if(!handle) {
        return 0;
    }
    uint8_t mem_buffer[MAX_BUFFERLEN];
#ifdef __aarch64__
    if((handle->flags & GPWN_AARCH64_NANOHOOK) == GPWN_AARCH64_NANOHOOK) {
        if(!read_mem(mem_buffer,
            handle->trampoline_addr + AARCH64_LEGACY_HOOKBYTES_LEN,
            AARCH64_NANO_HOOKBYTES_LEN)) {
            // fputs("read_mem() failed.\n", stderr);
            return 0;
        }
        if(!write_mem(handle->address, mem_buffer, AARCH64_NANO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            return 0;
        }
    }
    else if((handle->flags & GPWN_AARCH64_MICROHOOK) == GPWN_AARCH64_MICROHOOK) {
        if(!read_mem(mem_buffer, handle->trampoline_addr + 8, AARCH64_MICRO_HOOKBYTES_LEN)) {
            // fputs("read_mem() failed.\n", stderr);
            return 0;
        }
        if(!write_mem(handle->address, mem_buffer, AARCH64_MICRO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            return 0;
        }
    }
    else if((handle->flags & GPWN_AARCH64_LEGACYHOOK) == GPWN_AARCH64_LEGACYHOOK) {
        if(!read_mem(mem_buffer, handle->trampoline_addr, AARCH64_LEGACY_HOOKBYTES_LEN)) {
            // fputs("read_mem() failed.\n", stderr);
            return 0;
        }
        if(!write_mem(handle->address, mem_buffer, AARCH64_LEGACY_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            return 0;
        }
    }
#elif defined(__arm__)
    if((handle->flags & GPWN_ARM_NANOHOOK) == GPWN_ARM_NANOHOOK) {
        if(!read_mem(mem_buffer,
            handle->trampoline_addr + ARM_LEGACY_HOOKBYTES_LEN,
            ARM_NANO_HOOKBYTES_LEN)) {
            // fputs("read_mem() failed.\n", stderr);
            return 0;
        }
        if(!write_mem(handle->address, mem_buffer, ARM_NANO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            return 0;
        }
    }
    else if((handle->flags & GPWN_ARM_LEGACYHOOK) == GPWN_ARM_LEGACYHOOK) {
        if(!read_mem(mem_buffer, handle->trampoline_addr, ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("read_mem() failed.\n", stderr);
            return 0;
        }
        if(!write_mem(handle->address, mem_buffer, ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            return 0;
        }
    }
#elif defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__x86__)
    if(handle->flags == GPWN_X86_SHORTHOOK) {
        if(!read_mem(mem_buffer, handle->trampoline_addr, handle->rbyte_len)) {
            // fputs("read_mem() failed.\n", stderr);
            return 0;
        }
        if(!write_mem(handle->address, mem_buffer, handle->rbyte_len)) {
            // fputs("write_mem() failed.\n", stderr);
            return 0;
        }
    }
#if defined(__x86_64__) || defined(__amd64__)
    if(handle->flags == GPWN_X86_64_LONGHOOK) {
        if(!read_mem(mem_buffer, handle->trampoline_addr + sizeof(void*), handle->rbyte_len)) {
            // fputs("read_mem() failed.\n", stderr);
            return 0;
        }
        if(!write_mem(handle->address, mem_buffer, handle->rbyte_len)) {
            // fputs("write_mem() failed.\n", stderr);
            return 0;
        }
    }
#endif
#endif
    munmap(handle->trampoline_addr, sysconf(_SC_PAGESIZE));
    free(handle);
    return 1;
}
