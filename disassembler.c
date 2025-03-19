/*
 * Copyright 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

#include "next/apf_defs.h"
#include "next/apf.h"
#include "disassembler.h"

// If "c" is of a signed type, generate a compile warning that gets promoted to an error.
// This makes bounds checking simpler because ">= 0" can be avoided. Otherwise adding
// superfluous ">= 0" with unsigned expressions generates compile warnings.
#define ENFORCE_UNSIGNED(c) ((c)==(uint32_t)(c))

char prefix_buf[16];
char print_buf[8196];
char* buf_ptr;
int buf_remain;
bool v6_mode = false;

__attribute__ ((format (printf, 1, 2) ))
static void bprintf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buf_ptr, buf_remain, format, args);
    va_end(args);
    if (ret < 0) return;
    if (ret >= buf_remain) ret = buf_remain;
    buf_ptr += ret;
    buf_remain -= ret;
}

static void print_opcode(const char* opcode) {
    bprintf("%-12s", opcode);
}

// Mapping from opcode number to opcode name.
static const char* opcode_names [] = {
    [LDB_OPCODE] = "ldb",
    [LDH_OPCODE] = "ldh",
    [LDW_OPCODE] = "ldw",
    [LDBX_OPCODE] = "ldbx",
    [LDHX_OPCODE] = "ldhx",
    [LDWX_OPCODE] = "ldwx",
    [ADD_OPCODE] = "add",
    [MUL_OPCODE] = "mul",
    [DIV_OPCODE] = "div",
    [AND_OPCODE] = "and",
    [OR_OPCODE] = "or",
    [SH_OPCODE] = "sh",
    [LI_OPCODE] = "li",
    [JMP_OPCODE] = "jmp",
    [JEQ_OPCODE] = "jeq",
    [JNE_OPCODE] = "jne",
    [JGT_OPCODE] = "jgt",
    [JLT_OPCODE] = "jlt",
    [JSET_OPCODE] = "jset",
    [JBSMATCH_OPCODE] = NULL,
    [LDDW_OPCODE] = "lddw",
    [STDW_OPCODE] = "stdw",
    [WRITE_OPCODE] = "write",
    [JNSET_OPCODE] = "jnset",
};

static void print_jump_target(uint32_t target, uint32_t program_len) {
    if (target == program_len) {
        bprintf("PASS");
    } else if (target == program_len + 1) {
        bprintf("DROP");
    } else if (target > program_len + 1) {
        uint32_t ofs = target - program_len;
        uint32_t imm = ofs >> 1;
        bprintf((ofs & 1) ? "cnt_and_drop" : "cnt_and_pass");
        bprintf("[cnt=%d]", imm);
    } else {
        bprintf("%u", target);
    }
}

static void print_qtype(int qtype) {
    switch(qtype) {
        case 1:
            bprintf("A, ");
            break;
        case 28:
            bprintf("AAAA, ");
            break;
        case 12:
            bprintf("PTR, ");
            break;
        case 33:
            bprintf("SRV, ");
            break;
        case 16:
            bprintf("TXT, ");
            break;
        default:
            bprintf("%d, ", qtype);
    }
}

disas_ret apf_disassemble(const uint8_t* program, uint32_t program_len, uint32_t* const ptr2pc, bool is_v6) {
    buf_ptr = print_buf;
    buf_remain = sizeof(print_buf);
    if (*ptr2pc > program_len + 1) {
        snprintf(prefix_buf, sizeof(prefix_buf), "(%4u) ", 0);
        bprintf("pc is overflow: pc %d, program_len: %d", *ptr2pc, program_len);
        disas_ret ret = {
            .prefix = prefix_buf,
            .content = print_buf
        };
        return ret;
    }
    uint32_t prev_pc = *ptr2pc;

    bprintf("%4u: ", *ptr2pc);

    if (*ptr2pc == program_len) {
        snprintf(prefix_buf, sizeof(prefix_buf), "(%4u) ", 0);
        bprintf("PASS");
        ++(*ptr2pc);
        disas_ret ret = {
            .prefix = prefix_buf,
            .content = print_buf
        };
        return ret;
    }

    if (*ptr2pc == program_len + 1) {
        snprintf(prefix_buf, sizeof(prefix_buf), "(%4u) ", 0);
        bprintf("DROP");
        ++(*ptr2pc);
        disas_ret ret = {
            .prefix = prefix_buf,
            .content = print_buf
        };
        return ret;
    }

    const uint8_t bytecode = program[(*ptr2pc)++];
    const uint32_t opcode = EXTRACT_OPCODE(bytecode);

#define PRINT_OPCODE() print_opcode(opcode_names[opcode])
#define DECODE_IMM(length)  ({                                        \
    uint32_t value = 0;                                               \
    for (uint32_t i = 0; i < (length) && *ptr2pc < program_len; i++)  \
        value = (value << 8) | program[(*ptr2pc)++];                  \
    value;})

    const uint32_t reg_num = EXTRACT_REGISTER(bytecode);
    // All instructions have immediate fields, so load them now.
    const uint32_t len_field = EXTRACT_IMM_LENGTH(bytecode);
    uint32_t imm = 0;
    int32_t signed_imm = 0;
    if (len_field != 0) {
        const uint32_t imm_len = 1 << (len_field - 1);
        imm = DECODE_IMM(imm_len);
        // Sign extend imm into signed_imm.
        signed_imm = imm << ((4 - imm_len) * 8);
        signed_imm >>= (4 - imm_len) * 8;
    }
    switch (opcode) {
        case PASSDROP_OPCODE:
            if (reg_num == 0) {
                print_opcode("pass");
            } else {
                print_opcode("drop");
            }
            if (imm > 0) {
                bprintf("counter=%d", imm);
            }
            break;
        case LDB_OPCODE:
        case LDH_OPCODE:
        case LDW_OPCODE:
            PRINT_OPCODE();
            bprintf("r%d, [%u]", reg_num, imm);
            break;
        case LDBX_OPCODE:
        case LDHX_OPCODE:
        case LDWX_OPCODE:
            PRINT_OPCODE();
            if (imm) {
                bprintf("r%d, [r1+%u]", reg_num, imm);
            } else {
                bprintf("r%d, [r1]", reg_num);
            }
            break;
        case JMP_OPCODE:
            if (reg_num == 0) {
                PRINT_OPCODE();
                print_jump_target(*ptr2pc + imm, program_len);
            } else {
                v6_mode = true;
                print_opcode("data");
                bprintf("%d, ", imm);
                uint32_t len = imm;
                while (len--) bprintf("%02x", program[(*ptr2pc)++]);
            }
            break;
        case JEQ_OPCODE:
        case JNE_OPCODE:
        case JGT_OPCODE:
        case JLT_OPCODE:
        case JSET_OPCODE:
        case JNSET_OPCODE: {
            PRINT_OPCODE();
            bprintf("r0, ");
            // Load second immediate field.
            if (reg_num == 1) {
                bprintf("r1, ");
            } else if (len_field == 0) {
                bprintf("0, ");
            } else {
                uint32_t cmp_imm = DECODE_IMM(1 << (len_field - 1));
                bprintf("0x%x, ", cmp_imm);
            }
            print_jump_target(*ptr2pc + imm, program_len);
            break;
        }
        case JBSMATCH_OPCODE: {
            if (reg_num == 0) {
                print_opcode("jbsne");
            } else {
                print_opcode("jbseq");
            }
            bprintf("r0, ");
            const uint32_t cmp_imm = DECODE_IMM(1 << (len_field - 1));
            const uint32_t cnt = (cmp_imm >> 11) + 1; // 1+, up to 32 fits in u16
            const uint32_t len = cmp_imm & 2047; // 0..2047
            bprintf("(%u), ", len);
            print_jump_target(*ptr2pc + imm + cnt * len, program_len);
            bprintf(", ");
            if (cnt > 1) {
                bprintf("{ ");
            }
            for (uint32_t i = 0; i < cnt; ++i) {
                for (uint32_t j = 0; j < len; ++j) {
                    uint8_t byte = program[(*ptr2pc)++];
                    bprintf("%02x", byte);
                }
                if (i != cnt - 1) {
                    bprintf(", ");
                }
            }
            if (cnt > 1) {
                bprintf(" }[%d]", cnt);
            }
            break;
        }
        case SH_OPCODE:
            PRINT_OPCODE();
            if (reg_num) {
                bprintf("r0, r1");
            } else {
                bprintf("r0, %d", signed_imm);
            }
            break;
        case ADD_OPCODE:
        case AND_OPCODE: {
            PRINT_OPCODE();
            if (is_v6) {
                bprintf(reg_num == 0 ? "r0, " : "r1, ");
                if (!imm) {
                    bprintf(reg_num == 1 ? "r0, " : "r1, ");
                } else {
                    bprintf("%d", signed_imm);
                }
            } else {
                if (reg_num) {
                    bprintf("r0, r1");
                } else {
                    bprintf("r0, %u", imm);
                }
            }
            break;
        }
        case MUL_OPCODE:
        case DIV_OPCODE:
        case OR_OPCODE:
            PRINT_OPCODE();
            if (reg_num) {
                bprintf("r0, r1");
            } else if (!imm && opcode == DIV_OPCODE) {
                bprintf("pass (div 0)");
            } else {
                bprintf("r0, %u", imm);
            }
            break;
        case LI_OPCODE:
            PRINT_OPCODE();
            bprintf("r%d, %d", reg_num, signed_imm);
            break;
        case EXT_OPCODE:
            if (
// If LDM_EXT_OPCODE is 0 and imm is compared with it, a compiler error will result,
// instead just enforce that imm is unsigned (so it's always greater or equal to 0).
#if LDM_EXT_OPCODE == 0
                ENFORCE_UNSIGNED(imm) &&
#else
                imm >= LDM_EXT_OPCODE &&
#endif
                imm < (LDM_EXT_OPCODE + MEMORY_ITEMS)) {
                print_opcode("ldm");
                bprintf("r%d, m[%u]", reg_num, imm - LDM_EXT_OPCODE);
            } else if (imm >= STM_EXT_OPCODE && imm < (STM_EXT_OPCODE + MEMORY_ITEMS)) {
                print_opcode("stm");
                bprintf("r%d, m[%u]", reg_num, imm - STM_EXT_OPCODE);
            } else switch (imm) {
                case NOT_EXT_OPCODE:
                    print_opcode("not");
                    bprintf("r%d", reg_num);
                    break;
                case NEG_EXT_OPCODE:
                    print_opcode("neg");
                    bprintf("r%d", reg_num);
                    break;
                case SWAP_EXT_OPCODE:
                    print_opcode("swap");
                    break;
                case MOV_EXT_OPCODE:
                    print_opcode("mov");
                    bprintf("r%d, r%d", reg_num, reg_num ^ 1);
                    break;
                case ALLOCATE_EXT_OPCODE:
                    print_opcode("allocate");
                    if (reg_num == 0) {
                        bprintf("r%d", reg_num);
                    } else {
                        uint32_t alloc_len = DECODE_IMM(2);
                        bprintf("%d", alloc_len);
                    }
                    break;
                case TRANSMIT_EXT_OPCODE:
                    print_opcode(reg_num ? "transmitudp" : "transmit");
                    u8 ip_ofs = DECODE_IMM(1);
                    u8 csum_ofs = DECODE_IMM(1);
                    if (csum_ofs < 255) {
                        u8 csum_start = DECODE_IMM(1);
                        u16 partial_csum = DECODE_IMM(2);
                        bprintf("ip_ofs=%d, csum_ofs=%d, csum_start=%d, partial_csum=0x%04x",
                                ip_ofs, csum_ofs, csum_start, partial_csum);
                    } else {
                        bprintf("ip_ofs=%d", ip_ofs);
                    }
                    break;
                case EWRITE1_EXT_OPCODE: print_opcode("ewrite1"); bprintf("r%d", reg_num); break;
                case EWRITE2_EXT_OPCODE: print_opcode("ewrite2"); bprintf("r%d", reg_num); break;
                case EWRITE4_EXT_OPCODE: print_opcode("ewrite4"); bprintf("r%d", reg_num); break;
                case EPKTDATACOPYIMM_EXT_OPCODE:
                case EPKTDATACOPYR1_EXT_OPCODE: {
                    if (reg_num == 0) {
                        print_opcode("epktcopy");
                    } else {
                        print_opcode("edatacopy");
                    }
                    if (imm == EPKTDATACOPYIMM_EXT_OPCODE) {
                        uint32_t len = DECODE_IMM(1);
                        bprintf("src=r0, len=%d", len);
                    } else {
                        bprintf("src=r0, len=r1");
                    }

                    break;
                }
                case JDNSAMATCH_EXT_OPCODE:
                case JDNSQMATCH_EXT_OPCODE:
                case JDNSQMATCH1_EXT_OPCODE:
                case JDNSQMATCH2_EXT_OPCODE:
                case JDNSAMATCHSAFE_EXT_OPCODE:
                case JDNSQMATCHSAFE_EXT_OPCODE:
                case JDNSQMATCHSAFE1_EXT_OPCODE:
                case JDNSQMATCHSAFE2_EXT_OPCODE: {
                    uint32_t offs = DECODE_IMM(1 << (len_field - 1));
                    int qtype1 = -1;
                    int qtype2 = -1;
                    switch (imm) {
                        case JDNSQMATCH_EXT_OPCODE:
                            print_opcode(reg_num ? "jdnsqeq" : "jdnsqne");
                            qtype1 = DECODE_IMM(1);
                            break;
                        case JDNSQMATCHSAFE_EXT_OPCODE:
                            print_opcode(reg_num ? "jdnsqeqsafe" : "jdnsqnesafe");
                            qtype1 = DECODE_IMM(1);
                            break;
                        case JDNSAMATCH_EXT_OPCODE:
                            print_opcode(reg_num ? "jdnsaeq" : "jdnsane"); break;
                        case JDNSAMATCHSAFE_EXT_OPCODE:
                            print_opcode(reg_num ? "jdnsaeqsafe" : "jdnsanesafe"); break;
                        case JDNSQMATCH2_EXT_OPCODE:
                            qtype1 = DECODE_IMM(1);
                            qtype2 = DECODE_IMM(1);
                            print_opcode(reg_num ? "jdnsqeq2" : "jdnsqne2");
                            break;
                        case JDNSQMATCHSAFE2_EXT_OPCODE:
                            qtype1 = DECODE_IMM(1);
                            qtype2 = DECODE_IMM(1);
                            print_opcode(reg_num ? "jdnsqeqsafe2" : "jdnsqnesafe2");
                            break;
                        case JDNSQMATCH1_EXT_OPCODE:
                            qtype1 = DECODE_IMM(2);
                            print_opcode(reg_num ? "jdnsqeq1" : "jdnsqne1");
                            break;
                        case JDNSQMATCHSAFE1_EXT_OPCODE:
                            qtype1 = DECODE_IMM(2);
                            print_opcode(reg_num ? "jdnsqeqsafe1" : "jdnsqnesafe1");
                            break;
                        default:
                            bprintf("unknown_ext %u", imm); break;
                    }
                    bprintf("r0, ");
                    uint32_t end = *ptr2pc;
                    while (end + 1 < program_len && !(program[end] == 0 && program[end + 1] == 0)) {
                        end++;
                    }
                    end += 2;
                    print_jump_target(end + offs, program_len);
                    bprintf(", ");
                    if (imm == JDNSQMATCH_EXT_OPCODE || imm == JDNSQMATCHSAFE_EXT_OPCODE ||
                        imm == JDNSQMATCH1_EXT_OPCODE || imm == JDNSQMATCHSAFE1_EXT_OPCODE) {
                        print_qtype(qtype1);
                    } else if (imm == JDNSQMATCH2_EXT_OPCODE || imm == JDNSQMATCHSAFE2_EXT_OPCODE) {
                        print_qtype(qtype1);
                        print_qtype(qtype2);
                    }
                    while (*ptr2pc < end) {
                        uint8_t byte = program[(*ptr2pc)++];
                        // value == 0xff is a wildcard that consumes the whole label.
                        // values < 0x40 could be lengths, but - and 0..9 are in practice usually
                        // too long to be lengths so print them as characters. All other chars < 0x40
                        // are not valid in dns character.
                        if (byte == 0xff) {
                            bprintf("(*)");
                        } else if (byte == '-' || (byte >= '0' && byte <= '9') || byte >= 0x40) {
                            bprintf("%c", byte);
                        } else {
                            bprintf("(%d)", byte);
                        }
                    }
                    break;
                }
                case JONEOF_EXT_OPCODE: {
                    const uint32_t imm_len = 1 << (len_field - 1);
                    uint32_t jump_offs = DECODE_IMM(imm_len);
                    uint8_t imm3 = DECODE_IMM(1);
                    bool jmp = imm3 & 1;
                    uint8_t len = ((imm3 >> 1) & 3) + 1;
                    uint8_t cnt = (imm3 >> 3) + 2;
                    if (jmp) {
                        print_opcode("jnoneof");
                    } else {
                        print_opcode("joneof");
                    }
                    bprintf("r%d, ", reg_num);
                    print_jump_target(*ptr2pc + jump_offs + cnt * len, program_len);
                    bprintf(", { ");
                    while (cnt--) {
                        uint32_t v = DECODE_IMM(len);
                        if (cnt) {
                            bprintf("%d, ", v);
                        } else {
                            bprintf("%d ", v);
                        }
                    }
                    bprintf("}");
                    break;
                }
                case EXCEPTIONBUFFER_EXT_OPCODE: {
                    uint32_t buf_size = DECODE_IMM(2);
                    print_opcode("debugbuf");
                    bprintf("size=%d", buf_size);
                    break;
                }
                default:
                    bprintf("unknown_ext %u", imm);
                    break;
            }
            break;
        case LDDW_OPCODE:
        case STDW_OPCODE:
            PRINT_OPCODE();
            if (v6_mode) {
                if (opcode == LDDW_OPCODE) {
                    bprintf("r%u, counter=%d", reg_num, imm);
                } else {
                    bprintf("counter=%d, r%u", imm, reg_num);
                }
            } else {
                if (signed_imm > 0) {
                    bprintf("r%u, [r%u+%d]", reg_num, reg_num ^ 1, signed_imm);
                } else if (signed_imm < 0) {
                    bprintf("r%u, [r%u-%d]", reg_num, reg_num ^ 1, -signed_imm);
                } else {
                    bprintf("r%u, [r%u]", reg_num, reg_num ^ 1);
                }
            }
            break;
        case WRITE_OPCODE: {
            PRINT_OPCODE();
            uint32_t write_len = 1 << (len_field - 1);
            if (write_len > 0) {
                bprintf("0x");
            }
            for (uint32_t i = 0; i < write_len; ++i) {
                uint8_t byte =
                    (uint8_t) ((imm >> (write_len - 1 - i) * 8) & 0xff);
                bprintf("%02x", byte);

            }
            break;
        }
        case PKTDATACOPY_OPCODE: {
            uint32_t src_offs = imm;
            uint32_t copy_len = DECODE_IMM(1);
            if (reg_num == 0) {
                print_opcode("pktcopy");
                bprintf("src=%d, len=%d", src_offs, copy_len);
            } else {
                print_opcode("datacopy");
                bprintf("src=%d, (%d)", src_offs, copy_len);
                for (uint32_t i = 0; i < copy_len; ++i) {
                    uint8_t byte = program[src_offs + i];
                    bprintf("%02x", byte);
                }
            }
            break;
        }
        // Unknown opcode
        default:
            bprintf("unknown %u", opcode);
            break;
    }
    snprintf(prefix_buf, sizeof(prefix_buf), "(%4u) ", (*ptr2pc - prev_pc));
    disas_ret ret = {
        .prefix = prefix_buf,
        .content = print_buf
    };
    return ret;
}
