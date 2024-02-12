/*
 * Copyright 2023, The Android Open Source Project
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

#include "apf_interpreter.h"

// TODO: Remove the dependency of the standard library and make the interpreter self-contained.
#include <string.h>  // For memcmp

#if __GNUC__ >= 7 || __clang__
#define FALLTHROUGH __attribute__((fallthrough))
#else
#define FALLTHROUGH
#endif

typedef enum { false, true } bool;

#define DO_NOT_NEED_OLD_CHECKSUM_CODE
#include "apf_defs.h"
#include "apf.h"
#include "apf_utils.h"
#include "apf_dns.h"
#include "apf_checksum.h"

// User hook for interpreter debug tracing.
#ifdef APF_TRACE_HOOK
extern void APF_TRACE_HOOK(u32 pc, const u32* regs, const u8* program,
                           u32 program_len, const u8 *packet, u32 packet_len,
                           const u32* memory, u32 ram_len);
#else
#define APF_TRACE_HOOK(pc, regs, program, program_len, packet, packet_len, memory, memory_len) \
    do { /* nop*/                                                                              \
    } while (0)
#endif

// Frame header size should be 14
#define APF_FRAME_HEADER_SIZE 14
// Return code indicating "packet" should accepted.
#define PASS_PACKET 1
// Return code indicating "packet" should be dropped.
#define DROP_PACKET 0
// Verify an internal condition and accept packet if it fails.
#define ASSERT_RETURN(c) if (!(c)) return PASS_PACKET
// If "c" is of an unsigned type, generate a compile warning that gets promoted to an error.
// This makes bounds checking simpler because ">= 0" can be avoided. Otherwise adding
// superfluous ">= 0" with unsigned expressions generates compile warnings.
#define ENFORCE_UNSIGNED(c) ((c)==(u32)(c))

u32 apf_version(void) {
    return 20240126;
}

typedef struct {
    void *caller_ctx;  // Passed in to interpreter, passed through to alloc/transmit.
    u8* tx_buf;        // The output buffer pointer
    u32 tx_buf_len;    // The length of the output buffer
//  u8 err_code;       //
    u8 v6;             // Set to 1 by first jmpdata (APFv6+) instruction
//  u16 packet_len;    //
    u32 pc;            // Program counter.
    u32 registers[2];  // Register values.
    memory_type mem;   // Memory slot values.
} apf_context;

static int do_apf_run(apf_context* ctx, u8* const program, const u32 program_len,
                      const u32 ram_len, const u8* const packet,
                      const u32 packet_len) {
// Is offset within ram bounds?
#define IN_RAM_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < ram_len)
// Is offset within packet bounds?
#define IN_PACKET_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < packet_len)
// Is access to offset |p| length |size| within data bounds?
#define IN_DATA_BOUNDS(p, size) (ENFORCE_UNSIGNED(p) && \
                                 ENFORCE_UNSIGNED(size) && \
                                 (p) + (size) <= ram_len && \
                                 (p) + (size) >= (p))  // catch wraparounds
// Accept packet if not within ram bounds
#define ASSERT_IN_RAM_BOUNDS(p) ASSERT_RETURN(IN_RAM_BOUNDS(p))
// Accept packet if not within packet bounds
#define ASSERT_IN_PACKET_BOUNDS(p) ASSERT_RETURN(IN_PACKET_BOUNDS(p))
// Accept packet if not within data bounds
#define ASSERT_IN_DATA_BOUNDS(p, size) ASSERT_RETURN(IN_DATA_BOUNDS(p, size))

#define pc (ctx->pc)
#define registers (ctx->registers)
  // Counters start at end of RAM and count *backwards* so this array takes negative integers.
  u32 *counter = (u32*)(program + ram_len);

  ASSERT_IN_PACKET_BOUNDS(APF_FRAME_HEADER_SIZE);
  // Only populate if IP version is IPv4.
  if ((packet[APF_FRAME_HEADER_SIZE] & 0xf0) == 0x40) {
      ctx->mem.named.ipv4_header_size = (packet[APF_FRAME_HEADER_SIZE] & 15) * 4;
  }
  // Count of instructions remaining to execute. This is done to ensure an
  // upper bound on execution time. It should never be hit and is only for
  // safety. Initialize to the number of bytes in the program which is an
  // upper bound on the number of instructions in the program.
  u32 instructions_remaining = program_len;

// Is access to offset |p| length |size| within output buffer bounds?
#define IN_OUTPUT_BOUNDS(p, size) (ENFORCE_UNSIGNED(p) && \
                                 ENFORCE_UNSIGNED(size) && \
                                 (p) + (size) <= ctx->tx_buf_len && \
                                 (p) + (size) >= (p))
// Accept packet if not write within allocated output buffer
#define ASSERT_IN_OUTPUT_BOUNDS(p, size) ASSERT_RETURN(IN_OUTPUT_BOUNDS(p, size))

// Decode the imm length, does not do range checking.
// But note that program is at least 20 bytes shorter than ram, so first few
// immediates can always be safely decoded without exceeding ram buffer.
#define DECODE_IMM(value, length)                   \
    do {                                            \
        value = 0;                                  \
        u32 i;                                      \
        for (i = 0; i < (length); i++)              \
            value = (value << 8) | program[pc++];   \
    } while (0)

  do {
      APF_TRACE_HOOK(pc, registers, program, program_len, packet, packet_len, ctx->mem.slot, ram_len);
      if (pc == program_len + 1) return DROP_PACKET;
      if (pc >= program_len) return PASS_PACKET;

      const u8 bytecode = program[pc++];
      const u32 opcode = EXTRACT_OPCODE(bytecode);
      const u32 reg_num = EXTRACT_REGISTER(bytecode);
#define REG (registers[reg_num])
#define OTHER_REG (registers[reg_num ^ 1])
      // All instructions have immediate fields, so load them now.
      const u32 len_field = EXTRACT_IMM_LENGTH(bytecode);
      u32 imm = 0;
      s32 signed_imm = 0;
      if (len_field != 0) {
          const u32 imm_len = 1 << (len_field - 1);
          DECODE_IMM(imm, imm_len); // 1st immediate, at worst bytes 1-4 past opcode/program_len
          // Sign extend imm into signed_imm.
          signed_imm = (s32) (imm << ((4 - imm_len) * 8));
          signed_imm >>= (4 - imm_len) * 8;
      }

      u32 pktcopy_src_offset = 0;  // used for various pktdatacopy opcodes
      switch (opcode) {
          case PASSDROP_OPCODE: {
              if (len_field > 2) return PASS_PACKET;  // max 64K counters (ie. imm < 64K)
              if (imm) {
                  if (4 * imm > ram_len) return PASS_PACKET;
                  counter[-imm]++;
              }
              return reg_num ? DROP_PACKET : PASS_PACKET;
          }
          case LDB_OPCODE:
          case LDH_OPCODE:
          case LDW_OPCODE:
          case LDBX_OPCODE:
          case LDHX_OPCODE:
          case LDWX_OPCODE: {
              u32 offs = imm;
              if (opcode >= LDBX_OPCODE) {
                  // Note: this can overflow and actually decrease offs.
                  offs += registers[1];
              }
              ASSERT_IN_PACKET_BOUNDS(offs);
              u32 load_size = 0;
              switch (opcode) {
                  case LDB_OPCODE:
                  case LDBX_OPCODE:
                    load_size = 1;
                    break;
                  case LDH_OPCODE:
                  case LDHX_OPCODE:
                    load_size = 2;
                    break;
                  case LDW_OPCODE:
                  case LDWX_OPCODE:
                    load_size = 4;
                    break;
                  // Immediately enclosing switch statement guarantees
                  // opcode cannot be any other value.
              }
              const u32 end_offs = offs + (load_size - 1);
              // Catch overflow/wrap-around.
              ASSERT_RETURN(end_offs >= offs);
              ASSERT_IN_PACKET_BOUNDS(end_offs);
              u32 val = 0;
              while (load_size--)
                  val = (val << 8) | packet[offs++];
              REG = val;
              break;
          }
          case JMP_OPCODE:
              if (reg_num && !ctx->v6) {
                // First invocation of APFv6 jmpdata instruction
                counter[-1] = 0x12345678; // endianness marker
                counter[-2]++; // total packets ++
                ctx->v6 = (u8)true;
              }
              // This can jump backwards. Infinite looping prevented by instructions_remaining.
              pc += imm;
              break;
          case JEQ_OPCODE:
          case JNE_OPCODE:
          case JGT_OPCODE:
          case JLT_OPCODE:
          case JSET_OPCODE:
          case JBSMATCH_OPCODE: {
              // Load second immediate field.
              u32 cmp_imm = 0;
              if (reg_num == 1) {
                  cmp_imm = registers[1];
              } else if (len_field != 0) {
                  u32 cmp_imm_len = 1 << (len_field - 1);
                  DECODE_IMM(cmp_imm, cmp_imm_len); // 2nd imm, at worst 8 bytes past prog_len
              }
              switch (opcode) {
                  case JEQ_OPCODE:  if (registers[0] == cmp_imm) pc += imm; break;
                  case JNE_OPCODE:  if (registers[0] != cmp_imm) pc += imm; break;
                  case JGT_OPCODE:  if (registers[0] >  cmp_imm) pc += imm; break;
                  case JLT_OPCODE:  if (registers[0] <  cmp_imm) pc += imm; break;
                  case JSET_OPCODE: if (registers[0] &  cmp_imm) pc += imm; break;
                  case JBSMATCH_OPCODE: {
                      // cmp_imm is size in bytes of data to compare.
                      // pc is offset of program bytes to compare.
                      // imm is jump target offset.
                      // REG is offset of packet bytes to compare.
                      if (len_field > 2) return PASS_PACKET; // guarantees cmp_imm <= 0xFFFF
                      // pc < program_len < ram_len < 2GiB, thus pc + cmp_imm cannot wrap
                      if (!IN_RAM_BOUNDS(pc + cmp_imm - 1)) return PASS_PACKET;
                      ASSERT_IN_PACKET_BOUNDS(REG);
                      const u32 last_packet_offs = REG + cmp_imm - 1;
                      ASSERT_RETURN(last_packet_offs >= REG);
                      ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
                      if (memcmp(program + pc, packet + REG, cmp_imm))
                          pc += imm;
                      // skip past comparison bytes
                      pc += cmp_imm;
                      break;
                  }
              }
              break;
          }
          case ADD_OPCODE: registers[0] += reg_num ? registers[1] : imm; break;
          case MUL_OPCODE: registers[0] *= reg_num ? registers[1] : imm; break;
          case AND_OPCODE: registers[0] &= reg_num ? registers[1] : imm; break;
          case OR_OPCODE:  registers[0] |= reg_num ? registers[1] : imm; break;
          case DIV_OPCODE: {
              const u32 div_operand = reg_num ? registers[1] : imm;
              ASSERT_RETURN(div_operand);
              registers[0] /= div_operand;
              break;
          }
          case SH_OPCODE: {
              const s32 shift_val = reg_num ? (s32)registers[1] : signed_imm;
              if (shift_val > 0)
                  registers[0] <<= shift_val;
              else
                  registers[0] >>= -shift_val;
              break;
          }
          case LI_OPCODE:
              REG = (u32) signed_imm;
              break;
          case PKTDATACOPY_OPCODE:
              pktcopy_src_offset = imm;
              imm = PKTDATACOPYIMM_EXT_OPCODE;
              FALLTHROUGH;
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
                REG = ctx->mem.slot[imm - LDM_EXT_OPCODE];
              } else if (imm >= STM_EXT_OPCODE && imm < (STM_EXT_OPCODE + MEMORY_ITEMS)) {
                ctx->mem.slot[imm - STM_EXT_OPCODE] = REG;
              } else switch (imm) {
                  case NOT_EXT_OPCODE: REG = ~REG;      break;
                  case NEG_EXT_OPCODE: REG = -REG;      break;
                  case MOV_EXT_OPCODE: REG = OTHER_REG; break;
                  case SWAP_EXT_OPCODE: {
                    u32 tmp = REG;
                    REG = OTHER_REG;
                    OTHER_REG = tmp;
                    break;
                  }
                  case ALLOCATE_EXT_OPCODE:
                    ASSERT_RETURN(ctx->tx_buf == NULL);
                    if (reg_num == 0) {
                        ctx->tx_buf_len = REG;
                    } else {
                        DECODE_IMM(ctx->tx_buf_len, 2); // 2nd imm, at worst 6 bytes past prog_len
                    }
                    // checksumming functions requires minimum 266 byte buffer for correctness
                    if (ctx->tx_buf_len < 266) ctx->tx_buf_len = 266;
                    ctx->tx_buf = apf_allocate_buffer(ctx->caller_ctx, ctx->tx_buf_len);
                    if (!ctx->tx_buf) { counter[-3]++; return PASS_PACKET; } // allocate failure
                    memset(ctx->tx_buf, 0, ctx->tx_buf_len);
                    ctx->mem.named.tx_buf_offset = 0;
                    break;
                  case TRANSMIT_EXT_OPCODE:
                    ASSERT_RETURN(ctx->tx_buf != NULL);
                    u32 pkt_len = ctx->mem.named.tx_buf_offset;
                    // If pkt_len > allocate_buffer_len, it means sth. wrong
                    // happened and the tx_buf should be deallocated.
                    if (pkt_len > ctx->tx_buf_len) {
                        apf_transmit_buffer(ctx->caller_ctx, ctx->tx_buf, 0 /* len */, 0 /* dscp */);
                        ctx->tx_buf = NULL;
                        ctx->tx_buf_len = 0;
                        return PASS_PACKET;
                    }
                    // tx_buf_len cannot be large because we'd run out of RAM,
                    // so the above unsigned comparison effectively guarantees casting pkt_len
                    // to a signed value does not result in it going negative.
                    u8 ip_ofs, csum_ofs;
                    u8 csum_start = 0;
                    u16 partial_csum = 0;
                    DECODE_IMM(ip_ofs, 1);            // 2nd imm, at worst 5 bytes past prog_len
                    DECODE_IMM(csum_ofs, 1);          // 3rd imm, at worst 6 bytes past prog_len
                    if (csum_ofs < 255) {
                        DECODE_IMM(csum_start, 1);    // 4th imm, at worst 7 bytes past prog_len
                        DECODE_IMM(partial_csum, 2);  // 5th imm, at worst 9 bytes past prog_len
                    }
                    int dscp = csum_and_return_dscp(ctx->tx_buf, (s32)pkt_len, ip_ofs,
                                                    partial_csum, csum_start, csum_ofs,
                                                    (bool)reg_num);
                    int ret = apf_transmit_buffer(ctx->caller_ctx, ctx->tx_buf, pkt_len, dscp);
                    ctx->tx_buf = NULL;
                    ctx->tx_buf_len = 0;
                    if (ret) { counter[-4]++; return PASS_PACKET; } // transmit failure
                    break;
                  case EPKTDATACOPYIMM_EXT_OPCODE:  // 41
                  case EPKTDATACOPYR1_EXT_OPCODE:   // 42
                    pktcopy_src_offset = registers[0];
                    FALLTHROUGH;
                  case PKTDATACOPYIMM_EXT_OPCODE: { // 65536
                    u32 copy_len = registers[1];
                    if (imm != EPKTDATACOPYR1_EXT_OPCODE) {
                        DECODE_IMM(copy_len, 1); // 2nd imm, at worst 8 bytes past prog_len
                    }
                    ASSERT_RETURN(ctx->tx_buf != NULL);
                    u32 dst_offs = ctx->mem.named.tx_buf_offset;
                    ASSERT_IN_OUTPUT_BOUNDS(dst_offs, copy_len);
                    // reg_num == 0 copy from packet, reg_num == 1 copy from data.
                    if (reg_num == 0) {
                        ASSERT_IN_PACKET_BOUNDS(pktcopy_src_offset);
                        const u32 last_packet_offs = pktcopy_src_offset + copy_len - 1;
                        ASSERT_RETURN(last_packet_offs >= pktcopy_src_offset);
                        ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
                        memmove(ctx->tx_buf + dst_offs, packet + pktcopy_src_offset, copy_len);
                    } else {
                        ASSERT_IN_RAM_BOUNDS(pktcopy_src_offset + copy_len - 1);
                        memmove(ctx->tx_buf + dst_offs, program + pktcopy_src_offset, copy_len);
                    }
                    dst_offs += copy_len;
                    ctx->mem.named.tx_buf_offset = dst_offs;
                    break;
                  }
                  case JDNSQMATCH_EXT_OPCODE:       // 43
                  case JDNSAMATCH_EXT_OPCODE:       // 44
                  case JDNSQMATCHSAFE_EXT_OPCODE:   // 45
                  case JDNSAMATCHSAFE_EXT_OPCODE: { // 46
                    const u32 imm_len = 1 << (len_field - 1);
                    u32 jump_offs;
                    DECODE_IMM(jump_offs, imm_len); // 2nd imm, at worst 8 bytes past prog_len
                    int qtype = -1;
                    if (imm & 1) { // JDNSQMATCH & JDNSQMATCHSAFE are *odd* extended opcodes
                        DECODE_IMM(qtype, 1); // 3rd imm, at worst 9 bytes past prog_len
                    }
                    u32 udp_payload_offset = registers[0];
                    match_result_type match_rst = match_names(program + pc,
                                                              program + program_len,
                                                              packet + udp_payload_offset,
                                                              packet_len - udp_payload_offset,
                                                              qtype);
                    if (match_rst == error_program) return PASS_PACKET;
                    if (match_rst == error_packet) {
                        counter[-5]++; // increment error dns packet counter
                        return (imm >= JDNSQMATCHSAFE_EXT_OPCODE) ? PASS_PACKET : DROP_PACKET;
                    }
                    while (pc + 1 < program_len && !(program[pc] == 0 && program[pc + 1] == 0)) {
                        pc++;
                    }
                    pc += 2;
                    // relies on reg_num in {0,1} and match_rst being {false=0, true=1}
                    if (!(reg_num ^ (u32)match_rst)) pc += jump_offs;
                    break;
                  }
                  case EWRITE1_EXT_OPCODE:
                  case EWRITE2_EXT_OPCODE:
                  case EWRITE4_EXT_OPCODE: {
                    ASSERT_RETURN(ctx->tx_buf != NULL);
                    u32 offs = ctx->mem.named.tx_buf_offset;
                    const u32 write_len = 1 << (imm - EWRITE1_EXT_OPCODE);
                    ASSERT_IN_OUTPUT_BOUNDS(offs, write_len);
                    u32 i;
                    for (i = 0; i < write_len; ++i) {
                        *(ctx->tx_buf + offs) = (u8) ((REG >> (write_len - 1 - i) * 8) & 0xff);
                        offs++;
                    }
                    ctx->mem.named.tx_buf_offset = offs;
                    break;
                  }
                  default:  // Unknown extended opcode
                    return PASS_PACKET;  // Bail out
              }
              break;
          case LDDW_OPCODE: {
              u32 offs = OTHER_REG + (u32)signed_imm;
              u32 size = 4;
              u32 val = 0;
              // Negative offsets wrap around the end of the address space.
              // This allows us to efficiently access the end of the
              // address space with one-byte immediates without using %=.
              if (offs & 0x80000000) {
                  offs = ram_len + offs;  // unsigned overflow intended
              }
              ASSERT_IN_DATA_BOUNDS(offs, size);
              while (size--)
                  val = (val << 8) | program[offs++];
              REG = val;
              break;
          }
          case STDW_OPCODE: {
              u32 offs = OTHER_REG + (u32)signed_imm;
              u32 size = 4;
              u32 val = REG;
              // Negative offsets wrap around the end of the address space.
              // This allows us to efficiently access the end of the
              // address space with one-byte immediates without using %=.
              if (offs & 0x80000000) {
                  offs = ram_len + offs;  // unsigned overflow intended
              }
              ASSERT_IN_DATA_BOUNDS(offs, size);
              while (size--) {
                  program[offs++] = (val >> 24);
                  val <<= 8;
              }
              break;
          }
          case WRITE_OPCODE: {
              ASSERT_RETURN(ctx->tx_buf != NULL);
              ASSERT_RETURN(len_field > 0);
              u32 offs = ctx->mem.named.tx_buf_offset;
              const u32 write_len = 1 << (len_field - 1);
              ASSERT_RETURN(write_len > 0);
              ASSERT_IN_OUTPUT_BOUNDS(offs, write_len);
              u32 i;
              for (i = 0; i < write_len; ++i) {
                  *(ctx->tx_buf + offs) =
                      (u8) ((imm >> (write_len - 1 - i) * 8) & 0xff);
                  offs++;
              }
              ctx->mem.named.tx_buf_offset = offs;
              break;
          }
          default:  // Unknown opcode
              return PASS_PACKET;  // Bail out
      }
  } while (instructions_remaining--);
  return PASS_PACKET;
}

int apf_run(void* ctx, u32* const program, const u32 program_len,
            const u32 ram_len, const u8* const packet,
            const u32 packet_len, const u32 filter_age_16384ths) {
  // Due to direct 32-bit read/write access to counters at end of ram
  // APFv6 interpreter requires program & ram_len to be 4 byte aligned.
  if (3 & (uintptr_t)program) return PASS_PACKET;
  if (3 & ram_len) return PASS_PACKET;

  // We rely on ram_len + 65536 not overflowing, so require ram_len < 2GiB
  // Similarly LDDW/STDW have special meaning for negative ram offsets.
  // We also don't want garbage like program_len == 0xFFFFFFFF
  if ((program_len | ram_len) >> 31) return PASS_PACKET;

  // APFv6 requires at least 5 u32 counters at the end of ram, this makes counter[-5]++ valid
  // This cannot wrap due to previous check.
  if (program_len + 20 > ram_len) return PASS_PACKET;

  apf_context apf_ctx = {};
  apf_ctx.caller_ctx = ctx;
  // Fill in pre-filled memory slot values.
  apf_ctx.mem.named.program_size = program_len;
  apf_ctx.mem.named.ram_len = ram_len;
  apf_ctx.mem.named.packet_size = packet_len;
  apf_ctx.mem.named.filter_age = filter_age_16384ths >> 14;
  apf_ctx.mem.named.filter_age_16384ths = filter_age_16384ths;

  return do_apf_run(&apf_ctx, (u8*)program, program_len, ram_len, packet, packet_len);
}
