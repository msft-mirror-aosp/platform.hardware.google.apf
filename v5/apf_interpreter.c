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
#include <string.h>// For memcmp

/* Begin include of apf.h */
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

#ifndef ANDROID_APF_APF_H
#define ANDROID_APF_APF_H

// A brief overview of APF:
//
// APF machine is composed of:
//  1. A read-only program consisting of bytecodes as described below.
//  2. Two 32-bit registers, called R0 and R1.
//  3. Sixteen 32-bit temporary memory slots (cleared between packets).
//  4. A read-only packet.
// The program is executed by the interpreter below and parses the packet
// to determine if the application processor (AP) should be woken up to
// handle the packet or if can be dropped.
//
// APF bytecode description:
//
// The APF interpreter uses big-endian byte order for loads from the packet
// and for storing immediates in instructions.
//
// Each instruction starts with a byte composed of:
//  Top 5 bits form "opcode" field, see *_OPCODE defines below.
//  Next 2 bits form "size field", which indicate the length of an immediate
//  value which follows the first byte.  Values in this field:
//                 0 => immediate value is 0 and no bytes follow.
//                 1 => immediate value is 1 byte big.
//                 2 => immediate value is 2 bytes big.
//                 3 => immediate value is 4 bytes big.
//  Bottom bit forms "register" field, which indicates which register this
//  instruction operates on.
//
//  There are three main categories of instructions:
//  Load instructions
//    These instructions load byte(s) of the packet into a register.
//    They load either 1, 2 or 4 bytes, as determined by the "opcode" field.
//    They load into the register specified by the "register" field.
//    The immediate value that follows the first byte of the instruction is
//    the byte offset from the beginning of the packet to load from.
//    There are "indexing" loads which add the value in R1 to the byte offset
//    to load from. The "opcode" field determines which loads are "indexing".
//  Arithmetic instructions
//    These instructions perform simple operations, like addition, on register
//    values. The result of these instructions is always written into R0. One
//    argument of the arithmetic operation is R0's value. The other argument
//    of the arithmetic operation is determined by the "register" field:
//            If the "register" field is 0 then the immediate value following
//            the first byte of the instruction is used as the other argument
//            to the arithmetic operation.
//            If the "register" field is 1 then R1's value is used as the other
//            argument to the arithmetic operation.
//  Conditional jump instructions
//    These instructions compare register R0's value with another value, and if
//    the comparison succeeds, jump (i.e. adjust the program counter). The
//    immediate value that follows the first byte of the instruction
//    represents the jump target offset, i.e. the value added to the program
//    counter if the comparison succeeds. The other value compared is
//    determined by the "register" field:
//            If the "register" field is 0 then another immediate value
//            follows the jump target offset. This immediate value is of the
//            same size as the jump target offset, and represents the value
//            to compare against.
//            If the "register" field is 1 then register R1's value is
//            compared against.
//    The type of comparison (e.g. equal to, greater than etc) is determined
//    by the "opcode" field. The comparison interprets both values being
//    compared as unsigned values.
//
//  Miscellaneous details:
//
//  Pre-filled temporary memory slot values
//    When the APF program begins execution, three of the sixteen memory slots
//    are pre-filled by the interpreter with values that may be useful for
//    programs:
//      Slot #11 contains the size (in bytes) of the APF program.
//      Slot #12 contains the total size of the APF buffer (program + data).
//      Slot #13 is filled with the IPv4 header length. This value is calculated
//               by loading the first byte of the IPv4 header and taking the
//               bottom 4 bits and multiplying their value by 4. This value is
//               set to zero if the first 4 bits after the link layer header are
//               not 4, indicating not IPv4.
//      Slot #14 is filled with size of the packet in bytes, including the
//               link-layer header if any.
//      Slot #15 is filled with the filter age in seconds. This is the number of
//               seconds since the AP sent the program to the chipset. This may
//               be used by filters that should have a particular lifetime. For
//               example, it can be used to rate-limit particular packets to one
//               every N seconds.
//  Special jump targets:
//    When an APF program executes a jump to the byte immediately after the last
//      byte of the progam (i.e., one byte past the end of the program), this
//      signals the program has completed and determined the packet should be
//      passed to the AP.
//    When an APF program executes a jump two bytes past the end of the program,
//      this signals the program has completed and determined the packet should
//      be dropped.
//  Jump if byte sequence doesn't match:
//    This is a special instruction to facilitate matching long sequences of
//    bytes in the packet. Initially it is encoded like a conditional jump
//    instruction with two exceptions:
//      The first byte of the instruction is always followed by two immediate
//        fields: The first immediate field is the jump target offset like other
//        conditional jump instructions. The second immediate field specifies the
//        number of bytes to compare.
//      These two immediate fields are followed by a sequence of bytes. These
//        bytes are compared with the bytes in the packet starting from the
//        position specified by the value of the register specified by the
//        "register" field of the instruction.

// Number of temporary memory slots, see ldm/stm instructions.
#define MEMORY_ITEMS 16
// Upon program execution, some temporary memory slots are prefilled:

// Offset inside the output buffer where the next byte of output packet should
// be written to.
#define MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET 10
#define MEMORY_OFFSET_PROGRAM_SIZE 11     // Size of program (in bytes)
#define MEMORY_OFFSET_DATA_SIZE 12        // Total size of program + data
#define MEMORY_OFFSET_IPV4_HEADER_SIZE 13 // 4*([APF_FRAME_HEADER_SIZE]&15)
#define MEMORY_OFFSET_PACKET_SIZE 14      // Size of packet in bytes.
#define MEMORY_OFFSET_FILTER_AGE 15       // Age since filter installed in seconds.

// Leave 0 opcode unused as it's a good indicator of accidental incorrect execution (e.g. data).
#define LDB_OPCODE 1    // Load 1 byte from immediate offset, e.g. "ldb R0, [5]"
#define LDH_OPCODE 2    // Load 2 bytes from immediate offset, e.g. "ldh R0, [5]"
#define LDW_OPCODE 3    // Load 4 bytes from immediate offset, e.g. "ldw R0, [5]"
#define LDBX_OPCODE 4   // Load 1 byte from immediate offset plus register, e.g. "ldbx R0, [5+R0]"
#define LDHX_OPCODE 5   // Load 2 byte from immediate offset plus register, e.g. "ldhx R0, [5+R0]"
#define LDWX_OPCODE 6   // Load 4 byte from immediate offset plus register, e.g. "ldwx R0, [5+R0]"
#define ADD_OPCODE 7    // Add, e.g. "add R0,5"
#define MUL_OPCODE 8    // Multiply, e.g. "mul R0,5"
#define DIV_OPCODE 9    // Divide, e.g. "div R0,5"
#define AND_OPCODE 10   // And, e.g. "and R0,5"
#define OR_OPCODE 11    // Or, e.g. "or R0,5"
#define SH_OPCODE 12    // Left shift, e.g. "sh R0, 5" or "sh R0, -5" (shifts right)
#define LI_OPCODE 13    // Load signed immediate, e.g. "li R0,5"
#define JMP_OPCODE 14   // Unconditional jump, e.g. "jmp label"
#define JEQ_OPCODE 15   // Compare equal and branch, e.g. "jeq R0,5,label"
#define JNE_OPCODE 16   // Compare not equal and branch, e.g. "jne R0,5,label"
#define JGT_OPCODE 17   // Compare greater than and branch, e.g. "jgt R0,5,label"
#define JLT_OPCODE 18   // Compare less than and branch, e.g. "jlt R0,5,label"
#define JSET_OPCODE 19  // Compare any bits set and branch, e.g. "jset R0,5,label"
#define JNEBS_OPCODE 20 // Compare not equal byte sequence, e.g. "jnebs R0,5,label,0x1122334455"
#define EXT_OPCODE 21   // Immediate value is one of *_EXT_OPCODE
#define LDDW_OPCODE 22  // Load 4 bytes from data address (register + simm): "lddw R0, [5+R1]"
#define STDW_OPCODE 23  // Store 4 bytes to data address (register + simm): "stdw R0, [5+R1]"
#define WRITE_OPCODE 24 // Write 1, 2 or 4 bytes imm to the output buffer, e.g. "WRITE 5"
// Copy the data from input packet or APF data region to output buffer. Register bit is
// used to specify the source of data copy: R=0 means copy from packet, R=1 means copy
// from APF data region. The source offset is encoded in the first imm and the copy length
// is encoded in the second imm. "e.g. MEMCOPY(R=0), 5, 5"
#define MEMCOPY_OPCODE 25

// Extended opcodes. These all have an opcode of EXT_OPCODE
// and specify the actual opcode in the immediate field.
#define LDM_EXT_OPCODE 0   // Load from temporary memory, e.g. "ldm R0,5"
  // Values 0-15 represent loading the different temporary memory slots.
#define STM_EXT_OPCODE 16  // Store to temporary memory, e.g. "stm R0,5"
  // Values 16-31 represent storing to the different temporary memory slots.
#define NOT_EXT_OPCODE 32  // Not, e.g. "not R0"
#define NEG_EXT_OPCODE 33  // Negate, e.g. "neg R0"
#define SWAP_EXT_OPCODE 34 // Swap, e.g. "swap R0,R1"
#define MOV_EXT_OPCODE 35  // Move, e.g. "move R0,R1"
#define ALLOC_EXT_OPCODE 36 // Allocate buffer, "e.g. ALLOC R0"
#define TRANS_EXT_OPCODE 37 // Transmit buffer, "e.g. TRANS R0"
#define EWRITE1_EXT_OPCODE 38 // Write 1 byte from register to the output buffer, e.g. "EWRITE1 R0"
#define EWRITE2_EXT_OPCODE 39 // Write 2 bytes from register to the output buffer, e.g. "EWRITE2 R0"
#define EWRITE4_EXT_OPCODE 40 // Write 4 bytes from register to the output buffer, e.g. "EWRITE4 R0"
// Copy the data from input packet to output buffer. The source offset is encoded as [Rx + second imm].
// The copy length is encoded in the third imm. "e.g. EPKTCOPY [R0 + 5], 5"
#define EPKTCOPY 41
// Copy the data from APF data region to output buffer. The source offset is encoded as [Rx + second imm].
// The copy length is encoded in the third imm. "e.g. EDATACOPY [R0 + 5], 5"
#define EDATACOPY 42
// Jumps if the UDP payload content (starting at R0) does not contain the specified QNAME,
// applying MDNS case insensitivity.
// R0: Offset to UDP payload content
// imm1: Opcode
// imm2: Label offset
// imm3(u8): Question type (PTR/SRV/TXT/A/AAAA)
// imm4(bytes): TLV-encoded QNAME list (null-terminated)
// e.g.: "jdnsqmatch R0,label,0x0c,\002aa\005local\0\0"
#define JDNSQMATCH_EXT_OPCODE 43

#define EXTRACT_OPCODE(i) (((i) >> 3) & 31)
#define EXTRACT_REGISTER(i) ((i) & 1)
#define EXTRACT_IMM_LENGTH(i) (((i) >> 1) & 3)

#endif  // ANDROID_APF_APF_H
/* End include of apf.h */

#define TO_UPPER(a) ((a) >= 'a' && (a) <= 'z' ? ((a) - ('a' - 'A')) : (a))
#define ASSERT_POINTER_IN_BOUND(p, l, r)  if ((p) < (l) || (p) >= (r)) return -1
#define DECODE_BYTES(value, len, p, l, r)                     \
    do {                                                      \
        value = 0;                                            \
        ASSERT_POINTER_IN_BOUND(((p) + (len) - 1), (l), (r)); \
        uint32_t i;                                           \
        for (i = 0; i < (len); i++)                           \
            value = (value << 8) | *p++;                      \
    } while (0)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Compares a QNAME/NAME label sequence at *src with the target_name.
 *
 * @param target_name - TLV encoded name to match against.
 * @param target_name_max_len - Maximum possible length of the target_name.
 * @param udp_payload - Pointer to the start of the UDP payload (DNS header).
 * @param udp_payload_len - Length of the UDP payload.
 * @param src - Pointer to the beginning of the label sequence.
 *              Will be updated to point to the next position after the labels.
 *
 * @return 1 if matched, 0 if not matched, -1 if an error occurs.
 */
int match_labels(const uint8_t* const target_name,
                 const uint32_t target_name_max_len,
                 const uint8_t* const udp_payload,
                 const uint32_t udp_payload_len,
                 const uint8_t** src) {
    const uint8_t* p = *src;
    ASSERT_POINTER_IN_BOUND(p, udp_payload, udp_payload + udp_payload_len);
    const uint8_t* q = target_name;
    ASSERT_POINTER_IN_BOUND(q, target_name, target_name + target_name_max_len);
    const uint8_t* next_pos = NULL;
    if (*q == 0) {
        // target name is empty.
        return -1;
    }
    int is_qname_match = 1;// bool type is not supported in c89
    uint32_t label_size;
    uint32_t i;
    // handling loop by limiting the maximum number of pointer traces.
    for (i = 0; i < udp_payload_len; i += 2) {
        ASSERT_POINTER_IN_BOUND(p, udp_payload, udp_payload + udp_payload_len);
        // handling the message compression: rfc 1035 4.1.4.
        if (*p >= 0xc0) {
            if (next_pos == NULL) { next_pos = p + 2; }
            ASSERT_POINTER_IN_BOUND(p + 1, udp_payload,
                                    udp_payload + udp_payload_len);
            uint32_t offset = (uint32_t) (((p[0] & 0x3f) << 8) | p[1]);
            // checks the offset is inside the udp payloads.
            if (offset > udp_payload_len) { return -1; }
            // rfc 1035 4.1.4 does not mention forward jump is not allowed.
            p = udp_payload + offset;
        } else if (*p < 0 || *p > 63) {
            // based on rfc 1035 2.3.4., label size is 63 octets or less.
            return -1;
        } else if (*p) {
            label_size = *p++;
            // checks labels inside the udp payloads.
            if (p + label_size > udp_payload + udp_payload_len) { return -1; }
            ASSERT_POINTER_IN_BOUND(q, target_name,
                                    target_name + target_name_max_len);
            if (is_qname_match && label_size == *q++) {
                while (label_size--) {
                    ASSERT_POINTER_IN_BOUND(p, udp_payload,
                                            udp_payload + udp_payload_len);
                    uint8_t pc = *p++;
                    ASSERT_POINTER_IN_BOUND(q, target_name,
                                            target_name + target_name_max_len);
                    is_qname_match = is_qname_match && (TO_UPPER(pc) == *q++);
                }
            } else {
                is_qname_match = 0;
                p += label_size;
            }
        } else {
            // reach the label end
            if (next_pos == NULL) { next_pos = p + 1; }
            ASSERT_POINTER_IN_BOUND(next_pos, udp_payload,
                                    udp_payload + udp_payload_len);
            *src = next_pos;
            ASSERT_POINTER_IN_BOUND(q, target_name,
                                    target_name + target_name_max_len);
            return is_qname_match && *q == 0;
        }
    }
    return -1;
}



 /**
 * Checks if a DNS packet contains any of the target names with the provided
 * question type.
 *
 * @param target_names - TLV encoded names to match against.
 * @param remain_program_len - Remaining program length.
 * @param udp_payload - Pointer to the start of the UDP payload (DNS header).
 * @param udp_payload_len - Length of the UDP payload.
 * @param question_type - Question type to match against. Use -1 to match answers.
 *
 *
 * @return 1 if matched, 0 if not matched, -1 if an error occurs.
 */
int match_name(const uint8_t* const target_names,
               const uint32_t remain_program_len,
               const uint8_t* const udp_payload,
               const uint32_t udp_payload_len,
               const int question_type) {
    const uint8_t* src = udp_payload;
    uint32_t value;
    // skip tid and flags
    DECODE_BYTES(value, 4, src, udp_payload, udp_payload + udp_payload_len);
    uint32_t num_questions;
    DECODE_BYTES(num_questions, 2, src, udp_payload, udp_payload + udp_payload_len);

    uint32_t num_answers = 0;
    DECODE_BYTES(value, 2, src, udp_payload, udp_payload + udp_payload_len);
    num_answers += value;
    DECODE_BYTES(value, 2, src, udp_payload, udp_payload + udp_payload_len);
    num_answers += value;
    DECODE_BYTES(value, 2, src, udp_payload, udp_payload + udp_payload_len);
    num_answers += value;

    const uint8_t* q = target_names;
    while (*q != 0) {
        src = udp_payload + 12;
        ASSERT_POINTER_IN_BOUND(src, udp_payload, udp_payload + udp_payload_len);
        uint32_t j;
        const uint32_t checked_label_size = (uint32_t) (q - target_names);
        // match questions
        for (j = 0; j < num_questions; ++j) {
            int rst = match_labels(q, remain_program_len - checked_label_size,
                                   udp_payload, udp_payload_len, &src);
            if (rst == -1) {
                return -1;
            }
            int qtype;
            // read qtype
            DECODE_BYTES(qtype, 2, src, udp_payload, udp_payload + udp_payload_len);
            // skip qclass
            DECODE_BYTES(value, 2, src, udp_payload, udp_payload + udp_payload_len);
            if (rst != 1) {
                continue;
            }
            if ((question_type != -1)
                && (qtype == 0xff /* TYPE_ANY */ || qtype == question_type)) {
                return 1;
            }
        }
        // match answers
        for (j = 0; j < num_answers; ++j) {
            int rst = match_labels(q, remain_program_len - checked_label_size,
                                   udp_payload, udp_payload_len, &src);
            if (rst == -1) {
                return -1;
            }
            // skip type, class, ttl
            DECODE_BYTES(value, 8, src, udp_payload, udp_payload + udp_payload_len);
            // decode rdata length
            uint32_t len;
            DECODE_BYTES(len, 2, src, udp_payload, udp_payload + udp_payload_len);
            // skip rdata
            src += len;
            if (rst == 1) {
                return rst;
            }
        }
        // move the pointer to the next name.
        while (*q != 0) {
            uint32_t len = *q++;
            if (len < 1 || len > 63) {
                return -1;
            }
            q += len;
            ASSERT_POINTER_IN_BOUND(q, target_names, target_names + remain_program_len);
        }
        q++;
        ASSERT_POINTER_IN_BOUND(q, target_names, target_names + remain_program_len);
    }
    return 0;
}

#define ETH_HEADER_LEN 14
#define IPV4_HEADER_LEN 20
#define IPV6_HEADER_LEN 40
#define UDP_HEADER_LEN 8
#define ICMP6_HEADER_LEN 4
#define ETHER_TYPE_OFFSET 12
#define TOS_FIELD_OFFSET 15
#define IPV4_PROTOCOL_OFFSET 23
#define IPV4_CHECKSUM_OFFSET 24
#define IPV4_SRCIP_OFFSET 26
#define IPV4_DSTIP_OFFSET 30
#define IPV4_UDP_CHECKSUM_OFFSET 40
#define IPV6_VERSION_OFFSET 14
#define IPV6_PROTOCOL_OFFSET 20
#define IPV6_SRCIP_OFFSET 22
#define IPV6_DSTIP_OFFSET 38
#define IPV6_UDP_CHECKSUM_OFFSET 60
#define IPV6_ICMP6_CHECKSUM_OFFSET 56

/**
 * Calculate range sum of data word by word.
 *
 * @param data - pointer to the start of the data
 * @param data_len  - length of the data
 *
 * @return the sum of data word by word
 */
static uint32_t range_sum_word(const uint8_t* const data,
                               const uint32_t data_len) {
    uint32_t sum = 0;
    uint32_t i;
    uint32_t data_prefix_len = data_len;
    if (data_len % 2 != 0) {
        sum += (uint16_t) (data[data_len - 1] << 8);
        data_prefix_len--;
    }
    for (i = 0; i < data_prefix_len; i += 2) {
        sum += (uint16_t) ((data[i] << 8) | data[i + 1]);
    }
    return sum;
}

/**
 * Calculate the checksum from the range sum.
 *
 * @param range_sum - the range sum.
 * @param is_udp - is checksum for udp
 * @return  the checksum.
 */
static uint16_t calc_checksum_from_range_sum(uint32_t range_sum, int is_udp) {
    while (range_sum >> 16) {
        range_sum = (range_sum & 0xffff) + (range_sum >> 16);
    }
    uint16_t check_sum = ~range_sum;
    if (check_sum == 0 && is_udp) {
      check_sum = ~check_sum;
    }
    return check_sum;
}

/**
 * Calculate the ipv4 header checksum
 *
 * @param ipv4_hdr - pointer to the start of the ipv4 header.
 * @param hdr_len - length of ipv4_packet.
 *
 * @return the calculated checksum
 */
static uint16_t calculate_ipv4_header_checksum(const uint8_t* const ipv4_hdr,
                                               const uint32_t hdr_len) {
    uint32_t sum = range_sum_word(ipv4_hdr, hdr_len);
    return calc_checksum_from_range_sum(sum, 0 /* is_udp */);
}

/**
 * Calculate the layer 4 checksum
 *
 * @param transmit_pkt - pointer to the start of packet.
 * @param transmit_pkt_len - the length of the transmit packet.
 * @param is_ipv4 - if it is a ipv4 packet
 *
 * @return the calculated checksum
 */
static uint16_t calculate_layer4_checksum(const uint8_t* const transmit_pkt,
                                          const uint32_t transmit_pkt_len,
                                          const int is_ipv4) {
    uint32_t sum = 0;
    uint8_t protocol;
    // pseudo header checksum
    if (is_ipv4) {
        sum += range_sum_word(transmit_pkt + IPV4_SRCIP_OFFSET, 4);
        sum += range_sum_word(transmit_pkt + IPV4_DSTIP_OFFSET, 4);
        protocol = transmit_pkt[IPV4_PROTOCOL_OFFSET];
        sum += protocol;
    } else {
        sum += range_sum_word(transmit_pkt + IPV6_SRCIP_OFFSET, 16);
        sum += range_sum_word(transmit_pkt + IPV6_DSTIP_OFFSET, 16);
        protocol = transmit_pkt[IPV6_PROTOCOL_OFFSET];
        sum += protocol;
    }
    const uint32_t ip_hdr_len = is_ipv4 ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;
    const uint8_t* layer4_hdr = transmit_pkt + ETH_HEADER_LEN + ip_hdr_len;
    const uint16_t layer4_len = transmit_pkt_len - ETH_HEADER_LEN - ip_hdr_len;
    sum += layer4_len;
    sum += range_sum_word(layer4_hdr, layer4_len);
    return calc_checksum_from_range_sum(sum, protocol == 0x11 /* is_udp */ );
}

/**
 * Calculate the transmit packet checksum if necessary
 *
 * @param transmit_pkt - pointer to the start of the transmit packet.
 * @param transmit_pkt_len - length of the transmit packet.
 * @param dscp - the value holder for the dscp value.
 *
 * @return 1 if checksum calculate, 0 if no need to calculate checksum,
 *         -1 if error occurs.
 */
int calculate_checksum_and_get_dscp(uint8_t* const transmit_pkt,
                                    uint32_t transmit_pkt_len, uint8_t* dscp) {
#define ASSERT_PKT_LEN(l) if (transmit_pkt_len < (l)) return -1
    ASSERT_PKT_LEN(ETH_HEADER_LEN);
    if (transmit_pkt[ETHER_TYPE_OFFSET] == 0x08
        && transmit_pkt[ETHER_TYPE_OFFSET + 1] == 0x06) {
        // For ARP packet, no need to calculate the checksum
        return 0;
    } else if (transmit_pkt[ETHER_TYPE_OFFSET] == 0x08
               && transmit_pkt[ETHER_TYPE_OFFSET + 1] == 0x00) {
        ASSERT_PKT_LEN(ETH_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN);
        // for IPv4, only support UDP packet
        if (transmit_pkt[IPV4_PROTOCOL_OFFSET] != 0x11) {
            return -1;
        }
        // get dscp
        *dscp = (transmit_pkt[TOS_FIELD_OFFSET] >> 2) & 0x3f;
        // calculate ipv4 checksum
        const uint16_t ipv4_checksum = calculate_ipv4_header_checksum(
            transmit_pkt + ETH_HEADER_LEN, IPV4_HEADER_LEN);
        transmit_pkt[IPV4_CHECKSUM_OFFSET] =
            (uint8_t) ((ipv4_checksum >> 8) & 0xff);
        transmit_pkt[IPV4_CHECKSUM_OFFSET + 1] =
            (uint8_t) (ipv4_checksum & 0xff);
        const uint16_t layer4_checksum = calculate_layer4_checksum(
            transmit_pkt, transmit_pkt_len, 1 /* is_ipv4 */
        );
        transmit_pkt[IPV4_UDP_CHECKSUM_OFFSET] =
            (uint8_t) ((layer4_checksum >> 8) & 0xff);
        transmit_pkt[IPV4_UDP_CHECKSUM_OFFSET + 1] =
            (uint8_t) (layer4_checksum & 0xff);
        return 1;
    } else if (transmit_pkt[ETHER_TYPE_OFFSET] == 0x86
               && transmit_pkt[ETHER_TYPE_OFFSET + 1] == 0xdd) {
        ASSERT_PKT_LEN(ETH_HEADER_LEN + IPV6_HEADER_LEN);
        if (transmit_pkt[IPV6_PROTOCOL_OFFSET] == 0x11) {
            ASSERT_PKT_LEN(ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN);
        } else if (transmit_pkt[IPV6_PROTOCOL_OFFSET] == 0x3a) {
            ASSERT_PKT_LEN(ETH_HEADER_LEN + IPV6_HEADER_LEN + ICMP6_HEADER_LEN);
        } else {
             // only support udp and icmp6
            return -1;
        }
        *dscp = ((transmit_pkt[IPV6_VERSION_OFFSET] & 0xf) << 2)
            | (transmit_pkt[IPV6_VERSION_OFFSET + 1] >> 6 & 0x3);
        const uint16_t layer4_checksum = calculate_layer4_checksum(
            transmit_pkt, transmit_pkt_len, 0 /* is_ipv4 */
        );
        if (transmit_pkt[IPV6_PROTOCOL_OFFSET] == 0x11) {
            transmit_pkt[IPV6_UDP_CHECKSUM_OFFSET] =
                (uint8_t) ((layer4_checksum >> 8) & 0xff);
            transmit_pkt[IPV6_UDP_CHECKSUM_OFFSET + 1] =
                (uint8_t) (layer4_checksum & 0xff);
        } else if (transmit_pkt[IPV6_PROTOCOL_OFFSET] == 0x3a) {
            transmit_pkt[IPV6_ICMP6_CHECKSUM_OFFSET] =
                (uint8_t) ((layer4_checksum >> 8) & 0xff);
            transmit_pkt[IPV6_ICMP6_CHECKSUM_OFFSET + 1] =
                (uint8_t) (layer4_checksum & 0xff);
        }
        return 1;
    }
    return -1;
}

#ifdef __cplusplus
}
#endif

// User hook for interpreter debug tracing.
#ifdef APF_TRACE_HOOK
extern void APF_TRACE_HOOK(uint32_t pc, const uint32_t* regs, const uint8_t* program,
                           uint32_t program_len, const uint8_t *packet, uint32_t packet_len,
                           const uint32_t* memory, uint32_t ram_len);
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
#define ENFORCE_UNSIGNED(c) ((c)==(uint32_t)(c))

uint32_t apf_version(void) {
    return 20240123;
}

int apf_run(void* ctx, uint8_t* const program, const uint32_t program_len,
            const uint32_t ram_len, const uint8_t* const packet,
            const uint32_t packet_len, const uint32_t filter_age_16384ths) {
// Is offset within program bounds?
#define IN_PROGRAM_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < program_len)
// Is offset within ram bounds?
#define IN_RAM_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < ram_len)
// Is offset within packet bounds?
#define IN_PACKET_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < packet_len)
// Is access to offset |p| length |size| within data bounds?
#define IN_DATA_BOUNDS(p, size) (ENFORCE_UNSIGNED(p) && \
                                 ENFORCE_UNSIGNED(size) && \
                                 (p) + (size) <= ram_len && \
                                 (p) >= program_len && \
                                 (p) + (size) >= (p))  // catch wraparounds
// Accept packet if not within program bounds
#define ASSERT_IN_PROGRAM_BOUNDS(p) ASSERT_RETURN(IN_PROGRAM_BOUNDS(p))
// Accept packet if not within ram bounds
#define ASSERT_IN_RAM_BOUNDS(p) ASSERT_RETURN(IN_RAM_BOUNDS(p))
// Accept packet if not within packet bounds
#define ASSERT_IN_PACKET_BOUNDS(p) ASSERT_RETURN(IN_PACKET_BOUNDS(p))
// Accept packet if not within data bounds
#define ASSERT_IN_DATA_BOUNDS(p, size) ASSERT_RETURN(IN_DATA_BOUNDS(p, size))

  // Program counter.
  uint32_t pc = 0;
// Accept packet if not within program or not ahead of program counter
#define ASSERT_FORWARD_IN_PROGRAM(p) ASSERT_RETURN(IN_PROGRAM_BOUNDS(p) && (p) >= pc)
  // Memory slot values.
  uint32_t memory[MEMORY_ITEMS] = {};
  // Fill in pre-filled memory slot values.
  memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET] = 0;
  memory[MEMORY_OFFSET_PROGRAM_SIZE] = program_len;
  memory[MEMORY_OFFSET_DATA_SIZE] = ram_len;
  memory[MEMORY_OFFSET_PACKET_SIZE] = packet_len;
  memory[MEMORY_OFFSET_FILTER_AGE] = filter_age_16384ths >> 14;
  ASSERT_IN_PACKET_BOUNDS(APF_FRAME_HEADER_SIZE);
  // Only populate if IP version is IPv4.
  if ((packet[APF_FRAME_HEADER_SIZE] & 0xf0) == 0x40) {
      memory[MEMORY_OFFSET_IPV4_HEADER_SIZE] = (packet[APF_FRAME_HEADER_SIZE] & 15) * 4;
  }
  // Register values.
  uint32_t registers[2] = {};
  // Count of instructions remaining to execute. This is done to ensure an
  // upper bound on execution time. It should never be hit and is only for
  // safety. Initialize to the number of bytes in the program which is an
  // upper bound on the number of instructions in the program.
  uint32_t instructions_remaining = program_len;

  // The output buffer pointer
  uint8_t* allocated_buffer = NULL;
  // The length of the output buffer
  uint32_t allocated_buffer_len = 0;
// Is access to offset |p| length |size| within output buffer bounds?
#define IN_OUTPUT_BOUNDS(p, size) (ENFORCE_UNSIGNED(p) && \
                                 ENFORCE_UNSIGNED(size) && \
                                 (p) + (size) <= allocated_buffer_len && \
                                 (p) + (size) >= (p))
// Accept packet if not write within allocated output buffer
#define ASSERT_IN_OUTPUT_BOUNDS(p, size) ASSERT_RETURN(IN_OUTPUT_BOUNDS(p, size))

// Decode the imm length.
#define DECODE_IMM(value, length)                                              \
    do {                                                                       \
        ASSERT_FORWARD_IN_PROGRAM(pc + length - 1);                            \
        value = 0;                                                             \
        uint32_t i;                                                            \
        for (i = 0; i < (length) && pc < program_len; i++)                     \
            value = (value << 8) | program[pc++];                              \
    } while (0)

  do {
      APF_TRACE_HOOK(pc, registers, program, program_len, packet, packet_len, memory, ram_len);
      if (pc == program_len) {
          return PASS_PACKET;
      } else if (pc == (program_len + 1)) {
          return DROP_PACKET;
      }
      ASSERT_IN_PROGRAM_BOUNDS(pc);
      const uint8_t bytecode = program[pc++];
      const uint32_t opcode = EXTRACT_OPCODE(bytecode);
      const uint32_t reg_num = EXTRACT_REGISTER(bytecode);
#define REG (registers[reg_num])
#define OTHER_REG (registers[reg_num ^ 1])
      // All instructions have immediate fields, so load them now.
      const uint32_t len_field = EXTRACT_IMM_LENGTH(bytecode);
      uint32_t imm = 0;
      int32_t signed_imm = 0;
      if (len_field != 0) {
          const uint32_t imm_len = 1 << (len_field - 1);
          ASSERT_FORWARD_IN_PROGRAM(pc + imm_len - 1);
          DECODE_IMM(imm, imm_len);
          // Sign extend imm into signed_imm.
          signed_imm = (int32_t) (imm << ((4 - imm_len) * 8));
          signed_imm >>= (4 - imm_len) * 8;
      }

      switch (opcode) {
          case LDB_OPCODE:
          case LDH_OPCODE:
          case LDW_OPCODE:
          case LDBX_OPCODE:
          case LDHX_OPCODE:
          case LDWX_OPCODE: {
              uint32_t offs = imm;
              if (opcode >= LDBX_OPCODE) {
                  // Note: this can overflow and actually decrease offs.
                  offs += registers[1];
              }
              ASSERT_IN_PACKET_BOUNDS(offs);
              uint32_t load_size = 0;
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
              const uint32_t end_offs = offs + (load_size - 1);
              // Catch overflow/wrap-around.
              ASSERT_RETURN(end_offs >= offs);
              ASSERT_IN_PACKET_BOUNDS(end_offs);
              uint32_t val = 0;
              while (load_size--)
                  val = (val << 8) | packet[offs++];
              REG = val;
              break;
          }
          case JMP_OPCODE:
              // This can jump backwards. Infinite looping prevented by instructions_remaining.
              pc += imm;
              break;
          case JEQ_OPCODE:
          case JNE_OPCODE:
          case JGT_OPCODE:
          case JLT_OPCODE:
          case JSET_OPCODE:
          case JNEBS_OPCODE: {
              // Load second immediate field.
              uint32_t cmp_imm = 0;
              if (reg_num == 1) {
                  cmp_imm = registers[1];
              } else if (len_field != 0) {
                  uint32_t cmp_imm_len = 1 << (len_field - 1);
                  ASSERT_FORWARD_IN_PROGRAM(pc + cmp_imm_len - 1);
                  DECODE_IMM(cmp_imm, cmp_imm_len);
              }
              switch (opcode) {
                  case JEQ_OPCODE:
                      if (registers[0] == cmp_imm)
                          pc += imm;
                      break;
                  case JNE_OPCODE:
                      if (registers[0] != cmp_imm)
                          pc += imm;
                      break;
                  case JGT_OPCODE:
                      if (registers[0] > cmp_imm)
                          pc += imm;
                      break;
                  case JLT_OPCODE:
                      if (registers[0] < cmp_imm)
                          pc += imm;
                      break;
                  case JSET_OPCODE:
                      if (registers[0] & cmp_imm)
                          pc += imm;
                      break;
                  case JNEBS_OPCODE: {
                      // cmp_imm is size in bytes of data to compare.
                      // pc is offset of program bytes to compare.
                      // imm is jump target offset.
                      // REG is offset of packet bytes to compare.
                      ASSERT_FORWARD_IN_PROGRAM(pc + cmp_imm - 1);
                      ASSERT_IN_PACKET_BOUNDS(REG);
                      const uint32_t last_packet_offs = REG + cmp_imm - 1;
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
          case ADD_OPCODE:
              registers[0] += reg_num ? registers[1] : imm;
              break;
          case MUL_OPCODE:
              registers[0] *= reg_num ? registers[1] : imm;
              break;
          case DIV_OPCODE: {
              const uint32_t div_operand = reg_num ? registers[1] : imm;
              ASSERT_RETURN(div_operand);
              registers[0] /= div_operand;
              break;
          }
          case AND_OPCODE:
              registers[0] &= reg_num ? registers[1] : imm;
              break;
          case OR_OPCODE:
              registers[0] |= reg_num ? registers[1] : imm;
              break;
          case SH_OPCODE: {
              const int32_t shift_val = reg_num ? (int32_t)registers[1] : signed_imm;
              if (shift_val > 0)
                  registers[0] <<= shift_val;
              else
                  registers[0] >>= -shift_val;
              break;
          }
          case LI_OPCODE:
              REG = (uint32_t) signed_imm;
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
                REG = memory[imm - LDM_EXT_OPCODE];
              } else if (imm >= STM_EXT_OPCODE && imm < (STM_EXT_OPCODE + MEMORY_ITEMS)) {
                memory[imm - STM_EXT_OPCODE] = REG;
              } else switch (imm) {
                  case NOT_EXT_OPCODE:
                    REG = ~REG;
                    break;
                  case NEG_EXT_OPCODE:
                    REG = -REG;
                    break;
                  case SWAP_EXT_OPCODE: {
                    uint32_t tmp = REG;
                    REG = OTHER_REG;
                    OTHER_REG = tmp;
                    break;
                  }
                  case MOV_EXT_OPCODE:
                    REG = OTHER_REG;
                    break;
                  case ALLOC_EXT_OPCODE:
                    ASSERT_RETURN(allocated_buffer == NULL);
                    if (reg_num == 0) {
                        allocated_buffer_len = REG;
                    } else {
                        DECODE_IMM(allocated_buffer_len, 2);
                    }
                    allocated_buffer =
                        apf_allocate_buffer(ctx, allocated_buffer_len);
                    ASSERT_RETURN(allocated_buffer != NULL);
                    memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET] = 0;
                    break;
                  case TRANS_EXT_OPCODE:
                    ASSERT_RETURN(allocated_buffer != NULL);
                    uint32_t pkt_len = memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET];
                    // If pkt_len > allocate_buffer_len, it means sth. wrong
                    // happened and the allocated_buffer should be deallocated.
                    if (pkt_len > allocated_buffer_len) {
                        apf_transmit_buffer(
                            ctx,
                            allocated_buffer,
                            0 /* len */,
                            0 /* dscp */);
                        return PASS_PACKET;
                    }
                    uint8_t dscp = 0;
                    int chksum_rst = calculate_checksum_and_get_dscp(allocated_buffer,
                                                              pkt_len, &dscp);
                    // any error happened during checksum calculation
                    if (chksum_rst == -1) {
                        apf_transmit_buffer(ctx, allocated_buffer, 0 /* len */,
                                            0 /* dscp */);
                        return PASS_PACKET;
                    }
                    apf_transmit_buffer(
                        ctx,
                        allocated_buffer,
                        pkt_len,
                        dscp);
                    allocated_buffer = NULL;
                    break;
                  case JDNSQMATCH_EXT_OPCODE: {
                    const uint32_t imm_len = 1 << (len_field - 1);
                    uint32_t jump_offs;
                    DECODE_IMM(jump_offs, imm_len);
                    int qtype;
                    DECODE_IMM(qtype, 1);
                    uint32_t udp_payload_offset = registers[0];
                    int match_rst = match_name(&program[pc],
                                         program_len - pc,
                                         packet + udp_payload_offset,
                                         packet_len - udp_payload_offset,
                                         qtype);
                    if (match_rst == -1) {
                        return PASS_PACKET;
                    }
                    while (!(program[pc] == 0 && program[pc + 1] == 0)) {
                        pc++;
                    }
                    pc += 2;
                    if (reg_num == 0 && match_rst == 0) {
                        pc += jump_offs;
                    } else if (reg_num == 1 && match_rst == 1) {
                        pc += jump_offs;
                    }
                    break;
                  }
                  // Unknown extended opcode
                  default:
                    // Bail out
                    return PASS_PACKET;
              }
              break;
          case LDDW_OPCODE: {
              uint32_t offs = OTHER_REG + (uint32_t) signed_imm;
              uint32_t size = 4;
              uint32_t val = 0;
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
              uint32_t offs = OTHER_REG + (uint32_t) signed_imm;
              uint32_t size = 4;
              uint32_t val = REG;
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
              ASSERT_RETURN(allocated_buffer != NULL);
              ASSERT_RETURN(len_field > 0);
              uint32_t offs = memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET];
              const uint32_t write_len = 1 << (len_field - 1);
              ASSERT_RETURN(write_len > 0);
              ASSERT_IN_OUTPUT_BOUNDS(offs, write_len);
              uint32_t i;
              for (i = 0; i < write_len; ++i) {
                  *(allocated_buffer + offs) =
                      (uint8_t) ((imm >> (write_len - 1 - i) * 8) & 0xff);
                  offs++;
              }
              memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET] = offs;
              break;
          }
          case MEMCOPY_OPCODE: {
              ASSERT_RETURN(allocated_buffer != NULL);
              uint32_t src_offs = imm;
              uint32_t copy_len;
              DECODE_IMM(copy_len, 1);
              uint32_t dst_offs = memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET];
              ASSERT_IN_OUTPUT_BOUNDS(dst_offs, copy_len);
              // reg_num == 0 copy from packet, reg_num == 1 copy from data.
              if (reg_num == 0) {
                  ASSERT_IN_PACKET_BOUNDS(src_offs);
                  const uint32_t last_packet_offs = src_offs + copy_len - 1;
                  ASSERT_RETURN(last_packet_offs >= src_offs);
                  ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
                  memmove(allocated_buffer + dst_offs, packet + src_offs,
                          copy_len);
              } else {
                  ASSERT_IN_RAM_BOUNDS(src_offs + copy_len - 1);
                  memmove(allocated_buffer + dst_offs, program + src_offs,
                          copy_len);
              }
              dst_offs += copy_len;
              memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET] = dst_offs;
              break;
          }
          // Unknown opcode
          default:
              // Bail out
              return PASS_PACKET;
      }
  } while (instructions_remaining--);
  return PASS_PACKET;
}
