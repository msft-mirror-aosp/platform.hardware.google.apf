#include <stdint.h>
#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include "apf_defs.h"
#include "apf_utils.h"
#include "apf_checksum.h"

namespace apf {

TEST(ApfChecksumTest, CalcIPv4UDPChecksum) {
    // An IPv4 UDP packet with IPv4 header checksum and UDP checksum set to 0
    uint8_t ether_ipv4_udp_pkt[] = {
        0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb,
        0x38, 0xca, 0x84, 0xb7, 0x7f, 0x16,
        0x08, 0x00, // end of ethernet header
        0x45,
        0x00,
        0x00, 0x3f,
        0x43, 0xcd,
        0x40, 0x00,
        0xff,
        0x11,
        0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x03,
        0xe0, 0x00, 0x00, 0xfb, // end of ipv4 header
        0x14, 0xe9,
        0x14, 0xe9,
        0x00, 0x2b,
        0x00, 0x00, // end of udp header
        0x00, 0x00, 0x84, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x62, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00,
        0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8, 0x01, 0x09,
    };
    // Set the UDP checksum to UDP payload size
    *(__be16 *) (ether_ipv4_udp_pkt + ETH_HLEN + IPV4_HLEN + offsetof(udphdr, check)) = htons(sizeof(ether_ipv4_udp_pkt) - IPV4_HLEN - ETH_HLEN);
    uint8_t dscp = calculate_checksum_and_return_dscp(ether_ipv4_udp_pkt, sizeof(ether_ipv4_udp_pkt));
    EXPECT_EQ(dscp, 0);
    // Verify IPv4 header checksum
    EXPECT_EQ(read_be16(ether_ipv4_udp_pkt + 24), 0x9539);

    // verify UDP checksum
    EXPECT_EQ(read_be16(ether_ipv4_udp_pkt + 40), 0xa73d);
}

TEST(ApfChecksumTest, CalcIPv6UDPChecksum) {
    // An IPv6 UDP packet with UDP checksum set to 0
    uint8_t ether_ipv6_udp_pkt[] = {
        0x33, 0x33, 0x00, 0x00, 0x00, 0xfb,
        0x38, 0xca, 0x84, 0xb7, 0x7f, 0x16,
        0x86, 0xdd, // end of ethernet header
        0x60, 0x09, 0xf4, 0x6b,
        0x00, 0x2b,
        0x11,
        0xff,
        0x24, 0x0d, 0x00, 0x1a, 0x03, 0xa6, 0xc4, 0x00, 0xb7, 0x5a, 0xb4, 0x85, 0x28, 0x10, 0xad, 0x6b,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, // end of ipv6 header
        0x14, 0xe9,
        0x14, 0xe9,
        0x00, 0x2b,
        0x00, 0x00, // end of udp header
        0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x62, 0x05, 0x6c,
        0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0,
        0xa8, 0x01, 0x09
    };
    // Set the UDP checksum to UDP payload size
    *(__be16 *) (ether_ipv6_udp_pkt + ETH_HLEN + IPV6_HLEN + offsetof(udphdr, check)) = htons(sizeof(ether_ipv6_udp_pkt) - IPV6_HLEN - ETH_HLEN);
    uint8_t dscp = calculate_checksum_and_return_dscp(ether_ipv6_udp_pkt, sizeof(ether_ipv6_udp_pkt));
    EXPECT_EQ(dscp, 0);
    // verify UDP checksum
    EXPECT_EQ(read_be16(ether_ipv6_udp_pkt + 60), 0x1cbd);
}

TEST(ApfChecksumTest, CalcICMPv6Checksum) {
    // An ICMPv6 packet with checksum field set to 0
    uint8_t ether_ipv6_icmp6_pkt[] = {
        0xcc, 0x1a, 0xfa, 0xc7, 0xd2, 0xd8,
        0xbc, 0xd0, 0x74, 0x58, 0xf1, 0x4f,
        0x86, 0xdd, // end of ethernet header
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x18,
        0x3a,
        0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x12, 0x11, 0x2c, 0xdc, 0x04, 0x35, 0x11,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // end of ipv6 header
        0x88,
        0x00,
        0x00, 0x00, // end of icmpv6 header
        0x40, 0x00, 0x00, 0x00, 0x24, 0x0d, 0x00, 0x1a, 0x03, 0xa6, 0xc4, 0x00, 0xfd, 0x3d, 0x12, 0xb7,
        0x90, 0xb6, 0xe9, 0xd2
    };
    // Set the ICMPv6 checksum to ICMPv6 payload size
    *(__be16 *) (ether_ipv6_icmp6_pkt + ETH_HLEN + IPV6_HLEN + offsetof(icmp6hdr, icmp6_cksum)) = htons(sizeof(ether_ipv6_icmp6_pkt) - IPV6_HLEN - ETH_HLEN);
    uint8_t dscp = calculate_checksum_and_return_dscp(ether_ipv6_icmp6_pkt, sizeof(ether_ipv6_icmp6_pkt));
    EXPECT_EQ(dscp, 0);
    // verify layer 4 checksum
    EXPECT_EQ(read_be16(ether_ipv6_icmp6_pkt + 56), 0x8a09);
}

}  // namespace apf
